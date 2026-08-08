//! Generates vpp-offload's binary-API wire types from the vendored
//! `.api.json` files.
//!
//! Hand-transcribing `vl_api_fib_path_t` — 11 fields, a nested union,
//! and a 16-element label array — is exactly the maintenance promise
//! the plan refuses to make. The generated file is checked in and CI
//! re-runs this to diff, so a pin bump that changes the wire format
//! fails the build instead of corrupting a FIB.
//!
//! Scope is a WHITELIST, not the whole API. Ten `.api.json` files
//! reach ~900 messages; the sink needs eleven. Generating everything
//! would bury a real CRC change in noise, so [`MESSAGES`] names what
//! we encode and the type graph is closed transitively from there.
//!
//! Usage: `cargo run -p packetframe-vpp-api-codegen -- <api-dir> <out.rs>`

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

use serde_json::Value;

/// The messages the sink and supervisor actually send or receive.
///
/// `dev_*` are here because of the v7 driver pivot: the native octeon
/// driver is attached at runtime over this same socket, so the
/// supervisor's attach step is API traffic, not config-file content.
const MESSAGES: &[&str] = &[
    // Handshake + liveness.
    "sockclnt_create",
    "sockclnt_create_reply",
    "sockclnt_delete",
    "sockclnt_delete_reply",
    "control_ping",
    "control_ping_reply",
    // The FIB sink.
    "ip_route_add_del",
    "ip_route_add_del_reply",
    "ip_route_lookup",
    "ip_route_lookup_reply",
    // Reading VPP's FIB back. Also a DUMP (streamed `ip_route_details`
    // terminated by a trailing `control_ping`, same shape as
    // `sw_interface_dump`). Adoption needs it and cannot be trusted
    // without it: the resync diff derives withdrawals from the ledger,
    // and on adoption the ledger starts empty while a surviving VPP's
    // FIB does not — so a prefix withdrawn while packetframe was down
    // stays installed, where a stale more-specific keeps overriding the
    // live table. Verification cannot see it either, because it samples
    // only what the ledger knows about.
    "ip_route_dump",
    "ip_route_details",
    "ip_neighbor_add_del",
    "ip_neighbor_add_del_reply",
    // Reading VPP's neighbour table back, so adoption programs only the
    // neighbours VPP is MISSING. Re-adding an existing static neighbour
    // is not a no-op: VPP replaces the entry (the dump's own `age`
    // resets), and the replacement walks every dependent FIB entry —
    // ~1M routes hang off ONE adjacency on this topology — during which
    // traffic through it goes to null-node. Measured on the shadow
    // (2026-08-08): a 5.51 s blackhole at the moment of an otherwise
    // perfect adoption, and 21,055 blackholed packets across the three
    // drill-(d) runs that re-added it blind.
    "ip_neighbor_dump",
    "ip_neighbor_details",
    // Interface state.
    "sw_interface_set_flags",
    "sw_interface_set_flags_reply",
    // Making a member port able to FORWARD, which admin-up does not.
    //
    // Both were found by tracing a live VPP on 2026-08-07, in this
    // order, each hiding behind the previous one:
    //
    // - Without the PF's MAC on the interface, every steered frame is
    //   punted `ethernet-input: l3 mac mismatch`. MCAM redirects frames
    //   addressed to the PF into the VF, and the VF carries its own MAC,
    //   so VPP decides they are not for it. Setting it is also what makes
    //   VPP *source* MAC-PF on tx, which the design requires so the frame
    //   leaves the same LMAC and the upstream switch sees no MAC move.
    // - With the MAC right, frames reach IP and die at `ip4-not-enabled`.
    //   A VPP interface forwards only once IPv4 is enabled on it, and the
    //   scheme that works here is a loopback holding the router address
    //   with each member unnumbered to it (no overlapping-subnet
    //   rejection at /32).
    "sw_interface_set_mac_address",
    "sw_interface_set_mac_address_reply",
    "create_loopback",
    "create_loopback_reply",
    "sw_interface_add_del_address",
    "sw_interface_add_del_address_reply",
    "sw_interface_set_unnumbered",
    "sw_interface_set_unnumbered_reply",
    // Interface discovery + link state. `sw_interface_dump` is a DUMP:
    // it streams `sw_interface_details` and is terminated by trailing a
    // `control_ping`. Two jobs neither of which is optional — adoption
    // must find the interfaces a surviving VPP already has rather than
    // re-attaching them, and verification must confirm the link is UP,
    // since a VF that is admin-up with no carrier keeps every route on
    // the right index while forwarding nothing.
    "sw_interface_dump",
    "sw_interface_details",
    // Native-driver device attach (v7 pivot).
    "dev_attach",
    "dev_attach_reply",
    "dev_detach",
    "dev_detach_reply",
    "dev_create_port_if",
    "dev_create_port_if_reply",
    "dev_remove_port_if",
    "dev_remove_port_if_reply",
];

const FILES: &[&str] = &[
    "memclnt",
    "ip",
    "ip_neighbor",
    "interface",
    "dev",
    "ip_types",
    "fib_types",
    "ethernet_types",
    "interface_types",
    "mfib_types",
];

/// One field of a message or composite type.
#[derive(Debug, Clone)]
struct Field {
    ty: String,
    name: String,
    /// `Some(None)` = variable-length (count comes from another
    /// field); `Some(Some(n))` = fixed array of n.
    array: Option<Option<usize>>,
    /// Field holding the element count for a variable-length array.
    count_from: Option<String>,
    /// `string` with a declared max; 0 means variable-length.
    string_len: Option<usize>,
}

#[derive(Debug, Default)]
struct Api {
    /// name -> (fields, crc)
    messages: BTreeMap<String, (Vec<Field>, String)>,
    types: BTreeMap<String, Vec<Field>>,
    unions: BTreeMap<String, Vec<Field>>,
    /// name -> (backing scalar, variants)
    enums: BTreeMap<String, (String, Vec<(String, i64)>)>,
    /// name -> (backing scalar, length) — length None = scalar alias
    aliases: BTreeMap<String, (String, Option<usize>)>,
}

fn parse_fields(entries: &[Value]) -> (Vec<Field>, Option<String>) {
    let mut out = Vec::new();
    let mut crc = None;
    for e in entries {
        match e {
            Value::Object(o) => {
                if let Some(c) = o.get("crc").and_then(|v| v.as_str()) {
                    crc = Some(c.to_string());
                }
            }
            Value::Array(a) => {
                let ty = a[0].as_str().unwrap_or_default().to_string();
                let name = a[1].as_str().unwrap_or_default().to_string();
                let mut field = Field {
                    ty: ty.clone(),
                    name,
                    array: None,
                    count_from: None,
                    string_len: None,
                };
                // [ty, name, len]            -> fixed array / sized string
                // [ty, name, 0, "count_fld"] -> variable length
                if let Some(len) = a.get(2).and_then(|v| v.as_u64()) {
                    if let Some(cf) = a.get(3).and_then(|v| v.as_str()) {
                        field.array = Some(None);
                        field.count_from = Some(cf.to_string());
                        if ty == "string" {
                            field.string_len = Some(0);
                        }
                    } else if ty == "string" {
                        field.string_len = Some(len as usize);
                    } else {
                        field.array = Some(Some(len as usize));
                    }
                }
                out.push(field);
            }
            _ => {}
        }
    }
    (out, crc)
}

/// Wire size of the fixed-width fields that can precede `context`.
/// Only `_vl_msg_id` (u16) and `client_index` (u32) ever do; anything
/// else appearing before it means the schema changed shape and the
/// generator must be revisited rather than guessed at.
fn presize(f: &Field) -> usize {
    match f.ty.as_str() {
        "u16" => 2,
        "u32" => 4,
        other => panic!(
            "unexpected field `{}` of type {other} before `context`",
            f.name
        ),
    }
}

/// `(byte offset of context, client_index precedes context)`.
///
/// There is no request/reply rule here — it is per message, verified
/// against the vendored schemas: `sockclnt_create` is a REQUEST with
/// no client_index, `sockclnt_create_reply` is a REPLY that has one,
/// and `control_ping_reply` carries it AFTER context. Anything that
/// assumes a pattern gets one of these three wrong, and the failure
/// mode is a silently misparsed context (mismatched reply routing) or
/// a shifted request body (VPP reading `is_add` out of a client
/// index).
fn header_geometry(fields: &[Field]) -> (usize, bool) {
    let mut offset = 0usize;
    let mut client_index_first = false;
    for f in fields {
        if f.name == "context" {
            return (offset, client_index_first);
        }
        if f.name == "client_index" {
            client_index_first = true;
        }
        offset += presize(f);
    }
    panic!("message has no `context` field");
}

fn load(dir: &Path) -> Api {
    let mut api = Api::default();
    for f in FILES {
        let path = dir.join(format!("{f}.api.json"));
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let v: Value = serde_json::from_str(&text).expect("parse json");

        for m in v["messages"].as_array().into_iter().flatten() {
            let a = m.as_array().unwrap();
            let name = a[0].as_str().unwrap().to_string();
            let (fields, crc) = parse_fields(&a[1..]);
            api.messages.insert(name, (fields, crc.unwrap_or_default()));
        }
        for t in v["types"].as_array().into_iter().flatten() {
            let a = t.as_array().unwrap();
            let (fields, _) = parse_fields(&a[1..]);
            api.types.insert(a[0].as_str().unwrap().to_string(), fields);
        }
        for u in v["unions"].as_array().into_iter().flatten() {
            let a = u.as_array().unwrap();
            let (fields, _) = parse_fields(&a[1..]);
            api.unions
                .insert(a[0].as_str().unwrap().to_string(), fields);
        }
        for e in v["enums"].as_array().into_iter().flatten() {
            let a = e.as_array().unwrap();
            let name = a[0].as_str().unwrap().to_string();
            let mut backing = "u32".to_string();
            let mut variants = Vec::new();
            for item in &a[1..] {
                match item {
                    Value::Object(o) => {
                        if let Some(t) = o.get("enumtype").and_then(|v| v.as_str()) {
                            backing = t.to_string();
                        }
                    }
                    Value::Array(p) => variants.push((
                        p[0].as_str().unwrap().to_string(),
                        p[1].as_i64().unwrap_or(0),
                    )),
                    _ => {}
                }
            }
            api.enums.insert(name, (backing, variants));
        }
        // enumflags share the enum encoding; the distinction is
        // semantic (bitset vs closed set) and does not change the wire.
        for e in v["enumflags"].as_array().into_iter().flatten() {
            let a = e.as_array().unwrap();
            let name = a[0].as_str().unwrap().to_string();
            let mut backing = "u32".to_string();
            let mut variants = Vec::new();
            for item in &a[1..] {
                match item {
                    Value::Object(o) => {
                        if let Some(t) = o.get("enumtype").and_then(|v| v.as_str()) {
                            backing = t.to_string();
                        }
                    }
                    Value::Array(p) => variants.push((
                        p[0].as_str().unwrap().to_string(),
                        p[1].as_i64().unwrap_or(0),
                    )),
                    _ => {}
                }
            }
            api.enums.insert(name, (backing, variants));
        }
        if let Some(o) = v["aliases"].as_object() {
            for (name, spec) in o {
                let ty = spec["type"].as_str().unwrap_or("u8").to_string();
                let len = spec
                    .get("length")
                    .and_then(|v| v.as_u64())
                    .map(|n| n as usize);
                api.aliases.insert(name.clone(), (ty, len));
            }
        }
    }
    api
}

/// Rust keywords that appear as VPP field names (`fib_path.type` is
/// the one that bites). Raw identifiers keep the generated field name
/// identical to the wire name, which matters when reading a struct
/// next to the .api.json that defines it.
fn field_ident(name: &str) -> String {
    const KEYWORDS: &[&str] = &[
        "as", "break", "const", "continue", "crate", "else", "enum", "extern", "false", "fn",
        "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref",
        "return", "self", "static", "struct", "super", "trait", "true", "type", "unsafe", "use",
        "where", "while", "async", "await", "dyn", "abstract", "become", "box", "do", "final",
        "macro", "override", "priv", "typeof", "unsized", "virtual", "yield", "try",
    ];
    if KEYWORDS.contains(&name) {
        format!("r#{name}")
    } else {
        name.to_string()
    }
}

/// Strip VPP's `vl_api_..._t` wrapper to the bare type name.
fn bare(ty: &str) -> String {
    ty.strip_prefix("vl_api_")
        .and_then(|s| s.strip_suffix("_t"))
        .unwrap_or(ty)
        .to_string()
}

fn is_scalar(ty: &str) -> bool {
    matches!(
        ty,
        "u8" | "i8" | "u16" | "i16" | "u32" | "i32" | "u64" | "i64" | "f64" | "bool"
    )
}

fn pascal(s: &str) -> String {
    s.split('_')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let mut c = p.chars();
            match c.next() {
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                None => String::new(),
            }
        })
        .collect()
}

/// Rust type for a field, resolving aliases/enums to their backing
/// representation. Everything is fixed-size except explicit arrays and
/// strings, which encode/decode inline.
fn rust_ty(api: &Api, f: &Field) -> String {
    let b = bare(&f.ty);
    if f.ty == "string" {
        return "String".into();
    }
    let base = if is_scalar(&b) {
        if b == "bool" {
            "bool".into()
        } else {
            b.clone()
        }
    } else if let Some((backing, len)) = api.aliases.get(&b) {
        match len {
            Some(n) => format!("[{}; {}]", backing, n),
            None => rust_ty(
                api,
                &Field {
                    ty: backing.clone(),
                    name: String::new(),
                    array: None,
                    count_from: None,
                    string_len: None,
                },
            ),
        }
    } else if let Some((backing, _)) = api.enums.get(&b) {
        backing.clone()
    } else {
        pascal(&b)
    };
    match f.array {
        Some(Some(n)) => format!("[{}; {}]", base, n),
        Some(None) => format!("Vec<{}>", base),
        None => base,
    }
}

/// Close the type graph over everything the whitelisted messages touch.
fn collect_types(api: &Api, roots: &[String]) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let mut work: Vec<String> = Vec::new();
    for r in roots {
        if let Some((fields, _)) = api.messages.get(r) {
            for f in fields {
                work.push(bare(&f.ty));
            }
        }
    }
    while let Some(t) = work.pop() {
        if is_scalar(&t) || t == "string" || !seen.insert(t.clone()) {
            continue;
        }
        if let Some((backing, _)) = api.aliases.get(&t) {
            work.push(bare(backing));
        }
        if let Some(fields) = api.types.get(&t) {
            for f in fields {
                work.push(bare(&f.ty));
            }
        }
        if let Some(fields) = api.unions.get(&t) {
            for f in fields {
                work.push(bare(&f.ty));
            }
        }
    }
    seen
}

fn emit_struct(out: &mut String, api: &Api, name: &str, fields: &[Field], is_msg: bool) {
    let rname = pascal(name);
    writeln!(out, "/// `{name}` — generated from the pinned .api.json.").unwrap();
    writeln!(out, "#[derive(Debug, Clone, Default, PartialEq)]").unwrap();
    writeln!(out, "pub struct {rname} {{").unwrap();
    for f in fields {
        // _vl_msg_id and client_index are transport-owned: the codec
        // stamps them, so exposing them invites callers to set values
        // the transport will overwrite.
        if is_msg && (f.name == "_vl_msg_id" || f.name == "client_index") {
            continue;
        }
        writeln!(
            out,
            "    pub {}: {},",
            field_ident(&f.name),
            rust_ty(api, f)
        )
        .unwrap();
    }
    writeln!(out, "}}\n").unwrap();
}

fn emit_encode(out: &mut String, api: &Api, name: &str, fields: &[Field], is_msg: bool) {
    let rname = pascal(name);
    // count field name -> the array whose length defines it.
    let counts: BTreeMap<String, String> = fields
        .iter()
        .filter_map(|f| {
            f.count_from
                .as_ref()
                .map(|c| (c.clone(), field_ident(&f.name)))
        })
        .collect();
    // Whether this message's client_index sits at the prefix position
    // (before context). Only there is it the transport's to write —
    // `send` and the fakes' `reply_head` stamp id + prefix client_index
    // and nothing else. A MID-BODY client_index (control_ping_reply
    // puts it after retval) is written by nobody on that path, and the
    // decoder consumes it positionally, so an encoder that skips it
    // produces a frame 4 bytes short of what its own decoder demands.
    // Nothing in production ever encodes a reply, which is exactly why
    // this asymmetry survived: the only encoders of replies are the
    // test fakes, and a fake whose ping replies cannot be decoded made
    // every fake-backed liveness test run on a silently failing ping.
    let ci_prefix = is_msg && header_geometry(fields).1;
    writeln!(out, "impl Encode for {rname} {{").unwrap();
    writeln!(out, "    fn encode(&self, buf: &mut Vec<u8>) {{").unwrap();
    if fields.is_empty() {
        writeln!(out, "        let _ = buf;").unwrap();
    }
    for f in fields {
        if is_msg && (f.name == "_vl_msg_id" || (f.name == "client_index" && ci_prefix)) {
            continue;
        }
        if is_msg && f.name == "client_index" {
            // Transport-owned but mid-body: emit the placeholder so
            // encode and decode agree on the frame's length.
            writeln!(
                out,
                "        buf.extend_from_slice(&0u32.to_be_bytes()); // client_index"
            )
            .unwrap();
            continue;
        }
        // A count field is DERIVED, never taken from the struct. VPP
        // parses exactly `count` elements, so a caller-supplied value
        // that disagrees with the vector either truncates the route
        // silently or walks VPP off the end of the payload — an
        // earlier revision wrote the caller's value and a golden test
        // enshrined that as intended.
        if let Some(arr) = counts.get(&f.name) {
            writeln!(
                out,
                "        buf.extend_from_slice(&(self.{arr}.len() as {}).to_be_bytes());",
                f.ty
            )
            .unwrap();
            continue;
        }
        emit_field_encode(out, api, f);
    }
    writeln!(out, "    }}\n}}\n").unwrap();
}

fn emit_field_encode(out: &mut String, api: &Api, f: &Field) {
    let b = bare(&f.ty);
    let name = field_ident(&f.name);
    let name = &name;
    if f.ty == "string" {
        match f.string_len {
            Some(0) | None => {
                // Variable-length: u32 length prefix, no NUL.
                writeln!(
                    out,
                    "        buf.extend_from_slice(&(self.{name}.len() as u32).to_be_bytes());"
                )
                .unwrap();
                writeln!(
                    out,
                    "        buf.extend_from_slice(self.{name}.as_bytes());"
                )
                .unwrap();
            }
            Some(n) => {
                // Fixed: NUL-padded to n bytes, truncated if longer.
                writeln!(out, "        {{").unwrap();
                writeln!(out, "            let mut tmp = [0u8; {n}];").unwrap();
                writeln!(out, "            let b = self.{name}.as_bytes();").unwrap();
                writeln!(out, "            let k = b.len().min({n});").unwrap();
                writeln!(out, "            tmp[..k].copy_from_slice(&b[..k]);").unwrap();
                writeln!(out, "            buf.extend_from_slice(&tmp);").unwrap();
                writeln!(out, "        }}").unwrap();
            }
        }
        return;
    }
    // Variable-length arrays are preceded by their count field, which
    // the message also carries; we write from the vec's own length so
    // the two can never disagree on the wire.
    if matches!(f.array, Some(None)) {
        writeln!(out, "        for it in &self.{name} {{").unwrap();
        emit_scalar_or_nested_encode(out, api, &b, "it", true);
        writeln!(out, "        }}").unwrap();
        return;
    }
    if matches!(f.array, Some(Some(_))) {
        writeln!(out, "        for it in self.{name}.iter() {{").unwrap();
        emit_scalar_or_nested_encode(out, api, &b, "it", true);
        writeln!(out, "        }}").unwrap();
        return;
    }
    emit_scalar_or_nested_encode(out, api, &b, &format!("self.{name}"), false);
}

fn emit_scalar_or_nested_encode(out: &mut String, api: &Api, b: &str, expr: &str, by_ref: bool) {
    let deref = if by_ref { "*" } else { "" };
    if b == "bool" {
        writeln!(
            out,
            "        buf.push(if {deref}{expr} {{ 1u8 }} else {{ 0u8 }});"
        )
        .unwrap();
    } else if is_scalar(b) {
        writeln!(
            out,
            "        buf.extend_from_slice(&({deref}{expr}).to_be_bytes());"
        )
        .unwrap();
    } else if let Some((backing, len)) = api.aliases.get(b) {
        match len {
            Some(_) => writeln!(out, "        buf.extend_from_slice(&{expr}[..]);").unwrap(),
            None => emit_scalar_or_nested_encode(out, api, &bare(backing), expr, by_ref),
        }
    } else if let Some((backing, _)) = api.enums.get(b) {
        writeln!(
            out,
            "        buf.extend_from_slice(&({deref}{expr} as {backing}).to_be_bytes());"
        )
        .unwrap();
    } else {
        writeln!(out, "        {expr}.encode(buf);").unwrap();
    }
}

fn emit_decode(out: &mut String, api: &Api, name: &str, fields: &[Field], is_msg: bool) {
    let rname = pascal(name);
    writeln!(out, "impl Decode for {rname} {{").unwrap();
    writeln!(
        out,
        "    fn decode(d: &mut Decoder<'_>) -> Result<Self, WireError> {{"
    )
    .unwrap();
    let mut assigned: Vec<String> = Vec::new();
    for f in fields {
        if is_msg && (f.name == "_vl_msg_id" || f.name == "client_index") {
            // Present on the wire, not in the struct: consume at the
            // field's own width, in schema order. control_ping_reply
            // puts client_index AFTER context, so position must come
            // from the schema rather than an assumed header shape.
            let w = if f.name == "_vl_msg_id" { "u16" } else { "u32" };
            writeln!(out, "        let _ = d.{w}()?;").unwrap();
            continue;
        }
        emit_field_decode(out, api, f);
        assigned.push(field_ident(&f.name));
    }
    writeln!(out, "        Ok(Self {{").unwrap();
    for a in &assigned {
        writeln!(out, "            {a},").unwrap();
    }
    writeln!(out, "        }})").unwrap();
    writeln!(out, "    }}\n}}\n").unwrap();
}

fn emit_field_decode(out: &mut String, api: &Api, f: &Field) {
    let b = bare(&f.ty);
    let name = field_ident(&f.name);
    let name = &name;
    if f.ty == "string" {
        match f.string_len {
            Some(0) | None => writeln!(out, "        let {name} = d.string_var()?;").unwrap(),
            Some(n) => writeln!(out, "        let {name} = d.string_fixed({n})?;").unwrap(),
        }
        return;
    }
    match f.array {
        Some(None) => {
            let cf = field_ident(&f.count_from.clone().unwrap_or_default());
            writeln!(out, "        let {name} = {{").unwrap();
            writeln!(out, "            let n = {cf} as usize;").unwrap();
            writeln!(
                out,
                "            let mut v = Vec::with_capacity(n.min(1 << 16));"
            )
            .unwrap();
            writeln!(out, "            for _ in 0..n {{").unwrap();
            write!(out, "                v.push(").unwrap();
            emit_scalar_decode_expr(out, api, &b);
            writeln!(out, ");").unwrap();
            writeln!(out, "            }}").unwrap();
            writeln!(out, "            v").unwrap();
            writeln!(out, "        }};").unwrap();
        }
        Some(Some(n)) => {
            writeln!(out, "        let {name} = {{").unwrap();
            writeln!(out, "            let mut a = <[_; {n}]>::default();").unwrap();
            writeln!(out, "            for slot in a.iter_mut() {{").unwrap();
            write!(out, "                *slot = ").unwrap();
            emit_scalar_decode_expr(out, api, &b);
            writeln!(out, ";").unwrap();
            writeln!(out, "            }}").unwrap();
            writeln!(out, "            a").unwrap();
            writeln!(out, "        }};").unwrap();
        }
        None => {
            write!(out, "        let {name} = ").unwrap();
            emit_scalar_decode_expr(out, api, &b);
            writeln!(out, ";").unwrap();
        }
    }
}

fn emit_scalar_decode_expr(out: &mut String, api: &Api, b: &str) {
    if b == "bool" {
        write!(out, "d.bool()?").unwrap();
    } else if is_scalar(b) {
        write!(out, "d.{b}()?").unwrap();
    } else if let Some((backing, len)) = api.aliases.get(b) {
        match len {
            Some(n) => write!(out, "d.bytes::<{n}>()?").unwrap(),
            None => emit_scalar_decode_expr(out, api, &bare(backing)),
        }
    } else if let Some((backing, _)) = api.enums.get(b) {
        write!(out, "d.{backing}()?").unwrap();
    } else {
        write!(out, "{}::decode(d)?", pascal(b)).unwrap();
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: {} <api-dir> <out.rs>", args[0]);
        std::process::exit(2);
    }
    let api = load(Path::new(&args[1]));

    let roots: Vec<String> = MESSAGES.iter().map(|s| s.to_string()).collect();
    for m in &roots {
        assert!(
            api.messages.contains_key(m),
            "whitelisted message {m} not found in the vendored .api.json — pin drift?"
        );
    }
    let needed = collect_types(&api, &roots);

    let mut out = String::new();
    out.push_str(
        "// @generated by packetframe-vpp-api-codegen. DO NOT EDIT.\n\
         //\n\
         // Source: crates/modules/vpp-offload/vpp-api/*.api.json, vendored from\n\
         // the pinned VPP release's published API bundle. Regenerate with:\n\
         //   cargo run -p packetframe-vpp-api-codegen -- \\\n\
         //     crates/modules/vpp-offload/vpp-api \\\n\
         //     crates/modules/vpp-offload/src/vpp_api/generated.rs\n\
         // CI re-runs this and diffs, so a pin bump that changes the wire\n\
         // format fails the build rather than corrupting a FIB.\n\
         #![allow(clippy::all, dead_code, non_camel_case_types)]\n\n\
         use super::codec::{Decode, Decoder, Encode, Message, MessageMeta, WireError};\n\n",
    );

    // Per-message metadata. The handshake's table is keyed by
    // name_crc (so a CRC mismatch is a loud refusal), and the header
    // geometry is what lets the transport stamp requests and locate
    // `context` in replies WITHOUT assuming a uniform header — which
    // the schemas do not have.
    out.push_str(
        "/// `(name, crc, context_offset, client_index_precedes_context)`\n\
         /// for every message this client speaks.\n\
         ///\n\
         /// `context_offset` is where `context` sits in the full wire\n\
         /// payload; the transport needs it to correlate a reply before\n\
         /// it knows the message type. It is NOT constant: replies with\n\
         /// a leading client_index put context at 6, most at 2.\n",
    );
    out.push_str("pub const MESSAGE_META: &[MessageMeta] = &[\n");
    for m in &roots {
        let (fields, crc) = &api.messages[m];
        let (off, ci) = header_geometry(fields);
        writeln!(
            out,
            "    MessageMeta {{ name: \"{m}\", crc: \"{crc}\", context_offset: {off}, client_index_prefix: {ci} }},"
        )
        .unwrap();
    }
    out.push_str("];\n\n");

    for t in &needed {
        if let Some((backing, variants)) = api.enums.get(t) {
            writeln!(out, "// enum {t} : {backing}").unwrap();
            for (vn, vv) in variants {
                writeln!(
                    out,
                    "pub const {}: {backing} = {vv};",
                    vn.to_uppercase().replace('-', "_")
                )
                .unwrap();
            }
            out.push('\n');
        }
    }

    // Unions are fixed-size overlays on the wire; VPP sizes them to
    // their largest member. Only address_union is in scope, and its
    // largest member is ip6 (16 bytes) — emit as raw bytes with typed
    // accessors so the discriminator stays the caller's business.
    for t in &needed {
        if let Some(fields) = api.unions.get(t) {
            let size = fields
                .iter()
                .map(|f| match api.aliases.get(&bare(&f.ty)) {
                    Some((_, Some(n))) => *n,
                    _ => 0,
                })
                .max()
                .unwrap_or(0);
            let rname = pascal(t);
            writeln!(out, "/// `{t}` — fixed {size}-byte union overlay.").unwrap();
            writeln!(out, "#[derive(Debug, Clone, Copy, PartialEq)]").unwrap();
            writeln!(out, "pub struct {rname}(pub [u8; {size}]);\n").unwrap();
            writeln!(out, "impl Default for {rname} {{").unwrap();
            writeln!(
                out,
                "    fn default() -> Self {{ Self([0u8; {size}]) }}\n}}\n"
            )
            .unwrap();
            writeln!(out, "impl Encode for {rname} {{").unwrap();
            writeln!(
                out,
                "    fn encode(&self, buf: &mut Vec<u8>) {{ buf.extend_from_slice(&self.0); }}\n}}\n"
            )
            .unwrap();
            writeln!(out, "impl Decode for {rname} {{").unwrap();
            writeln!(out, "    fn decode(d: &mut Decoder<'_>) -> Result<Self, WireError> {{ Ok(Self(d.bytes::<{size}>()?)) }}\n}}\n").unwrap();
        }
    }

    for t in &needed {
        if let Some(fields) = api.types.get(t) {
            emit_struct(&mut out, &api, t, fields, false);
            emit_encode(&mut out, &api, t, fields, false);
            emit_decode(&mut out, &api, t, fields, false);
        }
    }

    for m in &roots {
        let (fields, crc) = &api.messages[m];
        emit_struct(&mut out, &api, m, fields, true);
        emit_encode(&mut out, &api, m, fields, true);
        emit_decode(&mut out, &api, m, fields, true);
        let (off, ci) = header_geometry(fields);
        let rname = pascal(m);
        writeln!(out, "impl Message for {rname} {{").unwrap();
        writeln!(out, "    const NAME: &'static str = \"{m}\";").unwrap();
        writeln!(out, "    const CRC: &'static str = \"{crc}\";").unwrap();
        writeln!(out, "    const CONTEXT_OFFSET: usize = {off};").unwrap();
        writeln!(out, "    const CLIENT_INDEX_PREFIX: bool = {ci};").unwrap();
        writeln!(
            out,
            "    fn set_context(&mut self, context: u32) {{ self.context = context; }}"
        )
        .unwrap();
        writeln!(out, "}}\n").unwrap();
    }

    std::fs::write(&args[2], out).expect("write output");
    eprintln!(
        "generated {} messages + {} types -> {}",
        roots.len(),
        needed.len(),
        args[2]
    );
}
