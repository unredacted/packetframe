# probe

A one-shot diagnostic that answers "what does this driver actually hand
to XDP?". It attaches a minimal XDP program to an interface, records
the first 16 bytes and the length of each packet it sees, detaches,
and prints what it found.

It exists because some drivers accept a native XDP attach but do not
point `xdp->data` at the Ethernet header. When that happens fast-path
runs but classifies every frame as `pass_not_ip`. The probe shows the
raw head bytes so that case can be told apart from a config problem.

**Status:** production. The probe only observes: every packet gets
`XDP_PASS`, and traffic is not modified.

## Usage

```sh
sudo packetframe probe --iface eth0 --mode native  --duration 2s
sudo packetframe probe --iface eth0 --mode generic --duration 2s
sudo packetframe probe --iface eth0 --mode native  --duration 2s --offset 128
```

| Flag | Default | Meaning |
|---|---|---|
| `--iface` | (required) | Interface to attach to |
| `--mode` | `auto` | `native`, `generic`, or `auto` (native, falling back to generic) |
| `--duration` | `10s` | How long to sample (`500ms`, `30s`, `1m`, or bare seconds) |
| `--offset` | `0` | Byte offset from `xdp->data` to sample at, up to 512; for drivers that point into headroom |

The output lists each sample with a relative timestamp, its length and
its head bytes in hex, then a verdict:

- **≥ 90 % plausible ethertypes** at bytes 12–13 (IPv4, IPv6, ARP,
  802.1Q, 802.1ad): the driver delivers standard Ethernet frames.
- **≤ 10 %**: the head is not Ethernet, which usually means a driver
  descriptor prefix. Run again with `--mode generic` to compare with
  what the kernel sees.
- The report also prints any prefix of 8 or more bytes shared by every
  sample. It calls that prefix a likely descriptor only when the
  ethertypes are also implausible (≤ 10 %), calls it inconclusive when
  they are mixed, and with plausible ethertypes (≥ 90 %) says the prefix
  fits a single L2 neighbour instead: traffic from one neighbour has
  the same destination and source MAC on every frame, and often the
  same ethertype and IP header start, so a conformant driver can share
  all 16 bytes. The shared prefix on its own proves nothing;
  go by the ethertype percentage and the `--mode generic` comparison.

The usual workflow is to compare `native` against `generic` on the same
interface, then use `--offset` to find where the real Ethernet header
starts.

## How it works

The BPF program (`bpf/src/main.rs`) writes a 32-byte `ProbeEvent`
(timestamp, packet length, 16 head bytes, explicit zeroed padding) to a
ring buffer for every packet. The userspace side
([`src/lib.rs`](src/lib.rs)) loads the embedded ELF, attaches it,
drains the ring buffer for the requested duration and returns the
samples. The CLI in `crates/cli/src/probe.rs` formats the report.

The probe is not a `Module`. It has no config section, no pins and no
place in the daemon lifecycle; the attach ends when the command
exits. It is built into the CLI through the `probe` cargo feature,
which is on by default.

The kernel allows one XDP program per interface, so the probe's attach
fails while fast-path holds that interface. Probe before attaching, or
detach fast-path first.

## Tests

```sh
cargo test -p packetframe-probe                                          # portable
sudo -E $(which cargo) test -p packetframe-probe --tests -- --ignored    # load + attach
```

## Further reading

- The root [README](../../../README.md#diagnosing-driver-specific-issues): diagnosing driver-specific issues
