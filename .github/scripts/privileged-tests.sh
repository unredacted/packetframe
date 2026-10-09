#!/usr/bin/env bash
# The privileged (`#[ignore]`d) integration tests, built once by ci.yml
# and run without cargo: natively under sudo (ci.yml) and inside the
# 5.15 and 6.6 guests (qemu-verifier.yml).
#
#   privileged-tests.sh bundle <cargo-json> <out.tar.zst>
#       index the test executables that `cargo test --no-run
#       --message-format=json-render-diagnostics` reported for the
#       packages in SELECTION, and pack them with the index
#   privileged-tests.sh run <native|vm>
#       run every binary SELECTION picks for that scope with --ignored,
#       from its package directory as cargo would, all of them, and exit
#       1 if any failed or any selection matched nothing
#
# Why not cargo in the guest: it relinked the test binaries inside the
# VM's tmpfs, filled it, and the packages after fast-path never compiled.
# And the guest ran them under `bash -c '...'`, whose quoting virtme-ng
# drops (it joins the arguments after `--` with spaces), so `set -e`
# never applied and only the last cargo's exit status counted. Together
# they hid real failures on every qemu leg from 2026-04 to 2026-10. So
# the guest gets one argument-free command, and this script owns the
# exit status.
#
# Run from the repository root. bundle needs jq, tar and zstd; run needs
# only bash and the unpacked bundle.
set -euo pipefail

INDEX=target/privileged-tests.tsv

# What runs, and where: one row per `cargo test` selection.
#   scope    both = native and vm; native = the runner's own kernel only
#   package  the package's directory, relative to the repository root
#   target   * = every test target (`--tests`), lib = the library's own
#            harness (`--lib`), anything else = that integration test
#            (`--test <name>`)
#   args     extra libtest arguments
SELECTION='
both    crates/modules/fast-path            *
both    crates/modules/guard                *
both    crates/modules/neigh-snoop          *
both    crates/modules/flow-export          *
both    crates/modules/probe                *
both    crates/modules/vpp-offload          drift_netns
native  crates/sampler-shm                  *
native  crates/vpp-plugins/pf-sampler-core  *
# The sampler tmpfs for real: mounted, marked, recorded, reused across a
# restart, released, and a crowded foreign mount refused.
native  crates/modules/vpp-offload          lib  --exact sampler::tests::the_live_mount_round_trips
'

die() {
    echo "::error::$*" >&2
    exit 1
}

# SELECTION's rows, comments and blank lines dropped.
rows() {
    grep -vE '^[[:space:]]*(#|$)' <<< "$SELECTION"
}

# Whether an index row (dir kind name) is picked by a selection row's
# package and target.
picks() {
    local package="$1" target="$2" dir="$3" kind="$4" name="$5"
    [ "$dir" = "$package" ] || return 1
    case "$target" in
        '*') return 0 ;;
        lib) [ "$kind" = lib ] ;;
        *) [ "$kind" = test ] && [ "$name" = "$target" ] ;;
    esac
}

# Fail unless every selection row of the given scopes picks at least one
# index row. A renamed test or package must not silently drop out.
# (Here-strings rather than process substitution throughout: the guest's
# /dev may have no /dev/fd.)
check_coverage() {
    local scopes="$1" where package target _ dir kind name exe found
    while read -r where package target _ <&4; do
        case " $scopes " in *" $where "*) ;; *) continue ;; esac
        found=0
        while IFS=$'\t' read -r dir kind name exe <&3; do
            if picks "$package" "$target" "$dir" "$kind" "$name"; then
                found=1
                break
            fi
        done 3< "$INDEX"
        [ "$found" = 1 ] || die "no test binary for '${package} ${target}' (renamed? moved?)"
    done 4<<< "$(rows)"
}

bundle() {
    local json="$1" out="$2" packages
    [ -s "$json" ] || die "no cargo JSON at ${json}"
    mkdir -p "$(dirname "$INDEX")"
    packages="$(rows | awk '{ print $2 }' | sort -u | jq -R . | jq -sc .)"
    # One row per test executable: package dir, kind (test for
    # tests/*.rs, bin, else lib, whatever the library's crate-type),
    # target name, executable. Paths relative to the repository root,
    # which is the same on every runner, so the bundle unpacks in place.
    jq -r --arg root "$(pwd)/" --argjson packages "$packages" '
        select(.reason == "compiler-artifact" and .profile.test and .executable != null)
        | (.manifest_path | rtrimstr("/Cargo.toml") | ltrimstr($root)) as $dir
        | select(any($packages[]; . == $dir))
        | [ $dir,
            (if any(.target.kind[]; . == "test") then "test"
             elif any(.target.kind[]; . == "bin") then "bin"
             else "lib" end),
            .target.name,
            (.executable | ltrimstr($root)) ]
        | @tsv' "$json" | sort -u > "$INDEX"
    [ -s "$INDEX" ] || die "cargo reported no test executables for the selected packages"
    if cut -f4 "$INDEX" | grep -q '^/'; then
        die "a test executable lies outside $(pwd); cannot bundle it relative to the repository"
    fi
    check_coverage "both native vm"
    { echo "$INDEX"; cut -f4 "$INDEX"; } | tar --zstd -cf "$out" -T -
    echo "bundled $(wc -l < "$INDEX") test binaries into ${out} ($(du -h "$out" | cut -f1))"
}

run() {
    local scope="$1" root where package target rest dir kind name exe rc f ran=0
    local -a args=() failed=()
    case "$scope" in native | vm) ;; *) die "scope must be native or vm, not '${scope}'" ;; esac
    [ -s "$INDEX" ] || die "no ${INDEX}: unpack the test bundle first"
    check_coverage "both ${scope}"
    echo "== ${scope} privileged tests on $(uname -sr)"
    root="$(pwd)"
    while read -r where package target rest <&4; do
        [ "$where" = both ] || [ "$where" = "$scope" ] || continue
        read -ra args <<< "$rest"
        while IFS=$'\t' read -r dir kind name exe <&3; do
            picks "$package" "$target" "$dir" "$kind" "$name" || continue
            ran=$((ran + 1))
            echo "==> ${dir} (${kind} ${name}) ${args[*]}"
            rc=0
            (cd "$dir" && "${root}/${exe}" --ignored --nocapture "${args[@]}" < /dev/null) || rc=$?
            if [ "$rc" != 0 ]; then
                failed+=("${dir} (${kind} ${name}): exit ${rc}")
            fi
        done 3< "$INDEX"
    done 4<<< "$(rows)"

    echo "== ${ran} test binaries ran, ${#failed[@]} failed"
    if [ "${#failed[@]}" -gt 0 ]; then
        for f in "${failed[@]}"; do
            echo "::error::privileged tests failed: ${f}"
        done
        # 1, never 255: qemu-verifier.yml reads 255 as "the VM died".
        exit 1
    fi
}

case "${1:-}" in
    bundle)
        [ "$#" = 3 ] || die "usage: $0 bundle <cargo-json> <out.tar.zst>"
        bundle "$2" "$3"
        ;;
    run)
        [ "$#" = 2 ] || die "usage: $0 run <native|vm>"
        run "$2"
        ;;
    *) die "usage: $0 bundle <cargo-json> <out.tar.zst> | run <native|vm>" ;;
esac
