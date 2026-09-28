#!/usr/bin/env bash
# Cases for release.sh, run by ci.yml. Hermetic: each case runs in a
# scratch directory with its own VERSION and CHANGELOG.md, and a stub
# `cargo` on PATH whose `metadata` output is set per case, so nothing
# here builds or reads the real workspace.
set -euo pipefail

SCRIPT="$(cd "$(dirname "$0")" && pwd)/release.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/bin"
cat > "$WORK/bin/cargo" <<'STUB'
#!/usr/bin/env bash
# `cargo metadata --no-deps --format-version 1`, versions from the case.
printf '{"packages":[{"name":"packetframe-cli","version":"%s"},{"name":"packetframe-probe","version":"%s"}]}\n' \
    "${STUB_CLI_VERSION:?}" "${STUB_PROBE_VERSION:-$STUB_CLI_VERSION}"
STUB
chmod +x "$WORK/bin/cargo"

pass=0
fail=0

# case <name> <want ok|fail> <VERSION> <heading line> <cmd...>
case_() {
    local name="$1" want="$2" version="$3" heading="$4"
    shift 4
    local dir="$WORK/case"
    rm -rf "$dir" && mkdir -p "$dir"
    printf '%s\n' "$version" > "$dir/VERSION"
    printf '# Changelog\n\n%s\n\nBody line.\n\n## [0.0.1] - 2020-01-01\n\nOld.\n\n[0.5.0]: https://example.invalid\n' \
        "$heading" > "$dir/CHANGELOG.md"
    local got out
    if out="$(cd "$dir" && PATH="$WORK/bin:$PATH" bash "$SCRIPT" "$@" 2>&1)"; then
        got=ok
    else
        got=fail
    fi
    if [ "$got" = "$want" ]; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
        echo "FAIL: ${name}: want ${want}, got ${got}: ${out}"
    fi
}

export STUB_CLI_VERSION=0.5.0

# Dispatch (no tag): VERSION + Cargo + a well-formed section.
case_ "dispatch, unreleased"        ok   0.5.0 "## [0.5.0] - UNRELEASED"  check
case_ "dispatch, dated"             ok   0.5.0 "## [0.5.0] - 2026-10-01"  check
case_ "dispatch, no date"           fail 0.5.0 "## [0.5.0]"               check
case_ "dispatch, TBD"               fail 0.5.0 "## [0.5.0] - TBD"         check
case_ "dispatch, missing section"   fail 0.5.0 "## [0.4.0] - 2026-10-01"  check
case_ "VERSION vs Cargo"            fail 0.5.1 "## [0.5.1] - 2026-10-01"  check

# Final tag: must match and be dated with a real date.
case_ "tag, dated"                  ok   0.5.0 "## [0.5.0] - 2026-10-01"  check v0.5.0
case_ "tag, unreleased"             fail 0.5.0 "## [0.5.0] - UNRELEASED"  check v0.5.0
case_ "tag, no date"                fail 0.5.0 "## [0.5.0]"               check v0.5.0
case_ "tag, TBD"                    fail 0.5.0 "## [0.5.0] - TBD"         check v0.5.0
case_ "tag, lowercase unreleased"   fail 0.5.0 "## [0.5.0] - unreleased"  check v0.5.0
case_ "tag, impossible date"        fail 0.5.0 "## [0.5.0] - 2026-02-30"  check v0.5.0
case_ "tag, month 13"               fail 0.5.0 "## [0.5.0] - 2026-13-01"  check v0.5.0
case_ "tag, short date"             fail 0.5.0 "## [0.5.0] - 2026-1-1"    check v0.5.0
case_ "tag, trailing text"          fail 0.5.0 "## [0.5.0] - 2026-10-01 (final)" check v0.5.0
case_ "tag, no separator"           fail 0.5.0 "## [0.5.0] 2026-10-01"    check v0.5.0
case_ "tag mismatch"                fail 0.5.0 "## [0.5.0] - 2026-10-01"  check v0.5.1

# Prerelease tag: may use the base section, may stay UNRELEASED.
STUB_CLI_VERSION=0.5.0-rc1 case_ "rc tag, base section unreleased" ok 0.5.0-rc1 "## [0.5.0] - UNRELEASED" check v0.5.0-rc1
STUB_CLI_VERSION=0.5.0-rc1 case_ "rc tag, base section TBD"        fail 0.5.0-rc1 "## [0.5.0] - TBD"   check v0.5.0-rc1

# A crate that hardcodes its own version.
STUB_PROBE_VERSION=0.4.9 case_ "crate drift" fail 0.5.0 "## [0.5.0] - 2026-10-01" check v0.5.0

# Notes extraction.
case_ "notes present"               ok   0.5.0 "## [0.5.0] - UNRELEASED"  notes 0.5.0
case_ "notes absent"                fail 0.5.0 "## [0.5.0] - UNRELEASED"  notes 0.4.0
case_ "notes rc falls back to base" ok   0.5.0 "## [0.5.0] - UNRELEASED"  notes 0.5.0-rc1

# The extracted body stops at the next section and before link refs.
dir="$WORK/case"
body="$(cd "$dir" && PATH="$WORK/bin:$PATH" bash "$SCRIPT" notes 0.5.0)"
if [ "$(printf '%s' "$body" | tr -d '\n')" = "Body line." ]; then
    pass=$((pass + 1))
else
    fail=$((fail + 1))
    echo "FAIL: notes body: got '${body}'"
fi

echo "release.sh: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
