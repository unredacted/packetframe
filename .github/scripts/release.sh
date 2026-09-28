#!/usr/bin/env bash
# Release consistency helpers for .github/workflows/release.yml.
#
#   release.sh check [<tag>]   fail unless every version source agrees
#   release.sh notes <version> print that version's CHANGELOG.md section
#
# Three things carry the version and nothing else ties them together:
# the tag (which names the release and the .deb), the root VERSION file
# (shipped in the tarball) and the workspace Cargo version (what the
# binary itself reports via CARGO_PKG_VERSION). A tag cut without the
# bump would publish a package whose binary reports the previous version,
# so the release refuses to build unless all of them agree. With no tag
# (a workflow_dispatch validation run on a branch) the tag leg is
# skipped and the rest still has to hold.
#
# Run from the repository root. Needs bash, awk and cargo.
set -euo pipefail

die() {
    echo "::error::$*" >&2
    exit 1
}

# Print the CHANGELOG.md section for exactly `## [<version>]`, without
# its heading, up to the next `## [` heading or the link-reference
# block. Prints nothing when the section is absent.
section() {
    awk -v want="## [$1]" '
        index($0, want) == 1 { found = 1; next }
        found && (/^## \[/ || /^\[[^]]+\]: /) { exit }
        found { print }
    ' CHANGELOG.md
}

# The heading line itself, so `check` can see whether it is dated.
heading() {
    awk -v want="## [$1]" 'index($0, want) == 1 { print; exit }' CHANGELOG.md
}

# A prerelease tag (0.5.0-rc1) may have its own section; if it does not,
# it is described by its base version's section.
notes_version() {
    local v="$1"
    if [ -n "$(heading "$v")" ]; then
        echo "$v"
    elif [[ "$v" == *-* ]] && [ -n "$(heading "${v%%-*}")" ]; then
        echo "${v%%-*}"
    else
        echo ""
    fi
}

cmd_check() {
    local tag="${1:-}"
    local file_version cargo_versions workspace_version

    [ -f VERSION ] || die "VERSION file missing"
    file_version="$(tr -d '[:space:]' < VERSION)"
    [ -n "$file_version" ] || die "VERSION file is empty"

    # Every workspace member, not just the root: a crate that hardcodes
    # its own version instead of `version.workspace = true` would drift.
    cargo_versions="$(cargo metadata --no-deps --format-version 1 \
        | python3 -c '
import json, sys
m = json.load(sys.stdin)
for p in m["packages"]:
    print(p["name"], p["version"])
')"
    workspace_version="$(awk '$1 == "packetframe-cli" { print $2 }' <<< "$cargo_versions")"
    [ -n "$workspace_version" ] || die "packetframe-cli not found in cargo metadata"

    local bad
    bad="$(awk -v v="$workspace_version" '$2 != v' <<< "$cargo_versions")"
    [ -z "$bad" ] || die "workspace crates disagree on the version (packetframe-cli is ${workspace_version}): ${bad//$'\n'/, }"

    [ "$file_version" = "$workspace_version" ] ||
        die "VERSION says ${file_version} but the workspace Cargo version is ${workspace_version}"

    local nv
    nv="$(notes_version "$file_version")"
    [ -n "$nv" ] || die "CHANGELOG.md has no '## [${file_version}]' section"

    if [ -n "$tag" ]; then
        local tag_version="${tag#v}"
        [ "$tag_version" = "$file_version" ] ||
            die "tag ${tag} (${tag_version}) does not match VERSION/Cargo (${file_version})"
        # A published release is dated; UNRELEASED is for main and for
        # prerelease tags (an rc is cut before the final date is known).
        if [[ "$tag_version" != *-* ]] && heading "$nv" | grep -q 'UNRELEASED'; then
            die "CHANGELOG.md '## [${nv}]' is still UNRELEASED — date it before tagging"
        fi
    fi

    echo "version ${file_version}: VERSION, Cargo workspace${tag:+, tag ${tag}} and CHANGELOG.md agree"
}

cmd_notes() {
    local v="${1:?notes needs a version}"
    local nv body
    nv="$(notes_version "$v")"
    [ -n "$nv" ] || die "CHANGELOG.md has no '## [${v}]' section"
    body="$(section "$nv")"
    [ -n "$(tr -d '[:space:]' <<< "$body")" ] || die "CHANGELOG.md '## [${nv}]' section is empty"
    printf '%s\n' "$body"
}

case "${1:-}" in
    check) shift; cmd_check "$@" ;;
    notes) shift; cmd_notes "$@" ;;
    *) die "usage: release.sh check [<tag>] | notes <version>" ;;
esac
