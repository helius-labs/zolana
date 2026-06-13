#!/usr/bin/env bash
# Build fixtures from an explicit fixture source tree.
#
# Expected source layout:
#   accounts/   JSON genesis/account fixtures
#
# Vendored programs:
#   spl_noop.so is fetched separately with tools/fetch-vendor-programs.sh and
#   verified against fixtures/vendor/spl-noop.lock.
#
# Source selection:
#   FIXTURES_SOURCE_DIR=/path/to/source-with-accounts
#   or FIXTURES_ACCOUNTS_DIR=/path/to/accounts
#   or ./fixtures/accounts when that directory exists
#
# Output:
#   target/fixtures/staging/        verified fixture directory
#
# Set FIXTURES_ARCHIVE=1 to additionally write:
#   target/fixtures/zolana-fixtures.tar.gz
#   target/fixtures/zolana-fixtures.tar.gz.sha256

set -euo pipefail

root=$(git rev-parse --show-toplevel)
spl_noop_lock="$root/fixtures/vendor/spl-noop.lock"
tag="fixtures-v1"
if [[ -f "$root/.fixtures-version" ]]; then
    tag=$(tr -d '[:space:]' < "$root/.fixtures-version")
fi

out="$root/target/fixtures"
staging="$out/staging"

json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

source_for() {
    case "$1" in
        bin/spl_noop.so)
            printf 'vendored SPL Noop program artifact'
            ;;
        accounts/*.json)
            printf 'generated account fixture from fixture source tree'
            ;;
        *)
            printf 'fixture source tree'
            ;;
    esac
}

lock_value() {
    awk -F= -v key="$1" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' "$spl_noop_lock"
}

if [[ -n "${FIXTURES_ACCOUNTS_DIR:-}" ]]; then
    src_accounts="$FIXTURES_ACCOUNTS_DIR"
    source_kind="accounts-directory"
    source_label="FIXTURES_ACCOUNTS_DIR"
elif [[ -n "${FIXTURES_SOURCE_DIR:-}" ]]; then
    src_accounts="$FIXTURES_SOURCE_DIR/accounts"
    source_kind="source-tree"
    source_label="FIXTURES_SOURCE_DIR"
elif [[ -d "$root/fixtures/accounts" ]]; then
    src_accounts="$root/fixtures/accounts"
    source_kind="workspace-source-tree"
    source_label="fixtures/accounts"
else
    cat >&2 <<'EOF'
error: no fixture accounts source found

Provide one of:
  FIXTURES_SOURCE_DIR=/path/to/source-with-accounts tools/build-fixtures.sh
  FIXTURES_ACCOUNTS_DIR=/path/to/accounts tools/build-fixtures.sh

The source tree must contain accounts/. Vendored programs are fetched and
verified separately.
EOF
    exit 1
fi

if [[ ! -d "$src_accounts" ]]; then
    echo "error: fixture accounts directory does not exist: $src_accounts" >&2
    exit 1
fi
if [[ -z "$(find "$src_accounts" -maxdepth 1 -type f -name '*.json' -print -quit)" ]]; then
    echo "error: fixture accounts directory has no JSON accounts: $src_accounts" >&2
    exit 1
fi

spl_noop="${SPL_NOOP_SO:-$root/target/fixtures/vendor/bin/spl_noop.so}"
expected_spl_noop_sha=$(lock_value sha256)
if [[ ! -f "$spl_noop" ]]; then
    echo "error: missing vendored spl_noop.so: $spl_noop" >&2
    echo "run: just fetch-vendor-programs" >&2
    exit 1
fi
actual_spl_noop_sha=$(shasum -a 256 "$spl_noop" | awk '{print $1}')
if [[ "$actual_spl_noop_sha" != "$expected_spl_noop_sha" ]]; then
    echo "error: vendored spl_noop.so sha256 mismatch: $spl_noop" >&2
    echo "expected: $expected_spl_noop_sha" >&2
    echo "actual  : $actual_spl_noop_sha" >&2
    exit 1
fi

rm -rf "$staging"
mkdir -p "$staging/bin" "$staging/accounts"

cp "$spl_noop" "$staging/bin/spl_noop.so"

find "$src_accounts" -maxdepth 1 -type f -name '*.json' -print0 |
    while IFS= read -r -d '' file; do
        cp "$file" "$staging/accounts/"
    done

manifest="$staging/MANIFEST.json"
{
    printf '{\n'
    printf '  "schema": 1,\n'
    printf '  "version": "%s",\n' "$(json_escape "$tag")"
    printf '  "source": {\n'
    printf '    "kind": "%s",\n' "$(json_escape "$source_kind")"
    printf '    "label": "%s"\n' "$(json_escape "$source_label")"
    printf '  },\n'
    printf '  "vendor": {\n'
    printf '    "spl_noop": {\n'
    printf '      "program_id": "%s",\n' "$(json_escape "$(lock_value program_id)")"
    printf '      "url": "%s",\n' "$(json_escape "$(lock_value url)")"
    printf '      "sha256": "%s",\n' "$(json_escape "$expected_spl_noop_sha")"
    printf '      "upstream": "%s"\n' "$(json_escape "$(lock_value upstream)")"
    printf '    }\n'
    printf '  },\n'
    printf '  "files": [\n'

    first=1
    while IFS= read -r rel; do
        sha=$(shasum -a 256 "$staging/$rel" | awk '{print $1}')
        bytes=$(wc -c < "$staging/$rel" | tr -d '[:space:]')
        src=$(source_for "$rel")
        if [[ "$first" -eq 0 ]]; then
            printf ',\n'
        fi
        first=0
        printf '    {"path": "%s", "sha256": "%s", "bytes": %s, "source": "%s"}' \
            "$(json_escape "$rel")" \
            "$sha" \
            "$bytes" \
            "$(json_escape "$src")"
    done < <(cd "$staging" && find bin accounts -type f | sort)

    printf '\n  ]\n'
    printf '}\n'
} > "$manifest"

(
    cd "$staging"
    find MANIFEST.json bin accounts -type f | sort | xargs shasum -a 256 > SHA256SUMS
    shasum -a 256 -c SHA256SUMS >/dev/null
)

echo "Built  : $staging"
echo "Tag    : $tag"
echo "Source : $source_label"

if [[ "${FIXTURES_ARCHIVE:-}" == "1" ]]; then
    archive="zolana-fixtures.tar.gz"
    tar --no-xattrs -czf "$out/$archive" \
        -C "$staging" \
        $(cd "$staging" && find . -type f | sort)

    shasum -a 256 "$out/$archive" |
        awk -v name="$archive" '{print $1"  "name}' \
            > "$out/$archive.sha256"

    echo "Archive: $out/$archive"
    echo "Sha    : $(awk '{print $1}' "$out/$archive.sha256")"
fi
