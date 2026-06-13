#!/usr/bin/env bash
# Build a fixtures bundle for upload to a GitHub release.
#
# Bin/accounts source defaults to sdk-libs/cli/{bin,accounts}, which only
# exists for the v1 bootstrap (`zolana-fixtures-zkc-0.28.4`). For subsequent
# releases, point FIXTURES_BIN_DIR / FIXTURES_ACCOUNTS_DIR at wherever you
# staged the new fixtures (e.g. an extracted prior release, or freshly built
# .so files).
#
# Output (under target/fixtures/):
#   zolana-fixtures.tar.gz          the archive to upload
#   zolana-fixtures.tar.gz.sha256   sha-of-the-archive (for release notes)
#
# Inside the archive:
#   bin/                            *.so test-validator binaries
#   accounts/                       *.json account fixtures
#   MANIFEST.json                   provenance per file
#   SHA256SUMS                      shasum -a 256 of every file in the bundle

set -euo pipefail

root=$(git rev-parse --show-toplevel)
src_bin="${FIXTURES_BIN_DIR:-$root/sdk-libs/cli/bin}"
src_accounts="${FIXTURES_ACCOUNTS_DIR:-$root/sdk-libs/cli/accounts}"

if [[ ! -d "$src_bin" || ! -d "$src_accounts" ]]; then
    echo "error: expected $src_bin and $src_accounts to exist" >&2
    exit 1
fi

tag="fixtures-v1"
if [[ -f "$root/.fixtures-version" ]]; then
    tag=$(tr -d '[:space:]' < "$root/.fixtures-version")
fi

out="$root/target/fixtures"
staging="$out/staging"
rm -rf "$staging"
mkdir -p "$staging/bin" "$staging/accounts"

# Copy fixtures; skip READMEs (they stay in-repo) and any prior SHA256SUMS.
find "$src_bin" -maxdepth 1 -type f \
    ! -name 'README.md' ! -name 'SHA256SUMS' \
    -exec cp {} "$staging/bin/" \;
find "$src_accounts" -maxdepth 1 -type f -name '*.json' \
    -exec cp {} "$staging/accounts/" \;

# Generate MANIFEST.json with per-source-of-truth provenance. Per-file sha256s
# are also in SHA256SUMS; the manifest documents *where* each file came from.
cat > "$staging/MANIFEST.json" <<EOF
{
  "version": "$tag",
  "sources": {
    "bin/light_system_program_pinocchio.so": "@lightprotocol/zk-compression-cli@0.28.4 (upstream Lightprotocol/light-protocol programs/system)",
    "bin/spl_noop.so": "upstream Lightprotocol/light-protocol third-party/solana-program-library/spl_noop.so",
    "accounts/*.json": "@lightprotocol/zk-compression-cli@0.28.4"
  }
}
EOF

# SHA256SUMS covers everything in the bundle so `shasum -a 256 -c SHA256SUMS`
# from inside the extracted dir verifies the full bundle.
(
    cd "$staging"
    find bin accounts MANIFEST.json -type f | sort | xargs shasum -a 256 > SHA256SUMS
)

# Repeatable archive: sort entries so two builds from the same source produce
# byte-identical tarballs (modulo gzip headers).
archive="zolana-fixtures.tar.gz"

tar --no-xattrs -czf "$out/$archive" \
    -C "$staging" \
    $(cd "$staging" && find . -type f | sort)

shasum -a 256 "$out/$archive" \
    | awk -v name="$archive" '{print $1"  "name}' \
    > "$out/$archive.sha256"

echo "Built  : $out/$archive"
echo "Sha    : $(awk '{print $1}' "$out/$archive.sha256")"
echo "Tag    : $tag"
echo "Files  :"
tar -tzf "$out/$archive" | sed 's/^/  /'
