#!/usr/bin/env bash
set -euo pipefail

release_tag="${PHOTON_ZOLANA_RELEASE_TAG:-photon-zolana-ae5234d0c9e8}"
asset="${PHOTON_ZOLANA_ASSET:-photon-zolana-linux-x86_64.tar.gz}"
expected_sha256="${PHOTON_ZOLANA_SHA256:-be260fd8b7f6fae86e8da258b07882698b4d6abbc0a22eba3ada5fb9d4a8ccee}"
repo="${PHOTON_ZOLANA_RELEASE_REPO:-helius-labs/zolana}"
out_dir="${PHOTON_BIN_DIR:-target/bin}"
out_bin="${PHOTON_BIN_PATH:-${out_dir}/photon}"

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64|Linux-amd64) ;;
  *)
    echo "unsupported Photon release platform: $(uname -s)-$(uname -m)" >&2
    echo "Only ${asset} is pinned right now; build Photon locally with 'just build-photon' on this host." >&2
    exit 1
    ;;
esac

url="https://github.com/${repo}/releases/download/${release_tag}/${asset}"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

mkdir -p "$out_dir"

echo "Downloading ${asset} from ${repo}@${release_tag}"
if command -v gh >/dev/null 2>&1; then
  if [[ -n "${GH_TOKEN:-${GITHUB_TOKEN:-}}" ]]; then
    export GH_TOKEN="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
  fi
  gh release download "$release_tag" --repo "$repo" --pattern "$asset" --dir "$tmpdir" --clobber
else
  curl -fsSL "$url" -o "${tmpdir}/${asset}"
fi

if command -v sha256sum >/dev/null 2>&1; then
  echo "${expected_sha256}  ${tmpdir}/${asset}" | sha256sum -c -
else
  actual_sha256="$(shasum -a 256 "${tmpdir}/${asset}" | awk '{print $1}')"
  if [[ "$actual_sha256" != "$expected_sha256" ]]; then
    echo "checksum mismatch for ${asset}" >&2
    echo "expected: ${expected_sha256}" >&2
    echo "actual:   ${actual_sha256}" >&2
    exit 1
  fi
fi

tar -xzf "${tmpdir}/${asset}" -C "$tmpdir"
if [[ ! -f "${tmpdir}/photon" ]]; then
  echo "photon binary not found in ${asset}" >&2
  exit 1
fi

install -m 0755 "${tmpdir}/photon" "$out_bin"
"$out_bin" --help >/dev/null
echo "Installed Photon to ${out_bin}"
