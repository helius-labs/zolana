#!/usr/bin/env bash
set -euo pipefail

release_tag="${PHOTON_ZOLANA_RELEASE_TAG:-photon-zolana-4a75d435626c}"
repo="${PHOTON_ZOLANA_RELEASE_REPO:-helius-labs/zolana}"
out_dir="${PHOTON_BIN_DIR:-target/bin}"
out_bin="${PHOTON_BIN_PATH:-${out_dir}/photon}"

# Default asset + checksum per host platform; env vars override either. Both
# platform assets live on the same release tag. A `__...__` placeholder means that
# platform's binary has not been published for this tag yet (build it with the
# `publish-photon` workflow, or set PHOTON_ZOLANA_SHA256 for a local build).
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64|Linux-amd64)
    default_asset="photon-zolana-linux-x86_64.tar.gz"
    default_sha256="941f09a69e2eb458a3385a39ed40fc37a83979f315c1c35c82bee7993c0405b4"
    ;;
  Darwin-arm64)
    default_asset="photon-zolana-macos-aarch64.tar.gz"
    default_sha256="9800119f30f6311312997b721223381342816a86aabb5fdcf2ccc2c38779705e"
    ;;
  *)
    echo "unsupported Photon release platform: $(uname -s)-$(uname -m)" >&2
    echo "Build Photon locally with 'just build-photon' on this host." >&2
    exit 1
    ;;
esac

asset="${PHOTON_ZOLANA_ASSET:-$default_asset}"
expected_sha256="${PHOTON_ZOLANA_SHA256:-$default_sha256}"

if [[ "$expected_sha256" == __*__ ]]; then
  echo "No published checksum for ${asset} on ${repo}@${release_tag} yet." >&2
  echo "Build + publish it via the publish-photon workflow, or set PHOTON_ZOLANA_SHA256." >&2
  exit 1
fi

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
