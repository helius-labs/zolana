#!/usr/bin/env bash
# A gh token keeps the download off the anonymous GitHub limits.
set -euo pipefail

if [[ $# -ne 5 ]]; then
  echo "usage: $0 <owner/repo> <tag> <asset> <sha256> <dir>" >&2
  exit 2
fi
repo=$1 tag=$2 asset=$3 sha256=$4 dir=$5

mkdir -p "$dir"
for attempt in 1 2 3 4 5; do
  if gh auth token >/dev/null 2>&1; then
    gh release download "$tag" -R "$repo" -p "$asset" -D "$dir" --clobber && break
  else
    curl -sSfL "https://github.com/$repo/releases/download/$tag/$asset" -o "$dir/$asset" && break
  fi
  if (( attempt == 5 )); then
    exit 1
  fi
  echo "$asset download failed, attempt $attempt" >&2
  sleep $((attempt * 10))
done
echo "$sha256  $dir/$asset" | shasum -a 256 -c -
