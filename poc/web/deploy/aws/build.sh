#!/usr/bin/env bash
# Build a versioned release from explicitly supplied Mopro artifacts and test data.
set -euo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../../../.." && pwd)"
release="${1:?usage: build.sh RELEASE_ID MOPRO_BINDINGS KEYS_DIRECTORY LOCAL_TEST_REQUEST}"
bindings="${2:?Mopro bindings directory required}"
keys="${3:?Pinned proving keys directory required}"
sample="${4:?Local test request required}"
: "${MOPRO_REVISION:?Set MOPRO_REVISION to the source commit used to build the supplied bindings}"
[[ "$release" =~ ^[a-zA-Z0-9][a-zA-Z0-9-]{0,100}$ ]] || { echo 'Invalid release ID' >&2; exit 1; }
cd "$repo_root"
node poc/web/scripts/stage-mopro.mjs "$bindings" "$keys" "$sample"
prover/server/scripts/build_prover_wasm.sh poc/web/public/prover poc/core/src/vendor
npm run build:ts
VITE_ZOLANA_WASM_URL="/releases/$release/prover" \
VITE_ZOLANA_KEYS_URL="/releases/$release/keys" \
  npm run build --workspace @zolana/poc-web -- --base "/releases/$release/"
node --input-type=module - "$release" <<'JS'
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
const release = process.argv[2];
const files = ['prover/zolana-prover.wasm', 'prover/accelerator/gnark_kernel_bg.wasm', 'keys/manifest.json', 'fixtures/transfer-2x3.json'];
const manifest = {
  release,
  sourceCommit: execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(),
  sourceDirty: execFileSync('git', ['status', '--porcelain'], { encoding: 'utf8' }).trim().length > 0,
  moproCommit: process.env.MOPRO_REVISION,
  arithmetic: 'arkworks-0.5',
  solver: 'gnark-go',
  builtAt: new Date().toISOString(),
  files: Object.fromEntries(files.map(file => {
    const bytes = readFileSync(`poc/web/dist/${file}`);
    return [file, { bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') }];
  })),
};
writeFileSync('poc/web/dist/build-info.json', `${JSON.stringify(manifest, null, 2)}\n`);
JS
printf 'Built release %s in poc/web/dist\n' "$release"
