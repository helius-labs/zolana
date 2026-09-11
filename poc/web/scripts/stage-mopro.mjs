// Stage a built Mopro kernel and local test artifacts. No downloads or key setup.
import { createHash } from 'node:crypto';
import { cp, mkdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const [bindings, keysDir, samplePath] = process.argv.slice(2);
if (!bindings || !keysDir || !samplePath) {
  throw new Error('Usage: node poc/web/scripts/stage-mopro.mjs <MoproWasmBindings-or-package> <keys-directory> <local-test-transfer-2x3.json>');
}
const root = fileURLToPath(new URL('../../../', import.meta.url));
const publicDir = join(root, 'poc/web/public');
const accelerator = join(resolve(bindings), 'gnark/accelerator');
for (const file of ['gnark_kernel.js', 'gnark_kernel_bg.wasm', 'LICENSE-APACHE', 'LICENSE-MIT']) {
  if (!(await stat(join(accelerator, file))).isFile()) throw new Error(`Missing Mopro artifact: ${file}`);
}

const kernelSource = await readFile(join(accelerator, 'gnark_kernel.js'), 'utf8');
if (kernelSource.includes('set_solver(') || !kernelSource.includes('parts(sa, sb, sk, a, b, c)')) {
  throw new Error('This demo requires the Arkworks kernel from Mopro feat/gnark-web-arkworks');
}

const sample = await readFile(resolve(samplePath), 'utf8');
const request = JSON.parse(sample);
if (request.circuitType !== 'transfer-confidential' || request.nInputs !== 2 || request.nOutputs !== 3) {
  throw new Error('The playground sample must be a local test transfer-confidential 2x3 request');
}
const lock = JSON.parse(await readFile(join(root, 'prover/server/prover/provingkeys/proving-keys.lock'), 'utf8'));
const manifest = {};
const available = [];
for (const [name, entry] of Object.entries(lock.keys)) {
  if (!/^(transfer_confidential_\d+_\d+|merge_8_1)\.key$/.test(name)) continue;
  manifest[name] = { size: entry.size, sha256: entry.sha256 };
  const source = join(resolve(keysDir), name);
  let bytes;
  try { bytes = await readFile(source); }
  catch (error) { if (error.code === 'ENOENT') continue; throw error; }
  if (bytes.length !== entry.size || createHash('sha256').update(bytes).digest('hex') !== entry.sha256) {
    throw new Error(`${name} does not match the proving-keys.lock pinned by this checkout`);
  }
  available.push({ name, source });
}
if (!available.some(({ name }) => name === 'transfer_confidential_2_3.key')) {
  throw new Error('The sample requires transfer_confidential_2_3.key in the keys directory');
}

// Validate all supplied inputs before copying into the app's generated folders.
await mkdir(join(publicDir, 'prover'), { recursive: true });
await mkdir(join(publicDir, 'keys'), { recursive: true });
await mkdir(join(publicDir, 'fixtures'), { recursive: true });
await rm(join(publicDir, 'prover/accelerator'), { recursive: true, force: true });
await cp(accelerator, join(publicDir, 'prover/accelerator'), { recursive: true });
for (const { source, name } of available) await cp(source, join(publicDir, 'keys', name));
await writeFile(join(publicDir, 'keys/manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
await writeFile(join(publicDir, 'fixtures/transfer-2x3.json'), sample);
console.log(`Staged Mopro arithmetic kernel, ${available.length} pinned keys and the local test sample.`);
console.log('Run just build-prover-wasm to build Zolana’s Go bridge and matching shim, then npm run poc:dev.');
