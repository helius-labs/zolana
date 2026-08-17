// Recomputes the derivation-dependent fields in fixtures/transaction/*.json
// with the current library and rewrites fixtures/manifest.json. Run after a
// build: `npm run build && node scripts/regenerate-fixtures.mjs`.
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

import {
  ShieldedKeypair,
  SigningKey,
  ViewingKey,
  initializePoseidon,
} from "../dist/keypair/index.js";

const FIXTURES = new URL("../fixtures/", import.meta.url);

function readJson(name) {
  return JSON.parse(readFileSync(new URL(name, FIXTURES), "utf8"));
}

function writeJson(name, value) {
  writeFileSync(new URL(name, FIXTURES), `${JSON.stringify(value, null, 2)}\n`);
}

function bytes(value) {
  return Uint8Array.from(value.match(/../g)?.map((pair) => Number.parseInt(pair, 16)) ?? []);
}

function hex(value) {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function keypairFromInputs(inputs) {
  const signing = SigningKey.fromBytes(bytes(inputs.signingSecretBytes));
  const viewing = ViewingKey.fromSeed(bytes(inputs.viewingSeedBytes), 0);
  return { keypair: ShieldedKeypair.withViewingKey(signing, viewing), signing };
}

await initializePoseidon();

const authority = readJson("transaction/authority-v1.json");
{
  const { keypair, signing } = keypairFromInputs(authority.inputs);
  const nullifierPubkey = hex(keypair.nullifierPublicKey());
  authority.expected.authority.nullifierPubkeyBytes = nullifierPubkey;
  authority.expected.authority.shieldedAddress.nullifierPubkeyBytes = nullifierPubkey;
  const signature = signing.sign(bytes(authority.inputs.messageHashBytes));
  authority.expected.p256Signature.rBytes = hex(signature.slice(0, 32));
  authority.expected.p256Signature.sBytes = hex(signature.slice(32));
  writeJson("transaction/authority-v1.json", authority);
}

const walletState = readJson("transaction/wallet-state-v1.json");
{
  const { keypair } = keypairFromInputs(walletState.inputs);
  const nullifierKey = keypair.nullifierKey();
  for (const row of walletState.inputs.walletUtxos) {
    row.nullifierBytes = hex(
      nullifierKey.nullifier(bytes(row.hashBytes), bytes(row.utxo.blindingBytes)),
    );
  }
  writeJson("transaction/wallet-state-v1.json", walletState);
}

const manifest = readJson("manifest.json");
for (const entry of manifest.files) {
  const text = readFileSync(new URL(entry.path, FIXTURES), "utf8");
  entry.sha256 = createHash("sha256").update(text, "utf8").digest("hex");
}
writeJson("manifest.json", manifest);

console.log("fixtures regenerated");
