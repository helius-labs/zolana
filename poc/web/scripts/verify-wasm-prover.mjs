// Verifies the browser proving path without a browser.
//
// Runs one transfer against the remote prover to capture a real /prove request,
// then replays that request through the wasm module in Node. This is the only way
// to see the module's actual error: the SDK reduces a prover failure to
// "status: 500" and drops the body, and a page cannot show a Go fatal error at
// all -- it kills the wasm instance.
//
// Usage, with the localnet up (`just poc-up`):
//   ZOLANA_TREE=<tree> node poc/web/scripts/verify-wasm-prover.mjs
//
// Usable from any working directory: every path is resolved from this module.
import { createRequire } from "node:module";
import { readFile } from "node:fs/promises";
import nodeFs from "node:fs";
import nodePath from "node:path";
import { ed25519 } from "@noble/curves/ed25519.js";
import {
  airdropFactory,
  createKeyPairSignerFromBytes,
  getSignatureFromTransaction,
  lamports,
  sendTransactionWithoutConfirmingFactory,
  signTransactionWithSigners,
} from "@solana/kit";
import {
  LocalWalletAuthority,
  ShieldedKeypair,
  Wallet,
  buildDepositTransaction,
  buildRegistrationTransaction,
  buildTransferTransaction,
  createZolanaClient,
  syncWallet,
} from "@zolana/sdk";

// ---------- 1. capture a real prove request ----------

const captured = [];
const realFetch = globalThis.fetch;
globalThis.fetch = async (input, init) => {
  const url = typeof input === "string" ? input : (input?.url ?? String(input));
  if (url.includes("/prove") && typeof init?.body === "string") captured.push(init.body);
  return await realFetch(input, init);
};

const client = await createZolanaClient({
  solanaRpcUrl: "http://127.0.0.1:8899",
  indexerUrl: "http://127.0.0.1:8784",
  proverUrl: "http://127.0.0.1:3001",
  ...(process.env.ZOLANA_TREE === undefined ? {} : { tree: process.env.ZOLANA_TREE }),
});

async function send(transaction, signers) {
  const signed = await signTransactionWithSigners(signers, transaction);
  const signature = getSignatureFromTransaction(signed);
  await sendTransactionWithoutConfirmingFactory({ rpc: client.solanaRpc })(signed, {
    commitment: client.commitment,
  });
  for (let i = 0; i < 150; i++) {
    const { value } = await client.solanaRpc.getSignatureStatuses([signature]).send();
    const status = value[0];
    if (status?.confirmationStatus === "confirmed" || status?.confirmationStatus === "finalized") {
      if (status.err !== null) throw new Error(JSON.stringify(status.err));
      return;
    }
    await new Promise((r) => setTimeout(r, 400));
  }
  throw new Error("not confirmed");
}

async function actor() {
  const seed = new Uint8Array(32);
  crypto.getRandomValues(seed);
  return {
    signer: await createKeyPairSignerFromBytes(
      Uint8Array.of(...seed, ...ed25519.getPublicKey(seed)),
    ),
    keypair: ShieldedKeypair.fromEd25519(seed, 0),
  };
}

const sender = await actor();
const receiver = await actor();
const airdrop = airdropFactory({
  rpc: client.solanaRpc,
  rpcSubscriptions: client.solanaRpcSubscriptions,
});
await Promise.all(
  [sender, receiver].map((a) =>
    airdrop({
      commitment: "confirmed",
      recipientAddress: a.signer.address,
      lamports: lamports(3_000_000_000n),
    }),
  ),
);
for (const a of [sender, receiver]) {
  const reg = await buildRegistrationTransaction({
    client,
    owner: a.signer.address,
    address: a.keypair.shieldedAddress(),
  });
  if (reg !== undefined) await send(reg, [a.signer]);
}
const wallet = new Wallet({ identity: sender.keypair.shieldedAddress() });
const authority = new LocalWalletAuthority({
  solanaPublicKey: sender.signer.address,
  keypair: sender.keypair,
});
await send(
  await buildDepositTransaction({
    client,
    feePayer: sender.signer.address,
    recipient: sender.keypair.shieldedAddress(),
    amount: 200_000_000n,
  }),
  [sender.signer],
);
await syncWallet({ client, wallet, authority, config: { waitForIndexer: true } });
await buildTransferTransaction({
  client,
  wallet,
  authority,
  feePayer: sender.signer.address,
  recipient: receiver.signer.address,
  amount: BigInt(process.env.TRANSFER ?? "50000000"),
});

const body = captured.at(-1);
if (body === undefined) throw new Error("no /prove request was captured");
const request = JSON.parse(body);
const counts = (r) => ({
  inputs: r.inputs?.length,
  outputs: r.outputs?.length,
  publicAssets: r.publicAssets?.length,
  publicAmounts: r.publicAmounts?.length,
  signerPkHashes: r.signerPkHashes?.length,
  publishedOutputOwnerPkHashes: r.publishedOutputOwnerPkHashes?.length,
});
console.log(
  `captured: circuitType=${request.circuitType} shape=${request.nInputs}x${request.nOutputs}`,
);
console.log(`  counts: ${JSON.stringify(counts(request))}`);

// ---------- 2. boot the wasm module ----------

globalThis.require = createRequire(import.meta.url);
globalThis.fs = nodeFs;
globalThis.path = nodePath;
await import("../../core/src/vendor/wasm_exec.js");

const ready = new Promise((resolve) => {
  globalThis.__zolanaProverReady = resolve;
});
const go = new globalThis.Go();
const wasm = await readFile(new URL("../public/prover/zolana-prover.wasm", import.meta.url));
const { instance } = await WebAssembly.instantiate(wasm, go.importObject);
void go.run(instance);
await ready;
const api = globalThis.__zolanaProver;
console.log("wasm instance ready");

// ---------- 3. load the key the request names ----------

// PRELOAD_KEYS lets a run reproduce the page's ordering, which loads a guessed
// shape before the one the request actually names.
const wanted = `transfer_confidential_${request.nInputs}_${request.nOutputs}.key`;
const keyFiles = [
  ...(process.env.PRELOAD_KEYS ?? "").split(",").filter(Boolean),
  wanted,
];
let started = Date.now();
for (const keyFile of keyFiles) {
  const keyBytes = await readFile(
    new URL(`../../../prover/server/proving-keys/${keyFile}`, import.meta.url),
  );
  started = Date.now();
  const loaded = api.loadKey(keyFile, new Uint8Array(keyBytes));
  if (loaded.error !== undefined) throw new Error(`loadKey ${keyFile}: ${loaded.error}`);
  console.log(
    `loaded ${keyFile} as ${loaded.key} nIn=${loaded.nInputs} nOut=${loaded.nOutputs} nbPublic=${loaded.nbPublic} nbSecret=${loaded.nbSecret} witness=${loaded.nbPublic + loaded.nbSecret - 1} in ${Date.now() - started}ms`,
  );
}

// ---------- 4. prove ----------

started = Date.now();
const result = api.prove(body);
const elapsed = Date.now() - started;
if (result.error !== undefined) {
  console.log(`\nWASM PROVE FAILED after ${elapsed}ms:\n  ${result.error}`);
  process.exitCode = 1;
} else {
  console.log(`\nWASM PROVE OK in ${elapsed}ms`);
  console.log(`  proof: ${String(result.proof).slice(0, 160)}...`);
}
process.exit(process.exitCode ?? 0);
