import { readFile, writeFile, mkdir, open } from "node:fs/promises";
import { resolve } from "node:path";
import { randomBytes } from "node:crypto";
import {
  createKeyPairSignerFromBytes,
  signTransactionWithSigners,
  getBase64EncodedWireTransaction,
  getSignatureFromTransaction,
} from "@solana/kit";
import {
  createZolanaClient,
  ShieldedKeypair,
  SigningKey,
  buildDepositTransaction,
} from "../../sdk-libs/ts/dist/index.js";

const directory = resolve(process.env.PROVER_FIXTURE_DIR ?? "target/prover-rtt/private");
const rpc = process.env.SOLANA_RPC_URL ?? "https://api.devnet.solana.com";
const indexer = process.env.INDEXER_URL ?? "https://d2xah7tnhdhcom.cloudfront.net";
const payerPath = process.env.PROVER_FIXTURE_PAYER;
if (!payerPath) throw new Error("PROVER_FIXTURE_PAYER is required");
await mkdir(directory, { recursive: true, mode: 0o700 });
const ownerPath = resolve(directory, "owner-seed.json");
let seed;
try {
  seed = Uint8Array.from(JSON.parse(await readFile(ownerPath, "utf8")));
} catch (error) {
  if (error.code !== "ENOENT") throw error;
  seed = randomBytes(32);
  await writeFile(ownerPath, JSON.stringify([...seed]), { mode: 0o600, flag: "wx" });
}
const owner = ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(seed));
const payer = await createKeyPairSignerFromBytes(
  Uint8Array.from(JSON.parse(await readFile(payerPath, "utf8"))),
);
const client = await createZolanaClient({ solanaRpcUrl: rpc, indexerUrl: indexer });
const call = async (method, params) => {
  const response = await fetch(rpc, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    signal: AbortSignal.timeout(15_000),
  });
  const body = await response.json();
  if (body.error) throw new Error(JSON.stringify(body.error));
  return body.result;
};
if ((await call("getGenesisHash", [])) !== "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG") {
  throw new Error("Fixture deposits require Solana devnet");
}
const balance = await call("getBalance", [payer.address]);
if (balance.value < 1_000_000) throw new Error("Fixture payer needs at least 0.001 devnet SOL");
for (let index = 0; index < 2; index++) {
  try {
    await readFile(resolve(directory, `deposit-${index}.json`));
    throw new Error("Fixture deposits already exist");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
}
// 1. An uncertain submission must retain its attempt marker.
const attempt = await open(resolve(directory, "deposit-attempt.json"), "wx", 0o600);
await attempt.writeFile(JSON.stringify({ createdAt: new Date().toISOString(), ownerPath }));
await attempt.close();
try {
  for (let index = 0; index < 2; index++) {
    const transaction = await buildDepositTransaction(
      {
        client,
        feePayer: payer.address,
        recipient: owner.shieldedAddress(),
        amount: 10_000n,
      },
      { signal: AbortSignal.timeout(15_000) },
    );
    const signed = await signTransactionWithSigners([payer], transaction);
    const encoded = getBase64EncodedWireTransaction(signed);
    const simulation = await call("simulateTransaction", [
      encoded,
      { encoding: "base64", sigVerify: true, commitment: "confirmed" },
    ]);
    if (simulation.value.err) {
      throw new Error(`Deposit simulation failed ${JSON.stringify(simulation.value)}`);
    }
    const signature = await call("sendTransaction", [
      encoded,
      { encoding: "base64", maxRetries: 0, preflightCommitment: "confirmed" },
    ]);
    if (signature !== getSignatureFromTransaction(signed))
      throw new Error("Deposit signature mismatch");
    await writeFile(
      resolve(directory, `deposit-${index}.json`),
      JSON.stringify({ signature, ownerPath, tree: client.tree }),
      { mode: 0o600, flag: "wx" },
    );
    console.log(JSON.stringify({ signature, tree: client.tree, lamports: 10_000 }));
    const deadline = Date.now() + 30_000;
    let confirmed = false;
    while (Date.now() < deadline) {
      const status = (await call("getSignatureStatuses", [[signature]])).value[0];
      if (status?.err) throw new Error("Deposit transaction failed");
      if (["confirmed", "finalized"].includes(status?.confirmationStatus)) {
        confirmed = true;
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
    if (!confirmed) throw new Error("Deposit confirmation timed out");
  }
} finally {
  owner.destroy();
  seed.fill(0);
}
