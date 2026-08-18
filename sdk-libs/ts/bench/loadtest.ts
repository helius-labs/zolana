/**
 * Sustained shielded transfers through the TypeScript SDK, reporting where the
 * time goes.
 *
 * The Rust `xtask loadtest` measures the Rust client. That leaves the SDK most
 * integrators actually use unmeasured, and a slow client is indistinguishable
 * from a saturated backend if throughput is all you look at -- both just show
 * low tps against healthy infrastructure. Running the same shape through both
 * clients makes the difference visible.
 *
 * Deliberately mirrors `xtask/src/loadtest.rs`: same wallet-file format, same
 * ring of transfers, same four phases, same 30s progress windows. Numbers are
 * meant to be read side by side with it, so changes here should keep that true.
 *
 * The shielded key derivation matches Rust's `ShieldedKeypair::from_keypair`
 * for the wallet's 32-byte Ed25519 secret, so wallet directories funded by
 * `xtask fund` produce the same shielded identities.
 *
 * Runs against `dist/`, so it measures the SDK as published rather than as
 * sourced; `npm run loadtest` builds first.
 *
 *   npm run loadtest -- --rpc <url> --indexer <url> --prover <url> \
 *     --tree <address> --keypairs <dir> --duration 420
 */

import { AsyncLocalStorage } from "node:async_hooks";
import { readdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { ed25519 } from "@noble/curves/ed25519.js";
import {
  address,
  createKeyPairSignerFromBytes,
  getSignatureFromTransaction,
  sendTransactionWithoutConfirmingFactory,
  signTransactionWithSigners,
  type Address,
  type KeyPairSigner,
  type Signature,
} from "@solana/kit";

import {
  LocalWalletAuthority,
  ShieldedKeypair,
  SigningKey,
  Wallet,
  buildTransferTransaction,
  createZolanaClient,
  syncWallet,
  type Bytes32,
} from "../dist/index.js";
import type { ZolanaClient } from "../dist/client/client.js";

interface Options {
  readonly rpcUrl: string;
  readonly indexerUrl: string;
  readonly proverUrl: string;
  readonly tree: Address;
  readonly keypairs: string;
  readonly durationSecs: number;
  readonly amount: bigint;
  readonly json: string | undefined;
}

interface Timing {
  readonly syncMs: number;
  readonly proveMs: number;
  /** Of `proveMs`, time inside HTTP requests rather than local compute. */
  readonly proveNetworkMs: number;
  readonly sendMs: number;
  readonly confirmMs: number;
  readonly totalMs: number;
}

/**
 * Per-transfer HTTP time, so `prove` can be split into waiting on the indexer
 * and prover versus computing locally.
 *
 * Workers run concurrently, so a single accumulator would blend them; the store
 * is bound per transfer with `AsyncLocalStorage` and every fetch the SDK makes
 * inside that transfer lands in the right bucket.
 */
const networkTime = new AsyncLocalStorage<{ ms: number }>();

const timedFetch: typeof globalThis.fetch = async (input, init) => {
  const started = Date.now();
  try {
    return await globalThis.fetch(input, init);
  } finally {
    const store = networkTime.getStore();
    if (store !== undefined) store.ms += Date.now() - started;
  }
};

interface Actor {
  readonly signer: KeyPairSigner;
  readonly wallet: Wallet;
  readonly authority: LocalWalletAuthority;
  readonly shieldedAddress: ReturnType<ShieldedKeypair["shieldedAddress"]>;
}

const PROGRESS_INTERVAL_MS = 30_000;

function usage(message: string): never {
  console.error(`loadtest: ${message}

usage: npm run loadtest -- --rpc <url> --indexer <url> --prover <url>
                          --tree <address> --keypairs <dir>
                          [--duration 300] [--amount 200000] [--json out.json]

Worker count is the number of .json keypair files in --keypairs.`);
  process.exit(2);
}

function parseOptions(argv: readonly string[]): Options {
  const values = new Map<string, string>();
  for (let i = 0; i < argv.length; i += 2) {
    const flag = argv[i];
    const value = argv[i + 1];
    if (flag === undefined || !flag.startsWith("--")) usage(`unexpected argument ${flag}`);
    if (value === undefined) usage(`${flag} needs a value`);
    values.set(flag.slice(2), value);
  }
  const required = (name: string): string => values.get(name) ?? usage(`--${name} is required`);

  return {
    rpcUrl: required("rpc"),
    indexerUrl: required("indexer"),
    proverUrl: required("prover"),
    tree: address(required("tree")),
    keypairs: required("keypairs"),
    durationSecs: Number(values.get("duration") ?? 300),
    amount: BigInt(values.get("amount") ?? 200_000),
    json: values.get("json"),
  };
}

/**
 * Solana CLI keypair files: a JSON array of 64 bytes, secret then public. The
 * first 32 are the seed both the signer and the shielded keypair derive from.
 */
async function loadActors(dir: string): Promise<Actor[]> {
  const files = (await readdir(dir)).filter((name) => name.endsWith(".json")).sort();
  if (files.length < 2) usage(`--keypairs ${dir} needs at least two keypair files`);

  const actors: Actor[] = [];
  for (const file of files) {
    const raw = JSON.parse(await readFile(join(dir, file), "utf8")) as unknown;
    if (!Array.isArray(raw) || raw.length !== 64) {
      usage(`${file} is not a 64-byte Solana keypair array`);
    }
    const bytes = Uint8Array.from(raw as number[]);
    const seed = bytes.slice(0, 32) as Bytes32;
    const signer = await createKeyPairSignerFromBytes(
      Uint8Array.of(...seed, ...ed25519.getPublicKey(seed)),
    );
    const keypair = ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(seed));
    actors.push({
      signer,
      wallet: new Wallet({ identity: keypair.shieldedAddress() }),
      authority: new LocalWalletAuthority({ solanaPublicKey: signer.address, keypair }),
      shieldedAddress: keypair.shieldedAddress(),
    });
  }
  return actors;
}

/**
 * Group failures by their SDK error code rather than message text. Messages
 * carry addresses and request ids that would make every occurrence unique;
 * `code`/`causeCode` are the SDK's own taxonomy and stay stable.
 */
function errorKey(error: unknown): string {
  if (typeof error === "object" && error !== null) {
    const { code, causeCode } = error as { code?: unknown; causeCode?: unknown };
    if (typeof code === "string") {
      return typeof causeCode === "string" ? `${code} / ${causeCode}` : code;
    }
  }
  return error instanceof Error ? error.message.slice(0, 120) : String(error).slice(0, 120);
}

function percentile(sorted: readonly number[], fraction: number): number {
  if (sorted.length === 0) return 0;
  const index = Math.min(sorted.length - 1, Math.floor(sorted.length * fraction));
  return sorted[index] ?? 0;
}

function reportPhase(label: string, values: readonly number[]): void {
  if (values.length === 0) {
    console.log(`  ${label.padEnd(10)} no samples`);
    return;
  }
  const sorted = [...values].sort((a, b) => a - b);
  const mean = sorted.reduce((sum, value) => sum + value, 0) / sorted.length;
  const cell = (value: number) => `${Math.round(value)}ms`.padStart(9);
  console.log(
    `  ${label.padEnd(10)} p50${cell(percentile(sorted, 0.5))}  p95${cell(
      percentile(sorted, 0.95),
    )}  p99${cell(percentile(sorted, 0.99))}  max${cell(sorted[sorted.length - 1] ?? 0)}  mean${cell(
      mean,
    )}`,
  );
}

async function transferOnce(
  client: ZolanaClient,
  from: Actor,
  to: Actor,
  amount: bigint,
): Promise<Timing> {
  const started = Date.now();

  await syncWallet({ client, wallet: from.wallet, authority: from.authority });
  const synced = Date.now();

  // Proving happens inside the build: two indexer round-trips for the input
  // merkle and dummy non-inclusion proofs, local assembly, then the prover
  // call. The Rust harness brackets the same work, so the phases compare.
  const proveNetwork = { ms: 0 };
  const transaction = await networkTime.run(proveNetwork, () =>
    buildTransferTransaction({
      client,
      wallet: from.wallet,
      authority: from.authority,
      feePayer: from.signer.address,
      recipient: to.shieldedAddress,
      amount,
    }),
  );
  const proved = Date.now();

  const signed = await signTransactionWithSigners([from.signer], transaction);
  const signature = getSignatureFromTransaction(signed);
  await sendTransactionWithoutConfirmingFactory({ rpc: client.solanaRpc })(signed, {
    commitment: client.commitment,
  });
  const sent = Date.now();

  await confirm(client, signature);
  const confirmed = Date.now();

  return {
    syncMs: synced - started,
    proveMs: proved - synced,
    proveNetworkMs: proveNetwork.ms,
    sendMs: sent - proved,
    confirmMs: confirmed - sent,
    totalMs: confirmed - started,
  };
}

async function confirm(client: ZolanaClient, signature: Signature): Promise<void> {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    const { value } = await client.solanaRpc
      .getSignatureStatuses([signature], { searchTransactionHistory: true })
      .send({ abortSignal: AbortSignal.timeout(5_000) });
    const status = value[0];
    if (status?.err !== null && status?.err !== undefined) {
      throw new Error(`transaction failed: ${JSON.stringify(status.err)}`);
    }
    if (status?.confirmationStatus === "confirmed" || status?.confirmationStatus === "finalized") {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw new Error(`transaction ${signature} not confirmed within 30s`);
}

async function main(): Promise<void> {
  const options = parseOptions(process.argv.slice(2));
  // Before the wallets: deriving a shielded address hashes, and the Poseidon
  // WASM module is loaded by `createZolanaClient`.
  const client = await createZolanaClient({
    solanaRpcUrl: options.rpcUrl,
    indexerUrl: options.indexerUrl,
    proverUrl: options.proverUrl,
    tree: options.tree,
    // Explicitly insecure, matching `xtask loadtest`: devnet's ALB has no
    // certificate yet, so the indexer and prover are plain http. That is a real
    // exposure -- the wallet's UTXO set and every proof witness cross the
    // network in the clear -- and it is spelled out here rather than defaulted,
    // so it disappears the moment the certificate is issued.
    allowInsecureHttp: true,
    fetch: timedFetch,
  });
  const actors = await loadActors(options.keypairs);

  console.log(
    `loadtest: ${actors.length} workers, ${options.durationSecs}s, ${options.amount} lamports/transfer`,
  );

  const timings: Timing[] = [];
  const errors = new Map<string, number>();
  const warmupMs: number[] = [];
  let ok = 0;
  let failed = 0;

  const startedAt = Date.now();
  const deadline = startedAt + options.durationSecs * 1_000;
  let nextProgress = startedAt + PROGRESS_INTERVAL_MS;
  let lastOk = 0;

  const progress = setInterval(() => {
    const now = Date.now();
    if (now < nextProgress) return;
    const elapsed = (now - startedAt) / 1_000;
    const window = (ok - lastOk) / ((now - nextProgress + PROGRESS_INTERVAL_MS) / 1_000);
    console.log(
      `  [${String(Math.round(elapsed)).padStart(5)}s] ${ok} ok, ${(ok / elapsed).toFixed(
        2,
      )} tps overall, ${window.toFixed(2)} tps last 30s`,
    );
    lastOk = ok;
    nextProgress = now + PROGRESS_INTERVAL_MS;
  }, 1_000);

  // One loop per wallet, each sending to the next in a ring, so every transfer
  // spends an input and produces a nullifier.
  await Promise.all(
    actors.map(async (from, index) => {
      const to = actors[(index + 1) % actors.length];
      if (to === undefined) return;

      let first = true;
      while (Date.now() < deadline) {
        try {
          const timing = await transferOnce(client, from, to, options.amount);
          if (first) {
            warmupMs.push(timing.syncMs);
            first = false;
          }
          timings.push(timing);
          ok += 1;
        } catch (error) {
          if (first) first = false;
          const key = errorKey(error);
          errors.set(key, (errors.get(key) ?? 0) + 1);
          failed += 1;
        }
      }
    }),
  );

  clearInterval(progress);

  const elapsed = (Date.now() - startedAt) / 1_000;
  console.log(`\n${"─".repeat(61)}`);
  console.log(`ok ${ok}  failed ${failed}  in ${Math.round(elapsed)}s`);
  console.log(
    `throughput ${(ok / elapsed).toFixed(2)} transfers/sec (${((ok / elapsed) * 60).toFixed(
      1,
    )}/min)`,
  );

  if (errors.size > 0) {
    console.log("\nerrors:");
    for (const [key, count] of [...errors].sort((a, b) => b[1] - a[1])) {
      console.log(`  ${String(count).padStart(6)}x  ${key}`);
    }
  }

  console.log("\nphase latency:");
  reportPhase(
    "sync",
    timings.map((timing) => timing.syncMs),
  );
  reportPhase(
    "prove",
    timings.map((timing) => timing.proveMs),
  );
  // Splitting prove tells a client problem from a service one: `net` is time
  // inside the indexer and prover requests, `local` is everything this process
  // computes around them.
  reportPhase(
    "  net",
    timings.map((timing) => timing.proveNetworkMs),
  );
  reportPhase(
    "  local",
    timings.map((timing) => timing.proveMs - timing.proveNetworkMs),
  );
  reportPhase(
    "send",
    timings.map((timing) => timing.sendMs),
  );
  reportPhase(
    "confirm",
    timings.map((timing) => timing.confirmMs),
  );
  reportPhase(
    "total",
    timings.map((timing) => timing.totalMs),
  );

  if (warmupMs.length > 0) {
    const mean = warmupMs.reduce((sum, value) => sum + value, 0) / warmupMs.length;
    console.log(`\nwallet depth:`);
    console.log(
      `  first sync   mean ${Math.round(mean).toString().padStart(8)}ms   across ${
        warmupMs.length
      } wallets`,
    );
    console.log(
      "  Sync cost scales with a wallet's history, and every run leaves more\n" +
        "  behind on these wallets. Compare runs only at similar first-sync cost.",
    );
  }

  if (options.json !== undefined) {
    await writeFile(
      options.json,
      `${JSON.stringify(
        {
          client: "typescript",
          workers: actors.length,
          durationSecs: Math.round(elapsed),
          ok,
          failed,
          tps: Number((ok / elapsed).toFixed(3)),
          errors: Object.fromEntries(errors),
          phases: {
            sync: timings.map((timing) => timing.syncMs),
            prove: timings.map((timing) => timing.proveMs),
            proveNetwork: timings.map((timing) => timing.proveNetworkMs),
            send: timings.map((timing) => timing.sendMs),
            confirm: timings.map((timing) => timing.confirmMs),
            total: timings.map((timing) => timing.totalMs),
          },
        },
        null,
        2,
      )}\n`,
    );
    console.log(`\nwrote ${options.json}`);
  }
}

await main();
