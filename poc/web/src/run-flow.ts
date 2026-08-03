/**
 * Browser-side setup for one shield -> transfer -> unshield round trip.
 *
 * Mirrors the sequence in the SDK README and the e2e test: fund a signer by
 * airdrop, register both parties in the user registry (a transfer to an
 * unregistered Solana recipient is refused by design -- the SDK will not silently
 * downgrade a private payment into a public withdrawal), then run the legs.
 *
 * This needs a live localnet, indexer, and a funded pool tree. The key benchmark
 * on the page deliberately does not.
 */

import { ed25519 } from "@noble/curves/ed25519.js";
import { airdropFactory, createKeyPairSignerFromBytes, lamports } from "@solana/kit";
import {
  LocalWalletAuthority,
  ShieldedKeypair,
  Wallet,
  buildRegistrationTransaction,
  createZolanaClient,
} from "@zolana/sdk";

import {
  RunRecorder,
  canonicalShape,
  signSendAndConfirm,
  proverMeasurementSink,
  runFlow,
  type Measurement,
  type ProverKind,
  type RunResult,
  type WasmProver,
} from "@zolana/poc-core";

import type { PocConfig } from "./config.js";

export interface FlowRunOptions {
  readonly config: PocConfig;
  readonly prover: ProverKind;
  /** Notes to fan into before transferring; drives the transfer's shape. */
  readonly notes: number;
  /** Present when proving locally; supplies the injected fetch and key preload. */
  readonly wasm?: WasmProver;
  readonly onMeasurement?: (measurement: Measurement) => void;
  readonly onLog?: (line: string) => void;
}

// Divisible by every note count the sweep uses (LCM of 1..5 is 60), because
// `split` refuses an amount it cannot divide evenly: WALLET_SPLIT_NOT_DIVISIBLE.
const SHIELD_LAMPORTS = 240_000_000n;
const AIRDROP_LAMPORTS = 4_000_000_000n;
const PREFLIGHT_TIMEOUT_MS = 3_000;

/**
 * Probes the endpoints the flow needs before touching any of them.
 *
 * Without this the first failure is a bare `TypeError: Failed to fetch` from
 * whichever call happened to run first, which names neither the endpoint nor the
 * fix. A browser deliberately hides the distinction between "connection refused"
 * and "blocked by CORS", so the only way to report something actionable is to
 * check each service by name up front.
 */
async function preflight(config: PocConfig, prover: ProverKind): Promise<void> {
  const targets: readonly Readonly<{ name: string; url: string; body?: string }>[] = [
    {
      name: "Solana RPC",
      url: config.solanaRpcUrl,
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "getHealth" }),
    },
    {
      name: "indexer",
      url: config.indexerUrl,
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "getIndexerHealth" }),
    },
    // Only probed when it is actually going to be used; local proving needs no
    // prover server at all, which is the point of the wasm path.
    ...(prover === "remote"
      ? [{ name: "prover", url: config.proverUrl, body: JSON.stringify({}) }]
      : []),
  ];

  const results = await Promise.all(
    targets.map(async (target) => {
      try {
        await fetch(target.url, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: target.body ?? "{}",
          signal: AbortSignal.timeout(PREFLIGHT_TIMEOUT_MS),
        });
        // Any HTTP response at all means the service is reachable; a 404 or 400
        // still proves something is listening and speaking HTTP.
        return undefined;
      } catch {
        return `${target.name} (${target.url})`;
      }
    }),
  );

  const unreachable = results.filter((entry): entry is string => entry !== undefined);
  if (unreachable.length > 0) {
    throw new Error(
      `unreachable: ${unreachable.join(", ")}. Start the stack with \`just poc-up\`, then ` +
        `export the VITE_ZOLANA_* values it prints and restart the dev server.`,
    );
  }
}

/**
 * One participant, whose Solana signer and shielded signing key are the SAME
 * Ed25519 key.
 *
 * This is not a convenience: on the eddsa rail the shielded signing key *is* the
 * owner identity the program and circuit bind to, so deriving it independently of
 * the Solana signer produces a wallet whose notes the payer cannot spend.
 * Registration still succeeds -- the registry stores whatever keys it is given --
 * and the mismatch only surfaces later, when building a transfer finds no usable
 * inputs. `ShieldedKeypair.generate()` alone is therefore never right for a
 * transacting wallet; the SDK's own e2e helper derives both from one seed.
 */
async function actor(): Promise<
  Readonly<{ signer: Awaited<ReturnType<typeof createKeyPairSignerFromBytes>>; keypair: ShieldedKeypair }>
> {
  const seed = new Uint8Array(32);
  crypto.getRandomValues(seed);
  const signer = await createKeyPairSignerFromBytes(
    Uint8Array.of(...seed, ...ed25519.getPublicKey(seed)),
  );
  return Object.freeze({ signer, keypair: ShieldedKeypair.fromEd25519(seed as never, 0) });
}

export async function runBrowserFlow(options: FlowRunOptions): Promise<RunResult> {
  const { config, prover, wasm } = options;
  const log = options.onLog ?? ((): void => {});
  const shape = canonicalShape(Math.max(1, options.notes), 2);

  // Setup failures must still produce a RunResult so the page can show which
  // stage broke instead of an empty table.
  const setup = new RunRecorder(shape.label, prover);
  try {
    await preflight(config, prover);
    const client = await setup.step("poseidon-init", () =>
      createZolanaClient({
        solanaRpcUrl: config.solanaRpcUrl,
        indexerUrl: config.indexerUrl,
        proverUrl: config.proverUrl,
        ...(config.tree === undefined ? {} : { tree: config.tree as never }),
        // Routing prove requests into wasm is the entire local-proving
        // integration; every other request falls through to the real fetch.
        ...(prover === "wasm" && wasm !== undefined ? { fetch: wasm.createFetch() } : {}),
      }),
    );
    log(`client ready (prover: ${prover})`);

    const [sender, receiver] = await Promise.all([actor(), actor()]);
    const funding = sender.signer;
    const recipientSigner = receiver.signer;
    const airdrop = airdropFactory({
      rpc: client.solanaRpc,
      rpcSubscriptions: client.solanaRpcSubscriptions,
    });
    await setup.step("wallet-sync", async () => {
      await Promise.all([
        airdrop({
          commitment: "confirmed",
          recipientAddress: funding.address,
          lamports: lamports(AIRDROP_LAMPORTS),
        }),
        airdrop({
          commitment: "confirmed",
          recipientAddress: recipientSigner.address,
          lamports: lamports(AIRDROP_LAMPORTS / 2n),
        }),
      ]);
    });
    log("airdrops confirmed");

    const keypair = sender.keypair;
    const recipientKeypair = receiver.keypair;
    // The SDK is build-only, so each registration is built, signed, then sent.
    // A recipient must be registered before a transfer: the SDK refuses to turn
    // a private payment into a public withdrawal silently.
    for (const [signer, party] of [
      [funding, keypair],
      [recipientSigner, recipientKeypair],
    ] as const) {
      const registration = await buildRegistrationTransaction({
        client,
        owner: signer.address,
        address: party.shieldedAddress(),
      });
      if (registration !== undefined) {
        await signSendAndConfirm(client, registration, [signer]);
      }
    }
    log("both parties registered");

    const wallet = new Wallet({ identity: keypair.shieldedAddress() });
    const authority = new LocalWalletAuthority({
      solanaPublicKey: funding.address,
      keypair,
    });

    return await runFlow(
      {
        client,
        wallet,
        authority,
        shieldedAddress: keypair.shieldedAddress(),
        signer: funding,
        transferRecipient: recipientSigner.address,
        withdrawalRecipient: recipientSigner.address,
        shieldAmount: SHIELD_LAMPORTS,
        prover,
        ...(options.onMeasurement === undefined
          ? {}
          : { onMeasurement: options.onMeasurement }),
        ...(prover === "wasm" && wasm !== undefined
          ? { prepareShape: (target) => wasm.ensureKey(target) }
          : {}),
      },
      { notes: Math.max(1, options.notes) },
    );
  } catch (error) {
    return setup.finish(error);
  } finally {
    void proverMeasurementSink;
  }
}
