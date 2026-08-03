/**
 * What the PoC measures, split into two benchmarks with very different
 * infrastructure needs.
 *
 * 1. `benchmarkShapeKeys` -- per-shape proving-key fetch and deserialization.
 *    Needs only the key files, no validator, no indexer, no notes. This is the
 *    cold-start cost of local proving and it is the number that decides whether
 *    browser proving is usable at all, so it must be runnable on its own.
 *
 * 2. `runFlow` -- one real shield -> transfer -> unshield round trip against a
 *    running stack, with real proofs. "Shield" is the SDK's `deposit`, "unshield"
 *    is `withdraw`.
 *
 * The two are kept apart because a synthetic per-shape prove benchmark is not
 * possible: Groth16 needs a satisfiable witness, so a prove timing for shape NxM
 * only exists if the wallet actually held N spendable notes. The UI labels which
 * shapes got real prove numbers rather than implying a full matrix.
 */

import {
  buildDepositTransaction,
  buildSplitTransaction,
  buildTransferTransaction,
  buildWithdrawalTransaction,
  syncWallet,
  type ShieldedAddress,
  type TransferDestination,
  type Wallet,
  type WalletAuthority,
} from "@zolana/sdk";
import type { Address } from "@zolana/sdk";

import { signSendAndConfirm, type Signer, type SubmitClient } from "./submit.js";

import { RunRecorder, type Measurement, type ProverKind, type RunResult } from "./bench.js";
import { canonicalShape, type ShapeKey } from "./shapes.js";

/** Loads one shape's proving key and reports how long each stage took. */
export interface KeyLoader {
  ensureKey(shape: ShapeKey): Promise<void>;
}

/**
 * Times key fetch and deserialization for each shape.
 *
 * Measurements are emitted by the loader itself (it is the only thing that knows
 * whether a fetch was a cache hit), so this drives the sweep and attributes the
 * results to a shape. Shapes run sequentially: the wasm instance deserializes on
 * one thread and parallel fetches would distort both numbers.
 */
export async function benchmarkShapeKeys(
  loader: KeyLoader,
  shapes: readonly ShapeKey[],
  prover: ProverKind,
  onRun?: (run: RunResult) => void,
): Promise<readonly RunResult[]> {
  const results: RunResult[] = [];
  for (const shape of shapes) {
    const recorder = new RunRecorder(shape.label, prover);
    // The loader is the only thing that can tell fetch from deserialize (and a
    // cache hit from a download), so its measurements are the record here. An
    // outer timed step would collapse both into one row and mislabel it.
    const restore = installMeasurementSink((measurement) => {
      recorder.record(measurement);
    });
    let run: RunResult;
    try {
      await loader.ensureKey(shape);
      run = recorder.finish();
    } catch (error) {
      // No bytes are claimed on a failure: the fetch either never completed or
      // returned the wrong thing, so `shape.keyBytes` would be fiction.
      run = recorder.finish(error);
    } finally {
      restore();
    }
    results.push(run);
    onRun?.(run);
  }
  return results;
}

export interface FlowContext {
  /** A `ZolanaClient`; the actions each need a subset of its methods. */
  readonly client: Parameters<typeof buildDepositTransaction>[0]["client"] &
    Parameters<typeof buildTransferTransaction>[0]["client"] &
    Parameters<typeof syncWallet>[0]["client"] &
    SubmitClient;
  readonly wallet: Wallet;
  readonly authority: WalletAuthority;
  readonly shieldedAddress: ShieldedAddress;
  /** Funds and pays for every leg, and signs the submitted transactions. */
  readonly signer: Signer & { readonly address: Address };
  /** Registered shielded recipient for the transfer leg. */
  readonly transferRecipient: TransferDestination;
  /** Public address the unshield leg settles to. */
  readonly withdrawalRecipient: Address;
  /** Base units shielded before the run. */
  readonly shieldAmount: bigint;
  readonly prover: ProverKind;
  readonly onMeasurement?: (measurement: Measurement) => void;
  /** Preloads the proving key for a shape before it is proved. */
  readonly prepareShape?: (shape: ShapeKey) => Promise<void>;
}

export interface FlowOptions {
  /**
   * Notes to fan the shielded amount into before transferring, which is what
   * drives the transfer's input count and therefore its shape. One note means a
   * 1xN transfer; the split itself is proved as a 1xparts shape.
   */
  readonly notes: number;
  /** Skip the shield leg when the wallet already holds funds. */
  readonly reuseExistingNotes?: boolean;
}

/**
 * Runs one shield -> transfer -> unshield round trip.
 *
 * Never throws: a failed leg is a data point, and a sweep should report the
 * configuration that broke rather than discarding the ones that worked. The
 * caller wires `onMeasurement` to the prover so in-worker prove timings land in
 * the same recorder as the step timings.
 */
export async function runFlow(context: FlowContext, options: FlowOptions): Promise<RunResult> {
  const notes = Math.max(1, options.notes);
  const shape = canonicalShape(notes, 2);
  const recorder = new RunRecorder(shape.label, context.prover);

  // Prove timings are produced inside the worker and surfaced through the
  // prover's callback, so route them into this run for its lifetime.
  const restore = installMeasurementSink((measurement) => {
    recorder.record(measurement);
    context.onMeasurement?.(measurement);
  });

  /**
   * Solana confirmation says a transaction landed; it says nothing about Photon
   * having indexed the resulting notes. Without waitForIndexer the next leg reads
   * an empty wallet and fails to find spendable inputs.
   */
  const sync = (): Promise<unknown> =>
    syncWallet({
      client: context.client,
      wallet: context.wallet,
      authority: context.authority,
      config: { waitForIndexer: true },
    });

  try {
    if (context.prepareShape !== undefined) {
      await recorder.step("key-fetch", () => context.prepareShape?.(shape) ?? Promise.resolve(), {
        bytes: shape.keyBytes,
        note: shape.keyFile,
      });
    }

    if (options.reuseExistingNotes !== true) {
      await recorder.step(
        "shield-submit",
        async () => {
          const transaction = await buildDepositTransaction({
            client: context.client,
            feePayer: context.signer.address,
            recipient: context.shieldedAddress,
            amount: context.shieldAmount,
          });
          await signSendAndConfirm(context.client, transaction, [context.signer]);
        },
        { note: `shielded ${context.shieldAmount.toString()} base units` },
      );
    }

    await recorder.step("wallet-sync", sync);

    // Fanning one note into `notes` is itself a 1xN proof, so it is timed
    // separately rather than folded into the transfer leg.
    if (notes > 1) {
      await recorder.step(
        "transfer-build",
        async () => {
          const transaction = await buildSplitTransaction({
            client: context.client,
            wallet: context.wallet,
            authority: context.authority,
            feePayer: context.signer.address,
            parts: notes,
          });
          await signSendAndConfirm(context.client, transaction, [context.signer]);
        },
        { note: `split into ${String(notes)} notes (1x${String(notes)} proof)` },
      );
      await recorder.step("wallet-sync", sync);
    }

    const perLeg = context.shieldAmount / BigInt(notes + 2);
    await recorder.step(
      "transfer-submit",
      async () => {
        const transaction = await buildTransferTransaction({
          client: context.client,
          wallet: context.wallet,
          authority: context.authority,
          feePayer: context.signer.address,
          recipient: context.transferRecipient,
          amount: perLeg,
        });
        await signSendAndConfirm(context.client, transaction, [context.signer]);
      },
      { note: `transfer, ${String(notes)} note(s) available` },
    );

    await recorder.step("wallet-sync", sync);

    await recorder.step(
      "unshield-submit",
      async () => {
        const transaction = await buildWithdrawalTransaction({
          client: context.client,
          wallet: context.wallet,
          authority: context.authority,
          feePayer: context.signer.address,
          recipient: context.withdrawalRecipient,
          amount: perLeg,
        });
        await signSendAndConfirm(context.client, transaction, [context.signer]);
      },
      { note: "withdraw to public address" },
    );

    return recorder.finish();
  } catch (error) {
    return recorder.finish(error);
  } finally {
    restore();
  }
}

/**
 * Where prove timings from the worker are delivered.
 *
 * A module-level sink rather than a parameter because the measurement is
 * produced by the prover's `fetch` shim, which the SDK owns and calls without
 * any reference to the current run.
 */
let measurementSink: ((measurement: Measurement) => void) | undefined;

/** Hand to `WasmProverOptions.onMeasurement` so prove timings reach the run. */
export function proverMeasurementSink(measurement: Measurement): void {
  measurementSink?.(measurement);
}

/**
 * Routes prover measurements into `sink` until the returned function is called.
 * Restores the previous sink rather than clearing it, so nesting a key sweep
 * inside a flow run does not silently orphan the outer run's measurements.
 */
export function installMeasurementSink(sink: (measurement: Measurement) => void): () => void {
  const previous = measurementSink;
  measurementSink = sink;
  return () => {
    measurementSink = previous;
  };
}

/** Sweeps note counts, mapping each to the shape it produces. */
export async function runSweep(
  context: FlowContext,
  noteCounts: readonly number[],
  onRun?: (run: RunResult) => void,
): Promise<readonly RunResult[]> {
  const results: RunResult[] = [];
  for (const notes of noteCounts) {
    const run = await runFlow(context, { notes });
    results.push(run);
    onRun?.(run);
  }
  return results;
}
