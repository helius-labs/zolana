/**
 * The native proving slot for iOS/Android, and the two things that must live
 * behind it.
 *
 * React Native has two hard blockers that the browser does not:
 *
 *  1. Hermes has no WebAssembly. `@lightprotocol/hasher.rs` is a wasm module, so
 *     the SDK's Poseidon does not run at all on device. Every SDK operation that
 *     hashes -- UTXO commitments, nullifiers, view tags, wallet sync -- is
 *     blocked on this, not just proving.
 *  2. gnark proving needs native code. Go's js/wasm target (which the web PoC
 *     uses) is not available here.
 *
 * So the native module has to provide BOTH Poseidon and proving. That is exactly
 * what mopro is for -- its gnark adapter is `#[cfg(not(target_arch = "wasm32"))]`,
 * which excludes the browser but includes iOS and Android.
 *
 * One caveat worth stating plainly: mopro's stock gnark adapter exposes
 * `generate_gnark_proof(r1cs_path, pk_path, witness_json)`. Zolana's keys are not
 * in that shape -- a `.key` file is a single `TransferProofSystem` blob (an
 * nInputs/nOutputs/requiresP256 header, then pk, vk, and the constraint system),
 * and its witness comes from `TransferParameters`, not a flat JSON map. Proving
 * Zolana circuits natively therefore needs a Zolana-specific entry point that
 * reuses `prover/prover/transfer_eddsa_only`, not the stock adapter. See
 * poc/native/MOPRO.md.
 */

import type { Measurement, ProverKind } from "@zolana/poc-core";

/** What a native module must expose for the app to be fully on-device. */
export interface NativeProverModule {
  /** Poseidon over big-endian field elements, replacing the wasm hasher. */
  poseidon(inputs: readonly Uint8Array[]): Uint8Array;
  /** Loads one `TransferProofSystem` blob, keyed as circuitType_nIn_nOut. */
  loadKey(fileName: string, key: Uint8Array): string;
  /** Takes a `POST /prove` body, returns the same JSON the server would. */
  prove(requestJson: string): string;
}

export type NativeAvailability =
  | Readonly<{ available: true; module: NativeProverModule }>
  | Readonly<{ available: false; reason: string }>;

/**
 * Resolves the native module if it has been built and linked.
 *
 * Deliberately a runtime lookup rather than a static import: the app must still
 * launch and benchmark remote proving on a device where the module is absent,
 * and a missing-module crash at import time would prevent that.
 */
export function resolveNativeProver(): NativeAvailability {
  const registry = (globalThis as { __zolanaNativeProver?: unknown }).__zolanaNativeProver;
  if (
    typeof registry === "object" &&
    registry !== null &&
    typeof (registry as NativeProverModule).prove === "function" &&
    typeof (registry as NativeProverModule).poseidon === "function"
  ) {
    return Object.freeze({ available: true, module: registry as NativeProverModule });
  }
  return Object.freeze({
    available: false,
    reason:
      "native prover module not linked. Build it with the steps in poc/native/MOPRO.md, " +
      "then rebuild the dev client (expo run:ios / run:android).",
  });
}

/** Which prover kinds this device can actually use right now. */
export function availableProvers(native: NativeAvailability): readonly ProverKind[] {
  return native.available ? (["native", "remote"] as const) : (["remote"] as const);
}

/**
 * Times a native prove call. Uses `Date.now` rather than `performance.now`
 * because Hermes only exposes the latter behind a polyfill, and a benchmark that
 * silently reports zeros is worse than a coarser one.
 */
export function timedNativeProve(
  module: NativeProverModule,
  requestJson: string,
): Readonly<{ proof: string; measurement: Measurement }> {
  const started = Date.now();
  const proof = module.prove(requestJson);
  return Object.freeze({
    proof,
    measurement: Object.freeze({
      step: "transfer-prove" as const,
      ms: Date.now() - started,
      note: "native gnark groth16.Prove",
    }),
  });
}
