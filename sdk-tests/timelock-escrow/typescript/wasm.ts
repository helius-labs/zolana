import { readFileSync } from "node:fs";

import type { ProgramTransaction } from "@heliuslabs/spr/program";
import { TransactionError } from "@heliuslabs/spr/transaction";
import type { ProgramProof } from "../../../target/zk/timelock-escrow-program/wasm-node/timelock_escrow_program.js";
export type {
  CompressedProof as CompressedGroth16Proof,
  DataUtxo,
  EscrowTerms,
  ProgramProof as Proof,
} from "../../../target/zk/timelock-escrow-program/wasm-node/timelock_escrow_program.js";

const started = performance.now();
export const wasm =
  await import("../../../target/zk/timelock-escrow-program/wasm-node/timelock_escrow_program.js");
export const wasmLoadMs = performance.now() - started;
export const escrowTermsDataUtxo = wasm.escrowTermsDataUtxo;

export type EscrowCircuit = "escrow" | "withdraw";

function circuitFile(circuit: EscrowCircuit, file: string): URL {
  return new URL(`../../../target/zk/timelock-escrow-program/${circuit}/${file}`, import.meta.url);
}

/**
 * A proof its trusted verifying key rejects. The client-side counterpart of the
 * program's `TimelockEscrowError::ProofVerificationFailed` (9000): such a proof
 * must never reach a transaction.
 */
export class ProofVerificationError extends Error {
  readonly code = "PROOF_VERIFICATION_FAILED";

  constructor(
    readonly circuit: EscrowCircuit,
    readonly verifyingKey: EscrowCircuit,
  ) {
    super(`the ${circuit} proof fails verification against the ${verifyingKey} verifying key`);
    this.name = "ProofVerificationError";
  }
}

/** Owns Xark's decoded circuit, proving key and verifier for repeated proofs. */
export class ProgramProver implements Disposable {
  readonly #session: InstanceType<typeof wasm.ProvingSession>;
  readonly #verifier: InstanceType<typeof wasm.VerifyingKey>;
  #disposed = false;

  /** `verifyingKey` names the circuit whose verifying key checks each proof: its own unless overridden. */
  constructor(
    readonly name: EscrowCircuit,
    readonly verifyingKey: EscrowCircuit = name,
  ) {
    this.#verifier = new wasm.VerifyingKey(readFileSync(circuitFile(verifyingKey, "vk.bin")));
    try {
      this.#session = new wasm.ProvingSession(
        readFileSync(circuitFile(name, "circuit.xbc")),
        readFileSync(circuitFile(name, "pk.bin")),
        readFileSync(circuitFile(name, "sources.json"), "utf8"),
      );
    } catch (error) {
      this.#verifier.free();
      throw error;
    }
  }

  prove(transaction: Pick<ProgramTransaction, "proofInputs" | "publicHash">): ProgramProof {
    if (this.#disposed)
      throw new TransactionError("TRANSACTION_PROGRAM_BUILD", { field: "prover.disposed" });
    const bundle = this.#session.prove(transaction.proofInputs, {});
    try {
      if (!this.#verifier.verify(bundle.proof, bundle.publicInputs))
        throw new ProofVerificationError(this.name, this.verifyingKey);
      return wasm.programProof(bundle.proof, bundle.publicInputs, transaction.publicHash);
    } finally {
      bundle.free();
    }
  }

  [Symbol.dispose](): void {
    if (this.#disposed) return;
    this.#disposed = true;
    this.#session.free();
    this.#verifier.free();
  }
}
