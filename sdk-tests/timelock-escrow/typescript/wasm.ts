import { readFileSync } from "node:fs";

import { TransactionError, type ProgramTransaction } from "@heliuslabs/zolana/transaction";
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

/** Owns Xark's decoded circuit, proving key and verifier for repeated proofs. */
export class ProgramProver implements Disposable {
  readonly #session: InstanceType<typeof wasm.ProvingSession>;
  readonly #verifier: InstanceType<typeof wasm.VerifyingKey>;
  #disposed = false;

  constructor(readonly name: "escrow" | "withdraw") {
    const directory = new URL(
      `../../../target/zk/timelock-escrow-program/${name}/`,
      import.meta.url,
    );
    this.#verifier = new wasm.VerifyingKey(readFileSync(new URL("vk.bin", directory)));
    try {
      this.#session = new wasm.ProvingSession(
        readFileSync(new URL("circuit.xbc", directory)),
        readFileSync(new URL("pk.bin", directory)),
        readFileSync(new URL("sources.json", directory), "utf8"),
      );
    } catch (error) {
      this.#verifier.free();
      throw error;
    }
  }

  prove(transaction: Pick<ProgramTransaction, "proofInputs" | "publicHash">): ProgramProof {
    if (this.#disposed)
      throw new TransactionError("TRANSACTION_PROGRAM_BUILD", { field: "prover.disposed" });
    const bundle = this.#session.prove(transaction.proofInputs);
    try {
      if (!this.#verifier.verify(bundle.proof, bundle.publicInputs))
        throw new TransactionError("TRANSACTION_DESERIALIZE", { field: "proof" });
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
