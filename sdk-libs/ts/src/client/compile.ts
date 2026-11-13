import { compileUnsignedTransaction } from "../flows/compile.js";
import type { Address, Instruction, Transaction } from "../interface/types.js";
import { ClientError } from "./error.js";
import type { LatestBlockhash } from "./kit.js";

/**
 * Compute-unit ceiling a private transaction is submitted with unless the
 * caller overrides it, matching Rust's `DEFAULT_TRANSACT_CU_LIMIT`. A shielded
 * transact verifies a Groth16 proof on chain, which does not fit inside the
 * budget a legacy transaction received per instruction.
 *
 * Sized from the widest shape this client can send on the rail it sends it on:
 * proving goes through the EdDSA rail, and the widest confidential transaction,
 * 49x2 with every input real, consumes 305,340 CU on a validator
 * (`program-tests/spp-test-validator/tests/max_shapes.rs`). The remaining
 * headroom absorbs the per-input `create_nullifier_pdas` cost, which moves with
 * tree state rather than with the shape.
 *
 * Under transaction version 1 this rides in the message header, and requested
 * units rather than consumed ones set the priority fee, so a caller sending
 * only small shapes should pass a lower `computeUnitLimit`.
 */
export const DEFAULT_TRANSACT_COMPUTE_UNIT_LIMIT = 450_000;

/** What {@link compileVersion1Transaction} compiles. */
export interface Version1TransactionOptions {
  readonly feePayer: Address;
  readonly lifetime: LatestBlockhash;
  readonly instructions: readonly Instruction[];
  /**
   * The compute units the transaction may use, at most 1,400,000. Defaults to
   * {@link DEFAULT_TRANSACT_COMPUTE_UNIT_LIMIT}, the budget the SDK gives a
   * shielded transact; add what your own program's instruction consumes.
   */
  readonly computeUnitLimit?: number;
  /** The whole transaction's priority fee in lamports, not a price per compute unit. */
  readonly priorityFeeLamports?: bigint;
}

/**
 * Compiles `instructions` into an unsigned version 1 transaction the way the
 * SDK's own builders do, for a program that wraps a shielded-pool instruction
 * in an instruction of its own. A version 1 transaction carries its budget in
 * the message header and budgets zero for a limit it leaves out, so both the
 * compute-unit limit and the loaded-accounts-data-size limit are always
 * written. A transaction past 4,096 bytes throws the `InterfaceError`
 * `INTERFACE_TRANSACTION_TOO_LARGE`.
 */
export function compileVersion1Transaction(options: Version1TransactionOptions): Transaction {
  const computeUnitLimit = options.computeUnitLimit ?? DEFAULT_TRANSACT_COMPUTE_UNIT_LIMIT;
  // A zero limit compiles but cannot execute.
  if (computeUnitLimit === 0) {
    throw new ClientError("CLIENT_INVALID_INTEGER", { details: { field: "computeUnitLimit" } });
  }
  return compileUnsignedTransaction({
    feePayer: options.feePayer,
    lifetime: options.lifetime,
    instructions: options.instructions,
    computeUnitLimit,
    ...(options.priorityFeeLamports === undefined
      ? {}
      : { priorityFeeLamports: options.priorityFeeLamports }),
  });
}
