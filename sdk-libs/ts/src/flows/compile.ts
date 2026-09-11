import {
  appendTransactionMessageInstructions,
  compileTransaction,
  createTransactionMessage,
  pipe,
  setTransactionMessageConfig,
  setTransactionMessageFeePayer,
  setTransactionMessageLifetimeUsingBlockhash,
} from "@solana/kit";

import { ClientError } from "../client/error.js";
import type { LatestBlockhash } from "../client/kit.js";
import type { Shape } from "../interface/shape.js";
import { checkedTransactionSize } from "../interface/transaction-size.js";
import type { Address, Instruction, Transaction } from "../interface/types.js";
import { checkedAddress, checkedComputeUnitLimit, checkedPriorityFee } from "./internal.js";

/**
 * Every account the pool, the registry and a settlement touch fits well under
 * this. A version 1 transaction budgets zero bytes of account data when the
 * field is left out, so it is always sent.
 */
export const LOADED_ACCOUNTS_DATA_SIZE_LIMIT = 64 * 1024 * 1024;

/** @internal */
export interface TransactionCompilerOptions {
  readonly feePayer: Address;
  readonly lifetime: LatestBlockhash;
  /** The payload, appended after the setup instructions. */
  readonly instructions: readonly Instruction[];
  /** Carried in the version 1 header. Unset budgets zero units, so it is required. */
  readonly computeUnitLimit: number;
  /** The whole transaction's fee, not a price per compute unit. */
  readonly priorityFeeLamports?: bigint;
  readonly setupInstructions?: readonly Instruction[];
  /** Names the proof shape when the compiled bytes exceed the limit. */
  readonly sizeShape?: Shape;
}

/** @internal One compile path, refused past the version 1 size limit. */
export function compileUnsignedTransaction(options: TransactionCompilerOptions): Transaction {
  checkedAddress(options.feePayer, "feePayer");
  checkedComputeUnitLimit(options.computeUnitLimit);
  checkedPriorityFee(options.priorityFeeLamports);
  const instructions: readonly Instruction[] = [
    ...(options.setupInstructions ?? []),
    ...options.instructions,
  ];
  let compiled: Transaction;
  try {
    const message = pipe(
      createTransactionMessage({ version: 1 }),
      (tx) => setTransactionMessageFeePayer(options.feePayer, tx),
      (tx) => setTransactionMessageLifetimeUsingBlockhash(options.lifetime, tx),
      (tx) =>
        setTransactionMessageConfig(
          {
            computeUnitLimit: options.computeUnitLimit,
            loadedAccountsDataSizeLimit: LOADED_ACCOUNTS_DATA_SIZE_LIMIT,
            ...(options.priorityFeeLamports === undefined
              ? {}
              : { priorityFeeLamports: options.priorityFeeLamports }),
          },
          tx,
        ),
      (tx) => appendTransactionMessageInstructions(instructions, tx),
    );
    compiled = compileTransaction(message);
  } catch (cause) {
    throw new ClientError("CLIENT_TRANSACTION_ASSEMBLY", { cause });
  }
  return checkedTransactionSize(compiled, options.sizeShape);
}
