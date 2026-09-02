import {
  getSetComputeUnitLimitInstruction,
  getSetComputeUnitPriceInstruction,
} from "@solana-program/compute-budget";
import {
  appendTransactionMessageInstructions,
  compileTransaction,
  compressTransactionMessageUsingAddressLookupTables,
  createTransactionMessage,
  pipe,
  setTransactionMessageFeePayer,
  setTransactionMessageLifetimeUsingBlockhash,
} from "@solana/kit";

import { ClientError } from "../client/error.js";
import type { LatestBlockhash } from "../client/kit.js";
import type { Shape } from "../interface/shape.js";
import { checkedTransactionSize } from "../interface/transaction-size.js";
import type { Address, Instruction, Transaction } from "../interface/types.js";
import { checkedAddress, checkedComputeUnitPrice, checkedU32 } from "./internal.js";

/** @internal */
export interface TransactionCompilerOptions {
  readonly feePayer: Address;
  readonly lifetime: LatestBlockhash;
  /** The payload, appended after the budget and setup instructions. */
  readonly instructions: readonly Instruction[];
  readonly computeUnitLimit?: number;
  readonly computeUnitPriceMicroLamports?: bigint;
  readonly setupInstructions?: readonly Instruction[];
  readonly lookupTables?: Readonly<Record<Address, readonly Address[]>>;
  /** Names the proof shape when the compiled bytes exceed the packet. */
  readonly sizeShape?: Shape;
}

/** @internal One compile path, refused past the packet limit. */
export function compileUnsignedTransaction(options: TransactionCompilerOptions): Transaction {
  checkedAddress(options.feePayer, "feePayer");
  if (options.computeUnitLimit !== undefined) {
    checkedU32(options.computeUnitLimit, "computeUnitLimit");
  }
  checkedComputeUnitPrice(options.computeUnitPriceMicroLamports);
  const instructions: readonly Instruction[] = [
    ...(options.computeUnitLimit === undefined
      ? []
      : [getSetComputeUnitLimitInstruction({ units: options.computeUnitLimit })]),
    ...(options.computeUnitPriceMicroLamports === undefined
      ? []
      : [
          getSetComputeUnitPriceInstruction({
            microLamports: options.computeUnitPriceMicroLamports,
          }),
        ]),
    ...(options.setupInstructions ?? []),
    ...options.instructions,
  ];
  const lookupTables = options.lookupTables;
  let compiled: Transaction;
  try {
    const message = pipe(
      createTransactionMessage({ version: 0 }),
      (tx) => setTransactionMessageFeePayer(options.feePayer, tx),
      (tx) => setTransactionMessageLifetimeUsingBlockhash(options.lifetime, tx),
      (tx) => appendTransactionMessageInstructions(instructions, tx),
      (tx) =>
        lookupTables === undefined
          ? tx
          : compressTransactionMessageUsingAddressLookupTables(
              tx,
              lookupTables as Parameters<
                typeof compressTransactionMessageUsingAddressLookupTables
              >[1],
            ),
    );
    compiled = compileTransaction(message);
  } catch (cause) {
    throw new ClientError("CLIENT_TRANSACTION_ASSEMBLY", { cause });
  }
  return checkedTransactionSize(compiled, options.sizeShape);
}
