import type {
  SignatureDictionary,
  Transaction as KitTransaction,
  TransactionPartialSigner,
  TransactionWithinSizeLimit,
  TransactionWithLifetime,
} from "@solana/kit";
import {
  checkedTransactionSize,
  signerIndex,
  withSignature,
  type Transaction,
  type TransactionSigner,
} from "@zolana/interface";

import { fromKitAddress, toKitAddress } from "./address.js";
import { KitError } from "./error.js";
import {
  fromKitTransaction,
  fromSignatureBytes,
  toKitTransaction,
  toSignatureBytes,
} from "./transaction.js";

type SignableTransaction = KitTransaction & TransactionWithinSizeLimit & TransactionWithLifetime;

/**
 * Adapts a Zolana `TransactionSigner` to Kit's `TransactionPartialSigner`.
 *
 * `signNativeTransaction` returns the full transaction with this signer's slot
 * filled; Kit wants only that signature entry, so it is taken by signer index.
 */
export function toKitSigner(signer: TransactionSigner): TransactionPartialSigner {
  const address = toKitAddress(signer.address);
  return {
    address,
    async signTransactions(transactions) {
      return Promise.all(
        transactions.map(async (transaction): Promise<SignatureDictionary> => {
          const signed = await signer.signNativeTransaction(fromKitTransaction(transaction));
          const signature = signed.signatures[signerIndex(signed, signer.address)];
          if (signature === undefined) throw didNotSign(signer.address);
          return Object.freeze({ [address]: toSignatureBytes(signature) });
        }),
      );
    },
  };
}

/**
 * Adapts a Kit `TransactionPartialSigner` to a Zolana `TransactionSigner`.
 * Kit returns only this signer's entry; `withSignature` merges it without
 * changing other slots.
 */
export function fromKitSigner(signer: TransactionPartialSigner): TransactionSigner {
  const address = fromKitAddress(signer.address);
  return {
    address,
    async signNativeTransaction(transaction: Transaction): Promise<Transaction> {
      const [dictionary] = await signer.signTransactions([signable(transaction)]);
      if (dictionary === undefined) {
        throw new KitError("KIT_SIGNER_RETURNED_NOTHING", "signer answered with no dictionary", {
          details: { address },
        });
      }
      const signature = dictionary[signer.address];
      if (signature === undefined) throw didNotSign(address);
      return withSignature(transaction, address, fromSignatureBytes(signature));
    },
  };
}

/**
 * Kit's `signTransactions` expects a size-checked transaction with a lifetime.
 * Size is enforced against Zolana's limit. Lifetime comes from the compiled
 * legacy message's recent blockhash, which `toKitTransaction` already parses.
 */
function signable(transaction: Transaction): SignableTransaction {
  return toKitTransaction(checkedTransactionSize(transaction)) as SignableTransaction;
}

function didNotSign(address: string): KitError {
  return new KitError("KIT_SIGNER_DID_NOT_SIGN", "signer left its own slot empty", {
    details: { address },
  });
}
