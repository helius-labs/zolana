import type { Address } from "@solana/kit";

import { encodeMergeOutputDerivation, mergeMaskNonces } from "../../src/interface/codecs/index.js";
import type { Bytes31, Bytes32 } from "../../src/interface/types.js";
import {
  mergeAmountMask,
  mergeMaskedAmount,
  mergeMaskedMint,
  mergeMintMask,
} from "../../src/keypair/merge/index.js";
import type { NullifierKey } from "../../src/keypair/nullifier-key.js";
import { decodeAddress } from "../../src/transaction/internal.js";

/**
 * The message a merge of `amount` of `mint` publishes for its owner, under a
 * fixed mask seed, as the indexer republishes it.
 */
export function mergeMessageData(
  nullifierKey: NullifierKey,
  firstNullifier: Bytes32,
  amount: bigint,
  mint: Address,
  outputRingDataHash?: Bytes32,
): Uint8Array {
  const maskSeed = new Uint8Array(31).fill(0x5e) as Bytes31;
  const nonces = mergeMaskNonces(maskSeed);
  return encodeMergeOutputDerivation({
    maskedAmount: mergeMaskedAmount(
      amount,
      mergeAmountMask(nullifierKey, firstNullifier, nonces.amount),
    ),
    maskedMint: mergeMaskedMint(decodeAddress(mint), [
      mergeMintMask(nullifierKey, firstNullifier, nonces.mint, 0),
      mergeMintMask(nullifierKey, firstNullifier, nonces.mint, 1),
    ]),
    maskSeed,
    ...(outputRingDataHash === undefined ? {} : { outputRingDataHash }),
  });
}
