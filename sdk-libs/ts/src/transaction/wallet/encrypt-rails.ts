import type { Bytes16, Bytes32, MessageData } from "../../interface/types.js";
import { randomSalt } from "../../keypair/bytes.js";
import type { X25519PublicKey } from "../../keypair/x25519.js";
import type { ViewingKey } from "../../keypair/viewing-key.js";

import { encodeConfidentialSlots } from "../instructions/transact.js";
import {
  EncryptedScheme,
  encodeOutputData,
  encodeSplitBundle,
  encryptSplit as encryptSplitSlot,
  type SplitBundlePlaintext,
} from "../serialization/codecs.js";
import type { ProofOutputUtxo } from "../utxo.js";
import type { AssetRegistry } from "../asset.js";

export type { SplitBundlePlaintext };

/**
 * Per-transaction encryption envelope: the ephemeral transaction viewing key
 * and salt every ciphertext in the transaction shares (published in the
 * clear), plus the sealed payload the operation produced.
 */
export interface EncryptedEnvelope<P> {
  readonly txViewingPublicKey: X25519PublicKey;
  readonly salt: Bytes16;
  readonly payload: P;
}

/**
 * Transfer payload: one ciphertext per output slot, keyed to that output's
 * owner. `undefined` marks a dummy slot the transfer builder pads with a
 * length-matched random ciphertext.
 */
export type EncryptedTransfer = EncryptedEnvelope<readonly (MessageData | undefined)[]>;

/**
 * Split payload: the single sealed slot-0 bundle covering every real output.
 * Unlike a transfer there is exactly one ciphertext; all other slots stay empty
 * on the wire.
 */
export type EncryptedSplit = EncryptedEnvelope<MessageData>;

/**
 * Every sealing step of a transaction, over the per-transaction key
 * `ShieldedKeys.transactionKeys` returns for its first nullifier. The key is
 * the caller's to destroy once the proof inputs are finalized.
 */
export function encryptConfidentialTransfer(
  tx: ViewingKey,
  // A registry is needed only for outputs without retained Mint metadata.
  input: Readonly<{ outputs: readonly ProofOutputUtxo[]; assets?: AssetRegistry }>,
): EncryptedTransfer {
  const salt = randomSalt();
  return {
    txViewingPublicKey: tx.publicKey(),
    salt,
    payload: encodeConfidentialSlots(input.outputs, input.assets, tx, salt),
  };
}

export function encryptSplit(
  tx: ViewingKey,
  input: Readonly<{
    /** The wallet's own viewing public key, which opens the bundle. */
    viewingPublicKey: X25519PublicKey;
    viewTag: Bytes32;
    bundle: SplitBundlePlaintext;
  }>,
): EncryptedSplit {
  const salt = randomSalt();
  return {
    txViewingPublicKey: tx.publicKey(),
    salt,
    payload: {
      viewTag: input.viewTag,
      data: encodeOutputData(
        EncryptedScheme.split,
        encryptSplitSlot(tx, input.viewingPublicKey, encodeSplitBundle(input.bundle), salt, 0),
        "encrypted",
      ),
    },
  };
}
