import type { Bytes16, MessageData } from "../../interface/types.js";
import { randomSalt } from "../../keypair/bytes.js";
import type { X25519PublicKey } from "../../keypair/x25519.js";
import type { ViewingKey } from "../../keypair/viewing-key.js";

import { encodeConfidentialSlots } from "../instructions/transact.js";
import type { ProofOutputUtxo } from "../utxo.js";
import type { AssetRegistry } from "../asset.js";

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
