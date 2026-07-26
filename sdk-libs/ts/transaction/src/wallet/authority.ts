import type { Address, Bytes16, Bytes32, MessageData } from "@zolana/interface";
import {
  randomSalt,
  type NullifierKey,
  type P256PublicKey,
  type ShieldedAddress,
  type ShieldedKeypair,
  type ViewingKey,
} from "@zolana/keypair";

import {
  EncryptedScheme,
  encodeAnonymousRecipient,
  encodeAnonymousSender,
  encodeOutputData,
  encodeSplitBundle,
  encryptAnonymous,
  encryptSplit,
  type AnonymousRecipientPlaintext,
  type AnonymousSenderPlaintext,
  type SplitBundlePlaintext,
} from "../serialization/codecs.js";
import { encodeConfidentialSlots, type P256Signature } from "../instructions/transact.js";
import type { ProofOutputUtxo } from "../utxo.js";
import type { AssetRegistry } from "./asset.js";

export type { SplitBundlePlaintext };

export type { P256Signature };

export interface ApprovalRequest {
  readonly solanaPublicKey: Address;
  readonly summary: string;
}

/**
 * Per-transaction encryption envelope an authority returns: the ephemeral
 * transaction viewing key and salt every ciphertext in the transaction shares
 * (published in the clear), plus the sealed payload the operation produced.
 */
export interface EncryptedEnvelope<P> {
  readonly txViewingPublicKey: P256PublicKey;
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

export interface AnonymousRecipientSlot {
  readonly viewTag: Bytes32;
  readonly recipientPublicKey: P256PublicKey;
  readonly plaintext: AnonymousRecipientPlaintext;
}

export interface WalletSyncMaterial {
  readonly identity: ShieldedAddress;
  readonly viewingKeys: readonly ViewingKey[];
  readonly nullifierKey: NullifierKey;
}

export interface SyncWalletAuthority {
  syncMaterial(): Promise<WalletSyncMaterial>;
}

export interface WalletAuthority {
  solanaPublicKey(): Address;
  shieldedAddress(): Promise<ShieldedAddress>;
  viewingKeys(): Promise<readonly ViewingKey[]>;
  spendNullifierKey(): Promise<NullifierKey>;
  syncMaterial(): Promise<WalletSyncMaterial>;
  encryptConfidentialTransfer(
    input: Readonly<{
      firstNullifier: Bytes32;
      outputs: readonly ProofOutputUtxo[];
      assets: AssetRegistry;
    }>,
  ): Promise<EncryptedTransfer>;
  encryptAnonymousTransfer(
    input: Readonly<{
      firstNullifier: Bytes32;
      senderViewTag: Bytes32;
      sender: AnonymousSenderPlaintext;
      recipients: readonly AnonymousRecipientSlot[];
    }>,
  ): Promise<EncryptedTransfer>;
  encryptSplit(
    input: Readonly<{
      firstNullifier: Bytes32;
      viewTag: Bytes32;
      bundle: SplitBundlePlaintext;
    }>,
  ): Promise<EncryptedSplit>;
  requestUserApproval(request: ApprovalRequest): Promise<void>;
  signP256(messageHash: Bytes32): Promise<P256Signature>;
}

/** Binds local shielded keys to the Solana address that publishes them. */
export class LocalWalletAuthority implements WalletAuthority {
  readonly #solanaPublicKey: Address;
  readonly #keypair: ShieldedKeypair;

  constructor(input: Readonly<{ solanaPublicKey: Address; keypair: ShieldedKeypair }>) {
    this.#solanaPublicKey = input.solanaPublicKey;
    this.#keypair = input.keypair;
  }

  solanaPublicKey(): Address {
    return this.#solanaPublicKey;
  }

  shieldedAddress(): Promise<ShieldedAddress> {
    return Promise.resolve(this.#keypair.shieldedAddress());
  }

  viewingKeys(): Promise<readonly ViewingKey[]> {
    return Promise.resolve([this.#keypair.viewingKey()]);
  }

  spendNullifierKey(): Promise<NullifierKey> {
    return Promise.resolve(this.#keypair.nullifierKey());
  }

  syncMaterial(): Promise<WalletSyncMaterial> {
    return Promise.resolve({
      identity: this.#keypair.shieldedAddress(),
      viewingKeys: [this.#keypair.viewingKey()],
      nullifierKey: this.#keypair.nullifierKey(),
    });
  }

  encryptConfidentialTransfer(
    input: Readonly<{
      firstNullifier: Bytes32;
      outputs: readonly ProofOutputUtxo[];
      assets: AssetRegistry;
    }>,
  ): Promise<EncryptedTransfer> {
    const tx = this.#keypair.viewingKey().transactionViewingKey(input.firstNullifier);
    const salt = randomSalt();
    return Promise.resolve({
      txViewingPublicKey: tx.publicKey(),
      salt,
      payload: encodeConfidentialSlots(input.outputs, input.assets, tx, salt),
    });
  }

  /**
   * Slot 0 carries the sender bundle encrypted to this wallet's own viewing
   * key; recipient `i` occupies slot `i + 1`. Both the order and the slot
   * indices are bound into each ciphertext, so they must match the layout the
   * transfer instruction publishes.
   */
  encryptAnonymousTransfer(
    input: Readonly<{
      firstNullifier: Bytes32;
      senderViewTag: Bytes32;
      sender: AnonymousSenderPlaintext;
      recipients: readonly AnonymousRecipientSlot[];
    }>,
  ): Promise<EncryptedTransfer> {
    const viewingKey = this.#keypair.viewingKey();
    const tx = viewingKey.transactionViewingKey(input.firstNullifier);
    const salt = randomSalt();
    const slot = (
      scheme: EncryptedScheme,
      recipient: P256PublicKey,
      plaintext: Uint8Array,
      slotIndex: number,
      viewTag: Bytes32,
    ): MessageData => ({
      viewTag,
      data: encodeOutputData(
        scheme,
        encryptAnonymous(tx, recipient, plaintext, salt, slotIndex),
        "encrypted",
      ),
    });
    return Promise.resolve({
      txViewingPublicKey: tx.publicKey(),
      salt,
      payload: [
        slot(
          EncryptedScheme.anonymousSender,
          viewingKey.publicKey(),
          encodeAnonymousSender(input.sender),
          0,
          input.senderViewTag,
        ),
        ...input.recipients.map((recipient, index) =>
          slot(
            EncryptedScheme.anonymousRecipient,
            recipient.recipientPublicKey,
            encodeAnonymousRecipient(recipient.plaintext),
            index + 1,
            recipient.viewTag,
          ),
        ),
      ],
    });
  }

  encryptSplit(
    input: Readonly<{
      firstNullifier: Bytes32;
      viewTag: Bytes32;
      bundle: SplitBundlePlaintext;
    }>,
  ): Promise<EncryptedSplit> {
    const viewingKey = this.#keypair.viewingKey();
    const tx = viewingKey.transactionViewingKey(input.firstNullifier);
    const salt = randomSalt();
    const body = encryptSplit(tx, viewingKey.publicKey(), encodeSplitBundle(input.bundle), salt, 0);
    return Promise.resolve({
      txViewingPublicKey: tx.publicKey(),
      salt,
      payload: {
        viewTag: input.viewTag,
        data: encodeOutputData(EncryptedScheme.split, body, "encrypted"),
      },
    });
  }

  /** Local keys approve unattended; Rust takes the trait default here. */
  requestUserApproval(request: ApprovalRequest): Promise<void> {
    void request;
    return Promise.resolve();
  }

  signP256(messageHash: Bytes32): Promise<P256Signature> {
    return Promise.resolve(this.#keypair.signP256(messageHash));
  }
}
