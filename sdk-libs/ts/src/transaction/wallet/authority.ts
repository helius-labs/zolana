import type { Address, Bytes16, Bytes32, MessageData } from "../../interface/types.js";
import { auditorMessageData, encryptTransactionViewingSecret } from "../../keypair/audit.js";
import { randomSalt } from "../../keypair/bytes.js";
import { roleExpansion } from "../../keypair/derivation.js";
import { NullifierKey } from "../../keypair/nullifier-key.js";
import { type P256PublicKey, ShieldedPublicKey } from "../../keypair/public-key.js";
import { ShieldedAddress, type ShieldedKeypair } from "../../keypair/shielded.js";
import { ViewingKey } from "../../keypair/viewing-key.js";

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
import { encodeConfidentialSlots } from "../instructions/transact.js";
import { decodeAddress } from "../internal.js";
import type { ProofOutputUtxo } from "../utxo.js";
import type { AssetRegistry } from "./asset.js";

export type { SplitBundlePlaintext };

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

/** `txViewingSecret` is what the auditor key opens. It leaves the authority only for the ring's own prover. */
export interface AuditWitness {
  readonly txViewingSecret: Bytes32;
  readonly ephemeralSecret: Bytes32;
}

export interface EncryptedCustomRingTransfer extends EncryptedTransfer {
  readonly auditorMessage: MessageData;
  readonly audit: AuditWitness;
}

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
  encryptCustomRingTransfer(
    input: Readonly<{
      firstNullifier: Bytes32;
      outputs: readonly ProofOutputUtxo[];
      assets: AssetRegistry;
      auditorPublicKey: P256PublicKey;
    }>,
  ): Promise<EncryptedCustomRingTransfer>;
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
}

/**
 * Binds local shielded keys to the Solana address that publishes them. The
 * Solana signature of the transaction authorizes the spend, so the signing
 * secret is not held here.
 */
export class LocalWalletAuthority implements WalletAuthority {
  readonly #solanaPublicKey: Address;
  readonly #address: ShieldedAddress;
  readonly #viewing: ViewingKey;
  readonly #nullifier: NullifierKey;

  constructor(
    input: Readonly<
      { solanaPublicKey: Address } & (
        | { keypair: ShieldedKeypair }
        | { address: ShieldedAddress; viewingKey: ViewingKey; nullifierKey: NullifierKey }
      )
    >,
  ) {
    this.#solanaPublicKey = input.solanaPublicKey;
    if ("keypair" in input) {
      this.#address = input.keypair.shieldedAddress();
      this.#viewing = input.keypair.viewingKey();
      this.#nullifier = input.keypair.nullifierKey();
    } else {
      this.#address = input.address;
      this.#viewing = input.viewingKey;
      this.#nullifier = input.nullifierKey;
    }
  }

  /** `derivationSeed` is the wallet's signature over `ed25519DerivationMessage(publicKey)`. */
  static fromDerivationSeed(
    input: Readonly<{ solanaPublicKey: Address; derivationSeed: Uint8Array }>,
  ): LocalWalletAuthority {
    const expansion = roleExpansion(input.derivationSeed, "ed25519");
    const viewing = ViewingKey.fromBytes(expansion.viewingSecret());
    const nullifier = NullifierKey.fromSecret(expansion.nullifierSecret());
    const signing = ShieldedPublicKey.fromEd25519(decodeAddress(input.solanaPublicKey));
    const address = ShieldedAddress.fromPublicKeys(
      signing,
      nullifier.publicKey(),
      viewing.publicKey(),
    );
    return new LocalWalletAuthority({
      solanaPublicKey: input.solanaPublicKey,
      address,
      viewingKey: viewing,
      nullifierKey: nullifier,
    });
  }

  solanaPublicKey(): Address {
    return this.#solanaPublicKey;
  }

  // A fresh key object per call, so a caller that destroys one cannot disarm the authority.
  #viewingKey(): ViewingKey {
    const secret = this.#viewing.secretBytes();
    try {
      return ViewingKey.fromBytes(secret);
    } finally {
      secret.fill(0);
    }
  }

  #nullifierKey(): NullifierKey {
    const secret = this.#nullifier.secretBytes();
    try {
      return NullifierKey.fromSecret(secret);
    } finally {
      secret.fill(0);
    }
  }

  shieldedAddress(): Promise<ShieldedAddress> {
    return Promise.resolve(this.#address);
  }

  viewingKeys(): Promise<readonly ViewingKey[]> {
    return Promise.resolve([this.#viewingKey()]);
  }

  spendNullifierKey(): Promise<NullifierKey> {
    return Promise.resolve(this.#nullifierKey());
  }

  syncMaterial(): Promise<WalletSyncMaterial> {
    return Promise.resolve({
      identity: this.#address,
      viewingKeys: [this.#viewingKey()],
      nullifierKey: this.#nullifierKey(),
    });
  }

  encryptConfidentialTransfer(
    input: Readonly<{
      firstNullifier: Bytes32;
      outputs: readonly ProofOutputUtxo[];
      assets: AssetRegistry;
    }>,
  ): Promise<EncryptedTransfer> {
    const tx = this.#viewing.transactionViewingKey(input.firstNullifier);
    const salt = randomSalt();
    return Promise.resolve({
      txViewingPublicKey: tx.publicKey(),
      salt,
      payload: encodeConfidentialSlots(input.outputs, input.assets, tx, salt),
    });
  }

  encryptCustomRingTransfer(
    input: Readonly<{
      firstNullifier: Bytes32;
      outputs: readonly ProofOutputUtxo[];
      assets: AssetRegistry;
      auditorPublicKey: P256PublicKey;
    }>,
  ): Promise<EncryptedCustomRingTransfer> {
    const tx = this.#viewing.transactionViewingKey(input.firstNullifier);
    const salt = randomSalt();
    const txViewingSecret = tx.secretBytes();
    const encryption = encryptTransactionViewingSecret(txViewingSecret, input.auditorPublicKey);
    return Promise.resolve({
      txViewingPublicKey: tx.publicKey(),
      salt,
      payload: encodeConfidentialSlots(input.outputs, input.assets, tx, salt),
      auditorMessage: auditorMessageData(encryption.message, input.auditorPublicKey),
      audit: Object.freeze({ txViewingSecret, ephemeralSecret: encryption.ephemeralSecret }),
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
    const viewingKey = this.#viewing;
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
    const viewingKey = this.#viewing;
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
}
