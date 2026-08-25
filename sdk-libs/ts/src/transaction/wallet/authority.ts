import { ed25519 } from "@noble/curves/ed25519.js";
import { getAddressEncoder } from "@solana/kit";

import type { Address, Bytes16, Bytes32, Bytes64, MessageData } from "../../interface/types.js";
import { checkedBytes, randomSalt } from "../../keypair/bytes.js";
import {
  checkedDerivationSeed,
  ed25519DerivationMessage,
  roleExpansion,
} from "../../keypair/derivation.js";
import { NullifierKey } from "../../keypair/nullifier-key.js";
import { P256PublicKey, ShieldedPublicKey } from "../../keypair/public-key.js";
import { ShieldedAddress, type ShieldedKeypair } from "../../keypair/shielded.js";
import { TransactionError } from "../error.js";
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
}

const addressEncoder = getAddressEncoder();

/**
 * Client-owned privacy roles derived from a deterministic Ed25519 signature
 * produced by a remote signer.
 *
 * This authority contains no Solana signing key. It verifies the derivation
 * signature, expands the viewing/nullifier roles in this process, and supports
 * local wallet sync and proof construction. The completed transaction must be
 * authorized through a separate, typed remote operation.
 */
export class ClientEd25519WalletAuthority implements WalletAuthority {
  readonly #solanaPublicKey: Address;
  readonly #signingPublicKey: ShieldedPublicKey;
  readonly #nullifierKey: NullifierKey;
  readonly #viewingKey: ViewingKey;

  private constructor(
    solanaPublicKey: Address,
    signingPublicKey: ShieldedPublicKey,
    nullifierKey: NullifierKey,
    viewingKey: ViewingKey,
  ) {
    this.#solanaPublicKey = solanaPublicKey;
    this.#signingPublicKey = signingPublicKey;
    this.#nullifierKey = nullifierKey;
    this.#viewingKey = viewingKey;
  }

  static fromDerivationSeed(
    input: Readonly<{
      solanaPublicKey: Address;
      derivationSeed: Bytes64;
    }>,
  ): ClientEd25519WalletAuthority {
    const publicKey = checkedBytes<Bytes32>(
      new Uint8Array(addressEncoder.encode(input.solanaPublicKey)),
      32,
      "Ed25519 public key",
    );
    const seed = checkedDerivationSeed<Bytes64>(input.derivationSeed, "ed25519");
    const message = ed25519DerivationMessage(publicKey);
    if (!ed25519.verify(seed, message, publicKey, { zip215: false })) {
      seed.fill(0);
      // Mirrors Rust `TransactionError::InvalidDerivationSeed`. The seed is the
      // right width but is not a signature over this key's derivation message,
      // which is a different failure from a wrong-width seed.
      throw new TransactionError("TRANSACTION_INVALID_DERIVATION_SEED");
    }

    try {
      const expansion = roleExpansion(seed, "ed25519");
      const nullifierSecret = expansion.nullifierSecret();
      const viewingSecret = expansion.viewingSecret();
      try {
        return new ClientEd25519WalletAuthority(
          input.solanaPublicKey,
          ShieldedPublicKey.fromEd25519(publicKey),
          NullifierKey.fromSecret(nullifierSecret),
          ViewingKey.fromBytes(viewingSecret),
        );
      } finally {
        nullifierSecret.fill(0);
        viewingSecret.fill(0);
      }
    } finally {
      seed.fill(0);
    }
  }

  solanaPublicKey(): Address {
    return this.#solanaPublicKey;
  }

  shieldedAddress(): Promise<ShieldedAddress> {
    return Promise.resolve(
      ShieldedAddress.fromPublicKeys(
        this.#signingPublicKey,
        this.#nullifierKey.publicKey(),
        this.#viewingKey.publicKey(),
      ),
    );
  }

  viewingKeys(): Promise<readonly ViewingKey[]> {
    return Promise.resolve([this.#copyViewingKey()]);
  }

  spendNullifierKey(): Promise<NullifierKey> {
    return Promise.resolve(this.#copyNullifierKey());
  }

  async syncMaterial(): Promise<WalletSyncMaterial> {
    return {
      identity: await this.shieldedAddress(),
      viewingKeys: [this.#copyViewingKey()],
      nullifierKey: this.#copyNullifierKey(),
    };
  }

  encryptConfidentialTransfer(
    input: Readonly<{
      firstNullifier: Bytes32;
      outputs: readonly ProofOutputUtxo[];
      assets: AssetRegistry;
    }>,
  ): Promise<EncryptedTransfer> {
    const tx = this.#viewingKey.transactionViewingKey(input.firstNullifier);
    const salt = randomSalt();
    return Promise.resolve({
      txViewingPublicKey: tx.publicKey(),
      salt,
      payload: encodeConfidentialSlots(input.outputs, input.assets, tx, salt),
    });
  }

  encryptAnonymousTransfer(
    input: Readonly<{
      firstNullifier: Bytes32;
      senderViewTag: Bytes32;
      sender: AnonymousSenderPlaintext;
      recipients: readonly AnonymousRecipientSlot[];
    }>,
  ): Promise<EncryptedTransfer> {
    const tx = this.#viewingKey.transactionViewingKey(input.firstNullifier);
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
          this.#viewingKey.publicKey(),
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
    const tx = this.#viewingKey.transactionViewingKey(input.firstNullifier);
    const salt = randomSalt();
    return Promise.resolve({
      txViewingPublicKey: tx.publicKey(),
      salt,
      payload: {
        viewTag: input.viewTag,
        data: encodeOutputData(
          EncryptedScheme.split,
          encryptSplit(tx, this.#viewingKey.publicKey(), encodeSplitBundle(input.bundle), salt, 0),
          "encrypted",
        ),
      },
    });
  }

  /**
   * Deliberately a no-op. This authority holds no signing key and cannot reach
   * a user: the remote signer authorizes the finished Solana transaction in a
   * separate step, and that step is the approval gate. Rejecting here instead
   * would make the type unusable, since transaction construction — which this
   * authority exists to serve — calls this before it has a transaction to
   * approve.
   */
  requestUserApproval(request: ApprovalRequest): Promise<void> {
    void request;
    return Promise.resolve();
  }

  #copyViewingKey(): ViewingKey {
    const secret = this.#viewingKey.secretBytes();
    try {
      return ViewingKey.fromBytes(secret);
    } finally {
      secret.fill(0);
    }
  }

  #copyNullifierKey(): NullifierKey {
    const secret = this.#nullifierKey.secretBytes();
    try {
      return NullifierKey.fromSecret(secret);
    } finally {
      secret.fill(0);
    }
  }
}

/** Binds a shielded keypair to the Solana address that publishes it. */
export class KeypairWalletAuthority implements WalletAuthority {
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
}
