import type { Address, Bytes16, Bytes32, MessageData } from "../../interface/types.js";
import { randomSalt } from "../../keypair/bytes.js";
import type { NullifierKey } from "../../keypair/nullifier-key.js";
import type { P256PublicKey } from "../../keypair/public-key.js";
import type { ShieldedAddress, ShieldedKeypair } from "../../keypair/shielded.js";
import type { ViewingKey } from "../../keypair/viewing-key.js";

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
import { TransactionError } from "../error.js";
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

export interface ConfidentialTransferInput {
  readonly firstNullifier: Bytes32;
  readonly outputs: readonly ProofOutputUtxo[];
  readonly assets: AssetRegistry;
}

export interface AnonymousTransferInput {
  readonly firstNullifier: Bytes32;
  readonly senderViewTag: Bytes32;
  readonly sender: AnonymousSenderPlaintext;
  readonly recipients: readonly AnonymousRecipientSlot[];
}

export interface SplitInput {
  readonly firstNullifier: Bytes32;
  readonly viewTag: Bytes32;
  readonly bundle: SplitBundlePlaintext;
}

/**
 * The keys that open a transaction: a shielded identity, its viewing keys, and
 * its nullifier key. Reading a wallet needs no spend authority, so a viewing
 * key alone satisfies this. `ShieldedKeypair` holds all three and can be passed
 * directly, as in Rust.
 *
 * Resolving them must not block, which is what keeps decryption synchronous. An
 * authority that fetches keys off-box resolves first and passes the result
 * through `syncWalletAuthorityFromMaterial`.
 */
export interface DecryptionKeys {
  syncMaterial(): WalletSyncMaterial;
}

/**
 * The same keys, resolved. A remote signer produces these by awaiting its
 * authority; `syncWallet` accepts either form.
 */
export interface SyncMaterialSource {
  syncMaterial(): WalletSyncMaterial | Promise<WalletSyncMaterial>;
}

/**
 * Blocking form of the whole authority capability, for local wallets, tests,
 * and synchronous clients. `walletAuthorityFromSync` exposes any blocking
 * authority as a `WalletAuthority`; this is not a smaller, least-privilege
 * capability.
 */
export interface SyncWalletAuthority {
  solanaPublicKey(): Address;
  shieldedAddress(): ShieldedAddress;
  viewingKeys(): readonly ViewingKey[];
  spendNullifierKey(): NullifierKey;
  syncMaterial(): WalletSyncMaterial;
  encryptConfidentialTransfer(input: ConfidentialTransferInput): EncryptedTransfer;
  encryptAnonymousTransfer(input: AnonymousTransferInput): EncryptedTransfer;
  encryptSplit(input: SplitInput): EncryptedSplit;
  requestUserApproval(request: ApprovalRequest): void;
}

/**
 * The awaiting form of the same capability. A remote signer or hardware wallet
 * implements this directly; a blocking one reaches it through
 * `walletAuthorityFromSync`.
 */
export interface WalletAuthority {
  solanaPublicKey(): Address;
  shieldedAddress(): Promise<ShieldedAddress>;
  viewingKeys(): Promise<readonly ViewingKey[]>;
  spendNullifierKey(): Promise<NullifierKey>;
  syncMaterial(): Promise<WalletSyncMaterial>;
  encryptConfidentialTransfer(input: ConfidentialTransferInput): Promise<EncryptedTransfer>;
  encryptAnonymousTransfer(input: AnonymousTransferInput): Promise<EncryptedTransfer>;
  encryptSplit(input: SplitInput): Promise<EncryptedSplit>;
  requestUserApproval(request: ApprovalRequest): Promise<void>;
}

/**
 * Rust gives `sync_material` a default body on both authority traits. Compose
 * it once here so the two forms cannot drift apart.
 */
export function syncMaterialFrom(
  source: Readonly<{
    identity: ShieldedAddress;
    viewingKeys: readonly ViewingKey[];
    nullifierKey: NullifierKey;
  }>,
): WalletSyncMaterial {
  return {
    identity: source.identity,
    viewingKeys: source.viewingKeys,
    nullifierKey: source.nullifierKey,
  };
}

/**
 * A read-only blocking authority over already-fetched material, for the decrypt
 * path. Rust reaches this by passing any blocking authority straight to
 * `decrypt_transactions`; an awaiting authority cannot become a blocking one, so
 * a caller that holds one passes the material it resolved instead. The
 * encrypting methods are unreachable here and throw rather than sign anything.
 */
export function syncWalletAuthorityFromMaterial(material: WalletSyncMaterial): SyncWalletAuthority {
  const unsupported = (): never => {
    throw new TransactionError("TRANSACTION_AUTHORITY_READ_ONLY");
  };
  return {
    solanaPublicKey: unsupported,
    shieldedAddress: () => material.identity,
    viewingKeys: () => material.viewingKeys,
    spendNullifierKey: () => material.nullifierKey,
    syncMaterial: () => material,
    encryptConfidentialTransfer: unsupported,
    encryptAnonymousTransfer: unsupported,
    encryptSplit: unsupported,
    requestUserApproval: unsupported,
  };
}

/** Stands in for Rust's blanket `impl<T: SyncWalletAuthority> WalletAuthority for T`. */
export function walletAuthorityFromSync(sync: SyncWalletAuthority): WalletAuthority {
  return {
    solanaPublicKey: () => sync.solanaPublicKey(),
    shieldedAddress: () => Promise.resolve(sync.shieldedAddress()),
    viewingKeys: () => Promise.resolve(sync.viewingKeys()),
    spendNullifierKey: () => Promise.resolve(sync.spendNullifierKey()),
    syncMaterial: () => Promise.resolve(sync.syncMaterial()),
    encryptConfidentialTransfer: (input) =>
      Promise.resolve(sync.encryptConfidentialTransfer(input)),
    encryptAnonymousTransfer: (input) => Promise.resolve(sync.encryptAnonymousTransfer(input)),
    encryptSplit: (input) => Promise.resolve(sync.encryptSplit(input)),
    requestUserApproval: (request) => Promise.resolve(sync.requestUserApproval(request)),
  };
}

/** Binds local shielded keys to the Solana address that publishes them. */
export class LocalWalletAuthority implements SyncWalletAuthority {
  readonly #solanaPublicKey: Address;
  readonly #keypair: ShieldedKeypair;

  constructor(input: Readonly<{ solanaPublicKey: Address; keypair: ShieldedKeypair }>) {
    this.#solanaPublicKey = input.solanaPublicKey;
    this.#keypair = input.keypair;
  }

  solanaPublicKey(): Address {
    return this.#solanaPublicKey;
  }

  shieldedAddress(): ShieldedAddress {
    return this.#keypair.shieldedAddress();
  }

  viewingKeys(): readonly ViewingKey[] {
    return [this.#keypair.viewingKey()];
  }

  spendNullifierKey(): NullifierKey {
    return this.#keypair.nullifierKey();
  }

  syncMaterial(): WalletSyncMaterial {
    return this.#keypair.syncMaterial();
  }

  encryptConfidentialTransfer(input: ConfidentialTransferInput): EncryptedTransfer {
    const tx = this.#keypair.viewingKey().transactionViewingKey(input.firstNullifier);
    const salt = randomSalt();
    return {
      txViewingPublicKey: tx.publicKey(),
      salt,
      payload: encodeConfidentialSlots(input.outputs, input.assets, tx, salt),
    };
  }

  /**
   * Slot 0 carries the sender bundle encrypted to this wallet's own viewing
   * key; recipient `i` occupies slot `i + 1`. Both the order and the slot
   * indices are bound into each ciphertext, so they must match the layout the
   * transfer instruction publishes.
   */
  encryptAnonymousTransfer(input: AnonymousTransferInput): EncryptedTransfer {
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
    return {
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
    };
  }

  encryptSplit(input: SplitInput): EncryptedSplit {
    const viewingKey = this.#keypair.viewingKey();
    const tx = viewingKey.transactionViewingKey(input.firstNullifier);
    const salt = randomSalt();
    const body = encryptSplit(tx, viewingKey.publicKey(), encodeSplitBundle(input.bundle), salt, 0);
    return {
      txViewingPublicKey: tx.publicKey(),
      salt,
      payload: {
        viewTag: input.viewTag,
        data: encodeOutputData(EncryptedScheme.split, body, "encrypted"),
      },
    };
  }

  /** Local keys approve unattended; Rust takes the trait default here. */
  requestUserApproval(request: ApprovalRequest): void {
    void request;
  }
}
