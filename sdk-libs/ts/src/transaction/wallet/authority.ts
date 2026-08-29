import { ed25519 } from "@noble/curves/ed25519.js";
import { getAddressEncoder } from "@solana/kit";

import type { Address, Bytes16, Bytes32, Bytes64, MessageData } from "../../interface/types.js";
import { checkedBytes } from "../../keypair/bytes.js";
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

import type {
  AnonymousRecipientPlaintext,
  AnonymousSenderPlaintext,
  SplitBundlePlaintext,
} from "../serialization/codecs.js";
import { decodeAddress } from "../internal.js";
import { runSpendSession, runSyncSession } from "./encrypt-rails.js";
import { approveIntent, type IntentApproval, type TransactionIntent } from "./intent.js";
import type { ProofOutputUtxo } from "../utxo.js";
import type { AssetRegistry } from "./asset.js";

export type { SplitBundlePlaintext };

export interface ApprovalRequest {
  readonly solanaPublicKey: Address;
  readonly intent: TransactionIntent;
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

/** Spend-scoped capabilities over one borrowed key set. */
export interface SpendSession {
  /** The same borrowed key on every call, wiped when the session ends. */
  nullifierKey(): NullifierKey;
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
}

export interface SpendAuthority {
  /** Keys lent to `run` are wiped when the callback settles, do not retain them. */
  withSpendSession<T>(run: (session: SpendSession) => Promise<T>): Promise<T>;
}

export interface SyncAuthority {
  /** The lent material's keys are wiped when the callback settles, do not retain them. */
  withSyncSession<T>(run: (session: SyncWalletAuthority) => Promise<T>): Promise<T>;
}

export interface WalletAuthority extends SpendAuthority, SyncAuthority {
  solanaPublicKey(): Address;
  shieldedAddress(): Promise<ShieldedAddress>;
  requestUserApproval(request: ApprovalRequest): Promise<IntentApproval>;
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

  withSpendSession<T>(run: (session: SpendSession) => Promise<T>): Promise<T> {
    return runSpendSession(this.#copyViewingKey(), this.#copyNullifierKey(), run);
  }

  async withSyncSession<T>(run: (session: SyncWalletAuthority) => Promise<T>): Promise<T> {
    return runSyncSession(
      {
        identity: await this.shieldedAddress(),
        viewingKeys: [this.#copyViewingKey()],
        nullifierKey: this.#copyNullifierKey(),
      },
      run,
    );
  }

  /** Approves unattended, the remote signer of the finished transaction is the approval gate. */
  requestUserApproval(request: ApprovalRequest): Promise<IntentApproval> {
    return Promise.resolve(approveIntent(request.intent));
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

/**
 * Binds a shielded keypair to the Solana address that publishes it. The Solana
 * signature of the transaction authorizes the spend, so the signing secret is
 * not held here.
 */
export class KeypairWalletAuthority implements WalletAuthority {
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
  ): KeypairWalletAuthority {
    const expansion = roleExpansion(input.derivationSeed, "ed25519");
    const viewingSecret = expansion.viewingSecret();
    const nullifierSecret = expansion.nullifierSecret();
    try {
      const viewing = ViewingKey.fromBytes(viewingSecret);
      const nullifier = NullifierKey.fromSecret(nullifierSecret);
      const signing = ShieldedPublicKey.fromEd25519(decodeAddress(input.solanaPublicKey));
      const address = ShieldedAddress.fromPublicKeys(
        signing,
        nullifier.publicKey(),
        viewing.publicKey(),
      );
      return new KeypairWalletAuthority({
        solanaPublicKey: input.solanaPublicKey,
        address,
        viewingKey: viewing,
        nullifierKey: nullifier,
      });
    } finally {
      viewingSecret.fill(0);
      nullifierSecret.fill(0);
    }
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

  withSpendSession<T>(run: (session: SpendSession) => Promise<T>): Promise<T> {
    return runSpendSession(this.#viewingKey(), this.#nullifierKey(), run);
  }

  withSyncSession<T>(run: (session: SyncWalletAuthority) => Promise<T>): Promise<T> {
    return runSyncSession(
      {
        identity: this.#address,
        viewingKeys: [this.#viewingKey()],
        nullifierKey: this.#nullifierKey(),
      },
      run,
    );
  }

  /** Local keys approve unattended; Rust takes the trait default here. */
  requestUserApproval(request: ApprovalRequest): Promise<IntentApproval> {
    return Promise.resolve(approveIntent(request.intent));
  }
}

export { KeypairWalletAuthority as LocalWalletAuthority };
