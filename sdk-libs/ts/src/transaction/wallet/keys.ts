import { ed25519 } from "@noble/curves/ed25519.js";
import { getAddressEncoder } from "@solana/kit";

import type { Address, Bytes16, Bytes32, Bytes64, RequestContext } from "../../interface/types.js";
import { checkedBytes } from "../../keypair/bytes.js";
import {
  checkedDerivationSeed,
  ed25519DerivationMessage,
  roleExpansion,
} from "../../keypair/derivation.js";
import { mergeDummyNullifier, mergeOutputBlinding } from "../../keypair/merge/index.js";
import { NullifierKey } from "../../keypair/nullifier-key.js";
import { P256PublicKey, ShieldedPublicKey } from "../../keypair/public-key.js";
import { ShieldedAddress, type ShieldedKeypair } from "../../keypair/shielded.js";
import { ViewingKey } from "../../keypair/viewing-key.js";

import { TransactionError } from "../error.js";
import { equal } from "../internal.js";

/**
 * Which cipher label a ciphertext was sealed under. Every UTXO ciphertext a
 * wallet can open is the transfer cipher keyed by ECDH between the wallet's
 * viewing key and the transaction's viewing key; only the ring-deposit
 * envelope uses its own label.
 */
export type DecryptLabel = "transfer" | "ringDeposit";

export interface DecryptRequest {
  readonly ciphertext: Uint8Array;
  /** Which of the wallet's viewing keys to open with; a retired key still opens what was sent to it. */
  readonly viewingPublicKey: P256PublicKey;
  readonly txViewingPublicKey: P256PublicKey;
  readonly salt: Bytes16;
  /** Zero for a ring deposit, which carries one envelope. */
  readonly slotIndex: number;
  readonly label: DecryptLabel;
}

export interface TransactionKeyRequest {
  readonly viewingPublicKey: P256PublicKey;
  readonly firstNullifier: Bytes32;
}

/**
 * Every value the protocol derives from the nullifier secret. `nullifier`
 * spends a UTXO; the two merge derivations let the owner recognise the padded
 * slots and the output of a consolidation without any ciphertext.
 */
export type DeriveRequest =
  | Readonly<{ kind: "nullifier"; utxoHash: Bytes32; blinding: Bytes32 }>
  | Readonly<{ kind: "mergeDummyNullifier"; firstNullifier: Bytes32; slotIndex: number }>
  | Readonly<{ kind: "mergeOutputBlinding"; firstNullifier: Bytes32 }>;

/**
 * The privacy roles of one shielded wallet, exposed as the functions the
 * protocol needs of them and nothing more: no method returns a long-lived
 * secret, and every method takes a batch so a remote holder answers a sync or
 * a spend in one round trip per method.
 *
 * `decrypt` returns the transfer cipher's output, not the ECDH shared point:
 * the view root is itself an ECDH with a fixed point, and ECDH is linear, so a
 * chosen-point oracle over the viewing key would leak every per-transaction
 * key this wallet ever used. Keystream results do not compose that way.
 *
 * Proving is the one place the nullifier secret is consumed rather than
 * derived from; it lives on the client-layer `ProofAuthority`, next to the
 * witness types it needs.
 *
 * Every batch method takes the caller's `RequestContext`: a sync or a build
 * that is cancelled or times out passes its signal on, so a remote holder
 * stops the round trip too. In-process keys have nothing to cancel and ignore
 * it.
 */
export interface ShieldedKeys {
  address(): ShieldedAddress;
  /** Every viewing key held, the current one first. Sync opens under each. */
  viewingPublicKeys(): readonly P256PublicKey[];
  decrypt(
    requests: readonly DecryptRequest[],
    context?: RequestContext,
  ): Promise<readonly Uint8Array[]>;
  derive(requests: readonly DeriveRequest[], context?: RequestContext): Promise<readonly Bytes32[]>;
  /** Fresh key objects; the caller destroys them. */
  transactionKeys(
    requests: readonly TransactionKeyRequest[],
    context?: RequestContext,
  ): Promise<readonly ViewingKey[]>;
}

const addressEncoder = getAddressEncoder();

/**
 * In-process keys. The counterpart of the enclave-backed implementation: the
 * same interface answered from a `ViewingKey` and a `NullifierKey` held here.
 */
export class LocalShieldedKeys implements ShieldedKeys {
  readonly #address: ShieldedAddress;
  /** Current first, retired after; `viewingPublicKeys` reports them in this order. */
  readonly #viewing: readonly ViewingKey[];
  readonly #nullifier: NullifierKey;

  private constructor(
    address: ShieldedAddress,
    viewing: readonly ViewingKey[],
    nullifier: NullifierKey,
  ) {
    this.#address = address;
    this.#viewing = viewing;
    this.#nullifier = nullifier;
  }

  /** Copies the keypair's roles; the keypair stays the caller's. */
  static fromKeypair(keypair: ShieldedKeypair): LocalShieldedKeys {
    return new LocalShieldedKeys(
      keypair.shieldedAddress(),
      [keypair.viewingKey()],
      keypair.nullifierKey(),
    );
  }

  /**
   * Copies every key; the caller's objects stay the caller's. `viewingKeys`
   * lists the current key first and any retired keys after it, so outputs sent
   * before a rotation still open.
   */
  static fromKeys(
    input: Readonly<{
      address: ShieldedAddress;
      viewingKeys: readonly ViewingKey[];
      nullifierKey: NullifierKey;
    }>,
  ): LocalShieldedKeys {
    const viewing: ViewingKey[] = [];
    let nullifier: NullifierKey | undefined;
    try {
      for (const key of input.viewingKeys) viewing.push(copyViewingKey(key));
      nullifier = copyNullifierKey(input.nullifierKey);
    } catch (cause) {
      for (const key of viewing) key.destroy();
      throw cause;
    }
    const keys = new LocalShieldedKeys(input.address, viewing, nullifier);
    keys.#checkIdentity();
    return keys;
  }

  /**
   * The roles behind a Solana wallet: `derivationSeed` is that wallet's
   * Ed25519 signature over `ed25519DerivationMessage(publicKey)`, verified
   * here so a seed that is the right width but not that signature fails
   * before it derives anything.
   */
  static fromDerivationSeed(
    input: Readonly<{ solanaPublicKey: Address; derivationSeed: Uint8Array }>,
  ): LocalShieldedKeys {
    const publicKey = checkedBytes<Bytes32>(
      new Uint8Array(addressEncoder.encode(input.solanaPublicKey)),
      32,
      "Ed25519 public key",
    );
    const seed = checkedDerivationSeed<Bytes64>(input.derivationSeed, "ed25519");
    try {
      if (
        !ed25519.verify(seed, ed25519DerivationMessage(publicKey), publicKey, { zip215: false })
      ) {
        throw new TransactionError("TRANSACTION_INVALID_DERIVATION_SEED");
      }
      return roleExpansion(seed, "ed25519", (roles) => {
        const viewing = ViewingKey.fromBytes(roles.viewingSecret);
        const nullifier = NullifierKey.fromSecret(roles.nullifierSecret);
        try {
          const address = ShieldedAddress.fromPublicKeys(
            ShieldedPublicKey.fromEd25519(publicKey),
            nullifier.publicKey(),
            viewing.publicKey(),
          );
          return new LocalShieldedKeys(address, [viewing], nullifier);
        } catch (cause) {
          viewing.destroy();
          nullifier.destroy();
          throw cause;
        }
      });
    } finally {
      seed.fill(0);
    }
  }

  address(): ShieldedAddress {
    return this.#address;
  }

  viewingPublicKeys(): readonly P256PublicKey[] {
    return this.#viewing.map((key) => key.publicKey());
  }

  async decrypt(requests: readonly DecryptRequest[]): Promise<readonly Uint8Array[]> {
    return requests.map((request) => this.decryptOne(request));
  }

  async derive(requests: readonly DeriveRequest[]): Promise<readonly Bytes32[]> {
    return requests.map((request) => this.deriveOne(request));
  }

  /** A request this holder cannot answer rejects the whole batch; no key is created for the rest. */
  async transactionKeys(
    requests: readonly TransactionKeyRequest[],
  ): Promise<readonly ViewingKey[]> {
    const keys: ViewingKey[] = [];
    try {
      for (const request of requests) keys.push(this.transactionKey(request));
    } catch (cause) {
      for (const key of keys) key.destroy();
      throw cause;
    }
    return keys;
  }

  /** Synchronous forms, for callers that hold the keys in-process. */
  decryptOne(request: DecryptRequest): Uint8Array {
    checkDecryptRequest(request);
    const viewing = this.#viewingKey(request.viewingPublicKey);
    return request.label === "ringDeposit"
      ? viewing.decryptRingDeposit(request.ciphertext, request.txViewingPublicKey, request.salt)
      : viewing.decryptUtxo(
          request.ciphertext,
          request.txViewingPublicKey,
          request.salt,
          request.slotIndex,
        );
  }

  deriveOne(request: DeriveRequest): Bytes32 {
    switch (request.kind) {
      case "nullifier":
        return this.#nullifier.nullifier(request.utxoHash, request.blinding);
      case "mergeDummyNullifier":
        checkSlotIndex(request.slotIndex, 0xff);
        return mergeDummyNullifier(this.#nullifier, request.firstNullifier, request.slotIndex);
      case "mergeOutputBlinding":
        return mergeOutputBlinding(this.#nullifier, request.firstNullifier);
    }
  }

  transactionKey(request: TransactionKeyRequest): ViewingKey {
    return this.#viewingKey(request.viewingPublicKey).transactionViewingKey(request.firstNullifier);
  }

  /**
   * Lends a copy of the nullifier key for the duration of `use`: the one
   * place the secret itself, not a derivation, is needed is the proof witness.
   * The copy is destroyed when `use` settles, so it must not be retained.
   */
  withNullifierKey<T>(use: (key: NullifierKey) => T): T {
    const key = copyNullifierKey(this.#nullifier);
    try {
      return use(key);
    } finally {
      key.destroy();
    }
  }

  destroy(): void {
    for (const key of this.#viewing) key.destroy();
    this.#nullifier.destroy();
  }

  #viewingKey(publicKey: P256PublicKey): ViewingKey {
    if (!(publicKey instanceof P256PublicKey)) {
      throw new TransactionError("TRANSACTION_DESERIALIZE", { field: "viewingPublicKey" });
    }
    const wanted = publicKey.toBytes();
    const key = this.#viewing.find((candidate) => equal(candidate.publicKey().toBytes(), wanted));
    if (key === undefined) throw new TransactionError("TRANSACTION_MISSING_CURRENT_VIEWING_KEY");
    return key;
  }

  #checkIdentity(): void {
    const current = this.#viewing[0];
    if (
      current === undefined ||
      !equal(current.publicKey().toBytes(), this.#address.viewingPublicKey.toBytes()) ||
      !equal(this.#nullifier.publicKey(), this.#address.nullifierPublicKey)
    ) {
      this.destroy();
      throw new TransactionError("TRANSACTION_WALLET_AUTHORITY_MISMATCH");
    }
  }
}

/**
 * Checks `keys` describes `identity` before anything is decrypted with it: a
 * key set for another wallet would decode nothing and silently report an
 * empty sync.
 */
export function checkKeysIdentity(keys: ShieldedKeys, identity: ShieldedAddress): void {
  const address = keys.address();
  if (
    !equal(address.signingPublicKey.toBytes(), identity.signingPublicKey.toBytes()) ||
    !equal(address.nullifierPublicKey, identity.nullifierPublicKey) ||
    !equal(address.viewingPublicKey.toBytes(), identity.viewingPublicKey.toBytes())
  ) {
    throw new TransactionError("TRANSACTION_WALLET_AUTHORITY_MISMATCH");
  }
}

/**
 * The viewing public keys held, checked to lead with `identity`'s: sync opens
 * under each of them, and a set without the current key would open nothing
 * addressed to this wallet and report an empty sync.
 */
export function checkViewingPublicKeys(
  keys: ShieldedKeys,
  identity: ShieldedAddress,
): readonly P256PublicKey[] {
  const held = keys.viewingPublicKeys();
  if (!held.every((key) => key instanceof P256PublicKey)) {
    throw new TransactionError("TRANSACTION_DESERIALIZE", { field: "viewingPublicKeys" });
  }
  const current = held[0];
  if (current === undefined || !equal(current.toBytes(), identity.viewingPublicKey.toBytes())) {
    throw new TransactionError("TRANSACTION_MISSING_CURRENT_VIEWING_KEY");
  }
  return held;
}

function checkDecryptRequest(request: DecryptRequest): void {
  if (!(request.txViewingPublicKey instanceof P256PublicKey)) {
    throw new TransactionError("TRANSACTION_DESERIALIZE", { field: "txViewingPublicKey" });
  }
  checkedBytes<Bytes16>(request.salt, 16, "salt");
  checkSlotIndex(request.slotIndex, request.label === "ringDeposit" ? 0 : 0xffff_ffff);
}

function checkSlotIndex(slotIndex: number, max: number): void {
  if (!Number.isInteger(slotIndex) || slotIndex < 0 || slotIndex > max) {
    throw new TransactionError("TRANSACTION_INVALID_POSITION", { position: slotIndex });
  }
}

function copyViewingKey(key: ViewingKey): ViewingKey {
  const secret = key.secretBytes();
  try {
    return ViewingKey.fromBytes(secret);
  } finally {
    secret.fill(0);
  }
}

function copyNullifierKey(key: NullifierKey): NullifierKey {
  const secret = key.secretBytes();
  try {
    return NullifierKey.fromSecret(secret);
  } finally {
    secret.fill(0);
  }
}
