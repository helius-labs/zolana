import type { Address, Bytes32, RequestContext } from "../interface/types.js";
import { NullifierKey } from "../keypair/nullifier-key.js";
import type { X25519PublicKey } from "../keypair/x25519.js";
import type { ShieldedAddress, ShieldedKeypair, ShieldedKeypairLike } from "../keypair/shielded.js";
import { ShieldedPublicKey } from "../keypair/public-key.js";
import type { ProofInputUtxo } from "../transaction/utxo.js";
import type { ViewingKey } from "../keypair/viewing-key.js";
import {
  LocalShieldedKeys,
  type DecryptRequest,
  type DeriveRequest,
  type TransactionKeyRequest,
} from "../transaction/wallet/keys.js";
import { ClientError } from "./error.js";
import { bytesField, hasIndexedMethod, hasProofMethods, poseidon } from "./internal.js";
import type {
  ProofAuthority,
  ProofService,
  WalletKeys,
  IndexedProofInputs,
  IndexedProofResult,
  PreparedTransferInput,
} from "./ports.js";
import { decodeIndexedInputs } from "./prover/indexed.js";
import { asField } from "./prover/assembly.js";
import type { Field, MergeInputs, ProverInputs } from "./prover/types.js";

/**
 * A wallet's privacy roles held in-process. Answers `ShieldedKeys` from the
 * viewing and nullifier keys and `ProofAuthority` by completing the proof
 * inputs with the nullifier secret and forwarding them to the prover, the
 * same two things an enclave-backed implementation does behind its transport.
 * Application code takes `WalletKeys` and never learns which one it holds.
 */
export class LocalKeys implements WalletKeys {
  readonly #keys: LocalShieldedKeys;
  readonly #proofs: ProofService;

  private constructor(keys: LocalShieldedKeys, proofs: ProofService) {
    this.#keys = keys;
    this.#proofs = proofs;
  }

  /** Copies the keypair's roles; the keypair stays the caller's. */
  static fromKeypair(keypair: ShieldedKeypair, proofs: ProofService): LocalKeys {
    // Checked first: a refused service must not leave copied keys behind.
    const service = checkProofService(proofs);
    return new LocalKeys(LocalShieldedKeys.fromKeypair(keypair), service);
  }

  /** Copies both keys; the caller's objects stay the caller's. */
  static fromKeys(
    input: Readonly<{
      address: ShieldedAddress;
      viewingKeys: readonly ViewingKey[];
      nullifierKey: NullifierKey;
    }>,
    proofs: ProofService,
  ): LocalKeys {
    const service = checkProofService(proofs);
    return new LocalKeys(LocalShieldedKeys.fromKeys(input), service);
  }

  /** `derivationSeed` is the Solana wallet's signature over its derivation message. */
  static fromDerivationSeed(
    input: Readonly<{ solanaPublicKey: Address; derivationSeed: Uint8Array }>,
    proofs: ProofService,
  ): LocalKeys {
    const service = checkProofService(proofs);
    return new LocalKeys(LocalShieldedKeys.fromDerivationSeed(input), service);
  }

  address(): ShieldedAddress {
    return this.#keys.address();
  }

  viewingPublicKeys(): readonly X25519PublicKey[] {
    return this.#keys.viewingPublicKeys();
  }

  decrypt(requests: readonly DecryptRequest[]): Promise<readonly Uint8Array[]> {
    return this.#keys.decrypt(requests);
  }

  derive(requests: readonly DeriveRequest[]): Promise<readonly Bytes32[]> {
    return this.#keys.derive(requests);
  }

  transactionKeys(requests: readonly TransactionKeyRequest[]): Promise<readonly ViewingKey[]> {
    return this.#keys.transactionKeys(requests);
  }

  async prove(inputs: ProverInputs, context?: RequestContext): Promise<Proof> {
    const complete = this.#keys.withNullifierKey((key) => completeTransferInputs(inputs, key));
    return this.#proofs.prove(complete, context);
  }

  async proveMerge(inputs: MergeInputs, context?: RequestContext): Promise<Proof> {
    const complete = this.#keys.withNullifierKey((key) => completeMergeInputs(inputs, key));
    return this.#proofs.proveMerge(complete, context);
  }

  proveIndexed(request: IndexedProofInputs, context?: RequestContext): Promise<IndexedProofResult> {
    return proveIndexedWith(
      this.#proofs,
      request,
      (use) => this.#keys.withNullifierKey(use),
      context,
    );
  }

  destroy(): void {
    this.#keys.destroy();
  }
}

/**
 * The proving half over a nullifier key held without its wallet. The key is
 * copied here and destroyed with this object.
 */
export class NullifierKeyProofAuthority implements ProofAuthority {
  readonly #key: NullifierKey;
  readonly #proofs: ProofService;

  constructor(nullifierKey: NullifierKey, proofs: ProofService) {
    this.#proofs = checkProofService(proofs);
    this.#key = nullifierKey.clone();
  }

  prove(inputs: ProverInputs, context?: RequestContext): Promise<Proof> {
    return this.#proofs.prove(completeTransferInputs(inputs, this.#key), context);
  }

  proveMerge(inputs: MergeInputs, context?: RequestContext): Promise<Proof> {
    return this.#proofs.proveMerge(completeMergeInputs(inputs, this.#key), context);
  }

  proveIndexed(request: IndexedProofInputs, context?: RequestContext): Promise<IndexedProofResult> {
    return proveIndexedWith(this.#proofs, request, (use) => use(this.#key), context);
  }

  destroy(): void {
    this.#key.destroy();
  }
}

type Proof = Awaited<ReturnType<ProofService["prove"]>>;

/** @internal Adapts owner-bound local keys to the shared proof pipeline. */
export class KeypairProofAuthority implements ProofAuthority {
  readonly #keys: readonly NullifierKey[];
  readonly #slots: readonly (NullifierKey | undefined)[];
  readonly #inputs: readonly ProofInputUtxo[];
  readonly #proofs: ProofService;

  private constructor(
    keys: readonly NullifierKey[],
    slots: readonly (NullifierKey | undefined)[],
    inputs: readonly ProofInputUtxo[],
    proofs: ProofService,
  ) {
    this.#keys = keys;
    this.#slots = slots;
    this.#inputs = inputs;
    this.#proofs = proofs;
  }

  static async create(
    keypairs: readonly ShieldedKeypairLike[],
    inputs: readonly ProofInputUtxo[],
    proofs: ProofService,
  ): Promise<KeypairProofAuthority> {
    const owned: NullifierKey[] = [];
    try {
      const service = checkProofService(proofs);
      const owners: { signing: ShieldedPublicKey; key: NullifierKey }[] = [];
      const keypairSnapshot = keypairs.slice();
      for (const keypair of keypairSnapshot) {
        if (
          typeof keypair !== "object" ||
          keypair === null ||
          typeof keypair.signingPublicKey !== "function" ||
          typeof keypair.nullifierKey !== "function" ||
          typeof keypair.nullifierPublicKey !== "function"
        )
          throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
        const signing = await keypair.signingPublicKey();
        if (!(signing instanceof ShieldedPublicKey) || signing.isZero())
          throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
        const key = await keypair.nullifierKey();
        if (!(key instanceof NullifierKey)) throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
        owned.push(key);
        const pubkey = bytesField(key.publicKey(), "nullifier public key");
        if (pubkey !== bytesField(await keypair.nullifierPublicKey(), "nullifier public key"))
          throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
        const duplicate = owners.find((owner) => owner.signing.equals(signing));
        if (
          duplicate !== undefined &&
          bytesField(duplicate.key.publicKey(), "nullifier public key") !== pubkey
        )
          throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
        owners.push({ signing: ShieldedPublicKey.fromBytes(signing.toBytes()), key });
      }
      const slots = inputs.map((input) => {
        if (input.isDummy() || input.isAddress()) return undefined;
        const owner = owners.find((entry) => entry.signing.equals(input.utxo.owner));
        if (owner === undefined) throw new ClientError("CLIENT_MISSING_NULLIFIER_SECRET");
        if (
          bytesField(owner.key.publicKey(), "nullifier public key") !==
            bytesField(input.nullifierPublicKey, "nullifier public key") ||
          bytesField(owner.key.nullifier(input.hash(), input.utxo.blinding), "nullifier") !==
            bytesField(input.nullifier(), "nullifier")
        )
          throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
        return owner.key;
      });
      return new KeypairProofAuthority(owned, slots, inputs, service);
    } catch (cause) {
      owned.forEach((key) => key.destroy());
      throw cause;
    }
  }

  #complete<T extends PreparedTransferInput>(inputs: readonly T[]): readonly T[] {
    if (inputs.length !== this.#inputs.length) throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
    return Object.freeze(
      inputs.map((input, index) => {
        const original = this.#inputs[index];
        if (original === undefined) throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
        const key = this.#slots[index];
        if (key === undefined) {
          if ((!original.isDummy() && !original.isAddress()) || input.nullifierSecret !== 0n)
            throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
          return input;
        }
        const ownerHash = bytesField(original.utxo.owner.ownerProofInputHash(), "owner");
        if (
          input.isDummy !== 0n ||
          input.ownerPublicKeyHash !== ownerHash ||
          input.nullifier !== bytesField(original.nullifier(), "nullifier") ||
          input.circuit.owner !==
            poseidon([ownerHash, bytesField(key.publicKey(), "nullifier public key")])
        )
          throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
        return Object.freeze({ ...input, nullifierSecret: secretField(key) });
      }),
    );
  }

  prove(inputs: ProverInputs, context?: RequestContext): Promise<Proof> {
    return this.#proofs.prove(withInputs(inputs, this.#complete(inputs.payload.inputs)), context);
  }

  proveMerge(_inputs: MergeInputs, _context?: RequestContext): Promise<Proof> {
    throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
  }

  proveIndexed(request: IndexedProofInputs, context?: RequestContext): Promise<IndexedProofResult> {
    const service: unknown = this.#proofs;
    if (!hasIndexedMethod(service))
      throw new ClientError("CLIENT_INVALID_CONFIG", { details: { field: "proofs" } });
    const inputs = decodeIndexedInputs(request);
    if (inputs.circuit === "merge") throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
    return service.proveIndexed(withInputs(inputs, this.#complete(inputs.payload.inputs)), context);
  }

  destroy(): void {
    this.#keys.forEach((key) => key.destroy());
  }
}

function completeTransferInputs(inputs: ProverInputs, key: NullifierKey): ProverInputs {
  return withInputs(
    inputs,
    inputs.payload.inputs.map((input) => completeInput(input, key)),
  );
}

function withInputs<
  Request extends Readonly<{ payload: Readonly<{ inputs: readonly PreparedTransferInput[] }> }>,
>(request: Request, inputs: Request["payload"]["inputs"]): Request {
  return Object.freeze({
    ...request,
    payload: Object.freeze({ ...request.payload, inputs: Object.freeze(inputs) }),
  });
}

function completeMergeInputs(inputs: MergeInputs, key: NullifierKey): MergeInputs {
  if (inputs.userNullifierSecret !== undefined) return inputs;
  if (bytesField(key.publicKey(), "nullifier public key") !== inputs.userNullifierPublicKey) {
    throw new ClientError("CLIENT_MERGE_NULLIFIER_KEY_MISMATCH");
  }
  return Object.freeze({ ...inputs, userNullifierSecret: secretField(key) });
}

/** Fills the secret on this wallet's own real inputs; everything else passes through untouched. */
function completeInput<T extends PreparedTransferInput>(input: T, key: NullifierKey): T {
  const nullifierPublicKey = bytesField(key.publicKey(), "nullifier public key");
  if (
    input.nullifierSecret !== undefined ||
    input.isDummy !== 0n ||
    input.circuit.owner !== poseidon([input.ownerPublicKeyHash, nullifierPublicKey])
  ) {
    return input;
  }
  return Object.freeze({ ...input, nullifierSecret: secretField(key) });
}

function secretField(key: NullifierKey): Field {
  const secret = key.secretBytes();
  try {
    return asField(bytesField(secret, "nullifier secret"));
  } finally {
    secret.fill(0);
  }
}

function checkProofService(proofs: ProofService): ProofService {
  if (!hasProofMethods(proofs)) {
    throw new ClientError("CLIENT_INVALID_CONFIG", { details: { field: "proofs" } });
  }
  return proofs;
}

/** The caller's request is decoded before the nullifier secret joins it. */
async function proveIndexedWith(
  proofs: ProofService,
  request: IndexedProofInputs,
  withKey: (use: (key: NullifierKey) => IndexedProofInputs) => IndexedProofInputs,
  context: RequestContext | undefined,
): Promise<IndexedProofResult> {
  const service: unknown = proofs;
  if (!hasIndexedMethod(service)) {
    throw new ClientError("CLIENT_INVALID_CONFIG", { details: { field: "proofs" } });
  }
  const inputs = decodeIndexedInputs(request);
  return service.proveIndexed(
    withKey((key) => completeIndexedInputs(inputs, key)),
    context,
  );
}

function completeIndexedInputs(inputs: IndexedProofInputs, key: NullifierKey): IndexedProofInputs {
  if (inputs.circuit === "merge") {
    if (inputs.payload.userNullifierSecret !== undefined) return inputs;
    if (
      bytesField(key.publicKey(), "nullifier public key") !== inputs.payload.userNullifierPublicKey
    )
      throw new ClientError("CLIENT_MERGE_NULLIFIER_KEY_MISMATCH");
    return { ...inputs, payload: { ...inputs.payload, userNullifierSecret: secretField(key) } };
  }
  return withInputs(
    inputs,
    inputs.payload.inputs.map((input) => completeInput(input, key)),
  );
}
