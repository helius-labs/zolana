import type { Address, Bytes32, RequestContext } from "../interface/types.js";
import type { NullifierKey } from "../keypair/nullifier-key.js";
import type { P256PublicKey } from "../keypair/public-key.js";
import type { ShieldedAddress, ShieldedKeypair } from "../keypair/shielded.js";
import type { ViewingKey } from "../keypair/viewing-key.js";
import {
  LocalShieldedKeys,
  type DecryptRequest,
  type DeriveRequest,
  type TransactionKeyRequest,
} from "../transaction/wallet/keys.js";
import { equal } from "../transaction/internal.js";

import { ClientError } from "./error.js";
import { bytesField, hasProofMethods } from "./internal.js";
import type { ProofService, WalletKeys } from "./ports.js";
import { asField } from "./prover/assembly.js";
import type { Field, MergeInputs, ProverInputs, TransferInput } from "./prover/types.js";

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

  viewingPublicKeys(): readonly P256PublicKey[] {
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
    const complete = this.#keys.withNullifierKey((key) =>
      Object.freeze({
        circuit: inputs.circuit,
        payload: Object.freeze({
          ...inputs.payload,
          inputs: Object.freeze(inputs.payload.inputs.map((input) => completeInput(input, key))),
        }),
      }),
    );
    return this.#proofs.prove(complete, context);
  }

  async proveMerge(inputs: MergeInputs, context?: RequestContext): Promise<Proof> {
    const complete = this.#keys.withNullifierKey((key) => {
      if (
        inputs.userNullifierSecret !== undefined ||
        bytesField(key.publicKey(), "nullifier public key") !== inputs.userNullifierPublicKey
      ) {
        return inputs;
      }
      return Object.freeze({ ...inputs, userNullifierSecret: secretField(key) });
    });
    return this.#proofs.proveMerge(complete, context);
  }

  destroy(): void {
    this.#keys.destroy();
  }
}

type Proof = Awaited<ReturnType<ProofService["prove"]>>;

/** Fills the secret on this wallet's own real inputs; everything else passes through untouched. */
function completeInput(input: TransferInput, key: NullifierKey): TransferInput {
  if (
    input.nullifierSecret !== undefined ||
    input.utxo.isDummy() ||
    !equal(input.utxo.nullifierPublicKey, key.publicKey())
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
