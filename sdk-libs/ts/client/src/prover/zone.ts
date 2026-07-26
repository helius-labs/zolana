import type { Address, Bytes32, Shape } from "@zolana/interface";
import { SppProofInputs, type PreparedZoneAuthority } from "@zolana/transaction";

import { ClientError, fromClientCause } from "../error.js";
import {
  addressBytes,
  bigintToBytes,
  bytesField,
  bytesToBigInt,
  hashChain,
  hashField,
  p256Coordinates,
  poseidon,
  sha256Bytes,
} from "../internal.js";
import type { SpendProof } from "../rpc.js";
import {
  asField,
  asInteger,
  assembleSlots,
  checkedP256Owner,
  createOutput,
  findPublicSplAsset,
  signedField,
} from "./assembly.js";
import type {
  AssembledZone,
  AssembledZoneP256,
  TransferInputs,
  TransferP256Inputs,
} from "./types.js";

/// The three zone rails, ported from `sdk-libs/client/src/prover/transact/
/// zone_eddsa.rs`, `transact/zone_p256.rs`, and `zone_authority.rs`.
///
/// All three drop the confidential appendix -- the output-owner chain and the
/// shared `p256_signing_pk_field` -- from the public-input preimage, and all
/// three replace the confidential rail's zero `zone_program_id` element with the
/// zone's field. That element is the only value binding a proof to its zone, so
/// it is never allowed to be the zero a default-zone transfer carries.
///
/// They differ in exactly two places: which owner field each input contributes
/// (Rust's `OwnerMode`), and whether the chain carries the input-owner hash
/// chain at all. Zone transfers commit it, so SPP can route the per-input signer
/// check; the zone authority does not, because owners neither sign nor are named
/// on that rail.

/// Rust `program_id_field` for the `Some` case, which is the only case a zone
/// rail has: the `None` sentinel is the literal zero a default-zone transfer
/// carries, and requiring an `Address` here makes it unrepresentable. Rust's
/// zone provers accept `None` and would bind such a proof to nothing; that is a
/// Rust-side hazard for the cryptographic phase, not something to reject here
/// on one side only.
function zoneField(zoneProgramId: Address): bigint {
  return hashField(addressBytes(zoneProgramId));
}

/// Rust `zone_authority::SUPPORTED_SHAPES`. A zone-authority transition proves
/// no owner authorization and cannot move value out of the zone, so it
/// re-randomizes or reshuffles a fixed set of UTXOs rather than splitting or
/// merging them: inputs always equal outputs. `docs/spec.md`, "Zone-authority
/// instantiation", lists these four and `program-libs/interface/src/
/// verifying_keys/` holds exactly the four matching keys. The other six members
/// of `SPP_SUPPORTED_SHAPES` are the non-square ones, and a request in any of
/// them can never verify.
const ZONE_AUTHORITY_SHAPES: readonly Shape[] = Object.freeze([
  Object.freeze({ inputs: 1, outputs: 1 }),
  Object.freeze({ inputs: 2, outputs: 2 }),
  Object.freeze({ inputs: 3, outputs: 3 }),
  Object.freeze({ inputs: 4, outputs: 4 }),
]);

function checkedProofInputs(proofInputs: SppProofInputs): SppProofInputs {
  if (!(proofInputs instanceof SppProofInputs)) {
    throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
  }
  return proofInputs;
}

interface Common {
  readonly nullifiers: readonly Bytes32[];
  readonly outputHashes: readonly bigint[];
  readonly utxoRoots: readonly bigint[];
  readonly nullifierRoots: readonly bigint[];
  readonly inputOwnerFields: readonly bigint[];
  readonly rootIndexes: readonly (readonly [number, number])[];
  readonly privateTxHash: bigint;
  readonly externalDataHash: bigint;
  readonly publicSolAmount: bigint;
  readonly publicSplAmount: bigint;
  readonly publicSplAssetPublicKey: bigint;
  readonly payerPublicKeyHash: bigint;
  readonly zone: bigint;
  readonly transferInputs: ReturnType<typeof assembleSlots>["transferInputs"];
  readonly transferOutputs: readonly ReturnType<typeof createOutput>[];
}

function common(
  proofInputs: SppProofInputs,
  spendProofs: readonly SpendProof[],
  zoneProgramId: Address,
  ownerField: (input: Parameters<Parameters<typeof assembleSlots>[2]>[0], index: number) => bigint,
): Common {
  checkedProofInputs(proofInputs).checkShape();
  if (proofInputs.inputUtxos.every((input) => input.isDummy())) {
    throw new ClientError("CLIENT_NO_INPUTS");
  }
  const slots = assembleSlots(proofInputs, spendProofs, ownerField);
  const transferOutputs = proofInputs.outputs.map(createOutput);
  const outputHashes = proofInputs.outputs.map((output) => bytesToBigInt(output.hash()));
  const privateOutputHashes = proofInputs.outputs.map((output) =>
    output.isDummy() ? 0n : bytesToBigInt(output.hash()),
  );
  const externalDataHash = bytesField(proofInputs.externalData.hash(), "external data hash");
  const privateTxHash = poseidon([
    hashChain(slots.inputHashes),
    hashChain(privateOutputHashes),
    hashChain(Array.from({ length: slots.inputHashes.length }, () => 0n)),
    externalDataHash,
  ]);
  const amounts = proofInputs.publicAmounts();
  return {
    nullifiers: slots.nullifiers,
    outputHashes,
    utxoRoots: slots.utxoRoots,
    nullifierRoots: slots.nullifierRoots,
    inputOwnerFields: slots.inputOwnerFields,
    rootIndexes: slots.rootIndexes,
    privateTxHash,
    externalDataHash,
    publicSolAmount: signedField(amounts.sol ?? 0n, "public SOL amount"),
    publicSplAmount: signedField(amounts.spl ?? 0n, "public SPL amount"),
    publicSplAssetPublicKey:
      amounts.spl === undefined || amounts.spl === 0n
        ? 0n
        : hashField(addressBytes(findPublicSplAsset(proofInputs))),
    payerPublicKeyHash: bytesField(proofInputs.payerPublicKeyHash, "payer public key hash"),
    zone: zoneField(zoneProgramId),
    transferInputs: slots.transferInputs,
    transferOutputs,
  };
}

/// The twelve elements every zone rail shares, in Rust's order. The zone rails
/// put the zone field where the confidential rail puts zero.
function baseChain(value: Common, p256MessageElement: bigint): readonly bigint[] {
  return [
    hashChain(value.nullifiers.map(bytesToBigInt)),
    hashChain(value.outputHashes),
    hashChain(value.utxoRoots),
    hashChain(value.nullifierRoots),
    value.privateTxHash,
    hashField(bigintToBytes(p256MessageElement)),
    value.externalDataHash,
    value.publicSolAmount,
    value.publicSplAmount,
    value.publicSplAssetPublicKey,
    value.zone,
    value.payerPublicKeyHash,
  ];
}

function transferInputsOf(value: Common, publicInputHash: bigint): TransferInputs {
  return Object.freeze({
    inputs: value.transferInputs,
    outputs: Object.freeze(value.transferOutputs),
    externalDataHash: asField(value.externalDataHash),
    privateTxHash: asField(value.privateTxHash),
    publicSolAmount: asField(value.publicSolAmount),
    publicSplAmount: asField(value.publicSplAmount),
    publicSplAssetPublicKey: asField(value.publicSplAssetPublicKey),
    zoneProgramId: asField(value.zone),
    payerPublicKeyHash: asField(value.payerPublicKeyHash),
    publicInputHash: asField(publicInputHash),
  });
}

function result(
  value: Common,
  payload: TransferInputs,
  circuit: "transferZone" | "transferZoneAuthority",
): AssembledZone {
  return Object.freeze({
    proverInputs: Object.freeze({ circuit, payload }),
    publicInputHash: bigintToBytes(payload.publicInputHash) as Bytes32,
    nullifiers: Object.freeze(value.nullifiers.map((n) => new Uint8Array(n) as Bytes32)),
    outputHashes: Object.freeze(value.outputHashes.map((h) => bigintToBytes(h) as Bytes32)),
    privateTxHash: bigintToBytes(value.privateTxHash) as Bytes32,
    inputRootIndexes: value.rootIndexes,
  });
}

/// Rust `ZoneTransferProver`. The ed25519-only rail: owners are named, so the
/// input-owner chain closes the thirteen-element preimage, and the P256 message
/// element is `hash_field(0)`.
export function assembleZone(
  proofInputs: SppProofInputs,
  spendProofs: readonly SpendProof[],
  zoneProgramId: Address,
): AssembledZone {
  try {
    if (proofInputs.p256Signature() !== undefined) {
      throw new ClientError("CLIENT_PROOF_RAIL_MISMATCH");
    }
    const value = common(proofInputs, spendProofs, zoneProgramId, (input, index) => {
      // Rust `OwnerMode::ConfidentialEddsa` rejects a P256-owned input outright:
      // this rail has no P256 gadget to authorize one.
      if (input.utxo.owner.signatureType() === "p256") {
        throw new ClientError("CLIENT_EDDSA_INPUT_NOT_SOLANA_OWNED", { details: { index } });
      }
      return bytesField(input.utxo.owner.ownerPublicKeyField(), "owner public key");
    });
    const publicInputHash = hashChain([...baseChain(value, 0n), hashChain(value.inputOwnerFields)]);
    return result(value, transferInputsOf(value, publicInputHash), "transferZone");
  } catch (cause) {
    throw fromClientCause(cause);
  }
}

/// Rust `ZoneTransferP256Prover`. Same thirteen-element preimage as the ed25519
/// zone rail with the real P256 message element, but a P256 owner contributes
/// the zero sentinel rather than its identity, and the shared
/// `p256_signing_pk_field` rides in the witness without entering the hash.
export function assembleZoneP256(
  proofInputs: SppProofInputs,
  spendProofs: readonly SpendProof[],
  zoneProgramId: Address,
): AssembledZoneP256 {
  try {
    const signature = proofInputs.p256Signature();
    if (signature === undefined) throw new ClientError("CLIENT_MISSING_P256_SIGNATURE");
    const realInputs = proofInputs.inputUtxos.filter((input) => !input.isDummy());
    const signingOwner = checkedP256Owner(realInputs, signature.publicKey);
    const value = common(proofInputs, spendProofs, zoneProgramId, (input) =>
      input.utxo.owner.signatureType() === "p256"
        ? 0n
        : bytesField(input.utxo.owner.ownerPublicKeyField(), "owner public key"),
    );
    const p256MessageHash = bytesToBigInt(sha256Bytes(bigintToBytes(value.privateTxHash)));
    const publicInputHash = hashChain([
      ...baseChain(value, p256MessageHash),
      hashChain(value.inputOwnerFields),
    ]);
    const signingField = bytesField(signingOwner.ownerPublicKeyField(), "p256 signing public key");
    const [x, y] = p256Coordinates(signingOwner.p256().toBytes());
    const payload: TransferP256Inputs = Object.freeze({
      ...transferInputsOf(value, publicInputHash),
      p256PublicKeyX: asInteger(x),
      p256PublicKeyY: asInteger(y),
      p256SignatureR: asInteger(bytesToBigInt(signature.r)),
      p256SignatureS: asInteger(bytesToBigInt(signature.s)),
      p256MessageHashLow: asField(p256MessageHash & ((1n << 128n) - 1n)),
      p256MessageHashHigh: asField(p256MessageHash >> 128n),
      p256SigningPublicKeyField: asField(signingField),
    });
    return Object.freeze({
      proverInputs: Object.freeze({ circuit: "transferP256Zone", payload }),
      publicInputHash: bigintToBytes(publicInputHash) as Bytes32,
      nullifiers: Object.freeze(value.nullifiers.map((n) => new Uint8Array(n) as Bytes32)),
      outputHashes: Object.freeze(value.outputHashes.map((h) => bigintToBytes(h) as Bytes32)),
      privateTxHash: bigintToBytes(value.privateTxHash) as Bytes32,
      inputRootIndexes: value.rootIndexes,
      p256SigningPublicKeyField: asField(signingField),
      // The pre-hash x-coordinate the `Transact` instruction carries so the
      // program can reproduce `pk_field` on-chain.
      p256SigningPublicKeyX: signingOwner.confidentialViewTag(),
    });
  } catch (cause) {
    throw fromClientCause(cause);
  }
}

/// Rust `ZoneAuthorityProver`. The zone's `zone_config` PDA authorizes on-chain,
/// so no owner signs and no owner is named: the preimage is the twelve base
/// elements with no input-owner chain, and every owner field stays a private
/// witness bound only through its nullifier secret.
export function assembleZoneAuthority(
  proofInputs: SppProofInputs,
  spendProofs: readonly SpendProof[],
  zoneProgramId: Address,
): AssembledZone {
  try {
    const shape = checkedProofInputs(proofInputs).checkShape();
    if (
      !ZONE_AUTHORITY_SHAPES.some((c) => c.inputs === shape.inputs && c.outputs === shape.outputs)
    ) {
      throw new ClientError("CLIENT_UNSUPPORTED_ZONE_AUTHORITY_SHAPE", {
        details: { nIn: shape.inputs, nOut: shape.outputs },
      });
    }
    if (proofInputs.p256Signature() !== undefined) {
      throw new ClientError("CLIENT_PROOF_RAIL_MISMATCH");
    }
    const value = common(proofInputs, spendProofs, zoneProgramId, (input) =>
      bytesField(input.utxo.owner.ownerPublicKeyField(), "owner public key"),
    );
    const publicInputHash = hashChain(baseChain(value, 0n));
    return result(value, transferInputsOf(value, publicInputHash), "transferZoneAuthority");
  } catch (cause) {
    throw fromClientCause(cause);
  }
}

/// Rust `ZoneAuthorityWitness` together with its
/// `TryFrom<ZoneAuthorityWitness> for ZoneAuthorityProver`: fold the fetched
/// Merkle proofs into a prepared zone-authority transition. One
/// [`SpendProof`] per real (non-dummy) input, in input order, exactly as Rust
/// `attach_input_proofs` consumes them. The zone comes off the prepared value,
/// which pinned it and bound every real UTXO to it, so the proof cannot be
/// bound to a zone the preparation did not check.
export function assembleZoneAuthorityWitness(
  prepared: PreparedZoneAuthority,
  spendProofs: readonly SpendProof[],
): AssembledZone {
  try {
    return assembleZoneAuthority(
      new SppProofInputs({
        payerPublicKeyHash: prepared.payerPublicKeyHash,
        inputUtxos: prepared.inputs,
        outputs: prepared.outputs,
        externalData: prepared.externalData,
      }),
      spendProofs,
      prepared.zoneProgramId,
    );
  } catch (cause) {
    throw fromClientCause(cause);
  }
}
