import type { Address } from "@solana/kit";

import type { PreparedMergeInputs } from "../client/ports.js";
import type { AnonymousMergeProofRequest } from "../client/prover/ring.js";
import { ANONYMOUS_MERGE_WIDTHS } from "../client/prover/types.js";
import { hashBytes, hashChain4 } from "../hasher/index.js";
import { ringIdField } from "../keypair/ring-stream.js";
import {
  auditSharedSecret,
  openMergeDisclosureFields,
  sealMergeDisclosureFields,
} from "../keypair/audit.js";
import { randomBytes } from "../keypair/bytes.js";
import { symmetricApply } from "../keypair/merge/index.js";
import { X25519Keypair, X25519PublicKey } from "../keypair/x25519.js";
import { CUSTOM_RING_PROOF_LENGTH } from "../interface/custom-ring-proof.js";
import { Reader, Writer, addressBytes, encodeBase58 } from "../interface/internal.js";
import { pack33, rightAlign } from "../interface/merge-utils.js";
import { treeIdField } from "../interface/tree-slot.js";
import type {
  Bytes16,
  Bytes32,
  Bytes33,
  MergeTransactInstructionData,
} from "../interface/types.js";
import type { PreparedMerge } from "../transaction/instructions/builders.js";
import {
  U64_MAX,
  ZERO_32,
  bigIntBytes,
  bytesToBigInt,
  hashChain,
} from "../transaction/internal.js";
import { mergeMintChunks } from "../transaction/serialization/merge.js";
import { RingError } from "./error.js";

/** Rust `MERGE_DISCLOSURE_INFO`, the envelope of the disclosure key. */
const MERGE_DISCLOSURE_INFO = new TextEncoder().encode("CRING/mrg1");
/** Owner key, nullifier pk, mint, amount and output blinding ahead of the input commitments. */
const MERGE_DISCLOSURE_HEADER_LENGTH = 32 + 32 + 32 + 8 + 32;
const CHUNK_BYTES = 31;
const MERGE_ANONYMOUS_DOMAIN = 0x43524d47n;

/** Rust `merge_disclosure_field_count`. */
export function mergeDisclosureFieldCount(width: number): number {
  return Math.ceil((MERGE_DISCLOSURE_HEADER_LENGTH + 32 * width) / CHUNK_BYTES);
}

/** The auditor's half of an anonymous ring merge, Rust `MergeDisclosure`. */
export interface RingMergeDisclosure {
  readonly proof: Uint8Array;
  readonly ephemeralPublicKey: Bytes33;
  readonly ciphertext: Bytes32;
  readonly fields: readonly Bytes32[];
}

/** What an anonymous merge discloses, enough to recompute its output commitment. */
export interface RingMergeOpening {
  readonly ownerKey: Address;
  readonly nullifierPublicKey: Bytes32;
  readonly mint: Address;
  readonly amount: bigint;
  readonly outputBlinding: Bytes32;
  /** One per circuit slot, zero for padding. */
  readonly inputCommitments: readonly Bytes32[];
}

/** The wincode option ahead of the SPP merge body. */
export function writeRingMergeDisclosure(
  writer: Writer,
  disclosure: RingMergeDisclosure | undefined,
): Writer {
  return writer.option(disclosure, (inner, value) => {
    inner
      .bytes(value.proof, CUSTOM_RING_PROOF_LENGTH, "disclosure.proof")
      .bytes(value.ephemeralPublicKey, 33, "disclosure.ephemeralPublicKey")
      .bytes(value.ciphertext, 32, "disclosure.ciphertext")
      .u8(value.fields.length, "disclosure.fields.length");
    for (const field of value.fields) inner.bytes(field, 32, "disclosure.field");
  });
}

export function readRingMergeDisclosure(reader: Reader): RingMergeDisclosure | undefined {
  return reader.option("disclosure", (inner) => {
    const proof = inner.bytes(CUSTOM_RING_PROOF_LENGTH, "disclosure.proof");
    const ephemeralPublicKey = inner.bytes(33, "disclosure.ephemeralPublicKey") as Bytes33;
    const ciphertext = inner.bytes(32, "disclosure.ciphertext") as Bytes32;
    const count = inner.u8("disclosure.fields.length");
    const fields = Array.from(
      { length: count },
      () => inner.bytes(32, "disclosure.field") as Bytes32,
    );
    return Object.freeze({ proof, ephemeralPublicKey, ciphertext, fields: Object.freeze(fields) });
  });
}

/** Opens a disclosure the ring program verified, the caller checks it against the settled output. */
export function openRingMergeDisclosure(
  auditor: X25519Keypair,
  disclosure: RingMergeDisclosure,
  salt: Bytes16,
): RingMergeOpening {
  const width = ANONYMOUS_MERGE_WIDTHS.find(
    (count) => mergeDisclosureFieldCount(count) === disclosure.fields.length,
  );
  if (width === undefined) throw invalid("disclosure width");
  const ephemeral = X25519PublicKey.fromBytes(disclosure.ephemeralPublicKey);
  const dh = auditor.ecdh(ephemeral);
  const shared = auditSharedSecret(dh, ephemeral, auditor.publicKey());
  const key = symmetricApply(shared, MERGE_DISCLOSURE_INFO, disclosure.ciphertext) as Bytes32;
  let plaintext: Uint8Array | undefined;
  try {
    const opened = openMergeDisclosureFields(key, salt, disclosure.fields);
    plaintext = opened;
    const length = MERGE_DISCLOSURE_HEADER_LENGTH + 32 * width;
    if (opened.subarray(length).some((byte) => byte !== 0)) throw invalid("disclosure padding");
    const at = (offset: number, size = 32): Uint8Array => opened.slice(offset, offset + size);
    return Object.freeze({
      ownerKey: encodeBase58(at(0)),
      nullifierPublicKey: at(32) as Bytes32,
      mint: encodeBase58(at(64)),
      amount: bytesToBigInt(at(96, 8)),
      outputBlinding: at(104) as Bytes32,
      inputCommitments: Object.freeze(
        Array.from(
          { length: width },
          (_, index) => at(MERGE_DISCLOSURE_HEADER_LENGTH + 32 * index) as Bytes32,
        ),
      ),
    });
  } finally {
    dh.fill(0);
    shared.fill(0);
    key.fill(0);
    plaintext?.fill(0);
  }
}

/** Rust `MergeAnonymousPublicInput::hash`, the statement the ring program verifies. */
export function ringMergeAnonymousPublicInputHash(
  input: Readonly<{
    privateTxHash: Bytes32;
    outputUtxoHash: Bytes32;
    firstNullifier: Bytes32;
    /** `hashBytes` of the ring program id, the value the merged notes commit. */
    ringId: Bytes32;
    auditorPublicKey: X25519PublicKey;
    disclosure: Omit<RingMergeDisclosure, "proof">;
    salt: Bytes16;
  }>,
): Bytes32 {
  return hashChain([
    bigIntBytes(MERGE_ANONYMOUS_DOMAIN) as Bytes32,
    input.privateTxHash,
    input.outputUtxoHash,
    input.firstNullifier,
    input.ringId,
    ...pack33(input.auditorPublicKey.toBytes()),
    ...pack33(input.disclosure.ephemeralPublicKey),
    hashBytes(input.disclosure.ciphertext) as Bytes32,
    rightAlign(input.salt),
    hashChain4(input.disclosure.fields) as Bytes32,
  ]);
}

/** Rust `RingError::AnonymousMergeTooWide`, refused before any proof. */
export function checkAnonymousMergeWidth(width: number): void {
  if (!ANONYMOUS_MERGE_WIDTHS.includes(width))
    throw new RingError("RING_ANONYMOUS_MERGE_TOO_WIDE", { details: { width } });
}

/** The zeroed disclosure of `width` slots, sized exactly as the proved one. */
export function emptyRingMergeDisclosure(width: number): RingMergeDisclosure {
  checkAnonymousMergeWidth(width);
  return Object.freeze({
    proof: new Uint8Array(CUSTOM_RING_PROOF_LENGTH),
    ephemeralPublicKey: new Uint8Array(33) as Bytes33,
    ciphertext: new Uint8Array(32) as Bytes32,
    fields: Object.freeze(
      Array.from({ length: mergeDisclosureFieldCount(width) }, () => new Uint8Array(32) as Bytes32),
    ),
  });
}

/** The sealed half of a disclosure with the two secrets its proof witnesses. */
export interface SealedRingMergeDisclosure {
  readonly ephemeralSecret: Bytes32;
  readonly disclosureKey: Bytes32;
  readonly disclosure: Omit<RingMergeDisclosure, "proof">;
}

/** Rust `MergeDisclosureEncryption::new`, the ephemeral key and disclosure key are fresh per merge. */
export function sealRingMergeDisclosure(
  opening: RingMergeOpening,
  salt: Bytes16,
  auditor: X25519PublicKey,
): SealedRingMergeDisclosure {
  const ephemeral = X25519Keypair.generate();
  const disclosureKey = randomBytes(32) as Bytes32;
  try {
    return sealRingMergeDisclosureWith({ opening, salt, auditor, ephemeral, disclosureKey });
  } finally {
    ephemeral.destroy();
    disclosureKey.fill(0);
  }
}

/** @internal `salt` is the SPP merge output salt, the statement binds the pad to it. */
export function sealRingMergeDisclosureWith(
  input: Readonly<{
    opening: RingMergeOpening;
    salt: Bytes16;
    auditor: X25519PublicKey;
    ephemeral: X25519Keypair;
    disclosureKey: Bytes32;
  }>,
): SealedRingMergeDisclosure {
  checkAnonymousMergeWidth(input.opening.inputCommitments.length);
  const plaintext = encodeMergeOpening(input.opening);
  let dh: Bytes32 | undefined;
  let shared: Bytes32 | undefined;
  try {
    const ephemeralPublicKey = input.ephemeral.publicKey();
    dh = input.ephemeral.ecdh(input.auditor);
    shared = auditSharedSecret(dh, ephemeralPublicKey, input.auditor);
    const disclosure = Object.freeze({
      ephemeralPublicKey: ephemeralPublicKey.toBytes(),
      ciphertext: symmetricApply(shared, MERGE_DISCLOSURE_INFO, input.disclosureKey) as Bytes32,
      fields: sealMergeDisclosureFields(input.disclosureKey, input.salt, plaintext),
    });
    // The secrets are copied last, a refusal before them leaves no copy to wipe.
    return Object.freeze({
      ephemeralSecret: input.ephemeral.secretBytes(),
      disclosureKey: new Uint8Array(input.disclosureKey) as Bytes32,
      disclosure,
    });
  } finally {
    dh?.fill(0);
    shared?.fill(0);
    plaintext.fill(0);
  }
}

/** The anonymous merge disclosure request without the nullifier secret only its holder adds. */
export type RingMergeDisclosureRequest = Omit<AnonymousMergeProofRequest, "nullifierSecret">;

/** Rust `AnonymousMergeDisclosure::prove`, the statement binds the proved SPP merge `spp`. */
export function ringMergeDisclosureRequest(
  input: Readonly<{
    ringProgramId: Address;
    auditor: X25519PublicKey;
    prepared: PreparedMerge;
    slots: PreparedMergeInputs;
    spp: MergeTransactInstructionData;
  }>,
): Readonly<{
  request: RingMergeDisclosureRequest;
  disclosure: Omit<RingMergeDisclosure, "proof">;
}> {
  const { prepared, spp } = input;
  const firstNullifier = spp.nullifiers[0];
  if (firstNullifier === undefined || input.slots.inputs.length !== prepared.inputs.length)
    throw invalid("merge slots");
  const commitments = new Map(
    prepared.inputUtxoHashes().map(({ index, utxoHash }) => [index, utxoHash]),
  );
  const ownerKey = prepared.signingPublicKey.ed25519();
  const salt = prepared.outputCiphertextSalt();
  const sealed = sealRingMergeDisclosure(
    {
      ownerKey: encodeBase58(ownerKey),
      nullifierPublicKey: prepared.nullifierPublicKey,
      mint: prepared.output.asset,
      amount: prepared.output.amount,
      outputBlinding: prepared.output.blinding,
      inputCommitments: prepared.inputs.map((_, index) => commitments.get(index) ?? ZERO_32),
    },
    salt,
    input.auditor,
  );
  try {
    const ringId = ringIdField(input.ringProgramId);
    const field = (value: bigint): Bytes32 => bigIntBytes(value) as Bytes32;
    const request = Object.freeze({
      kind: "anonymousMerge" as const,
      publicInputHash: ringMergeAnonymousPublicInputHash({
        privateTxHash: spp.privateTxHash,
        outputUtxoHash: spp.outputUtxoHash,
        firstNullifier,
        ringId,
        auditorPublicKey: input.auditor,
        disclosure: sealed.disclosure,
        salt,
      }),
      privateTxHash: spp.privateTxHash,
      outputUtxoHash: spp.outputUtxoHash,
      firstNullifier,
      ringProgramId: ringId,
      auditorPk: input.auditor.u(),
      salt: rightAlign(salt),
      ephSk: sealed.ephemeralSecret,
      disclosureKey: sealed.disclosureKey,
      ownerKey,
      mintChunks: Object.freeze(mergeMintChunks(prepared.output.asset).map(field)),
      inputs: Object.freeze(
        prepared.inputs.map((spend, index) => {
          const slot = input.slots.inputs[index];
          if (slot === undefined) throw invalid("merge slots");
          return Object.freeze({
            domain: field(slot.circuit.domain),
            treeId: treeIdField(spend.treeId),
            amount: field(slot.circuit.amount),
            blinding: field(slot.circuit.blinding),
            ringDataHash: field(slot.circuit.ringDataHash),
          });
        }),
      ),
      outputTreeId: field(input.slots.outputTreeId),
      outputRingDataHash: field(input.slots.outputRingDataHash),
    });
    return Object.freeze({ request, disclosure: sealed.disclosure });
  } catch (cause) {
    sealed.ephemeralSecret.fill(0);
    sealed.disclosureKey.fill(0);
    throw cause;
  }
}

/** Zeroes the sealing secrets a disclosure request carries once its proof is back. */
export function wipeRingMergeDisclosureRequest(request: RingMergeDisclosureRequest): void {
  request.ephSk.fill(0);
  request.disclosureKey.fill(0);
}

/** Rust `MergeOpening::encode`, zero padded to whole 31-byte chunks. */
function encodeMergeOpening(opening: RingMergeOpening): Uint8Array {
  const width = opening.inputCommitments.length;
  if (opening.amount < 0n || opening.amount > U64_MAX) throw invalid("disclosure amount");
  const plaintext = new Uint8Array(mergeDisclosureFieldCount(width) * CHUNK_BYTES);
  try {
    plaintext.set(addressBytes(opening.ownerKey), 0);
    plaintext.set(opening.nullifierPublicKey, 32);
    plaintext.set(addressBytes(opening.mint), 64);
    plaintext.set(bigIntBytes(opening.amount, 8), 96);
    plaintext.set(opening.outputBlinding, 104);
    opening.inputCommitments.forEach((commitment, index) =>
      plaintext.set(commitment, MERGE_DISCLOSURE_HEADER_LENGTH + 32 * index),
    );
    return plaintext;
  } catch (cause) {
    plaintext.fill(0);
    throw cause;
  }
}

function invalid(reason: string): RingError {
  return new RingError("RING_AUDIT_MESSAGE", { details: { reason } });
}
