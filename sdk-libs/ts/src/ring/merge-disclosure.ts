import type { Address } from "@solana/kit";

import { hashBytes } from "../hasher/index.js";
import { auditSharedSecret, openMergeDisclosureFields } from "../keypair/audit.js";
import { symmetricApply } from "../keypair/merge/index.js";
import { X25519PublicKey, type X25519Keypair } from "../keypair/x25519.js";
import { CUSTOM_RING_PROOF_LENGTH } from "../interface/custom-ring-proof.js";
import { MERGE_SUPPORTED_INPUT_COUNTS } from "../interface/constants.js";
import { Reader, Writer, encodeBase58 } from "../interface/internal.js";
import { pack33, rightAlign } from "../interface/merge-utils.js";
import type { Bytes16, Bytes32, Bytes33 } from "../interface/types.js";
import { bigIntBytes, bytesToBigInt, hashChain, hashChain4 } from "../transaction/internal.js";
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
  const width = MERGE_SUPPORTED_INPUT_COUNTS.find(
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
    memberRegistryRoot: Bytes32;
    auditorPublicKey: X25519PublicKey;
    disclosure: RingMergeDisclosure;
    salt: Bytes16;
  }>,
): Bytes32 {
  return hashChain([
    bigIntBytes(MERGE_ANONYMOUS_DOMAIN) as Bytes32,
    input.privateTxHash,
    input.outputUtxoHash,
    input.firstNullifier,
    input.ringId,
    input.memberRegistryRoot,
    ...pack33(input.auditorPublicKey.toBytes()),
    ...pack33(input.disclosure.ephemeralPublicKey),
    hashBytes(input.disclosure.ciphertext) as Bytes32,
    rightAlign(input.salt),
    hashChain4(input.disclosure.fields),
  ]);
}

function invalid(reason: string): RingError {
  return new RingError("RING_AUDIT_MESSAGE", { details: { reason } });
}
