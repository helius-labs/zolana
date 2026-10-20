import { p256 } from "@noble/curves/nist.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import {
  getProgramDerivedAddress,
  isAddress,
  type Address,
  type Instruction,
  type ProgramDerivedAddress,
} from "@solana/kit";

import type { ChainReader } from "../client/ports.js";
import { SYSTEM_PROGRAM, meta, type SignerAccount } from "../interface/instructions/index.js";
import { addressBytes, encodeBase58, Reader, sha256 } from "../interface/internal.js";
import type { Bytes32, Bytes33, RequestContext } from "../interface/types.js";
import { ShieldedPublicKey } from "../keypair/public-key.js";
import { equal } from "../transaction/internal.js";

import { ringConfigAddress } from "../interface/pda/index.js";
import { RingError } from "./error.js";
import { checkedBytes, copyBytes } from "../keypair/bytes.js";
import { wrapKeypairError } from "../keypair/error.js";

const encoder = new TextEncoder();

/** Passkey public key for ring-rpc audit access. */
export class P256ReaderKey {
  readonly #bytes: Uint8Array;

  private constructor(bytes: Uint8Array) {
    this.#bytes = bytes;
  }

  static fromBytes(bytes: Bytes33): P256ReaderKey {
    const owned = checkedBytes<Bytes33>(bytes, 33, "P256 public key");
    try {
      p256.Point.fromBytes(owned);
    } catch (error) {
      throw wrapKeypairError("KEYPAIR_INVALID_PUBLIC_KEY", error);
    }
    return new P256ReaderKey(owned);
  }

  /** A 65-byte `0x04 || x || y` point, what WebAuthn and SPKI carry. */
  static fromUncompressed(bytes: Uint8Array): P256ReaderKey {
    try {
      return P256ReaderKey.fromBytes(p256.Point.fromBytes(bytes).toBytes(true) as Bytes33);
    } catch (error) {
      throw wrapKeypairError("KEYPAIR_INVALID_PUBLIC_KEY", error);
    }
  }

  toBytes(): Bytes33 {
    return copyBytes(this.#bytes) as Bytes33;
  }

  toUncompressed(): Uint8Array {
    return p256.Point.fromBytes(this.#bytes).toBytes(false);
  }

  /** Compares canonical compressed passkey encodings. */
  equals(other: P256ReaderKey): boolean {
    const left = this.#bytes;
    const right = other.#bytes;
    return left.length === right.length && left.every((byte, index) => byte === right[index]);
  }
}

/** Rust `tag::GRANT_READ_ACCESS` and `tag::REVOKE_READ_ACCESS`. */
const GRANT_READ_ACCESS_TAG = 4;
const REVOKE_READ_ACCESS_TAG = 5;
/** Rust `READER_KEY_P256` and `READER_KEY_ED25519`. */
const READER_KEY_P256 = 0x00;
const READER_KEY_ED25519 = 0x01;

/** Mirrors Rust `ReaderKey`. */
export type ReaderKey = Address | P256ReaderKey;

/** Mirrors Rust `ReadAccessRecord`. */
export interface ReadAccessRecord {
  readonly reader: ReaderKey;
  readonly bump: number;
}

const READ_ACCESS_RECORD_DISCRIMINATOR = 2;
const READ_ACCESS_RECORD_SIZE = 36;

/** Mirrors Rust `ReaderKey::ed25519` and `ReaderKey::p256`, a key that cannot sign a read is refused. */
export function checkedReaderKey(reader: ReaderKey): ReaderKey {
  if (typeof reader === "string") {
    const body = addressBytes(reader, "reader");
    let canonical = false;
    try {
      const point = ed25519.Point.fromBytes(body);
      canonical = equal(point.toBytes(), body) && point.isTorsionFree() && !point.isSmallOrder();
    } catch {
      canonical = false;
    }
    if (!canonical) throw new RingError("RING_READER_KEY", { details: { reader } });
    return reader;
  }
  return reader;
}

/** The program's 34-byte scheme-tagged layout. */
export function readerKeyBytes(reader: ReaderKey): Uint8Array {
  if (typeof reader === "string") {
    return ShieldedPublicKey.fromEd25519(addressBytes(reader, "reader") as Bytes32).toBytes();
  }
  const bytes = new Uint8Array(34);
  bytes.set(reader.toBytes(), 1);
  return bytes;
}

/** Mirrors Rust `ReaderKey::from_bytes`. */
export function readerKeyFromBytes(bytes: Uint8Array): ReaderKey {
  if (bytes.length !== 34) {
    throw new RingError("RING_READER_KEY", { details: { length: bytes.length } });
  }
  switch (bytes[0]) {
    case READER_KEY_ED25519:
      if (bytes[33] !== 0) throw new RingError("RING_READER_KEY", { details: { scheme: 1 } });
      return checkedReaderKey(encodeBase58(bytes.subarray(1, 33)));
    case READER_KEY_P256:
      return checkedReaderKey(P256ReaderKey.fromBytes(bytes.subarray(1) as Bytes33));
    default:
      throw new RingError("RING_READER_KEY", { details: { scheme: bytes[0] } });
  }
}

export function readerKeyEquals(left: ReaderKey, right: ReaderKey): boolean {
  return typeof left === "string" || typeof right === "string"
    ? left === right
    : left.equals(right);
}

/** Mirrors Rust `FromStr`, base58 for a wallet key and 66 hex characters for a P-256 key. */
export function parseReaderKey(text: string): ReaderKey {
  const trimmed = text.trim();
  if (isAddress(trimmed)) return checkedReaderKey(trimmed);
  if (!/^[0-9a-fA-F]{66}$/.test(trimmed)) {
    throw new RingError("RING_READER_KEY", { details: { text: trimmed } });
  }
  let key: P256ReaderKey;
  try {
    key = P256ReaderKey.fromBytes(hexToBytes(trimmed) as Bytes33);
  } catch (cause) {
    throw new RingError("RING_READER_KEY", { details: { text: trimmed }, cause });
  }
  return checkedReaderKey(key);
}

export function readerKeyToString(reader: ReaderKey): string {
  return typeof reader === "string" ? reader : bytesToHex(reader.toBytes());
}

/** Mirrors Rust `ReaderKey::record_address`. */
export async function readAccessRecordAddress(
  ringProgramId: Address,
  reader: ReaderKey,
): Promise<Address> {
  return (await readAccessRecordPda(ringProgramId, reader))[0];
}

async function readAccessRecordPda(
  ringProgramId: Address,
  reader: ReaderKey,
): Promise<ProgramDerivedAddress> {
  return getProgramDerivedAddress({
    programAddress: ringProgramId,
    seeds: [encoder.encode("reader"), sha256(readerKeyBytes(checkedReaderKey(reader)))],
  });
}

/** Mirrors Rust `GrantReadAccess`. The authority signs, so a Squads-held authority grants by proposal. */
export async function grantReadAccessInstruction(
  input: Readonly<{
    ringProgramId: Address;
    payer: SignerAccount;
    authority: SignerAccount;
    reader: ReaderKey;
  }>,
): Promise<Instruction> {
  const [config, record] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    readAccessRecordAddress(input.ringProgramId, input.reader),
  ]);
  return {
    programAddress: input.ringProgramId,
    accounts: [
      meta(input.payer, true, true),
      meta(input.authority, true, false),
      meta(config, false, false),
      meta(record, false, true),
      meta(SYSTEM_PROGRAM, false, false),
    ],
    data: readerInstructionData(GRANT_READ_ACCESS_TAG, input.reader),
  };
}

/** Mirrors Rust `RevokeReadAccess`. */
export async function revokeReadAccessInstruction(
  input: Readonly<{
    ringProgramId: Address;
    authority: SignerAccount;
    reader: ReaderKey;
    rentRecipient: Address;
  }>,
): Promise<Instruction> {
  const [config, record] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    readAccessRecordAddress(input.ringProgramId, input.reader),
  ]);
  return {
    programAddress: input.ringProgramId,
    accounts: [
      meta(input.authority, true, false),
      meta(config, false, false),
      meta(record, false, true),
      meta(input.rentRecipient, false, true),
    ],
    data: readerInstructionData(REVOKE_READ_ACCESS_TAG, input.reader),
  };
}

export function decodeReadAccessRecord(data: Uint8Array): ReadAccessRecord {
  if (data.length !== READ_ACCESS_RECORD_SIZE || data[0] !== READ_ACCESS_RECORD_DISCRIMINATOR) {
    throw new RingError("RING_READ_ACCESS_RECORD_INVALID", {
      details: { length: data.length, discriminator: data[0] },
    });
  }
  const reader = new Reader(data);
  reader.u8("discriminator");
  const tagged = reader.bytes(34, "reader");
  const bump = reader.u8("bump");
  reader.done();
  let key: ReaderKey;
  try {
    key = readerKeyFromBytes(tagged);
  } catch (cause) {
    throw new RingError("RING_READ_ACCESS_RECORD_INVALID", { cause });
  }
  return Object.freeze({ reader: key, bump });
}

/** Mirrors Rust `CustomRing::read_read_access_record`, a record under the address that names another key is invalid. */
export async function fetchReaderGrant(
  client: Pick<ChainReader, "getAccount">,
  ringProgramId: Address,
  reader: ReaderKey,
  context?: RequestContext,
): Promise<boolean> {
  const [record, bump] = await readAccessRecordPda(ringProgramId, reader);
  const account = await client.getAccount(record, context);
  if (account === undefined) return false;
  if (account.owner !== ringProgramId) {
    throw new RingError("RING_READ_ACCESS_RECORD_INVALID", { details: { record } });
  }
  const decoded = decodeReadAccessRecord(account.data);
  if (!readerKeyEquals(decoded.reader, reader) || decoded.bump !== bump) {
    throw new RingError("RING_READ_ACCESS_RECORD_INVALID", { details: { record } });
  }
  return true;
}

function readerInstructionData(tag: number, reader: ReaderKey): Uint8Array {
  const data = new Uint8Array(35);
  data[0] = tag;
  data.set(readerKeyBytes(reader), 1);
  return data;
}
