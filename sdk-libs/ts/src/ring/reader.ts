import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import {
  getProgramDerivedAddress,
  isAddress,
  type Address,
  type Instruction,
  type ProgramDerivedAddress,
} from "@solana/kit";

import type { ZolanaClient } from "../client/client.js";
import { SYSTEM_PROGRAM, meta, type SignerAccount } from "../interface/instructions/index.js";
import { addressBytes, encodeBase58, Reader, sha256 } from "../interface/internal.js";
import type { Bytes32, Bytes33, RequestContext } from "../interface/types.js";
import { isDerivationPoint } from "../keypair/derivation.js";
import { P256PublicKey, ShieldedPublicKey } from "../keypair/public-key.js";
import { equal } from "../transaction/internal.js";

import { ringConfigAddress } from "./config.js";
import { RingError } from "./error.js";

const encoder = new TextEncoder();

/** Rust `tag::GRANT_READER` and `tag::REVOKE_READER`. */
const GRANT_READER_TAG = 4;
const REVOKE_READER_TAG = 5;
/** Rust `READER_KEY_P256` and `READER_KEY_ED25519`. */
const READER_KEY_P256 = 0x00;
const READER_KEY_ED25519 = 0x01;

/** Mirrors Rust `ReaderKey`. */
export type ReaderKey = Address | P256PublicKey;

/** Mirrors Rust `ReaderRecord`. */
export interface ReaderRecord {
  readonly reader: ReaderKey;
  readonly bump: number;
}

const READER_RECORD_DISCRIMINATOR = 2;
const READER_RECORD_SIZE = 36;

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
  if (isDerivationPoint(reader)) {
    throw new RingError("RING_READER_KEY", { details: { reader: readerKeyToString(reader) } });
  }
  return reader;
}

/** The program's 34-byte scheme-tagged layout. */
export function readerKeyBytes(reader: ReaderKey): Uint8Array {
  return typeof reader === "string"
    ? ShieldedPublicKey.fromEd25519(addressBytes(reader, "reader") as Bytes32).toBytes()
    : ShieldedPublicKey.fromP256(reader).toBytes();
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
      return checkedReaderKey(P256PublicKey.fromBytes(bytes.subarray(1) as Bytes33));
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
  let key: P256PublicKey;
  try {
    key = P256PublicKey.fromBytes(hexToBytes(trimmed) as Bytes33);
  } catch (cause) {
    throw new RingError("RING_READER_KEY", { details: { text: trimmed }, cause });
  }
  return checkedReaderKey(key);
}

export function readerKeyToString(reader: ReaderKey): string {
  return typeof reader === "string" ? reader : bytesToHex(reader.toBytes());
}

/** Mirrors Rust `ReaderKey::record_address`. */
export async function readerRecordAddress(
  ringProgramId: Address,
  reader: ReaderKey,
): Promise<Address> {
  return (await readerRecordPda(ringProgramId, reader))[0];
}

async function readerRecordPda(
  ringProgramId: Address,
  reader: ReaderKey,
): Promise<ProgramDerivedAddress> {
  return getProgramDerivedAddress({
    programAddress: ringProgramId,
    seeds: [encoder.encode("reader"), sha256(readerKeyBytes(checkedReaderKey(reader)))],
  });
}

/** Mirrors Rust `GrantReader`. The authority signs, so a Squads-held authority grants by proposal. */
export async function grantReaderInstruction(
  input: Readonly<{
    ringProgramId: Address;
    payer: SignerAccount;
    authority: SignerAccount;
    reader: ReaderKey;
  }>,
): Promise<Instruction> {
  const [config, record] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    readerRecordAddress(input.ringProgramId, input.reader),
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
    data: readerInstructionData(GRANT_READER_TAG, input.reader),
  };
}

/** Mirrors Rust `RevokeReader`. */
export async function revokeReaderInstruction(
  input: Readonly<{
    ringProgramId: Address;
    authority: SignerAccount;
    reader: ReaderKey;
    rentRecipient: Address;
  }>,
): Promise<Instruction> {
  const [config, record] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    readerRecordAddress(input.ringProgramId, input.reader),
  ]);
  return {
    programAddress: input.ringProgramId,
    accounts: [
      meta(input.authority, true, false),
      meta(config, false, false),
      meta(record, false, true),
      meta(input.rentRecipient, false, true),
    ],
    data: readerInstructionData(REVOKE_READER_TAG, input.reader),
  };
}

export function decodeReaderRecord(data: Uint8Array): ReaderRecord {
  if (data.length !== READER_RECORD_SIZE || data[0] !== READER_RECORD_DISCRIMINATOR) {
    throw new RingError("RING_READER_RECORD_INVALID", {
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
    throw new RingError("RING_READER_RECORD_INVALID", { cause });
  }
  return Object.freeze({ reader: key, bump });
}

/** Mirrors Rust `CustomRing::read_reader_record`, a record under the address that names another key is invalid. */
export async function fetchReaderGrant(
  client: ZolanaClient,
  ringProgramId: Address,
  reader: ReaderKey,
  context?: RequestContext,
): Promise<boolean> {
  const [record, bump] = await readerRecordPda(ringProgramId, reader);
  const account = await client.getAccount(record, context);
  if (account === undefined) return false;
  if (account.owner !== ringProgramId) {
    throw new RingError("RING_READER_RECORD_INVALID", { details: { record } });
  }
  const decoded = decodeReaderRecord(account.data);
  if (!readerKeyEquals(decoded.reader, reader) || decoded.bump !== bump) {
    throw new RingError("RING_READER_RECORD_INVALID", { details: { record } });
  }
  return true;
}

function readerInstructionData(tag: number, reader: ReaderKey): Uint8Array {
  const data = new Uint8Array(35);
  data[0] = tag;
  data.set(readerKeyBytes(reader), 1);
  return data;
}
