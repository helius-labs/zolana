import type { Rpc } from "@zolana/client";
import {
  type Address,
  type Bytes32,
  type Bytes33,
  type Instruction,
  type RequestContext,
  type Transaction,
} from "@zolana/interface";
import { P256PublicKey, ShieldedAddress, ShieldedPublicKey } from "@zolana/keypair";

import { WalletError, wrapWalletError } from "./error.js";
import {
  checkedAddress,
  compileTransaction,
  concat,
  decodeBase58,
  encodeBase58,
  equalBytes,
} from "./internal.js";

const PROGRAM_ID = "EXM6UUA56UJySzRDCx4dKwN6Xdcrkq3kmizqgZwgwNEc" as Address;
const SYSTEM_PROGRAM = "11111111111111111111111111111111" as Address;
const RECORD_SEED = new TextEncoder().encode("zolana/registry/v0");
const PDA_MARKER = new TextEncoder().encode("ProgramDerivedAddress");
const P = (1n << 255n) - 19n;
const D = mod(-121665n * inverse(121666n));

export interface ResolvedAddress {
  readonly owner: Address;
  readonly address: ShieldedAddress;
  readonly viewTag: Bytes32;
}

export interface UserRecord {
  readonly owner: Address;
  readonly ownerP256?: Bytes33;
  readonly nullifierPublicKey: Bytes32;
  readonly viewingPublicKey: Bytes33;
  readonly bump: number;
}

interface DecodedUserRecord extends UserRecord {
  readonly mergingEnabled: boolean;
}

function mod(value: bigint): bigint {
  const result = value % P;
  return result < 0n ? result + P : result;
}

function power(base: bigint, exponent: bigint): bigint {
  let result = 1n;
  let factor = mod(base);
  let remaining = exponent;
  while (remaining > 0n) {
    if ((remaining & 1n) === 1n) result = mod(result * factor);
    factor = mod(factor * factor);
    remaining >>= 1n;
  }
  return result;
}

function inverse(value: bigint): bigint {
  return power(value, P - 2n);
}

function littleEndianInteger(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let index = bytes.length - 1; index >= 0; index--) {
    result = (result << 8n) | BigInt(bytes[index] ?? 0);
  }
  return result;
}

function isEd25519Point(bytes: Uint8Array): boolean {
  const encoded = new Uint8Array(bytes);
  encoded[31] = (encoded[31] ?? 0) & 0x7f;
  const y = littleEndianInteger(encoded);
  if (y >= P) return false;
  const y2 = mod(y * y);
  const x2 = mod((y2 - 1n) * inverse(D * y2 + 1n));
  let x = power(x2, (P + 3n) / 8n);
  if (mod(x * x - x2) !== 0n) {
    x = mod(x * power(2n, (P - 1n) / 4n));
  }
  return mod(x * x - x2) === 0n;
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  const owned = Uint8Array.from(bytes);
  return new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", owned));
}

async function userRecordAddress(owner: Address): Promise<
  Readonly<{
    address: Address;
    bump: number;
  }>
> {
  const ownerBytes = decodeBase58(owner, 32, "owner");
  const program = decodeBase58(PROGRAM_ID, 32, "programId");
  for (let bump = 255; bump >= 0; bump--) {
    const digest = await sha256(
      concat(RECORD_SEED, ownerBytes, Uint8Array.of(bump), program, PDA_MARKER),
    );
    if (!isEd25519Point(digest)) {
      return { address: encodeBase58(digest) as Address, bump };
    }
  }
  throw new WalletError("WALLET_PDA_DERIVATION");
}

export async function internalUserRecordAddress(owner: Address): Promise<Address> {
  return (await userRecordAddress(owner)).address;
}

export async function internalUserRecordPda(
  owner: Address,
): Promise<Readonly<{ address: Address; bump: number }>> {
  return userRecordAddress(owner);
}

export async function internalMergingEnabled(
  input: Readonly<{ rpc: Rpc; owner: Address }>,
  context?: RequestContext,
): Promise<boolean> {
  return (await fetchDecodedUserRecord(input, context))?.mergingEnabled ?? false;
}

class Reader {
  readonly #bytes: Uint8Array;
  #offset = 0;

  constructor(bytes: Uint8Array) {
    this.#bytes = bytes;
  }

  bytes(length: number): Uint8Array {
    const end = this.#offset + length;
    if (end > this.#bytes.length) throw new WalletError("WALLET_INVALID_USER_RECORD");
    const value = this.#bytes.slice(this.#offset, end);
    this.#offset = end;
    return value;
  }

  u8(): number {
    return this.bytes(1)[0] ?? 0;
  }

  u32(): number {
    const bytes = this.bytes(4);
    return (
      ((bytes[0] ?? 0) |
        ((bytes[1] ?? 0) << 8) |
        ((bytes[2] ?? 0) << 16) |
        ((bytes[3] ?? 0) << 24)) >>>
      0
    );
  }

  option(length: number): Uint8Array | undefined {
    const variant = this.u8();
    if (variant === 0) return undefined;
    if (variant !== 1) throw new WalletError("WALLET_INVALID_USER_RECORD");
    return this.bytes(length);
  }
}

function decodeRecord(
  data: Uint8Array,
  expectedOwner: Address,
  expectedBump: number,
): DecodedUserRecord {
  const reader = new Reader(data);
  if (reader.u8() !== 1) throw new WalletError("WALLET_INVALID_USER_RECORD");
  const ownerBytes = reader.bytes(32);
  if (!equalBytes(ownerBytes, decodeBase58(expectedOwner, 32, "owner"))) {
    throw new WalletError("WALLET_USER_RECORD_OWNER_MISMATCH");
  }
  const bump = reader.u8();
  if (bump !== expectedBump) throw new WalletError("WALLET_USER_RECORD_BUMP_MISMATCH");
  const ownerP256 = reader.option(33) as Bytes33 | undefined;
  const nullifierPublicKey = reader.bytes(32) as Bytes32;
  const viewingPublicKey = reader.bytes(33) as Bytes33;
  reader.option(32);
  const entryCount = reader.u32();
  reader.bytes(entryCount * 106);
  const mergingEnabled = reader.u8();
  if (mergingEnabled > 1) throw new WalletError("WALLET_INVALID_USER_RECORD");
  return Object.freeze({
    owner: expectedOwner,
    ...(ownerP256 === undefined ? {} : { ownerP256 }),
    nullifierPublicKey,
    viewingPublicKey,
    bump,
    mergingEnabled: mergingEnabled === 1,
  });
}

async function fetchDecodedUserRecord(
  input: Readonly<{ rpc: Rpc; owner: Address }>,
  context?: RequestContext,
): Promise<DecodedUserRecord | undefined> {
  checkedAddress(input.owner, "owner");
  const pda = await userRecordAddress(input.owner);
  const account = await input.rpc.getAccount(pda.address, context);
  if (account === undefined) return undefined;
  if (account.owner !== PROGRAM_ID) {
    throw new WalletError("WALLET_USER_RECORD_PROGRAM_MISMATCH");
  }
  return decodeRecord(account.data, input.owner, pda.bump);
}

export async function fetchUserRecord(
  input: Readonly<{ rpc: Rpc; owner: Address }>,
  context?: RequestContext,
): Promise<UserRecord | undefined> {
  try {
    const record = await fetchDecodedUserRecord(input, context);
    if (record === undefined) return undefined;
    return Object.freeze({
      owner: record.owner,
      ...(record.ownerP256 === undefined ? {} : { ownerP256: record.ownerP256 }),
      nullifierPublicKey: record.nullifierPublicKey,
      viewingPublicKey: record.viewingPublicKey,
      bump: record.bump,
    });
  } catch (cause) {
    throw wrapWalletError("WALLET_FETCH_USER_RECORD", cause);
  }
}

export async function isWalletRegistered(
  input: Readonly<{ rpc: Rpc; owner: Address }>,
  context?: RequestContext,
): Promise<boolean> {
  return (await fetchUserRecord(input, context)) !== undefined;
}

export async function resolveRegisteredAddress(
  input: Readonly<{ rpc: Rpc; owner: Address }>,
  context?: RequestContext,
): Promise<ResolvedAddress | undefined> {
  const record = await fetchUserRecord(input, context);
  if (record === undefined) return undefined;
  const signingPublicKey =
    record.ownerP256 === undefined
      ? ShieldedPublicKey.fromEd25519(decodeBase58(input.owner, 32, "owner") as Bytes32)
      : ShieldedPublicKey.fromP256(P256PublicKey.fromBytes(record.ownerP256));
  const viewingPublicKey = P256PublicKey.fromBytes(record.viewingPublicKey);
  return Object.freeze({
    owner: input.owner,
    address: ShieldedAddress.fromPublicKeys(
      signingPublicKey,
      record.nullifierPublicKey,
      viewingPublicKey,
    ),
    viewTag: viewingPublicKey.x(),
  });
}

export async function buildRegistrationTransaction(
  input: Readonly<{ rpc: Rpc; owner: Address; address: ShieldedAddress }>,
  context?: RequestContext,
): Promise<Transaction | undefined> {
  try {
    const pda = await userRecordAddress(input.owner);
    const existing = await fetchDecodedUserRecord({ rpc: input.rpc, owner: input.owner }, context);
    const ownerP256 =
      input.address.signingPublicKey.signatureType() === "p256"
        ? input.address.signingPublicKey.p256().toBytes()
        : undefined;
    const nullifierPublicKey = input.address.nullifierPublicKey;
    const viewingPublicKey = input.address.viewingPublicKey.toBytes();
    if (
      existing !== undefined &&
      ((existing.ownerP256 === undefined && ownerP256 === undefined) ||
        (existing.ownerP256 !== undefined &&
          ownerP256 !== undefined &&
          equalBytes(existing.ownerP256, ownerP256))) &&
      equalBytes(existing.nullifierPublicKey, nullifierPublicKey) &&
      equalBytes(existing.viewingPublicKey, viewingPublicKey)
    ) {
      return undefined;
    }
    const data = concat(
      Uint8Array.of(existing === undefined ? 0 : 5, ownerP256 === undefined ? 0 : 1),
      ...(ownerP256 === undefined ? [] : [ownerP256]),
      nullifierPublicKey,
      viewingPublicKey,
    );
    const instruction: Instruction = {
      programAddress: PROGRAM_ID,
      accounts: [
        { address: pda.address, isSigner: false, isWritable: true },
        { address: input.owner, isSigner: true, isWritable: true },
        ...(existing === undefined
          ? [{ address: SYSTEM_PROGRAM, isSigner: false, isWritable: false }]
          : []),
      ],
      data,
    };
    const latest = await input.rpc.getLatestBlockhash(context);
    return compileTransaction({
      feePayer: input.owner,
      recentBlockhash: latest.blockhash,
      instructions: [instruction],
    });
  } catch (cause) {
    throw wrapWalletError("WALLET_BUILD_REGISTRATION", cause);
  }
}
