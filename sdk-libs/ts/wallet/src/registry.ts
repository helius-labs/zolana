import type { Rpc, RpcAccount } from "@zolana/client";
import {
  type Address,
  type Bytes32,
  type Bytes33,
  type Instruction,
  type RequestContext,
  type Signature,
  type Transaction,
} from "@zolana/interface";
import { findProgramAddress } from "@zolana/interface/pda";
import {
  P256PublicKey,
  ShieldedAddress,
  ShieldedPublicKey,
  type ShieldedKeypair,
} from "@zolana/keypair";

import { WalletError, wrapWalletError } from "./error.js";
import {
  checkedAddress,
  compileTransaction,
  concat,
  decodeBase58,
  encodeBase58,
  equalBytes,
} from "./internal.js";
import type { TransactionSigner } from "./submit.js";

const PROGRAM_ID = "EXM6UUA56UJySzRDCx4dKwN6Xdcrkq3kmizqgZwgwNEc" as Address;
const SYSTEM_PROGRAM = "11111111111111111111111111111111" as Address;
const RECORD_SEED = new TextEncoder().encode("zolana/registry/v0");

export interface ResolvedAddress {
  readonly owner: Address;
  readonly address: ShieldedAddress;
  readonly viewTag: Bytes32;
}

export interface SyncDelegateEntry {
  readonly delegate: Bytes32;
  readonly syncPublicKey: Bytes33;
  readonly viewingPublicKey: Bytes33;
  readonly createdAt: bigint;
}

export interface UserRecord {
  readonly owner: Address;
  readonly ownerP256?: Bytes33;
  readonly nullifierPublicKey: Bytes32;
  readonly viewingPublicKey: Bytes33;
  readonly syncDelegate?: Bytes32;
  readonly entries: readonly SyncDelegateEntry[];
  readonly bump: number;
}

interface DecodedUserRecord extends UserRecord {
  readonly mergingEnabled: boolean;
}

/**
 * The viewing key a sender must encrypt to. While a sync delegate is active the
 * delegate's latest epoch key replaces the record's own key. Revoking the
 * delegate restores the owner key.
 */
export function senderViewingPublicKey(record: UserRecord): Bytes33 {
  if (record.syncDelegate === undefined) return record.viewingPublicKey;
  return record.entries.at(-1)?.viewingPublicKey ?? record.viewingPublicKey;
}

async function userRecordAddress(owner: Address): Promise<
  Readonly<{
    address: Address;
    bump: number;
  }>
> {
  try {
    const ownerBytes = decodeBase58(owner, 32, "owner");
    const [address, bump] = findProgramAddress([RECORD_SEED, ownerBytes], PROGRAM_ID);
    return { address, bump };
  } catch {
    throw new WalletError("WALLET_PDA_DERIVATION");
  }
}

export async function internalUserRecordAddress(owner: Address): Promise<Address> {
  return (await userRecordAddress(owner)).address;
}

export async function internalUserRecordPda(
  owner: Address,
): Promise<Readonly<{ address: Address; bump: number }>> {
  return userRecordAddress(owner);
}

export interface MergeSubmissionRecord {
  readonly mergingEnabled: boolean;
  readonly ownerP256?: Bytes33;
  readonly nullifierPublicKey: Bytes32;
  readonly viewingPublicKey: Bytes33;
}

/**
 * One read of the record for the whole merge submission check: merging opt-in
 * and the committed identity are validated against the same snapshot.
 */
export async function internalMergeSubmissionRecord(
  input: Readonly<{ rpc: Rpc; owner: Address }>,
  context?: RequestContext,
): Promise<MergeSubmissionRecord> {
  const record = await fetchDecodedUserRecord(input, context);
  if (record === undefined) {
    throw new WalletError("WALLET_USER_REGISTRY_RECORD_NOT_FOUND", {
      details: { owner: input.owner },
    });
  }
  return record;
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

  i64(): bigint {
    const bytes = this.bytes(8);
    return new DataView(bytes.buffer, bytes.byteOffset, 8).getBigInt64(0, true);
  }

  option(length: number): Uint8Array | undefined {
    const variant = this.u8();
    if (variant === 0) return undefined;
    if (variant !== 1) throw new WalletError("WALLET_INVALID_USER_RECORD");
    return this.bytes(length);
  }
}

function decodeRecordBody(data: Uint8Array): DecodedUserRecord {
  const reader = new Reader(data);
  if (reader.u8() !== 1) throw new WalletError("WALLET_INVALID_USER_RECORD");
  const owner = encodeBase58(reader.bytes(32)) as Address;
  const bump = reader.u8();
  const ownerP256 = reader.option(33) as Bytes33 | undefined;
  const nullifierPublicKey = reader.bytes(32) as Bytes32;
  const viewingPublicKey = reader.bytes(33) as Bytes33;
  const syncDelegate = reader.option(32) as Bytes32 | undefined;
  const entryCount = reader.u32();
  const entries: SyncDelegateEntry[] = [];
  for (let index = 0; index < entryCount; index++) {
    entries.push(
      Object.freeze({
        delegate: reader.bytes(32) as Bytes32,
        syncPublicKey: reader.bytes(33) as Bytes33,
        viewingPublicKey: reader.bytes(33) as Bytes33,
        createdAt: reader.i64(),
      }),
    );
  }
  const mergingEnabled = reader.u8();
  if (mergingEnabled > 1) throw new WalletError("WALLET_INVALID_USER_RECORD");
  return Object.freeze({
    owner,
    ...(ownerP256 === undefined ? {} : { ownerP256 }),
    nullifierPublicKey,
    viewingPublicKey,
    ...(syncDelegate === undefined ? {} : { syncDelegate }),
    entries: Object.freeze(entries),
    bump,
    mergingEnabled: mergingEnabled === 1,
  });
}

export function decodeUserRecordAccount(account: RpcAccount): UserRecord {
  if (account.owner !== PROGRAM_ID) {
    throw new WalletError("WALLET_USER_RECORD_PROGRAM_MISMATCH");
  }
  return decodeRecordBody(account.data);
}

function decodeRecord(
  account: RpcAccount,
  expectedOwner: Address,
  expectedBump: number,
): DecodedUserRecord {
  const record = decodeUserRecordAccount(account) as DecodedUserRecord;
  if (record.owner !== expectedOwner) {
    throw new WalletError("WALLET_USER_RECORD_OWNER_MISMATCH");
  }
  if (record.bump !== expectedBump) throw new WalletError("WALLET_USER_RECORD_BUMP_MISMATCH");
  return record;
}

async function fetchDecodedUserRecord(
  input: Readonly<{ rpc: Rpc; owner: Address }>,
  context?: RequestContext,
): Promise<DecodedUserRecord | undefined> {
  checkedAddress(input.owner, "owner");
  const pda = await userRecordAddress(input.owner);
  const account = await input.rpc.getAccount(pda.address, context);
  if (account === undefined) return undefined;
  return decodeRecord(account, input.owner, pda.bump);
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
      ...(record.syncDelegate === undefined ? {} : { syncDelegate: record.syncDelegate }),
      entries: record.entries,
      bump: record.bump,
    });
  } catch (cause) {
    throw wrapWalletError("WALLET_FETCH_USER_RECORD", cause);
  }
}

export async function fetchUserRecordChecked(
  input: Readonly<{ rpc: Rpc; owner: Address }>,
  context?: RequestContext,
): Promise<UserRecord> {
  const record = await fetchUserRecord(input, context);
  if (record === undefined) {
    throw new WalletError("WALLET_USER_REGISTRY_RECORD_NOT_FOUND", {
      details: { owner: input.owner },
    });
  }
  return record;
}

export async function isWalletRegistered(
  input: Readonly<{ rpc: Rpc; owner: Address }>,
  context?: RequestContext,
): Promise<boolean> {
  return (await fetchUserRecord(input, context)) !== undefined;
}

function signingPublicKeyFromRecord(owner: Address, record: UserRecord): ShieldedPublicKey {
  return record.ownerP256 === undefined
    ? ShieldedPublicKey.fromEd25519(decodeBase58(owner, 32, "owner") as Bytes32)
    : ShieldedPublicKey.fromP256(P256PublicKey.fromBytes(record.ownerP256));
}

export function resolvedAddressFromRecord(owner: Address, record: UserRecord): ResolvedAddress {
  const signingPublicKey = signingPublicKeyFromRecord(owner, record);
  const viewingPublicKey = P256PublicKey.fromBytes(senderViewingPublicKey(record));
  const address = ShieldedAddress.fromPublicKeys(
    signingPublicKey,
    record.nullifierPublicKey,
    viewingPublicKey,
  );
  // A sender that resolves a recipient here writes this tag onto the output it
  // creates, so it must be the owner tag every wallet scans for, not the
  // viewing key of the moment: a sync delegate rotates the viewing key while
  // the owner pubkey stays put.
  return Object.freeze({
    owner,
    address,
    viewTag: address.confidentialViewTag(),
  });
}

export async function resolveRegisteredAddress(
  input: Readonly<{ rpc: Rpc; owner: Address }>,
  context?: RequestContext,
): Promise<ResolvedAddress | undefined> {
  const record = await fetchUserRecord(input, context);
  if (record === undefined) return undefined;
  return resolvedAddressFromRecord(input.owner, record);
}

/** Resolves the shielded address of `owner`, or `undefined` when unregistered. */
export async function tryResolveRegisteredAddress(
  input: Readonly<{ rpc: Rpc; owner: Address }>,
  context?: RequestContext,
): Promise<ResolvedAddress | undefined> {
  return resolveRegisteredAddress(input, context);
}

/**
 * Rejects when the on-chain record under `owner` publishes keys other than
 * `keypair`'s. A shielded identity's nullifier key never rotates, so a
 * difference is an identity conflict rather than stale data.
 */
export async function validateRegisteredKeypair(
  input: Readonly<{ rpc: Rpc; owner: Address; keypair: ShieldedKeypair }>,
  context?: RequestContext,
): Promise<void> {
  const record = await fetchUserRecordChecked({ rpc: input.rpc, owner: input.owner }, context);
  const signingPublicKey = input.keypair.signingPublicKey();
  const expectedOwnerP256 =
    signingPublicKey.signatureType() === "p256" ? signingPublicKey.p256().toBytes() : undefined;
  const ownerP256Matches =
    expectedOwnerP256 === undefined
      ? record.ownerP256 === undefined
      : record.ownerP256 !== undefined && equalBytes(record.ownerP256, expectedOwnerP256);
  if (
    !ownerP256Matches ||
    !equalBytes(record.nullifierPublicKey, input.keypair.nullifierKey().publicKey()) ||
    !equalBytes(record.viewingPublicKey, input.keypair.viewingKey().publicKey().toBytes())
  ) {
    throw new WalletError("WALLET_REGISTERED_KEYPAIR_MISMATCH", {
      details: { owner: input.owner },
    });
  }
}

/**
 * Confidential output view tag for a transfer recipient. A registered owner
 * uses the tag of its published signing key. An unregistered owner, who can
 * only be paid by a public withdrawal, uses the zero tag.
 */
export async function recipientConfidentialViewTag(
  input: Readonly<{ rpc: Rpc; recipient: Address }>,
  context?: RequestContext,
): Promise<Bytes32> {
  const record = await fetchUserRecord({ rpc: input.rpc, owner: input.recipient }, context);
  if (record === undefined) return new Uint8Array(32) as Bytes32;
  return signingPublicKeyFromRecord(input.recipient, record).confidentialViewTag();
}

/**
 * The three published fields the registry keys a record by. A record matching
 * all three needs no transaction; one differing in any of them is an identity
 * change, which only the rotating path may write.
 */
function publishedKeysMatch(record: UserRecord, address: ShieldedAddress): boolean {
  const ownerP256 =
    address.signingPublicKey.signatureType() === "p256"
      ? address.signingPublicKey.p256().toBytes()
      : undefined;
  const ownerMatches =
    ownerP256 === undefined
      ? record.ownerP256 === undefined
      : record.ownerP256 !== undefined && equalBytes(record.ownerP256, ownerP256);
  return (
    ownerMatches &&
    equalBytes(record.nullifierPublicKey, address.nullifierPublicKey) &&
    equalBytes(record.viewingPublicKey, address.viewingPublicKey.toBytes())
  );
}

/** Outcome of the strict registration path, which never rotates keys. */
export type StrictRegistration =
  | Readonly<{ kind: "written"; signature: Signature }>
  | Readonly<{ kind: "current" }>
  | Readonly<{ kind: "mismatch" }>;

export async function fetchUserRecordOptionalChecked(
  input: Readonly<{ rpc: Rpc; owner: Address }>,
  context?: RequestContext,
): Promise<UserRecord | undefined> {
  return fetchUserRecord(input, context);
}

/**
 * Publish `keypair`'s shielded keys under the funding account, rotating a stale
 * record's keys. Returns no signature when the record already matches.
 */
export async function ensureRegistered(
  input: Readonly<{ rpc: Rpc; funding: TransactionSigner; keypair: ShieldedKeypair }>,
  context?: RequestContext,
): Promise<Signature | undefined> {
  try {
    const unsigned = await buildRegistrationTransaction(
      {
        rpc: input.rpc,
        owner: input.funding.address,
        address: input.keypair.shieldedAddress(),
      },
      context,
    );
    if (unsigned === undefined) return undefined;
    return await input.rpc.sendTransaction(
      await input.funding.signNativeTransaction(unsigned),
      context,
    );
  } catch (cause) {
    throw wrapWalletError("WALLET_ENSURE_REGISTERED", cause);
  }
}

/**
 * Write the record only when absent. A nullifier key never rotates, so a record
 * publishing different keys is reported as a conflict instead of being
 * overwritten.
 */
export async function registerIfAbsent(
  input: Readonly<{ rpc: Rpc; funding: TransactionSigner; keypair: ShieldedKeypair }>,
  context?: RequestContext,
): Promise<StrictRegistration> {
  try {
    const owner = input.funding.address;
    const address = input.keypair.shieldedAddress();
    const existing = await fetchUserRecord({ rpc: input.rpc, owner }, context);
    if (existing !== undefined) {
      return Object.freeze({
        kind: publishedKeysMatch(existing, address) ? "current" : "mismatch",
      });
    }
    const unsigned = await buildRegistrationTransaction(
      { rpc: input.rpc, owner, address },
      context,
    );
    if (unsigned === undefined) return Object.freeze({ kind: "current" });
    const signature = await input.rpc.sendTransaction(
      await input.funding.signNativeTransaction(unsigned),
      context,
    );
    return Object.freeze({ kind: "written", signature });
  } catch (cause) {
    throw wrapWalletError("WALLET_REGISTER_IF_ABSENT", cause);
  }
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
    if (existing !== undefined && publishedKeysMatch(existing, input.address)) {
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
