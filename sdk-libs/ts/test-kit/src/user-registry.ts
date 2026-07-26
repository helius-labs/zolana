import type { Rpc } from "@zolana/client";
import { checkedTransactionSize } from "@zolana/interface";
import type {
  Address,
  Bytes32,
  Instruction,
  RequestContext,
  Signature,
  Transaction,
} from "@zolana/interface";
import { findProgramAddress } from "@zolana/interface/pda";
import { ShieldedKeypair } from "@zolana/keypair";
import type { TransactionSigner } from "@zolana/wallet";

import { TestKitError } from "./error.js";

const USER_REGISTRY_PROGRAM_ID = "EXM6UUA56UJySzRDCx4dKwN6Xdcrkq3kmizqgZwgwNEc" as Address;
const RECORD_SEED = new TextEncoder().encode("zolana/registry/v0");
const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export interface UserRecordAddress {
  readonly address: Address;
  readonly bump: number;
}

export type MergingSetupResult =
  | Readonly<{ changed: false; userRecord: Address }>
  | Readonly<{ changed: true; signature: Signature; userRecord: Address }>;

export function createTestNativeSigner(seed: Bytes32): TransactionSigner {
  if (!(seed instanceof Uint8Array) || seed.length !== 32) {
    throw new TestKitError("TEST_KIT_INVALID_CONFIG", {
      details: {
        field: "seed",
        expected: 32,
        actual: seed instanceof Uint8Array ? seed.length : -1,
      },
    });
  }
  const keypair = ShieldedKeypair.fromEd25519(new Uint8Array(seed) as Bytes32, 0);
  const address = keypair.shieldedAddress().solanaAddress() as unknown as Address;
  return Object.freeze({
    address,
    signNativeTransaction(transaction: Transaction): Promise<Transaction> {
      try {
        return Promise.resolve(placeNativeSignature(transaction, address, keypair));
      } catch {
        // Hand-built TestRpc messages often omit a complete legacy header.
        // Fall back to a single-slot overwrite so those doubles keep working;
        // real create-tree / createAndSendTransaction paths hit the placed path.
        const signature = encodeBase58(keypair.sign(transaction.messageBytes)) as Signature;
        return Promise.resolve(
          Object.freeze({
            messageBytes: new Uint8Array(transaction.messageBytes),
            signatures: Object.freeze(
              transaction.signatures.length <= 1
                ? [signature]
                : transaction.signatures.map((existing, index) =>
                    index === 0 ? signature : existing,
                  ),
            ),
          }),
        );
      }
    },
  });
}

/**
 * Fill every required signature slot from `signers`. Legacy messages reserve one
 * slot per signing account key; callers that overwrite `signatures` with a
 * single entry break create-tree and any other multi-signer path.
 */
export async function signTestTransaction(
  transaction: Transaction,
  signers: readonly TransactionSigner[],
): Promise<Transaction> {
  let signed = transaction;
  for (const signer of signers) {
    signed = await signer.signNativeTransaction(signed);
  }
  const missing = signed.signatures.findIndex((signature) => signature === undefined);
  if (missing !== -1) {
    throw new TestKitError("TEST_KIT_INVALID_CONFIG", {
      details: { field: "signers", reason: "incompleteSignatures", missingIndex: missing },
    });
  }
  return signed;
}

function placeNativeSignature(
  transaction: Transaction,
  address: Address,
  keypair: ShieldedKeypair,
): Transaction {
  const required = transaction.messageBytes[0] ?? 0;
  if (required === 0 || transaction.signatures.length !== required) {
    throw new TestKitError("TEST_KIT_INVALID_CONFIG", {
      details: {
        field: "transaction",
        reason: "signatureCount",
        required,
        provided: transaction.signatures.length,
      },
    });
  }
  const index = signerSlot(transaction.messageBytes, required, address);
  if (index === undefined) {
    throw new TestKitError("TEST_KIT_INVALID_CONFIG", {
      details: { field: "signer", reason: "notRequired", address },
    });
  }
  const signatures = [...transaction.signatures];
  signatures[index] = encodeBase58(keypair.sign(transaction.messageBytes)) as Signature;
  return Object.freeze({
    messageBytes: new Uint8Array(transaction.messageBytes),
    signatures: Object.freeze(signatures),
  });
}

function signerSlot(
  messageBytes: Uint8Array,
  required: number,
  address: Address,
): number | undefined {
  let cursor = 3;
  const [accountCount, afterCount] = readCompactU16(messageBytes, cursor);
  cursor = afterCount;
  for (let index = 0; index < accountCount; index++) {
    const key = encodeBase58(messageBytes.subarray(cursor, cursor + 32));
    cursor += 32;
    if (index < required && key === address) return index;
  }
  return undefined;
}

function readCompactU16(bytes: Uint8Array, offset: number): readonly [number, number] {
  let value = 0;
  let shift = 0;
  let cursor = offset;
  for (let index = 0; index < 3; index++) {
    const byte = bytes[cursor++];
    if (byte === undefined) {
      throw new TestKitError("TEST_KIT_INVALID_CONFIG", {
        details: { field: "transaction", reason: "compactU16" },
      });
    }
    value |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) return [value, cursor];
    shift += 7;
  }
  throw new TestKitError("TEST_KIT_INVALID_CONFIG", {
    details: { field: "transaction", reason: "compactU16" },
  });
}

export async function userRecordAddress(owner: Address): Promise<UserRecordAddress> {
  try {
    const ownerBytes = decodeBase58(owner, "owner");
    const [address, bump] = findProgramAddress([RECORD_SEED, ownerBytes], USER_REGISTRY_PROGRAM_ID);
    return Object.freeze({ address, bump });
  } catch {
    throw new TestKitError("TEST_KIT_INVALID_CONFIG", {
      details: { field: "owner", reason: "pdaDerivation" },
    });
  }
}

export function setMergingEnabledInstruction(
  input: Readonly<{
    owner: Address;
    userRecord: Address;
    enabled: boolean;
  }>,
): Instruction {
  decodeBase58(input.owner, "owner");
  decodeBase58(input.userRecord, "userRecord");
  return Object.freeze({
    programAddress: USER_REGISTRY_PROGRAM_ID,
    accounts: Object.freeze([
      Object.freeze({ address: input.userRecord, isSigner: false, isWritable: true }),
      Object.freeze({ address: input.owner, isSigner: true, isWritable: false }),
    ]),
    data: Uint8Array.of(4, input.enabled ? 1 : 0),
  });
}

export async function enableMerging(
  input: Readonly<{
    rpc: Rpc;
    owner: Address;
    signer: TransactionSigner;
    registration?: Transaction;
  }>,
  context?: RequestContext,
): Promise<MergingSetupResult> {
  try {
    contextError(context);
    if (input.signer.address !== input.owner) {
      throw new TestKitError("TEST_KIT_INVALID_CONFIG", {
        details: { field: "signer", reason: "ownerMismatch" },
      });
    }
    const record = await userRecordAddress(input.owner);
    let account = await input.rpc.getAccount(record.address, context);
    if (input.registration !== undefined) {
      await submitAndConfirm(
        input.rpc,
        input.signer,
        input.registration,
        "confirmRegistration",
        context,
      );
      account = await input.rpc.getAccount(record.address, context);
    }
    if (account === undefined) {
      throw new TestKitError("TEST_KIT_INVALID_CONFIG", {
        details: { field: "registration", reason: "missingUserRecord" },
      });
    }
    if (mergingEnabled(account, input.owner, record)) {
      return Object.freeze({ changed: false, userRecord: record.address });
    }
    const signature = await submitSetMergingEnabled(
      {
        rpc: input.rpc,
        signer: input.signer,
        userRecord: record.address,
        enabled: true,
      },
      context,
    );
    return Object.freeze({ changed: true, signature, userRecord: record.address });
  } catch (cause) {
    throw typedRpcError(cause);
  }
}

export async function submitSetMergingEnabled(
  input: Readonly<{
    rpc: Rpc;
    signer: TransactionSigner;
    userRecord: Address;
    enabled: boolean;
  }>,
  context?: RequestContext,
): Promise<Signature> {
  try {
    contextError(context);
    const latest = await input.rpc.getLatestBlockhash(context);
    const transaction = compileTransaction({
      feePayer: input.signer.address,
      recentBlockhash: latest.blockhash,
      instructions: [
        setMergingEnabledInstruction({
          owner: input.signer.address,
          userRecord: input.userRecord,
          enabled: input.enabled,
        }),
      ],
    });
    return await submitAndConfirm(input.rpc, input.signer, transaction, "confirmMerging", context);
  } catch (cause) {
    throw typedRpcError(cause);
  }
}

async function submitAndConfirm(
  rpc: Rpc,
  signer: TransactionSigner,
  transaction: Transaction,
  stage: string,
  context?: RequestContext,
): Promise<Signature> {
  const signed = await signer.signNativeTransaction(transaction);
  if (signed.signatures.length !== transaction.signatures.length) {
    throw new TestKitError("TEST_KIT_INVALID_CONFIG", {
      details: { field: "signer", reason: "signatureCount" },
    });
  }
  const signature = await rpc.sendTransaction(signed, context);
  const timeoutMs = context?.timeoutMs ?? 10_000;
  const deadline = Date.now() + timeoutMs;
  while (!(await rpc.confirmTransaction(signature, context))) {
    contextError(context);
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      throw new TestKitError("TEST_KIT_TIMEOUT", {
        details: { stage, timeoutMs },
      });
    }
    await delay(Math.min(100, remaining), context?.signal);
  }
  return signature;
}

function mergingEnabled(
  account: Readonly<{ owner: Address; data: Uint8Array }>,
  owner: Address,
  record: UserRecordAddress,
): boolean {
  if (account.owner !== USER_REGISTRY_PROGRAM_ID) {
    throw new TestKitError("TEST_KIT_INVALID_CONFIG", {
      details: { field: "userRecord", reason: "programOwner" },
    });
  }
  const reader = new Reader(account.data);
  if (reader.u8() !== 1) invalidRecord("discriminator");
  if (!equalBytes(reader.bytes(32), decodeBase58(owner, "owner"))) invalidRecord("owner");
  if (reader.u8() !== record.bump) invalidRecord("bump");
  reader.option(33);
  reader.bytes(32);
  reader.bytes(33);
  reader.option(32);
  reader.bytes(reader.u32() * 106);
  const enabled = reader.u8();
  if (enabled > 1) invalidRecord("mergingEnabled");
  return enabled === 1;
}

function invalidRecord(reason: string): never {
  throw new TestKitError("TEST_KIT_INVALID_CONFIG", {
    details: { field: "userRecord", reason },
  });
}

class Reader {
  readonly #data: Uint8Array;
  #offset = 0;

  constructor(data: Uint8Array) {
    this.#data = data;
  }

  bytes(length: number): Uint8Array {
    const end = this.#offset + length;
    if (!Number.isSafeInteger(length) || length < 0 || end > this.#data.length) {
      invalidRecord("data");
    }
    const value = this.#data.slice(this.#offset, end);
    this.#offset = end;
    return value;
  }

  u8(): number {
    return this.bytes(1)[0] ?? 0;
  }

  u32(): number {
    const bytes = this.bytes(4);
    return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(0, true);
  }

  option(length: number): Uint8Array | undefined {
    const variant = this.u8();
    if (variant === 0) return undefined;
    if (variant !== 1) invalidRecord("option");
    return this.bytes(length);
  }
}

function contextError(context?: RequestContext): void {
  if (context?.signal?.aborted) throw new TestKitError("TEST_KIT_ABORTED");
  if (context?.timeoutMs !== undefined && context.timeoutMs <= 0) {
    throw new TestKitError("TEST_KIT_TIMEOUT", {
      details: { timeoutMs: context.timeoutMs },
    });
  }
}

function delay(milliseconds: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const aborted = (): void => {
      clearTimeout(timeout);
      reject(new TestKitError("TEST_KIT_ABORTED"));
    };
    const timeout = setTimeout(() => {
      signal?.removeEventListener("abort", aborted);
      resolve();
    }, milliseconds);
    signal?.addEventListener("abort", aborted, { once: true });
  });
}

function typedRpcError(cause: unknown): TestKitError {
  if (cause instanceof TestKitError) return cause;
  const code =
    typeof cause === "object" && cause !== null && "code" in cause ? String(cause.code) : "";
  if (code.includes("ABORT")) return new TestKitError("TEST_KIT_ABORTED", { cause });
  if (code.includes("TIMEOUT")) return new TestKitError("TEST_KIT_TIMEOUT", { cause });
  return new TestKitError("TEST_KIT_RPC", { cause });
}

function compileTransaction(
  input: Readonly<{
    feePayer: Address;
    recentBlockhash: string;
    instructions: readonly Instruction[];
  }>,
): Transaction {
  const accounts = new Map<
    Address,
    { address: Address; isSigner: boolean; isWritable: boolean; order: number }
  >();
  let order = 0;
  accounts.set(input.feePayer, {
    address: input.feePayer,
    isSigner: true,
    isWritable: true,
    order: order++,
  });
  for (const instruction of input.instructions) {
    for (const meta of instruction.accounts) {
      const existing = accounts.get(meta.address);
      accounts.set(meta.address, {
        address: meta.address,
        isSigner: (existing?.isSigner ?? false) || meta.isSigner,
        isWritable: (existing?.isWritable ?? false) || meta.isWritable,
        order: existing?.order ?? order++,
      });
    }
    if (!accounts.has(instruction.programAddress)) {
      accounts.set(instruction.programAddress, {
        address: instruction.programAddress,
        isSigner: false,
        isWritable: false,
        order: order++,
      });
    }
  }
  const ordered = [...accounts.values()].sort((left, right) => {
    if (left.address === input.feePayer) return -1;
    if (right.address === input.feePayer) return 1;
    if (left.isSigner !== right.isSigner) return left.isSigner ? -1 : 1;
    if (left.isWritable !== right.isWritable) return left.isWritable ? -1 : 1;
    const leftBytes = decodeBase58(left.address, "account");
    const rightBytes = decodeBase58(right.address, "account");
    for (let index = 0; index < leftBytes.length; index++) {
      if (leftBytes[index] !== rightBytes[index]) {
        return (leftBytes[index] ?? 0) - (rightBytes[index] ?? 0);
      }
    }
    return left.order - right.order;
  });
  const indexes = new Map(ordered.map((account, index) => [account.address, index]));
  const requiredSignatures = ordered.filter((account) => account.isSigner).length;
  const readonlySigners = ordered.filter(
    (account) => account.isSigner && !account.isWritable,
  ).length;
  const readonlyUnsigned = ordered.filter(
    (account) => !account.isSigner && !account.isWritable,
  ).length;
  const parts: Uint8Array[] = [
    Uint8Array.of(requiredSignatures, readonlySigners, readonlyUnsigned),
    compactU16(ordered.length),
    ...ordered.map((account) => decodeBase58(account.address, "account")),
    decodeBase58(input.recentBlockhash, "recentBlockhash"),
    compactU16(input.instructions.length),
  ];
  for (const instruction of input.instructions) {
    const programIndex = indexes.get(instruction.programAddress);
    const accountIndexes = instruction.accounts.map((account) => indexes.get(account.address));
    if (programIndex === undefined || accountIndexes.some((index) => index === undefined)) {
      throw new TestKitError("TEST_KIT_INVALID_CONFIG", {
        details: { field: "instruction", reason: "missingAccount" },
      });
    }
    parts.push(
      Uint8Array.of(programIndex),
      compactU16(accountIndexes.length),
      Uint8Array.from(accountIndexes as number[]),
      compactU16(instruction.data.length),
      instruction.data,
    );
  }
  return checkedTransactionSize(
    Object.freeze({
      messageBytes: concat(...parts),
      signatures: Object.freeze(
        Array.from({ length: requiredSignatures }, (): Signature | undefined => undefined),
      ),
    }),
  );
}

function compactU16(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff) {
    throw new TestKitError("TEST_KIT_INVALID_CONFIG", {
      details: { field: "transactionLength" },
    });
  }
  const bytes: number[] = [];
  let remaining = value;
  do {
    let byte = remaining & 0x7f;
    remaining >>>= 7;
    if (remaining !== 0) byte |= 0x80;
    bytes.push(byte);
  } while (remaining !== 0);
  return Uint8Array.from(bytes);
}

function decodeBase58(value: string, field: string): Uint8Array {
  if (typeof value !== "string" || value.length === 0) {
    throw new TestKitError("TEST_KIT_INVALID_CONFIG", { details: { field } });
  }
  let decoded = 0n;
  for (const character of value) {
    const digit = BASE58.indexOf(character);
    if (digit < 0) {
      throw new TestKitError("TEST_KIT_INVALID_CONFIG", { details: { field } });
    }
    decoded = decoded * 58n + BigInt(digit);
  }
  const bytes: number[] = [];
  while (decoded > 0n) {
    bytes.push(Number(decoded & 255n));
    decoded >>= 8n;
  }
  let zeros = 0;
  while (zeros < value.length && value[zeros] === "1") zeros++;
  const result = Uint8Array.from([...new Array<number>(zeros).fill(0), ...bytes.reverse()]);
  if (result.length !== 32) {
    throw new TestKitError("TEST_KIT_INVALID_CONFIG", {
      details: { field, expected: 32, actual: result.length },
    });
  }
  return result;
}

function encodeBase58(value: Uint8Array): string {
  let encoded = 0n;
  for (const byte of value) encoded = encoded * 256n + BigInt(byte);
  let result = "";
  while (encoded > 0n) {
    result = (BASE58[Number(encoded % 58n)] ?? "") + result;
    encoded /= 58n;
  }
  let zeros = 0;
  while (zeros < value.length && value[zeros] === 0) zeros++;
  return "1".repeat(zeros) + result;
}

function concat(...parts: readonly Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}

