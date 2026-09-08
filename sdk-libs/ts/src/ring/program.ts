import { getCreateAccountInstruction } from "@solana-program/system";
import { address, createNoopSigner, type Instruction } from "@solana/kit";

import type { BlockhashProvider, ChainReader, KitRpcAccess } from "../client/ports.js";
import { compileUnsignedTransaction } from "../flows/compile.js";
import { SYSTEM_PROGRAM, meta, type SignerAccount } from "../interface/instructions/index.js";
import { Reader, Writer, encodeBase58, sha256 } from "../interface/internal.js";
import { TRANSACTION_SIZE_LIMIT, transactionSize } from "../interface/transaction-size.js";
import type { Address, Bytes32, RequestContext, Transaction } from "../interface/types.js";
import { runKitRpc } from "../client/kit.js";
import { equalBytes } from "../wallet/internal.js";

import { BPF_LOADER_UPGRADEABLE_ID, ringProgramDataAddress } from "./config.js";
import { RingError, wrapRingError } from "./error.js";

export const RENT_SYSVAR = address("SysvarRent111111111111111111111111111111111");
export const CLOCK_SYSVAR = address("SysvarC1ock11111111111111111111111111111111");

/** Rust `UpgradeableLoaderState::size_of_*`. */
const BUFFER_METADATA_SIZE = 37;
const PROGRAM_DATA_METADATA_SIZE = 45;
const PROGRAM_SIZE = 36;
const PROGRAM_DATA_STATE = 3;
/** Rust `MINIMUM_EXTEND_PROGRAM_BYTES`. */
const MIN_EXTEND_BYTES = 10_240;
/** Rust `DEPLOY_FEE_BUDGET`. */
const DEPLOY_FEE_BUDGET = 20_000_000n;

/** Rust `UpgradeableLoaderInstruction`. */
const LoaderTag = Object.freeze({
  initializeBuffer: 0,
  write: 1,
  deployWithMaxDataLen: 2,
  upgrade: 3,
  setAuthority: 4,
  extendProgram: 6,
} as const);

export interface RingProgramBinary {
  readonly bytes: Uint8Array;
  readonly sha256: Bytes32;
}

export function ringProgramBinary(bytes: Uint8Array): RingProgramBinary {
  return Object.freeze({ bytes: new Uint8Array(bytes), sha256: sha256(bytes) as Bytes32 });
}

/** Mirrors Rust `ProgramDataInfo`. */
export interface RingProgramData {
  readonly lastDeploySlot: bigint;
  /** Absent once the program is immutable. */
  readonly upgradeAuthority: Address | undefined;
  readonly capacity: number;
  /** The hash of the first `length` deployed bytes, absent when the account holds fewer. */
  deployedHash(length: number): Bytes32 | undefined;
}

/** Mirrors Rust `read_program_data` over the `ProgramData` account bytes. */
export function decodeRingProgramData(data: Uint8Array): RingProgramData {
  if (data.length < PROGRAM_DATA_METADATA_SIZE) throw programDataInvalid();
  const reader = new Reader(data.subarray(0, PROGRAM_DATA_METADATA_SIZE));
  if (reader.u32("state") !== PROGRAM_DATA_STATE) throw programDataInvalid();
  const lastDeploySlot = reader.u64("slot");
  const hasAuthority = reader.u8("upgradeAuthority");
  const authority = reader.bytes(32, "upgradeAuthority");
  reader.done();
  if (hasAuthority > 1) throw programDataInvalid();
  const upgradeAuthority =
    hasAuthority === 1 && !equalBytes(authority, new Uint8Array(32))
      ? encodeBase58(authority)
      : undefined;
  const bytes = data.subarray(PROGRAM_DATA_METADATA_SIZE);
  return Object.freeze({
    lastDeploySlot,
    upgradeAuthority,
    capacity: bytes.length,
    deployedHash: (length: number) =>
      length <= bytes.length ? (sha256(bytes.subarray(0, length)) as Bytes32) : undefined,
  });
}

/** Undefined when the program is not deployed under the upgradeable loader. */
export async function fetchRingProgramData(
  client: Pick<ChainReader, "getAccount">,
  ringProgramId: Address,
  context?: RequestContext,
): Promise<RingProgramData | undefined> {
  const program = await client.getAccount(ringProgramId, context);
  if (program === undefined) return undefined;
  const account = await client.getAccount(await ringProgramDataAddress(ringProgramId), context);
  if (account === undefined) return undefined;
  if (account.owner !== BPF_LOADER_UPGRADEABLE_ID) throw programDataInvalid();
  return decodeRingProgramData(account.data);
}

/** Mirrors Rust `ProgramBinary::verify_deployed`. */
export async function verifyRingProgram(
  client: Pick<ChainReader, "getAccount">,
  ringProgramId: Address,
  binary: RingProgramBinary,
  context?: RequestContext,
): Promise<RingProgramData> {
  const programData = await fetchRingProgramData(client, ringProgramId, context);
  const found = programData?.deployedHash(binary.bytes.length);
  if (programData === undefined || found === undefined) {
    throw new RingError("RING_PROGRAM_NOT_DEPLOYED", { details: { ringProgramId } });
  }
  if (!equalBytes(found, binary.sha256)) {
    throw new RingError("RING_PROGRAM_MISMATCH", { details: { ringProgramId } });
  }
  return programData;
}

export function initializeBufferInstruction(
  input: Readonly<{ buffer: Address; authority: Address }>,
): Instruction {
  return {
    programAddress: BPF_LOADER_UPGRADEABLE_ID,
    accounts: [meta(input.buffer, false, true), meta(input.authority, false, false)],
    data: new Writer().u32(LoaderTag.initializeBuffer, "tag").finish(),
  };
}

export function writeBufferInstruction(
  input: Readonly<{ buffer: Address; authority: SignerAccount; offset: number; bytes: Uint8Array }>,
): Instruction {
  return {
    programAddress: BPF_LOADER_UPGRADEABLE_ID,
    accounts: [meta(input.buffer, false, true), meta(input.authority, true, false)],
    data: new Writer()
      .u32(LoaderTag.write, "tag")
      .u32(input.offset, "offset")
      .u64(BigInt(input.bytes.length), "bytes.length")
      .bytes(input.bytes)
      .finish(),
  };
}

export async function deployWithMaxDataLenInstruction(
  input: Readonly<{
    payer: SignerAccount;
    ringProgramId: Address;
    buffer: Address;
    authority: SignerAccount;
    maxDataLen: number;
  }>,
): Promise<Instruction> {
  return {
    programAddress: BPF_LOADER_UPGRADEABLE_ID,
    accounts: [
      meta(input.payer, true, true),
      meta(await ringProgramDataAddress(input.ringProgramId), false, true),
      meta(input.ringProgramId, false, true),
      meta(input.buffer, false, true),
      meta(RENT_SYSVAR, false, false),
      meta(CLOCK_SYSVAR, false, false),
      meta(SYSTEM_PROGRAM, false, false),
      meta(input.authority, true, false),
    ],
    data: new Writer()
      .u32(LoaderTag.deployWithMaxDataLen, "tag")
      .u64(BigInt(input.maxDataLen), "maxDataLen")
      .finish(),
  };
}

export async function upgradeInstruction(
  input: Readonly<{
    ringProgramId: Address;
    buffer: Address;
    /** Receives the buffer's lamports the program data does not need. */
    spill: Address;
    authority: SignerAccount;
  }>,
): Promise<Instruction> {
  return {
    programAddress: BPF_LOADER_UPGRADEABLE_ID,
    accounts: [
      meta(await ringProgramDataAddress(input.ringProgramId), false, true),
      meta(input.ringProgramId, false, true),
      meta(input.buffer, false, true),
      meta(input.spill, false, true),
      meta(RENT_SYSVAR, false, false),
      meta(CLOCK_SYSVAR, false, false),
      meta(input.authority, true, false),
    ],
    data: new Writer().u32(LoaderTag.upgrade, "tag").finish(),
  };
}

/** Without `newAuthority` the program becomes immutable. */
export async function setUpgradeAuthorityInstruction(
  input: Readonly<{ ringProgramId: Address; authority: SignerAccount; newAuthority?: Address }>,
): Promise<Instruction> {
  return {
    programAddress: BPF_LOADER_UPGRADEABLE_ID,
    accounts: [
      meta(await ringProgramDataAddress(input.ringProgramId), false, true),
      meta(input.authority, true, false),
      ...(input.newAuthority === undefined ? [] : [meta(input.newAuthority, false, false)]),
    ],
    data: new Writer().u32(LoaderTag.setAuthority, "tag").finish(),
  };
}

export async function extendProgramInstruction(
  input: Readonly<{ ringProgramId: Address; payer: SignerAccount; additionalBytes: number }>,
): Promise<Instruction> {
  return {
    programAddress: BPF_LOADER_UPGRADEABLE_ID,
    accounts: [
      meta(await ringProgramDataAddress(input.ringProgramId), false, true),
      meta(input.ringProgramId, false, true),
      meta(SYSTEM_PROGRAM, false, false),
      meta(input.payer, true, true),
    ],
    data: new Writer()
      .u32(LoaderTag.extendProgram, "tag")
      .u32(input.additionalBytes, "additionalBytes")
      .finish(),
  };
}

export type RingProgramDeploymentClient = BlockhashProvider &
  KitRpcAccess &
  Pick<ChainReader, "getAccount">;

export interface RingProgramDeploymentParams {
  readonly client: RingProgramDeploymentClient;
  readonly ringProgramId: Address;
  readonly binary: RingProgramBinary;
  /** The upgrade authority, signs every write and the finish. */
  readonly authority: Address;
  /** Pays and, on an upgrade, receives the spill. */
  readonly payer: Address;
  /** A fresh keypair's address, it signs `prepare`. */
  readonly buffer: Address;
  readonly computeUnitPriceMicroLamports?: bigint;
}

/** Mirrors Rust `DeployPlan`, a first deploy also signs `finish` with the program keypair. */
export type RingProgramDeployment =
  | Readonly<{ kind: "present"; programData: RingProgramData }>
  | Readonly<{
      kind: "deploy" | "upgrade";
      buffer: Address;
      prepare: Transaction;
      /** Independent, send them in parallel before `finish`, all under one blockhash. */
      writes: readonly Transaction[];
      finish: Transaction;
      /** Mirrors Rust `required_balance`, the payer needs this much before `prepare`. */
      requiredLamports: bigint;
    }>;

export async function planRingProgramDeployment(
  params: RingProgramDeploymentParams,
  context?: RequestContext,
): Promise<RingProgramDeployment> {
  try {
    const programData = await fetchRingProgramData(params.client, params.ringProgramId, context);
    if (programData !== undefined) {
      if (programData.upgradeAuthority === undefined) {
        throw new RingError("RING_PROGRAM_IMMUTABLE", {
          details: { ringProgramId: params.ringProgramId },
        });
      }
      if (programData.upgradeAuthority !== params.authority) {
        throw new RingError("RING_PROGRAM_AUTHORITY_MISMATCH", {
          details: { ringProgramId: params.ringProgramId, authority: programData.upgradeAuthority },
        });
      }
      const deployed = programData.deployedHash(params.binary.bytes.length);
      if (deployed !== undefined && equalBytes(deployed, params.binary.sha256)) {
        return Object.freeze({ kind: "present", programData });
      }
    }
    const length = params.binary.bytes.length;
    const rent = (space: number): Promise<bigint> =>
      runKitRpc("getMinimumBalanceForRentExemption", context, (abortSignal) =>
        params.client.solanaRpc
          .getMinimumBalanceForRentExemption(BigInt(space))
          .send({ abortSignal }),
      );
    const [bufferRent, lifetime] = await Promise.all([
      rent(BUFFER_METADATA_SIZE + length),
      params.client.getLatestBlockhash(context),
    ]);
    const payer = createNoopSigner(params.payer);
    const compile = (instructions: readonly Instruction[]): Transaction =>
      compileUnsignedTransaction({
        feePayer: params.payer,
        lifetime,
        instructions,
        ...(params.computeUnitPriceMicroLamports === undefined
          ? {}
          : { computeUnitPriceMicroLamports: params.computeUnitPriceMicroLamports }),
      });
    const prepare = compile([
      getCreateAccountInstruction({
        payer,
        newAccount: createNoopSigner(params.buffer),
        lamports: bufferRent,
        space: BigInt(BUFFER_METADATA_SIZE + length),
        programAddress: BPF_LOADER_UPGRADEABLE_ID,
      }),
      initializeBufferInstruction({ buffer: params.buffer, authority: params.authority }),
    ]);
    const writes = writeTransactions(params, compile);
    let requiredLamports = DEPLOY_FEE_BUDGET + bufferRent;
    let finish: Transaction;
    if (programData === undefined) {
      const [programRent, programDataRent] = await Promise.all([
        rent(PROGRAM_SIZE),
        rent(PROGRAM_DATA_METADATA_SIZE + length),
      ]);
      requiredLamports += programRent + programDataRent;
      finish = compile([
        getCreateAccountInstruction({
          payer,
          newAccount: createNoopSigner(params.ringProgramId),
          lamports: programRent,
          space: BigInt(PROGRAM_SIZE),
          programAddress: BPF_LOADER_UPGRADEABLE_ID,
        }),
        await deployWithMaxDataLenInstruction({
          payer: params.payer,
          ringProgramId: params.ringProgramId,
          buffer: params.buffer,
          authority: params.authority,
          maxDataLen: length,
        }),
      ]);
    } else {
      const instructions: Instruction[] = [];
      if (length > programData.capacity) {
        const grown = Math.max(length - programData.capacity, MIN_EXTEND_BYTES);
        const [before, after] = await Promise.all([
          rent(PROGRAM_DATA_METADATA_SIZE + programData.capacity),
          rent(PROGRAM_DATA_METADATA_SIZE + programData.capacity + grown),
        ]);
        requiredLamports += after > before ? after - before : 0n;
        instructions.push(
          await extendProgramInstruction({
            ringProgramId: params.ringProgramId,
            payer: params.payer,
            additionalBytes: grown,
          }),
        );
      }
      instructions.push(
        await upgradeInstruction({
          ringProgramId: params.ringProgramId,
          buffer: params.buffer,
          spill: params.payer,
          authority: params.authority,
        }),
      );
      finish = compile(instructions);
    }
    return Object.freeze({
      kind: programData === undefined ? "deploy" : "upgrade",
      buffer: params.buffer,
      prepare,
      writes,
      finish,
      requiredLamports,
    });
  } catch (cause) {
    throw wrapRingError("RING_BUILD_PROGRAM", cause);
  }
}

/** Every write fills the packet. */
function writeTransactions(
  params: RingProgramDeploymentParams,
  compile: (instructions: readonly Instruction[]) => Transaction,
): readonly Transaction[] {
  const write = (offset: number, bytes: Uint8Array): Instruction =>
    writeBufferInstruction({
      buffer: params.buffer,
      authority: params.authority,
      offset,
      bytes,
    });
  const envelope = transactionSize(compile([write(0, new Uint8Array())]));
  // The data length prefix grows by one byte past 127 bytes.
  const chunk = TRANSACTION_SIZE_LIMIT - envelope - 1;
  if (chunk <= 0) throw new RingError("RING_BUILD_PROGRAM");
  const transactions: Transaction[] = [];
  for (let offset = 0; offset < params.binary.bytes.length; offset += chunk) {
    transactions.push(
      compile([write(offset, params.binary.bytes.subarray(offset, offset + chunk))]),
    );
  }
  return Object.freeze(transactions);
}

function programDataInvalid(): RingError {
  return new RingError("RING_PROGRAM_DATA_INVALID");
}
