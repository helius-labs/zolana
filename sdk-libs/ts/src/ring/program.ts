import { getCreateAccountInstruction } from "@solana-program/system";
import {
  address,
  createTransactionMessage,
  createTransactionPlanExecutor,
  createTransactionPlanner,
  generateKeyPairSigner,
  getFirstFailedSingleTransactionPlanResult,
  isSuccessfulTransactionPlanResult,
  getMessagePackerInstructionPlanFromInstructions,
  getSignatureFromTransaction,
  isSolanaError,
  nonDivisibleSequentialInstructionPlan,
  parallelInstructionPlan,
  passthroughFailedTransactionPlanExecution,
  sendTransactionWithoutConfirmingFactory,
  SOLANA_ERROR__JSON_RPC__SERVER_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE,
  setTransactionMessageConfig,
  setTransactionMessageFeePayerSigner,
  setTransactionMessageLifetimeUsingBlockhash,
  signTransactionMessageWithSigners,
  singleInstructionPlan,
  type Instruction,
  type Signature,
  type TransactionMessage,
  type TransactionMessageWithFeePayer,
  type TransactionPlan,
  type TransactionSigner,
} from "@solana/kit";

import { ClientError } from "../client/error.js";
import { runKitRpc } from "../client/kit.js";
import { createIndexerPollConfig, pollUntil } from "../client/retry.js";
import type {
  BlockhashProvider,
  ChainReader,
  KitRpcAccess,
  TransactionConfirmer,
} from "../client/ports.js";
import { LOADED_ACCOUNTS_DATA_SIZE_LIMIT } from "../flows/compile.js";
import { SYSTEM_PROGRAM, meta, type SignerAccount } from "../interface/instructions/index.js";
import { Reader, Writer, addressBytes, encodeBase58, sha256 } from "../interface/internal.js";
import type { Address, Bytes32, RequestContext } from "../interface/types.js";
import { equalBytes } from "../wallet/internal.js";

import { BPF_LOADER_UPGRADEABLE_ID, ringProgramDataAddress } from "./config.js";
import { RingError, wrapRingError } from "./error.js";

export const RENT_SYSVAR = address("SysvarRent111111111111111111111111111111111");
export const CLOCK_SYSVAR = address("SysvarC1ock11111111111111111111111111111111");

/** Rust `UpgradeableLoaderState::size_of_*`. */
const BUFFER_METADATA_SIZE = 37;
const PROGRAM_DATA_METADATA_SIZE = 45;
const PROGRAM_SIZE = 36;
const BUFFER_STATE = 1;
const PROGRAM_STATE = 2;
const PROGRAM_DATA_STATE = 3;
const ELF_MAGIC = Uint8Array.of(0x7f, 0x45, 0x4c, 0x46);
const ELF_HEADER_SIZE = 64;
/** Rust `MINIMUM_EXTEND_PROGRAM_BYTES`. */
const MIN_EXTEND_BYTES = 10_240;
/** Rust `DEPLOY_FEE_BUDGET`. */
const DEPLOY_FEE_BUDGET = 20_000_000n;
/** What the runtime allows one transaction; a deploy step verifies a whole ELF. */
const DEPLOY_COMPUTE_UNIT_LIMIT = 1_400_000;
/** Agave's loader v3 limited_deserialize cap applies to each instruction, even in v1. */
const LOADER_INSTRUCTION_DATA_LIMIT = 1_232;
/** Bincode tag (u32), offset (u32), and byte-vector length (u64). */
const WRITE_HEADER_SIZE = 16;
const MAX_WRITE_BYTES = LOADER_INSTRUCTION_DATA_LIMIT - WRITE_HEADER_SIZE;

/** Rust `UpgradeableLoaderInstruction`. */
const LoaderTag = Object.freeze({
  initializeBuffer: 0,
  write: 1,
  deployWithMaxDataLen: 2,
  upgrade: 3,
  setAuthority: 4,
  close: 5,
  extendProgram: 6,
} as const);

/** A structural copy is not a checked binary. */
export class RingProgramBinary {
  readonly #bytes: Uint8Array;
  readonly sha256: Bytes32;

  private constructor(bytes: Uint8Array) {
    this.#bytes = bytes;
    this.sha256 = sha256(bytes) as Bytes32;
  }

  static parse(bytes: Uint8Array): RingProgramBinary {
    if (bytes.length < ELF_HEADER_SIZE || !equalBytes(bytes.subarray(0, 4), ELF_MAGIC)) {
      throw new RingError("RING_PROGRAM_BINARY_INVALID", { details: { length: bytes.length } });
    }
    return new RingProgramBinary(new Uint8Array(bytes));
  }

  get bytes(): Uint8Array {
    return this.#bytes;
  }
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

/** Undefined when nothing lives at the address, a foreign owner is refused. */
export async function fetchRingProgramData(
  client: Pick<ChainReader, "getAccount">,
  ringProgramId: Address,
  context?: RequestContext,
): Promise<RingProgramData | undefined> {
  const program = await client.getAccount(ringProgramId, context);
  if (program === undefined) return undefined;
  if (program.owner !== BPF_LOADER_UPGRADEABLE_ID) {
    throw new RingError("RING_PROGRAM_ADDRESS_OCCUPIED", {
      details: { ringProgramId, owner: program.owner },
    });
  }
  const programData = await ringProgramDataAddress(ringProgramId);
  const expected = new Writer()
    .u32(PROGRAM_STATE, "state")
    .bytes(addressBytes(programData), 32, "programData")
    .finish();
  if (!equalBytes(program.data, expected)) throw programDataInvalid();
  const account = await client.getAccount(programData, context);
  if (account === undefined || account.owner !== BPF_LOADER_UPGRADEABLE_ID) {
    throw programDataInvalid();
  }
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
  if (input.bytes.length > MAX_WRITE_BYTES) {
    throw new RingError("RING_PROGRAM_WRITE_TOO_LARGE", {
      details: { length: input.bytes.length, limit: MAX_WRITE_BYTES },
    });
  }
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
  input: Readonly<{
    ringProgramId: Address;
    payer: SignerAccount;
    additionalBytes: number;
  }>,
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

/** Reclaims the rent of a buffer a failed deploy left behind. */
export function closeBufferInstruction(
  input: Readonly<{ buffer: Address; recipient: Address; authority: SignerAccount }>,
): Instruction {
  return {
    programAddress: BPF_LOADER_UPGRADEABLE_ID,
    accounts: [
      meta(input.buffer, false, true),
      meta(input.recipient, false, true),
      meta(input.authority, true, false),
    ],
    data: new Writer().u32(LoaderTag.close, "tag").finish(),
  };
}

export type RingProgramDeployClient = BlockhashProvider &
  KitRpcAccess &
  Pick<TransactionConfirmer, "confirmTransaction"> &
  Pick<ChainReader, "getAccount" | "getBalance">;

export interface RingProgramDeployParams {
  readonly client: RingProgramDeployClient;
  readonly ringProgramId: Address;
  readonly binary: RingProgramBinary;
  readonly payer: TransactionSigner;
  readonly authority: TransactionSigner;
  /** Signs the first deploy only. */
  readonly program?: TransactionSigner;
  /** Pass the same keypair again to resume an interrupted upload. */
  readonly buffer?: TransactionSigner;
  /** Writes in flight at once. */
  readonly concurrency?: number;
  /** Sends of one transaction, each under a fresh blockhash. */
  readonly attempts?: number;
  readonly priorityFeeLamports?: bigint;
}

export interface RingProgramDeployOutcome {
  readonly kind: "present" | "deployed" | "upgraded";
  readonly programData: RingProgramData;
}

const DEFAULT_CONCURRENCY = 8;
const DEFAULT_ATTEMPTS = 5;
const USABLE_POLL = createIndexerPollConfig(150, 400n, 400n);

/** Mirrors the ring CLI `deploy`, returns once the program is usable. */
export async function deployRingProgram(
  params: RingProgramDeployParams,
  context?: RequestContext,
): Promise<RingProgramDeployOutcome> {
  let buffer: Address | undefined;
  try {
    const options = deployOptions(params);
    const existing = await fetchRingProgramData(params.client, params.ringProgramId, context);
    const present = deployPlan(params, existing);
    if (present !== undefined) return Object.freeze({ kind: "present", programData: present });
    const bufferSigner = params.buffer ?? (await generateKeyPairSigner());
    const length = params.binary.bytes.length;
    const bufferRent = await rent(params, BUFFER_METADATA_SIZE + length, context);
    const upload = await bufferState(params, bufferSigner.address, context);
    const programRent = existing === undefined ? await rent(params, PROGRAM_SIZE, context) : 0n;
    await checkFunding(params, { existing, upload, bufferRent, programRent }, context);
    const send = transactionSender(params, options, context);
    const planner = createTransactionPlanner({
      createTransactionMessage: () => baseMessage(params),
    });
    const plan = (input: Parameters<typeof planner>[0]) => planner(input, abortOption(context));
    buffer = bufferSigner.address;
    if (upload === "missing") {
      await send(
        await plan(
          nonDivisibleSequentialInstructionPlan([
            getCreateAccountInstruction({
              payer: params.payer,
              newAccount: bufferSigner,
              lamports: bufferRent,
              space: BigInt(BUFFER_METADATA_SIZE + length),
              programAddress: BPF_LOADER_UPGRADEABLE_ID,
            }),
            initializeBufferInstruction({
              buffer: bufferSigner.address,
              authority: params.authority.address,
            }),
          ]),
        ),
        async () => (await bufferState(params, bufferSigner.address, context)) === "resumed",
      );
    }
    await send(
      await plan(
        parallelInstructionPlan([
          getMessagePackerInstructionPlanFromInstructions(
            Array.from({ length: Math.ceil(length / MAX_WRITE_BYTES) }, (_, index) => {
              const offset = index * MAX_WRITE_BYTES;
              return writeBufferInstruction({
                buffer: bufferSigner.address,
                authority: params.authority,
                offset,
                bytes: params.binary.bytes.subarray(offset, offset + MAX_WRITE_BYTES),
              });
            }),
          ),
        ]),
      ),
    );
    await checkBufferContent(params, bufferSigner.address, context);
    const deployed = async () => {
      const data = await fetchRingProgramData(params.client, params.ringProgramId, context);
      return data !== undefined && holdsBinary(data, params.binary);
    };
    if (existing === undefined) {
      await send(
        await plan(
          nonDivisibleSequentialInstructionPlan([
            getCreateAccountInstruction({
              payer: params.payer,
              newAccount: programSigner(params),
              lamports: programRent,
              space: BigInt(PROGRAM_SIZE),
              programAddress: BPF_LOADER_UPGRADEABLE_ID,
            }),
            await deployWithMaxDataLenInstruction({
              payer: params.payer,
              ringProgramId: params.ringProgramId,
              buffer: bufferSigner.address,
              authority: params.authority,
              maxDataLen: length,
            }),
          ]),
        ),
        deployed,
      );
    } else {
      const current = await currentProgramData(params, context);
      if (length > current.capacity) {
        const target = current.capacity + growth(current, length);
        await send(
          await plan(
            singleInstructionPlan(
              await extendProgramInstruction({
                ringProgramId: params.ringProgramId,
                payer: params.payer,
                additionalBytes: target - current.capacity,
              }),
            ),
          ),
          async () => (await currentProgramData(params, context)).capacity >= target,
        );
        // The loader stamps the extend slot and refuses an upgrade in it.
        const extended = await currentProgramData(params, context);
        await waitUntilUsable(params, extended.lastDeploySlot, context);
      }
      await send(
        await plan(
          singleInstructionPlan(
            await upgradeInstruction({
              ringProgramId: params.ringProgramId,
              buffer: bufferSigner.address,
              spill: params.payer.address,
              authority: params.authority,
            }),
          ),
        ),
        deployed,
      );
    }
    const programData = await verifyRingProgram(
      params.client,
      params.ringProgramId,
      params.binary,
      context,
    );
    await waitUntilUsable(params, programData.lastDeploySlot, context);
    return Object.freeze({ kind: existing === undefined ? "deployed" : "upgraded", programData });
  } catch (cause) {
    throw wrapRingError(
      "RING_DEPLOY_PROGRAM",
      cause,
      buffer === undefined ? undefined : { buffer },
    );
  }
}

type DeployOptions = Readonly<{ concurrency: number; attempts: number }>;

function deployOptions(params: RingProgramDeployParams): DeployOptions {
  const options = {
    concurrency: params.concurrency ?? DEFAULT_CONCURRENCY,
    attempts: params.attempts ?? DEFAULT_ATTEMPTS,
  };
  if (Object.values(options).some((value) => !Number.isSafeInteger(value) || value < 1)) {
    throw new RingError("RING_DEPLOY_OPTIONS_INVALID", { details: options });
  }
  return options;
}

/** Mirrors Rust `Deploy::plan`, the program data when the binary is already on chain. */
function deployPlan(
  params: RingProgramDeployParams,
  existing: RingProgramData | undefined,
): RingProgramData | undefined {
  if (existing === undefined) {
    programSigner(params);
    return undefined;
  }
  if (existing.upgradeAuthority === undefined) {
    throw new RingError("RING_PROGRAM_IMMUTABLE", {
      details: { ringProgramId: params.ringProgramId },
    });
  }
  if (existing.upgradeAuthority !== params.authority.address) {
    throw new RingError("RING_PROGRAM_AUTHORITY_MISMATCH", {
      details: { ringProgramId: params.ringProgramId, authority: existing.upgradeAuthority },
    });
  }
  return holdsBinary(existing, params.binary) ? existing : undefined;
}

function holdsBinary(data: RingProgramData, binary: RingProgramBinary): boolean {
  const deployed = data.deployedHash(binary.bytes.length);
  return deployed !== undefined && equalBytes(deployed, binary.sha256);
}

function programSigner(params: RingProgramDeployParams): TransactionSigner {
  if (params.program === undefined || params.program.address !== params.ringProgramId) {
    throw new RingError("RING_PROGRAM_KEYPAIR_INVALID", {
      details: { ringProgramId: params.ringProgramId },
    });
  }
  return params.program;
}

async function currentProgramData(
  params: RingProgramDeployParams,
  context: RequestContext | undefined,
): Promise<RingProgramData> {
  const data = await fetchRingProgramData(params.client, params.ringProgramId, context);
  if (data === undefined) {
    throw new RingError("RING_PROGRAM_NOT_DEPLOYED", {
      details: { ringProgramId: params.ringProgramId },
    });
  }
  return data;
}

type BufferState = "missing" | "resumed";

async function bufferState(
  params: RingProgramDeployParams,
  buffer: Address,
  context: RequestContext | undefined,
): Promise<BufferState> {
  const size = BUFFER_METADATA_SIZE + params.binary.bytes.length;
  const account = await params.client.getAccount(buffer, context);
  if (account === undefined) return "missing";
  const reader = new Reader(
    account.data.subarray(0, Math.min(account.data.length, BUFFER_METADATA_SIZE)),
  );
  const usable =
    account.owner === BPF_LOADER_UPGRADEABLE_ID &&
    account.data.length === size &&
    reader.u32("state") === BUFFER_STATE &&
    reader.u8("authority") === 1 &&
    encodeBase58(reader.bytes(32, "authority")) === params.authority.address;
  if (!usable) throw new RingError("RING_PROGRAM_BUFFER_INVALID", { details: { buffer } });
  return "resumed";
}

/** The deploy drains the buffer into the payer before the program data rent is paid. */
async function checkFunding(
  params: RingProgramDeployParams,
  input: Readonly<{
    existing: RingProgramData | undefined;
    upload: BufferState;
    bufferRent: bigint;
    programRent: bigint;
  }>,
  context: RequestContext | undefined,
): Promise<void> {
  const { existing } = input;
  const length = params.binary.bytes.length;
  let required = DEPLOY_FEE_BUDGET + (input.upload === "missing" ? input.bufferRent : 0n);
  if (existing === undefined) {
    const programDataRent = await rent(params, PROGRAM_DATA_METADATA_SIZE + length, context);
    required += input.programRent + programDataRent - input.bufferRent;
  } else if (length > existing.capacity) {
    const before = await rent(params, PROGRAM_DATA_METADATA_SIZE + existing.capacity, context);
    const after = await rent(
      params,
      PROGRAM_DATA_METADATA_SIZE + existing.capacity + growth(existing, length),
      context,
    );
    required += after > before ? after - before : 0n;
  }
  const balance = await params.client.getBalance(params.payer.address, context);
  if (balance < required) {
    throw new RingError("RING_PROGRAM_UNDERFUNDED", {
      details: { payer: params.payer.address, required, balance },
    });
  }
}

function growth(existing: RingProgramData, length: number): number {
  return Math.max(length - existing.capacity, MIN_EXTEND_BYTES);
}

function rent(
  params: RingProgramDeployParams,
  space: number,
  context: RequestContext | undefined,
): Promise<bigint> {
  return runKitRpc("getMinimumBalanceForRentExemption", context, (abortSignal) =>
    params.client.solanaRpc.getMinimumBalanceForRentExemption(BigInt(space)).send({ abortSignal }),
  );
}

/**
 * A version 1 transaction budgets zero compute units when it names none, and a
 * deploy step never exceeds what the runtime allows one transaction, so the
 * ceiling is asked for outright. It costs nothing extra: the priority fee is a
 * flat amount, not a price per unit.
 */
function baseMessage(
  params: RingProgramDeployParams,
): TransactionMessage & TransactionMessageWithFeePayer {
  return setTransactionMessageConfig(
    {
      computeUnitLimit: DEPLOY_COMPUTE_UNIT_LIMIT,
      loadedAccountsDataSizeLimit: LOADED_ACCOUNTS_DATA_SIZE_LIMIT,
      ...(params.priorityFeeLamports === undefined
        ? {}
        : { priorityFeeLamports: params.priorityFeeLamports }),
    },
    setTransactionMessageFeePayerSigner(params.payer, createTransactionMessage({ version: 1 })),
  );
}

/** Reads whether the step is on chain, checked before a failed attempt is repeated. */
type Settled = () => Promise<boolean>;

/** A fresh blockhash per attempt, an earlier attempt that landed late still counts. */
function transactionSender(
  params: RingProgramDeployParams,
  options: DeployOptions,
  context: RequestContext | undefined,
): (plan: TransactionPlan, settled?: Settled) => Promise<void> {
  const gate = semaphore(options.concurrency);
  const sendTransaction = sendTransactionWithoutConfirmingFactory({ rpc: params.client.solanaRpc });
  return async (plan, settled) => {
    let failed: unknown;
    const executor = createTransactionPlanExecutor({
      executeTransactionMessage: async (_result, message, config) =>
        gate(async () => {
          const signatures: Signature[] = [];
          let lastError: unknown;
          for (let attempt = 0; attempt < options.attempts; attempt += 1) {
            if (failed !== undefined) throw failed;
            config?.abortSignal?.throwIfAborted();
            try {
              const lifetime = await params.client.getLatestBlockhash(context);
              const signed = await signTransactionMessageWithSigners(
                setTransactionMessageLifetimeUsingBlockhash(lifetime, message),
              );
              const signature = getSignatureFromTransaction(signed);
              signatures.push(signature);
              await runKitRpc("sendTransaction", context, async (abortSignal) => {
                try {
                  await sendTransaction(signed, {
                    commitment: params.client.commitment,
                    abortSignal,
                  });
                } catch (cause) {
                  throw refusedInPreflight(cause);
                }
              });
              await params.client.confirmTransaction(signature, undefined, context);
              return { signature };
            } catch (error) {
              const landed = await landedSignature(params, signatures, context);
              if (landed !== undefined) return { signature: landed };
              const last = signatures.at(-1);
              if (last !== undefined && settled !== undefined && (await settled())) {
                return { signature: last };
              }
              lastError = error;
              if (!retryable(error)) break;
            }
          }
          failed = lastError;
          throw lastError;
        }),
    });
    const result = await passthroughFailedTransactionPlanExecution(
      executor(plan, abortOption(context)),
    );
    if (!isSuccessfulTransactionPlanResult(result)) {
      throw getFirstFailedSingleTransactionPlanResult(result).error;
    }
  };
}

/** Left alone, `runKitRpc` folds the refusal into a retryable `CLIENT_RPC`. */
function refusedInPreflight(cause: unknown): unknown {
  return isSolanaError(
    cause,
    SOLANA_ERROR__JSON_RPC__SERVER_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE,
  )
    ? new ClientError("CLIENT_RPC", {
        details: { method: "sendTransaction", reason: "transaction failed" },
        cause,
      })
    : cause;
}

/** A transaction refused on chain or in preflight fails the same way again. */
function retryable(error: unknown): boolean {
  if (error instanceof ClientError) {
    if (error.code === "CLIENT_ABORTED") return false;
    return error.details?.["reason"] !== "transaction failed";
  }
  return !isSolanaError(
    error,
    SOLANA_ERROR__JSON_RPC__SERVER_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE,
  );
}

async function landedSignature(
  params: RingProgramDeployParams,
  signatures: readonly Signature[],
  context: RequestContext | undefined,
): Promise<Signature | undefined> {
  if (signatures.length === 0) return undefined;
  const { value } = await runKitRpc("getSignatureStatuses", context, (abortSignal) =>
    params.client.solanaRpc
      .getSignatureStatuses(signatures, { searchTransactionHistory: true })
      .send({ abortSignal }),
  );
  const index = value.findIndex(
    (status) =>
      status !== null &&
      status.err === null &&
      (status.confirmationStatus === "confirmed" || status.confirmationStatus === "finalized"),
  );
  return index < 0 ? undefined : signatures[index];
}

function abortOption(context: RequestContext | undefined): Readonly<{ abortSignal?: AbortSignal }> {
  return context?.signal === undefined ? {} : { abortSignal: context.signal };
}

function semaphore(limit: number): <T>(task: () => Promise<T>) => Promise<T> {
  let active = 0;
  const waiting: (() => void)[] = [];
  return async (task) => {
    if (active >= limit) {
      await new Promise<void>((resolve) => waiting.push(resolve));
    } else {
      active += 1;
    }
    try {
      return await task();
    } finally {
      const next = waiting.shift();
      if (next === undefined) active -= 1;
      else next();
    }
  };
}

/** The bytes on chain must hash to the binary before the loader reads them. */
async function checkBufferContent(
  params: RingProgramDeployParams,
  buffer: Address,
  context: RequestContext | undefined,
): Promise<void> {
  const account = await params.client.getAccount(buffer, context);
  const content = account?.data.subarray(BUFFER_METADATA_SIZE);
  if (content === undefined || !equalBytes(sha256(content), params.binary.sha256)) {
    throw new RingError("RING_PROGRAM_BUFFER_INVALID", { details: { buffer } });
  }
}

/** Mirrors Rust `wait_until_usable`, the loader refuses a program in its deploy slot. */
async function waitUntilUsable(
  params: RingProgramDeployParams,
  deploySlot: bigint,
  context: RequestContext | undefined,
): Promise<void> {
  const stalled = new ClientError("CLIENT_RPC", {
    details: { method: "getSlot", reason: "program not usable" },
  });
  try {
    await pollUntil(
      () =>
        runKitRpc("getSlot", context, (abortSignal) =>
          params.client.solanaRpc
            .getSlot({ commitment: params.client.commitment })
            .send({ abortSignal }),
        ),
      (slot) => slot > deploySlot,
      {
        config: USABLE_POLL,
        ...(context === undefined ? {} : { context }),
        onTimeout: () => stalled,
      },
    );
  } catch (cause) {
    if (cause !== stalled) throw cause;
    throw new RingError("RING_PROGRAM_NOT_USABLE", {
      details: { ringProgramId: params.ringProgramId, slot: deploySlot },
    });
  }
}

function programDataInvalid(): RingError {
  return new RingError("RING_PROGRAM_DATA_INVALID");
}
