import { getBase58Encoder, isAddress } from "@solana/kit";

import { runKitRpc, type SolanaRpc } from "../client/kit.js";
import { Reader } from "../interface/internal.js";
import {
  InstructionTag,
  SHIELDED_POOL_CPI_AUTHORITY,
  SHIELDED_POOL_PROGRAM_ID,
  SOL_INTERFACE,
} from "../interface/program.js";
import type { Address, InterfaceTransfer, RequestContext, Signature } from "../interface/types.js";
import { SOL_MINT } from "../transaction/asset.js";

import { RingError } from "./error.js";

const base58Encoder = getBase58Encoder();

/** The `circuit` selector that carries a BSB22 commitment and an owner tag inline. */
const RING_P256_CIRCUIT = 3;

/** Bytes of one `InputUtxo`, a nullifier hash and two root indexes. */
const INPUT_UTXO_SIZE = 36;

/** Mirrors Rust `TransactionOrigin`, an unknown signature is an error, never `false`. */
export interface TransactionOrigin {
  ringInvoked(signature: Signature, ring: Address, context?: RequestContext): Promise<boolean>;
}

export interface OriginInstruction {
  readonly programId: Address;
  /** 1 for an outer instruction, absent when the RPC reports none. */
  readonly stackHeight?: number;
  readonly accounts: readonly Address[];
  readonly data: Uint8Array;
}

/** Mirrors Rust `InstructionGroup`, one outer instruction with its inner instructions in execution order. */
export interface OriginInstructionGroup {
  readonly outer: OriginInstruction;
  readonly inner: readonly OriginInstruction[];
}

/** Mirrors Rust `RingWithdrawal`, one public settlement leg out of the ring. */
export interface RingWithdrawal {
  /** The wallet of a SOL leg, the credited token account of an SPL leg. */
  readonly recipient: Address;
  readonly asset: Address;
  readonly amount: bigint;
}

/** Mirrors Rust `ORIGIN_TRANSACTION_CONFIG`. */
export const ORIGIN_TRANSACTION_CONFIG = Object.freeze({
  encoding: "json",
  commitment: "confirmed",
  maxSupportedTransactionVersion: 0,
} as const);

/**
 * Mirrors Rust `ring_instructions_in`. `ring_transact` needs the ring's
 * `ring_auth` PDA as signer, so only a pool instruction whose direct caller is
 * `ring` belongs to the ring.
 */
export function ringInstructionsIn(
  groups: readonly OriginInstructionGroup[],
  ring: Address,
): readonly OriginInstruction[] {
  const found: OriginInstruction[] = [];
  for (const group of groups) {
    const callers: Address[] = [group.outer.programId];
    for (const inner of group.inner) {
      const height = inner.stackHeight;
      if (height === undefined) {
        throw new RingError("RING_ORIGIN_STACK", { details: { reason: "missing stack height" } });
      }
      const parentDepth = height - 2;
      if (!Number.isInteger(parentDepth) || parentDepth < 0 || parentDepth >= callers.length) {
        throw new RingError("RING_ORIGIN_STACK", { details: { reason: "no parent", height } });
      }
      if (inner.programId === SHIELDED_POOL_PROGRAM_ID && callers[parentDepth] === ring) {
        found.push(inner);
      }
      callers.length = parentDepth + 1;
      callers.push(inner.programId);
    }
  }
  return Object.freeze(found);
}

/** Mirrors Rust `ring_invoked_in`. */
export function ringInvokedIn(groups: readonly OriginInstructionGroup[], ring: Address): boolean {
  return ringInstructionsIn(groups, ring).length > 0;
}

/**
 * Mirrors Rust `ring_withdrawals_of`. One settlement account group per interface
 * transfer sits at the tail of the account list, in transfer order.
 */
export function ringWithdrawalsOf(
  instructions: readonly OriginInstruction[],
): readonly RingWithdrawal[] {
  const withdrawals: RingWithdrawal[] = [];
  for (const instruction of instructions) {
    const transfers = interfaceTransfersOf(instruction);
    if (transfers === undefined) continue;
    const total = transfers.reduce((sum, transfer) => sum + settlementWidth(transfer), 0);
    let at = instruction.accounts.length - total;
    if (at < 0) throw invalid("settlementAccounts");
    for (const transfer of transfers) {
      const width = settlementWidth(transfer);
      const leg = withdrawalLeg(transfer, instruction.accounts.slice(at, at + width));
      at += width;
      if (leg !== undefined) withdrawals.push(leg);
    }
  }
  return Object.freeze(withdrawals);
}

/**
 * Mirrors Rust `ConfirmedInstructionGroups::from_confirmed_transaction` over a
 * `getTransaction` JSON result. A v0 transaction resolves program ids through
 * `loadedAddresses`, appended writable first.
 */
export function confirmedInstructionGroups(
  transaction: unknown,
): readonly OriginInstructionGroup[] {
  const wire = record(transaction, "transaction");
  const encoded = record(wire["transaction"], "transaction.transaction");
  const message = record(encoded["message"], "transaction.transaction.message");
  const meta = record(wire["meta"], "transaction.meta");
  const accountKeys = addresses(message["accountKeys"], "message.accountKeys");
  const loaded = meta["loadedAddresses"];
  if (loaded !== undefined && loaded !== null) {
    const loadedRecord = record(loaded, "meta.loadedAddresses");
    accountKeys.push(
      ...addresses(loadedRecord["writable"], "meta.loadedAddresses.writable"),
      ...addresses(loadedRecord["readonly"], "meta.loadedAddresses.readonly"),
    );
  }
  const groups = list(message["instructions"], "message.instructions").map(
    (instruction, index): { outer: OriginInstruction; inner: OriginInstruction[] } => ({
      outer: parsed(accountKeys, instruction, `message.instructions[${index}]`),
      inner: [],
    }),
  );
  // Rust refuses a transaction without `innerInstructions`, the walk would miss every CPI.
  const innerGroups = list(meta["innerInstructions"], "meta.innerInstructions");
  innerGroups.forEach((entry, groupIndex) => {
    const path = `meta.innerInstructions[${groupIndex}]`;
    const innerGroup = record(entry, path);
    const outerIndex = innerGroup["index"];
    const group = typeof outerIndex === "number" ? groups[outerIndex] : undefined;
    if (group === undefined) throw invalid(`${path}.index`);
    group.inner = list(innerGroup["instructions"], `${path}.instructions`).map(
      (instruction, index): OriginInstruction => {
        const instructionPath = `${path}.instructions[${index}]`;
        const height = record(instruction, instructionPath)["stackHeight"];
        return {
          ...parsed(accountKeys, instruction, instructionPath),
          ...(height === undefined || height === null ? {} : { stackHeight: stackHeight(height) }),
        };
      },
    );
  });
  return groups.map((group) =>
    Object.freeze({ outer: Object.freeze(group.outer), inner: Object.freeze(group.inner) }),
  );
}

/** The public settlement legs a confirmed transaction paid out of `ring`. */
export function confirmedRingWithdrawals(
  transaction: unknown,
  ring: Address,
): readonly RingWithdrawal[] {
  return ringWithdrawalsOf(ringInstructionsIn(confirmedInstructionGroups(transaction), ring));
}

/**
 * The signer that owns one of the transaction's outputs, so the one that spent.
 * Slot position says nothing, a full spend leaves no change.
 */
export function senderOf(
  signers: readonly Address[],
  ownerTags: readonly (Address | undefined)[],
): Address | undefined {
  const owned = new Set(ownerTags.filter((tag): tag is Address => tag !== undefined));
  return signers.find((signer) => owned.has(signer));
}

/** Mirrors the Rust `TransactionOrigin` impl for `SolanaRpc`. */
export class RpcTransactionOrigin implements TransactionOrigin {
  readonly #rpc: SolanaRpc;

  constructor(rpc: SolanaRpc) {
    this.#rpc = rpc;
  }

  async ringInvoked(
    signature: Signature,
    ring: Address,
    context?: RequestContext,
  ): Promise<boolean> {
    let transaction: unknown;
    try {
      transaction = await runKitRpc("getTransaction", context, (abortSignal) =>
        this.#rpc.getTransaction(signature, ORIGIN_TRANSACTION_CONFIG).send({ abortSignal }),
      );
    } catch (cause) {
      throw new RingError("RING_ORIGIN_UNAVAILABLE", {
        details: { transactionId: signature },
        cause,
      });
    }
    if (transaction === null || transaction === undefined) {
      throw new RingError("RING_ORIGIN_UNAVAILABLE", { details: { transactionId: signature } });
    }
    return ringInvokedIn(confirmedInstructionGroups(transaction), ring);
  }
}

/** One lookup per signature, the scan sees a signature once per page it appears in. */
export class CachedTransactionOrigin implements TransactionOrigin {
  readonly #origin: TransactionOrigin;
  readonly #known = new Map<Signature, boolean>();

  constructor(origin: TransactionOrigin) {
    this.#origin = origin;
  }

  async ringInvoked(
    signature: Signature,
    ring: Address,
    context?: RequestContext,
  ): Promise<boolean> {
    const known = this.#known.get(signature);
    if (known !== undefined) return known;
    const invoked = await this.#origin.ringInvoked(signature, ring, context);
    this.#known.set(signature, invoked);
    return invoked;
  }
}

/** Mirrors Rust `settlement_width`, the accounts `append_interface_transfer_accounts` adds. */
function settlementWidth(transfer: InterfaceTransfer): number {
  return transfer.kind === "splDeposit" || transfer.kind === "splWithdrawal" ? 5 : 2;
}

/** A deposit settles value into the pool and names no recipient. */
function withdrawalLeg(
  transfer: InterfaceTransfer,
  group: readonly Address[],
): RingWithdrawal | undefined {
  if (transfer.kind === "solWithdrawal") {
    const recipient = group[1];
    if (group[0] !== SOL_INTERFACE || recipient === undefined) throw invalid("settlementAccounts");
    return Object.freeze({ recipient, asset: SOL_MINT, amount: transfer.amount });
  }
  if (transfer.kind === "splWithdrawal") {
    const asset = group[1];
    const recipient = group[3];
    if (group[0] !== SHIELDED_POOL_CPI_AUTHORITY || asset === undefined) {
      throw invalid("settlementAccounts");
    }
    if (recipient === undefined) throw invalid("settlementAccounts");
    return Object.freeze({ recipient, asset, amount: transfer.amount });
  }
  return undefined;
}

/** Mirrors Rust `interface_transfers`, `undefined` for a pool instruction that is not a `ring_transact`. */
function interfaceTransfersOf(
  instruction: OriginInstruction,
): readonly InterfaceTransfer[] | undefined {
  if (instruction.data[0] !== InstructionTag.ringTransact) return undefined;
  try {
    return readInterfaceTransfers(new Reader(instruction.data.slice(1)));
  } catch (cause) {
    throw new RingError("RING_ORIGIN_DECODE", { details: { path: "ringTransact" }, cause });
  }
}

/** Reads the fixed `TransactIxData` prefix, then the transfers, and leaves the rest. */
function readInterfaceTransfers(reader: Reader): readonly InterfaceTransfer[] {
  reader.u64("expiryUnixTs");
  reader.bytes(32, "privateTxHash");
  const circuit = reader.u16("circuit.kind");
  reader.bytes(3, "circuit.shape");
  if (circuit === RING_P256_CIRCUIT) reader.bytes(97, "circuit.ringP256");
  reader.bytes(33, "txViewingPk");
  reader.bytes(16, "salt");
  reader.bytes(128, "proof");
  reader.bytes(reader.u8("inputs.length") * INPUT_UTXO_SIZE, "inputs");
  const count = reader.u8("interfaceTransfers.length");
  return Array.from({ length: count }, () => readInterfaceTransfer(reader));
}

function readInterfaceTransfer(reader: Reader): InterfaceTransfer {
  const kind = reader.u8("interfaceTransfer.kind");
  const amount = reader.u64("interfaceTransfer.amount");
  switch (kind) {
    case 0:
      return { kind: "solDeposit", amount };
    case 1:
      return { kind: "solWithdrawal", amount };
    case 2:
    case 3:
      return {
        kind: kind === 2 ? "splDeposit" : "splWithdrawal",
        amount,
        splInterfaceBump: reader.u8("interfaceTransfer.splInterfaceBump"),
      };
    default:
      throw invalid("interfaceTransfer.kind");
  }
}

function parsed(
  accountKeys: readonly Address[],
  instruction: unknown,
  path: string,
): OriginInstruction {
  const fields = record(instruction, path);
  const accounts = list(fields["accounts"], `${path}.accounts`).map((index, at) => {
    const account = typeof index === "number" ? accountKeys[index] : undefined;
    if (account === undefined) throw invalid(`${path}.accounts[${at}]`);
    return account;
  });
  return {
    programId: programId(accountKeys, instruction, path),
    accounts,
    data: bytes(fields, path),
  };
}

function bytes(fields: Record<string, unknown>, path: string): Uint8Array {
  const data = fields["data"];
  if (typeof data !== "string") throw invalid(`${path}.data`);
  try {
    return new Uint8Array(base58Encoder.encode(data));
  } catch (cause) {
    throw new RingError("RING_ORIGIN_DECODE", { details: { path: `${path}.data` }, cause });
  }
}

function programId(accountKeys: readonly Address[], instruction: unknown, path: string): Address {
  const index = record(instruction, path)["programIdIndex"];
  const id = typeof index === "number" ? accountKeys[index] : undefined;
  if (id === undefined) throw invalid(`${path}.programIdIndex`);
  return id;
}

function stackHeight(value: unknown): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
    throw new RingError("RING_ORIGIN_STACK", { details: { reason: "invalid stack height" } });
  }
  return value;
}

function addresses(value: unknown, path: string): Address[] {
  return list(value, path).map((entry, index) => {
    if (typeof entry !== "string" || !isAddress(entry)) throw invalid(`${path}[${index}]`);
    return entry;
  });
}

function invalid(path: string): RingError {
  return new RingError("RING_ORIGIN_DECODE", { details: { path } });
}

function record(value: unknown, path: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw invalid(path);
  return value as Record<string, unknown>;
}

function list(value: unknown, path: string): readonly unknown[] {
  if (!Array.isArray(value)) throw invalid(path);
  return value;
}
