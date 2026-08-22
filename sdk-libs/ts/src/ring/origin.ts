import { isAddress } from "@solana/kit";

import { runKitRpc, type SolanaRpc } from "../client/kit.js";
import { SHIELDED_POOL_PROGRAM_ID, SOL_INTERFACE } from "../interface/program.js";
import type { Address, RequestContext, Signature } from "../interface/types.js";

import { RingError } from "./error.js";

/** Mirrors Rust `TransactionOrigin`, an unknown signature is an error, never `false`. */
export interface TransactionOrigin {
  ringInvoked(signature: Signature, ring: Address, context?: RequestContext): Promise<boolean>;
}

export interface OriginInstruction {
  readonly programId: Address;
  /** 1 for an outer instruction, absent when the RPC reports none. */
  readonly stackHeight?: number;
}

/** Mirrors Rust `InstructionGroup`, one outer instruction with its inner instructions in execution order. */
export interface OriginInstructionGroup {
  readonly outer: OriginInstruction;
  readonly inner: readonly OriginInstruction[];
}

/** Mirrors Rust `ORIGIN_TRANSACTION_CONFIG`. */
export const ORIGIN_TRANSACTION_CONFIG = Object.freeze({
  encoding: "json",
  commitment: "confirmed",
  maxSupportedTransactionVersion: 0,
} as const);

/**
 * Mirrors Rust `ring_invoked_in`. `ring_transact` needs the ring's `ring_auth`
 * PDA as signer, so only a pool instruction whose direct caller is `ring`
 * belongs to the ring.
 */
export function ringInvokedIn(groups: readonly OriginInstructionGroup[], ring: Address): boolean {
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
        return true;
      }
      callers.length = parentDepth + 1;
      callers.push(inner.programId);
    }
  }
  return false;
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
      outer: { programId: programId(accountKeys, instruction, `message.instructions[${index}]`) },
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
          programId: programId(accountKeys, instruction, instructionPath),
          ...(height === undefined || height === null ? {} : { stackHeight: stackHeight(height) }),
        };
      },
    );
  });
  return groups.map((group) =>
    Object.freeze({ outer: Object.freeze(group.outer), inner: Object.freeze(group.inner) }),
  );
}

/**
 * The accounts a transaction settled SOL to, so the recipients of a public
 * withdrawal. The pool's interface account precedes each one, which holds
 * however the fee was paid. Mirrors Rust `ring_withdrawals_of`, without the
 * per-leg amounts the instruction data carries.
 */
export function confirmedWithdrawalRecipients(transaction: unknown): readonly Address[] {
  const wire = record(transaction, "transaction");
  const encoded = record(wire["transaction"], "transaction.transaction");
  const message = record(encoded["message"], "transaction.transaction.message");
  const recipients: Address[] = [];
  for (const [index, instruction] of list(
    message["instructions"],
    "message.instructions",
  ).entries()) {
    const accounts = record(instruction, `message.instructions[${index}]`)["accounts"];
    if (accounts === undefined) continue;
    const named = addresses(accounts, `message.instructions[${index}].accounts`);
    named.forEach((account, at) => {
      const next = named[at + 1];
      if (account === SOL_INTERFACE && next !== undefined) recipients.push(next);
    });
  }
  return Object.freeze(recipients);
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
      throw new RingError("RING_ORIGIN_UNAVAILABLE", { details: { signature }, cause });
    }
    if (transaction === null || transaction === undefined) {
      throw new RingError("RING_ORIGIN_UNAVAILABLE", { details: { signature } });
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
