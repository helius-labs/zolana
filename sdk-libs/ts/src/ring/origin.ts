import { getBase58Encoder } from "@solana/kit";

import { runKitRpc, type SolanaRpc } from "../client/kit.js";
import { decompressG2 } from "../client/prover/proof.js";
import { MAX_CACHE_WRITES } from "../interface/cache.js";
import { wireDecoder } from "../interface/decode.js";
import { Reader, Writer, sha256, addressBytes, encodeBase58 } from "../interface/internal.js";
import { treeAddress } from "../interface/pda/index.js";
import { INPUT_TREES } from "../interface/tree-slot.js";
import { decodeRingDepositInstructionData, readMergeData } from "../interface/codecs/index.js";
import { CUSTOM_RING_PROOF_LENGTH } from "../interface/custom-ring-proof.js";
import { equal } from "../transaction/internal.js";
import type { IndexedShieldedTransaction } from "../transaction/instructions/transact.js";
import { X25519PublicKey } from "../keypair/x25519.js";
import {
  AUDITED_RING_DEPOSIT_TAG,
  encodeRingDepositCapsule,
  readRingDepositCapsule,
  RING_DEPOSIT_AUDIT_SLOTS,
  type RingDepositCapsule,
} from "./deposit-capsule.js";
import {
  InstructionTag,
  SHIELDED_POOL_CPI_AUTHORITY,
  SHIELDED_POOL_PROGRAM_ID,
  SOL_INTERFACE,
} from "../interface/program.js";
import type {
  Address,
  Bytes16,
  Bytes32,
  Bytes33,
  Bytes64,
  InterfaceTransfer,
  RequestContext,
  Signature,
} from "../interface/types.js";
import type { DisclosureLayout } from "../interface/ring-disclosure-layout.js";
import { SOL_MINT } from "../transaction/asset.js";
import { encodeMergeOutputData } from "../transaction/serialization/merge.js";

import { RingError } from "./error.js";
import {
  readRingMergeDisclosure,
  writeRingMergeDisclosure,
  type RingMergeDisclosure,
} from "./merge-disclosure.js";
import { RingTransactData, ringRailOf } from "./transact.js";

const base58Encoder = getBase58Encoder();

/** Mirrors Rust `ConfirmedEventKind`, the confirmed instruction selects it, never indexer metadata. */
export type ConfirmedEventKind = "deposit" | "transfer" | "merge";

/** Rust `RingOrigin` after `bind_transaction`, the indexed event bound to its confirmed instruction. */
export type ConfirmedRingTransaction =
  | Readonly<{
      kind: "transfer";
      transaction: IndexedShieldedTransaction;
      /** Rust `ConfirmedEvent::input_tree_ids`, an input spent from a tree other than the output tree has no id. */
      inputTreeIds: readonly (number | undefined)[];
      /** The layout the ring program verified the audit proof under, read from its confirmed instruction. */
      layout: DisclosureLayout;
    }>
  | Readonly<{
      kind: "deposit";
      transaction: IndexedShieldedTransaction;
      /** The capsule bindings of the audited deposit behind the event, empty for a plain one. */
      deposits: readonly ConfirmedDeposit[];
    }>
  | Readonly<{
      kind: "merge";
      transaction: IndexedShieldedTransaction;
      /** The anonymous merge disclosure whose proof the direct ring caller verified. */
      disclosure?: RingMergeDisclosure;
    }>;

/** Mirrors Rust `TransactionOrigin`, an unknown signature is an error, never absent. */
export interface TransactionOrigin {
  /** Binds indexed data to the exact confirmed transfer, deposit or merge. Other-ring events return undefined. */
  confirmedTransaction(
    transaction: IndexedShieldedTransaction,
    ring: Address,
    context?: RequestContext,
  ): Promise<ConfirmedRingTransaction | undefined>;
}

/** The ring forwards `ringDataHash || root || anonymous || body` with the body's `b` decompressed. */
function confirmedMergeDisclosureOf(found: TrustedEvent): RingMergeDisclosure | undefined {
  const wrapper = found.wrapper;
  if (
    found.source.data[0] !== InstructionTag.ringMergeTransact ||
    wrapper?.data[0] !== InstructionTag.ringMergeTransact
  )
    return undefined;
  const request = new Reader(wrapper.data.subarray(2));
  const ringDataHash = request.bytes(32, "merge.ringDataHash");
  const disclosure = readRingMergeDisclosure(request);
  if (disclosure === undefined) return undefined;
  const prefix = 2 + 32 + writeRingMergeDisclosure(new Writer(), disclosure).finish().length;
  const forwarded = found.source.data;
  if (
    !equal(forwarded.subarray(1, 33), ringDataHash) ||
    forwarded[65] !== 1 ||
    !equal(forwarded.subarray(FORWARDED_MERGE_PREFIX), sppMergeBody(wrapper.data.subarray(prefix)))
  )
    throw invalid("merge.disclosure");
  return disclosure;
}

/** `tag || ringDataHash || root || anonymous` ahead of the forwarded SPP merge body. */
const FORWARDED_MERGE_PREFIX = 1 + 32 + 32 + 1;
/** `expiry_unix_ts u64 || proof.a` ahead of `proof.b`, Rust `MERGE_B_OFFSET`. */
const MERGE_B_OFFSET = 8 + 32;

/** Rust `CustomRingMergeIxDataRef::spp_merge_body`, the compact body with `proof.b` decompressed. */
function sppMergeBody(compact: Uint8Array): Uint8Array {
  if (compact.length < MERGE_B_OFFSET + 64) throw invalid("merge.body");
  let b: Uint8Array;
  try {
    b = decompressG2(compact.slice(MERGE_B_OFFSET, MERGE_B_OFFSET + 64) as Bytes64);
  } catch (cause) {
    throw new RingError("RING_ORIGIN_DECODE", { details: { path: "merge.proof.b" }, cause });
  }
  const body = new Uint8Array(compact.length + 64);
  body.set(compact.subarray(0, MERGE_B_OFFSET), 0);
  body.set(b, MERGE_B_OFFSET);
  body.set(compact.subarray(MERGE_B_OFFSET + 64), MERGE_B_OFFSET + 128);
  return body;
}

const CONFIRMED_DEPOSIT = Symbol("confirmed audited deposit");

/** Authenticates one capsule against the successful audited deposit that published it. */
export class ConfirmedDeposit {
  readonly #ownerCommitment: Bytes32;
  readonly #capsuleHash: Uint8Array;
  private constructor(
    token: symbol,
    readonly slotIndex: number,
    ownerCommitment: Uint8Array,
    capsule: Uint8Array,
  ) {
    if (token !== CONFIRMED_DEPOSIT) throw invalid("confirmedDeposit");
    if (ownerCommitment.length !== 32) throw invalid("ownerCommitment");
    this.#ownerCommitment = ownerCommitment.slice() as Bytes32;
    this.#capsuleHash = sha256(capsule);
    Object.freeze(this);
  }

  /** Checks the private runtime brand, which a copied prototype cannot supply. */
  static is(value: unknown): value is ConfirmedDeposit {
    return typeof value === "object" && value !== null && #ownerCommitment in value;
  }

  /** Only exact successful event ancestry can mint a binding, never an indexed capsule alone. */
  static fromTransaction(
    transaction: unknown,
    signature: Signature,
    eventIndex: number,
    ring: Address,
  ): readonly ConfirmedDeposit[] {
    const wire = record(transaction, "transaction");
    if (record(wire["meta"], "meta")["err"] !== null) throw invalid("meta.err");
    const encoded = record(wire["transaction"], "transaction.transaction");
    if (list(encoded["signatures"], "signatures")[0] !== signature) throw invalid("signatures");
    const found = ringEventIn(confirmedInstructionGroups(transaction), eventIndex, ring);
    if (
      found === undefined ||
      found.source.data[0] !== InstructionTag.ringDeposit ||
      found.wrapper?.data[0] !== AUDITED_RING_DEPOSIT_TAG
    )
      return [];
    if (!equal(found.wrapper.data.subarray(CUSTOM_RING_PROOF_LENGTH + 2), found.source.data))
      throw invalid("auditedDeposit");
    return ConfirmedDeposit.#decode(found.source.data);
  }

  /** The digest covers the entire capsule, including recipient ciphertext and slot. */
  authenticate(capsule: RingDepositCapsule, ownerCommitment: Bytes32): void {
    if (
      capsule.slotIndex !== this.slotIndex ||
      !equal(ownerCommitment, this.#ownerCommitment) ||
      !equal(sha256(encodeRingDepositCapsule(capsule)), this.#capsuleHash)
    ) {
      throw new RingError("RING_AUDIT_MESSAGE", {
        details: { reason: "unconfirmed deposit capsule" },
      });
    }
  }

  static #decode(data: Uint8Array): readonly ConfirmedDeposit[] {
    const decoded = decodeRingDepositInstructionData(data.subarray(1));
    if (decoded.deposits.length < 1 || decoded.deposits.length > RING_DEPOSIT_AUDIT_SLOTS)
      throw invalid("deposits.length");
    const deposits = decoded.deposits.map((deposit, slot) => {
      const ciphertext = deposit.encrypted.ciphertext;
      const capsule = readRingDepositCapsule(ciphertext);
      if (capsule === undefined || capsule.slotIndex !== slot) throw invalid("deposit capsule");
      return new ConfirmedDeposit(CONFIRMED_DEPOSIT, slot, deposit.ownerUtxoHash, ciphertext);
    });
    return Object.freeze(deposits);
  }
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

/**
 * Mirrors Rust `ORIGIN_TRANSACTION_CONFIG`. A transact is a version 1
 * transaction, and an RPC allowed a lower version answers the read with an
 * unsupported-version error instead of the transaction.
 */
export const ORIGIN_TRANSACTION_CONFIG = Object.freeze({
  encoding: "json",
  commitment: "confirmed",
  maxSupportedTransactionVersion: 1,
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
  return Object.freeze(
    instructionAncestry(groups)
      .filter(
        ({ instruction, parent }) =>
          instruction.programId === SHIELDED_POOL_PROGRAM_ID && parent?.programId === ring,
      )
      .map(({ instruction }) => instruction),
  );
}

/** Mirrors Rust `ring_invoked_in`. */
export function ringInvokedIn(groups: readonly OriginInstructionGroup[], ring: Address): boolean {
  return ringInstructionsIn(groups, ring).length > 0;
}

interface TrustedEvent {
  readonly source: OriginInstruction;
  readonly event: OriginInstruction;
  readonly wrapper: OriginInstruction | undefined;
}

function ringEventIn(
  groups: readonly OriginInstructionGroup[],
  eventIndex: number,
  ring: Address,
): TrustedEvent | undefined {
  if (!Number.isInteger(eventIndex) || eventIndex < 0 || eventIndex > 0xffff)
    throw invalid("eventIndex");
  const found = trustedEvents(groups)[eventIndex];
  if (found === undefined) throw invalid("eventIndex");
  return found.wrapper?.programId === ring ? found : undefined;
}

/** One checked execution stack owns direct caller and exact self-CPI event attribution. */
function instructionAncestry(groups: readonly OriginInstructionGroup[]): readonly Readonly<{
  instruction: OriginInstruction;
  parent: OriginInstruction | undefined;
  grandparent: OriginInstruction | undefined;
}>[] {
  const ancestry = [];
  for (const group of groups) {
    const stack = [group.outer];
    for (const instruction of group.inner) {
      const height = instruction.stackHeight;
      if (height === undefined)
        throw new RingError("RING_ORIGIN_STACK", {
          details: { reason: "missing stack height" },
        });
      if (!Number.isInteger(height) || height < 2 || height > stack.length + 1)
        throw new RingError("RING_ORIGIN_STACK", {
          details: { reason: "no parent", height },
        });
      stack.length = height - 1;
      ancestry.push({
        instruction,
        parent: stack[height - 2],
        grandparent: stack[height - 3],
      });
      stack.push(instruction);
    }
  }
  return ancestry;
}

function trustedEvents(groups: readonly OriginInstructionGroup[]): readonly TrustedEvent[] {
  const events: TrustedEvent[] = [];
  for (const { instruction, parent, grandparent } of instructionAncestry(groups)) {
    if (
      instruction.programId === SHIELDED_POOL_PROGRAM_ID &&
      instruction.data[0] === InstructionTag.emitEvent &&
      parent?.programId === SHIELDED_POOL_PROGRAM_ID &&
      isEventSourceTag(parent.data[0])
    )
      events.push({ source: parent, event: instruction, wrapper: grandparent });
  }
  return events;
}

function isEventSourceTag(value: number | undefined): boolean {
  return (
    value === InstructionTag.deposit ||
    value === InstructionTag.ringDeposit ||
    value === InstructionTag.transact ||
    value === InstructionTag.ringTransact ||
    value === InstructionTag.ringAuthorityTransact ||
    value === InstructionTag.mergeTransact ||
    value === InstructionTag.ringMergeTransact
  );
}

/**
 * Mirrors Rust `ring_withdrawals_of`. One settlement account group per interface
 * transfer sits in transfer order before the cache accounts a cached selector
 * appends: the cache, then its signing writer when the selector writes.
 */
export function ringWithdrawalsOf(
  instructions: readonly OriginInstruction[],
): readonly RingWithdrawal[] {
  const withdrawals: RingWithdrawal[] = [];
  for (const instruction of instructions) {
    const settlement = settlementDataOf(instruction);
    if (settlement === undefined) continue;
    const { transfers, cacheAccountCount } = settlement;
    const total = transfers.reduce((sum, transfer) => sum + settlementWidth(transfer), 0);
    let at = instruction.accounts.length - cacheAccountCount - total;
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
 * `getTransaction` JSON result.
 */
export function confirmedInstructionGroups(
  transaction: unknown,
): readonly OriginInstructionGroup[] {
  const wire = record(transaction, "transaction");
  const encoded = record(wire["transaction"], "transaction.transaction");
  const message = record(encoded["message"], "transaction.transaction.message");
  const meta = record(wire["meta"], "transaction.meta");
  if (meta["err"] !== null) throw invalid("meta.err");
  const accountKeys = messageAccountKeys(message, meta);
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
    Object.freeze({
      outer: Object.freeze(group.outer),
      inner: Object.freeze(group.inner),
    }),
  );
}

/** Static keys, then the loaded writable and readonly addresses, the order instruction indexes count in. */
function messageAccountKeys(
  message: Readonly<Record<string, unknown>>,
  meta: Readonly<Record<string, unknown>>,
): readonly Address[] {
  const statics = addresses(message["accountKeys"], "message.accountKeys");
  const lookups = message["addressTableLookups"];
  const tables =
    lookups === undefined || lookups === null
      ? []
      : list(lookups, "message.addressTableLookups").map((lookup, index) =>
          record(lookup, `message.addressTableLookups[${index}]`),
        );
  const loaded = meta["loadedAddresses"];
  if (loaded === undefined || loaded === null) {
    if (tables.length > 0) throw invalid("meta.loadedAddresses");
    return statics;
  }
  const loadedRecord = record(loaded, "meta.loadedAddresses");
  const writable = addresses(loadedRecord["writable"], "meta.loadedAddresses.writable");
  const readonly = addresses(loadedRecord["readonly"], "meta.loadedAddresses.readonly");
  const indexes = (key: "writableIndexes" | "readonlyIndexes") =>
    tables.reduce(
      (count, table, index) =>
        count + list(table[key], `message.addressTableLookups[${index}].${key}`).length,
      0,
    );
  // Each lookup index loads one address, any other count names accounts no lookup loaded.
  if (
    writable.length !== indexes("writableIndexes") ||
    readonly.length !== indexes("readonlyIndexes")
  )
    throw invalid("meta.loadedAddresses");
  return [...statics, ...writable, ...readonly];
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

/** Mirrors the Rust `TransactionOrigin` impl for `SolanaRpc`, one read per signature. */
export class RpcTransactionOrigin implements TransactionOrigin {
  readonly #rpc: SolanaRpc;
  readonly #transactions = new Map<Signature, Promise<unknown>>();
  static readonly #MAX_TRANSACTIONS = 4096;

  constructor(rpc: SolanaRpc) {
    this.#rpc = rpc;
  }

  async confirmedTransaction(
    transaction: IndexedShieldedTransaction,
    ring: Address,
    context?: RequestContext,
  ): Promise<ConfirmedRingTransaction | undefined> {
    const confirmed = await this.#transaction(transaction.txSignature, context);
    return bindConfirmedTransaction(confirmed, transaction, ring);
  }

  #transaction(signature: Signature, context?: RequestContext): Promise<unknown> {
    // A caller's cancellation or timeout must not govern another caller's read.
    if (context?.signal !== undefined || context?.timeoutMs !== undefined)
      return this.#fetch(signature, context);
    const known = this.#transactions.get(signature);
    if (known !== undefined) return known;
    const pending = this.#fetch(signature, context).catch((error: unknown) => {
      if (this.#transactions.get(signature) === pending) this.#transactions.delete(signature);
      throw error;
    });
    if (this.#transactions.size >= RpcTransactionOrigin.#MAX_TRANSACTIONS) {
      const oldest = this.#transactions.keys().next().value;
      if (oldest !== undefined) this.#transactions.delete(oldest);
    }
    this.#transactions.set(signature, pending);
    return pending;
  }

  async #fetch(signature: Signature, context?: RequestContext): Promise<unknown> {
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
    if (transaction === null || transaction === undefined)
      throw new RingError("RING_ORIGIN_UNAVAILABLE", {
        details: { transactionId: signature },
      });
    const wire = record(transaction, "transaction");
    const encoded = record(wire["transaction"], "transaction.transaction");
    if (list(encoded["signatures"], "signatures")[0] !== signature) throw invalid("signatures");
    return transaction;
  }
}

interface ConfirmedEventData extends Pick<
  ConfirmedTransferData,
  "outputs" | "messages" | "nullifiers"
> {
  readonly kind: ConfirmedEventKind;
  /** SPP proved the transfer on the anonymous rail. */
  readonly anonymous?: boolean;
  readonly txViewingPk?: Bytes33;
  readonly salt?: Bytes16;
  readonly outputTree: Address;
  readonly firstLeaf: bigint;
  /** The tree each input of a transfer spends from. */
  readonly inputTrees: readonly Address[];
}

/** The compact transfer and merge events carry the execution-assigned tree positions. */
function readEventLocation(
  event: Reader,
): Readonly<{ trees: readonly Address[]; outputTree: Address; firstLeaf: bigint }> {
  const count = event.u32("event.inputTrees.length");
  if (count < 1 || count > INPUT_TREES) throw invalid("event.inputTrees.length");
  const trees = Array.from({ length: count }, () => {
    const tree = encodeBase58(event.bytes(32, "event.inputTree"));
    event.u64("event.inputTree.firstInputQueueSeq");
    return tree;
  });
  return {
    trees,
    outputTree: encodeBase58(event.bytes(32, "event.outputTree")),
    firstLeaf: event.u64("event.firstOutputLeafIndex"),
  };
}

/** Mirrors zolana_event_parser::reconstruct_general_event without trusting indexer fields. */
function readConfirmedEvent(
  source: OriginInstruction,
  emitted: OriginInstruction,
): ConfirmedEventData | undefined {
  const event = new Reader(emitted.data.slice(1));
  const kind = event.u8("event.kind");
  const tag = source.data[0];
  if (tag === InstructionTag.ringTransact || tag === InstructionTag.ringAuthorityTransact) {
    if (kind !== 2) throw invalid("event.kind");
    const data = readTransferData(new Reader(source.data.slice(1)), source.accounts);
    const { trees, outputTree, firstLeaf } = readEventLocation(event);
    event.done();
    const inputTrees = data.inputTreeIndexes.map((index) => {
      const tree = trees[index];
      if (tree === undefined) throw invalid("input.treeIndex");
      return tree;
    });
    return { ...data, outputTree, firstLeaf, kind: "transfer", inputTrees };
  }
  if (tag === InstructionTag.ringMergeTransact) {
    if (kind !== 3) throw invalid("event.kind");
    const data = new Reader(source.data.slice(1));
    const ringDataHash = data.bytes(32, "merge.ringDataHash") as Bytes32;
    data.bytes(32, "merge.memberRegistryRoot");
    data.bool("merge.anonymous");
    const merge = readMergeData(data);
    data.done();
    const { salt, ciphertext } = merge.outputEncryption;
    const payload = encodeMergeOutputData({ ringDataHash, salt, ciphertext });
    const { outputTree, firstLeaf } = readEventLocation(event);
    const viewTag = event.bytes(32, "merge.viewTag") as Bytes32;
    event.done();
    return {
      outputTree,
      firstLeaf,
      kind: "merge",
      inputTrees: [],
      nullifiers: merge.nullifiers,
      messages: [],
      outputs: [{ hash: merge.outputUtxoHash, viewTag, payload }],
    };
  }
  if (tag !== InstructionTag.ringDeposit) return undefined;
  if (kind !== 1) throw invalid("event.kind");
  // Deposit emits a complete Borsh GeneralEvent. Counts are bounded by the instruction's u8 vectors.
  const count = (name: string): number => {
    const length = event.u32(name);
    if (length > 255) throw invalid(name);
    return length;
  };
  const payload = (): Uint8Array => {
    const length = event.u32("event.data.length");
    if (length > 0xffff) throw invalid("event.data.length");
    return event.bytes(length, "event.data");
  };
  const nullifiers = Array.from({ length: count("event.inputs.length") }, () => {
    event.bytes(40, "event.inputTreeAndSequence");
    return event.bytes(32, "event.nullifier") as Bytes32;
  });
  const outputs = Array.from({ length: count("event.outputs.length") }, () => ({
    viewTag: event.bytes(32, "event.viewTag") as Bytes32,
    hash: event.bytes(32, "event.outputHash") as Bytes32,
    payload: payload(),
  }));
  const messages = Array.from({ length: count("event.messages.length") }, () => ({
    viewTag: event.bytes(32, "event.messageTag") as Bytes32,
    data: payload(),
  }));
  if (event.bytes(49, "event.zeroViewingKeyAndSalt").some((byte) => byte !== 0))
    throw invalid("event.depositKey");
  const firstLeaf = event.u64("event.firstOutputLeafIndex");
  const outputTree = encodeBase58(event.bytes(32, "event.outputTree"));
  for (let index = 0, length = count("event.transfers.length"); index < length; index++) {
    event.bool("event.transfer.isDeposit");
    event.u64("event.transfer.amount");
    event.option("event.transfer.asset", (reader) => reader.bytes(32, "event.transfer.asset"));
  }
  event.done();
  return {
    kind: "deposit",
    inputTrees: [],
    outputTree,
    firstLeaf,
    outputs,
    messages,
    nullifiers,
  };
}

/** Reconstructs the exact indexed view from its successful SPP source and self-CPI event. */
function bindConfirmedTransaction(
  confirmed: unknown,
  indexed: IndexedShieldedTransaction,
  ring: Address,
): ConfirmedRingTransaction | undefined {
  if (indexed.eventIndex === undefined) throw invalid("eventIndex");
  const found = ringEventIn(confirmedInstructionGroups(confirmed), indexed.eventIndex, ring);
  if (found === undefined) return undefined;
  try {
    const data = readConfirmedEvent(found.source, found.event);
    if (data === undefined) return undefined;
    const { outputTree, firstLeaf } = data;
    const rawSlot = record(confirmed, "transaction")["slot"];
    // Solana Kit promotes RPC u64 values to bigint. Raw JSON fixtures use number/string.
    const slot = typeof rawSlot === "bigint" ? rawSlot : integer(rawSlot, "slot");
    if (slot < 0n || slot > 0xffff_ffff_ffff_ffffn) throw invalid("slot");
    const proofless = data.kind === "deposit";
    if (
      indexed.slot !== slot ||
      indexed.proofless !== proofless ||
      indexed.ringProgramId !== ring ||
      (data.txViewingPk === undefined
        ? indexed.txViewingPublicKey !== undefined
        : indexed.txViewingPublicKey === undefined ||
          !equal(indexed.txViewingPublicKey.toBytes(), data.txViewingPk)) ||
      (indexed.salt === undefined
        ? data.salt?.some((byte) => byte !== 0) === true
        : data.salt === undefined || !equal(indexed.salt, data.salt)) ||
      indexed.nullifiers.length !== data.nullifiers.length ||
      indexed.nullifiers.some((nullifier, index) => !equal(nullifier, data.nullifiers[index]!)) ||
      indexed.messages.length !== data.messages.length ||
      indexed.messages.some((message, index) => {
        const expected = data.messages[index]!;
        return !equal(message.viewTag, expected.viewTag) || !equal(message.data, expected.data);
      }) ||
      indexed.outputSlots.length !== data.outputs.length
    )
      throw invalid("indexedTransfer");
    const outputSlots = data.outputs.map((output, index) => {
      const published = indexed.outputSlots[index]!;
      const treeId = published.outputContext.treeId;
      const leafIndex = firstLeaf + BigInt(index);
      if (
        treeId === undefined ||
        treeAddress(treeId) !== outputTree ||
        leafIndex > 0xffff_ffff_ffff_ffffn ||
        published.outputContext.tree !== outputTree ||
        published.outputContext.leafIndex !== leafIndex ||
        !equal(published.outputContext.hash, output.hash) ||
        !equal(published.viewTag, output.viewTag) ||
        !equal(published.payload, output.payload)
      )
        throw invalid("indexedTransfer.output");
      return Object.freeze({
        viewTag: output.viewTag,
        payload: output.payload,
        outputContext: Object.freeze({
          tree: outputTree,
          treeId,
          leafIndex,
          hash: output.hash,
        }),
      });
    });
    const transaction: IndexedShieldedTransaction = Object.freeze({
      slot,
      txSignature: indexed.txSignature,
      eventIndex: indexed.eventIndex,
      ringProgramId: ring,
      proofless,
      ...(data.txViewingPk === undefined
        ? {}
        : { txViewingPublicKey: X25519PublicKey.fromBytes(data.txViewingPk) }),
      ...(data.salt === undefined ? {} : { salt: data.salt }),
      outputSlots: Object.freeze(outputSlots),
      messages: Object.freeze(data.messages),
      nullifiers: Object.freeze(data.nullifiers),
    });
    if (data.kind === "deposit")
      return Object.freeze({
        kind: data.kind,
        transaction,
        deposits: ConfirmedDeposit.fromTransaction(
          confirmed,
          indexed.txSignature,
          indexed.eventIndex,
          ring,
        ),
      });
    if (data.kind === "merge") {
      const disclosure = confirmedMergeDisclosureOf(found);
      return Object.freeze({
        kind: data.kind,
        transaction,
        ...(disclosure === undefined ? {} : { disclosure }),
      });
    }
    // Rust `ConfirmedEvent::input_tree_ids`, the event names any other tree by its account alone.
    const outputTreeId = outputSlots[0]?.outputContext.treeId;
    return Object.freeze({
      kind: data.kind,
      transaction,
      inputTreeIds: Object.freeze(
        data.inputTrees.map((tree) => (tree === outputTree ? outputTreeId : undefined)),
      ),
      layout: boundLayout(found, {
        anonymous: data.anonymous === true,
        outputs: outputSlots.length,
        inputs: data.nullifiers.length,
      }),
    });
  } catch (cause) {
    if (cause instanceof RingError) throw cause;
    throw new RingError("RING_ORIGIN_DECODE", {
      details: { path: "confirmedTransaction" },
      cause,
    });
  }
}

/** The disclosure layout of the ring's own `Transact` or `DelegateTransact`, the frame the program verified. */
function boundLayout(
  found: TrustedEvent,
  published: Readonly<{ anonymous: boolean; outputs: number; inputs: number }>,
): DisclosureLayout {
  const instruction = found.wrapper?.data;
  const tag = instruction?.[0];
  if (instruction === undefined || tag === undefined) throw invalid("transfer.instruction");
  // Only an anonymous ring emits an anonymous transfer.
  const rail = ringRailOf(tag, published.anonymous ? "anonymous" : "off");
  const data = RingTransactData.parse(instruction.subarray(1), rail);
  if (data.outputs.length !== published.outputs || data.nullifiers.length !== published.inputs)
    throw invalid("transfer.instruction");
  return RingTransactData.disclosureLayout(data);
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
    return Object.freeze({
      recipient,
      asset: SOL_MINT,
      amount: transfer.amount,
    });
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

/**
 * Only the transfer list and the number of trailing cache accounts, 0, 1 or 2,
 * are returned from the instruction data.
 */
function settlementDataOf(
  instruction: OriginInstruction,
): { transfers: readonly InterfaceTransfer[]; cacheAccountCount: number } | undefined {
  const tag = instruction.data[0];
  if (tag !== InstructionTag.ringTransact && tag !== InstructionTag.ringAuthorityTransact)
    return undefined;
  try {
    return readTransferData(new Reader(instruction.data.slice(1)), instruction.accounts);
  } catch (cause) {
    throw new RingError("RING_ORIGIN_DECODE", {
      details: { path: "ringTransact" },
      cause,
    });
  }
}

interface ConfirmedTransferData {
  transfers: readonly InterfaceTransfer[];
  cacheAccountCount: number;
  txViewingPk: Bytes33;
  salt: Bytes16;
  outputs: readonly Readonly<{
    hash: Bytes32;
    viewTag: Bytes32;
    payload: Uint8Array;
  }>[];
  messages: readonly Readonly<{ viewTag: Bytes32; data: Uint8Array }>[];
  nullifiers: readonly Bytes32[];
  /** Per input, its position in the event's input trees. */
  inputTreeIndexes: readonly number[];
  anonymous: boolean;
}

/** One parser owns both settlement extraction and audited transfer authentication. */
function readTransferData(reader: Reader, accounts: readonly Address[]): ConfirmedTransferData {
  reader.u64("expiryUnixTs");
  const txViewingPk = reader.bytes(33, "txViewingPk") as Bytes33;
  const salt = reader.bytes(16, "salt") as Bytes16;
  const count = reader.u8("interfaceTransfers.length");
  const transfers = Array.from({ length: count }, () => readInterfaceTransfer(reader));
  reader.option("dataHash", (input) => input.bytes(32, "dataHash"));
  reader.option("ringDataHash", (input) => input.bytes(32, "ringDataHash"));
  const outputs = Array.from({ length: reader.u8("outputs.length") }, () => {
    const hash = reader.bytes(32, "output.utxoHash") as Bytes32;
    const ownerKind = reader.u8("output.ownerTag.kind");
    if (ownerKind !== 0 && ownerKind !== 1) throw invalid("output.ownerTag.kind");
    let viewTag: Bytes32;
    if (ownerKind === 0) viewTag = reader.bytes(32, "output.ownerTag") as Bytes32;
    else {
      const account = accounts[reader.u8("output.ownerTag.index")];
      if (account === undefined) throw invalid("output.ownerTag.account");
      viewTag = addressBytes(account) as Bytes32;
    }
    const payload = reader.option("output.data", (input) =>
      input.bytes(input.u16("output.data.length"), "output.data"),
    );
    return { hash, viewTag, payload: payload ?? new Uint8Array() };
  });
  const messages = Array.from({ length: reader.u8("messages.length") }, () => ({
    viewTag: reader.bytes(32, "message.viewTag") as Bytes32,
    data: reader.bytes(reader.u16("message.data.length"), "message.data"),
  }));
  reader.bytes(32, "privateTxHash");
  // CircuitId's u16 tags and payloads match the Rust wire format.
  const circuit = reader.u16("circuit.kind");
  if (circuit !== 1 && circuit !== 2 && circuit !== 3 && circuit !== 5 && circuit !== 6) {
    throw invalid("circuit.kind");
  }
  reader.bytes(3, "circuit.shape");
  if (circuit === 3 || circuit === 6) {
    reader.bytes(64, "circuit.bsb22Commitment");
    const present = reader.bool("circuit.defaultOwnerTag.present");
    const tag = reader.bytes(32, "circuit.defaultOwnerTag");
    if (!present && tag.some((byte) => byte !== 0)) throw invalid("circuit.defaultOwnerTag");
  }
  const hasCache = circuit === 5 || circuit === 6;
  let cacheAccountCount = 0;
  if (hasCache) {
    const reads = reader.u64("circuit.cacheAccess.readBitmap");
    const firstWrite = reader.bytes(2, "circuit.cacheAccess.writeSlots[0]");
    reader.bytes(2 * (MAX_CACHE_WRITES - 1), "circuit.cacheAccess.writeSlots");
    const writes = firstWrite.some((byte) => byte !== 0xff);
    cacheAccountCount = (reads === 0n ? 0 : 1) + (writes ? 2 : 0);
  }
  reader.bytes(192, "proof");
  const inputs = Array.from({ length: reader.u8("inputs.length") }, () => ({
    nullifier: reader.bytes(32, "input.nullifier") as Bytes32,
    treeIndex: reader.u8("input.treeIndex"),
  }));
  reader.bytes(reader.u8("treeContexts.length") * 4, "treeContexts");
  // Rust `control_cosigner`, the anonymous rail appends the ring's co-signer and nothing else.
  if (circuit === 3 || circuit === 6) reader.bytes(32, "coSigner");
  reader.done();
  return {
    transfers,
    cacheAccountCount,
    txViewingPk,
    salt,
    outputs,
    messages,
    nullifiers: inputs.map((input) => input.nullifier),
    inputTreeIndexes: inputs.map((input) => input.treeIndex),
    anonymous: circuit === 3 || circuit === 6,
  };
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
    throw new RingError("RING_ORIGIN_DECODE", {
      details: { path: `${path}.data` },
      cause,
    });
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
    throw new RingError("RING_ORIGIN_STACK", {
      details: { reason: "invalid stack height" },
    });
  }
  return value;
}

function addresses(value: unknown, path: string): Address[] {
  return list(value, path).map((entry, index) => decodeAddress(entry, `${path}[${index}]`));
}

function invalid(path: string): RingError {
  return new RingError("RING_ORIGIN_DECODE", { details: { path } });
}

const { record, list, integer, address: decodeAddress } = wireDecoder(invalid);
