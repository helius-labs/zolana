import { hexToBytes } from "@noble/hashes/utils.js";

import type { RingMemberOpening, RingSealedKey } from "../client/ports.js";
import { BN254_SCALAR_ORDER, hashBytes } from "../hasher/index.js";
import {
  MEMBER_REGISTRY_CAPACITY,
  QUAD_ARITY,
  QUAD_HEIGHT,
  type ApplyProofInputs,
  type MemberRecord,
  type QuadPath,
  type QueueEntry,
  type RecordOpening,
  type RecordWriteProofInput,
} from "../interface/member-registry.js";
import type { Bytes32 } from "../interface/types.js";
import { checkedBytes } from "../keypair/bytes.js";
import {
  ZERO_32,
  bigIntBytes,
  bytesToBigInt,
  copy,
  equal,
  poseidon,
} from "../transaction/internal.js";
import { bytesKey } from "../wallet/internal.js";

import { RingDomain, domainField } from "../keypair/ring-domain.js";
import { RingError } from "./error.js";
import { ListId, recordBit } from "./policy.js";
import type { ApplyRecordsStatement } from "./statement.js";

/** `q - 1`, the sentinel's next, every member sorts strictly below it. */
export const FIELD_MAX = bigIntBytes(BN254_SCALAR_ORDER - 1n) as Bytes32;
/** Rust `MEMBER_REGISTRY_EMPTY_ROOT`, the tree holding only the sentinel, a registry's first root. */
export const MEMBER_REGISTRY_EMPTY_ROOT = hexToBytes(
  "26becf712db619da223ecf9b8fd6c19a6f81f281e4d7acec9d6ab3af79722946",
) as Bytes32;

const U64_MAX = 0xffff_ffff_ffff_ffffn;
const CAPACITY = Number(MEMBER_REGISTRY_CAPACITY);

/** Rust `EscrowKey`, the record field a registered key sets. */
export interface EscrowKey {
  readonly nullifierPk: Bytes32;
  readonly ciphertext: Bytes32;
}

/** Leaf 0, every member sorts strictly between it and `FIELD_MAX`. */
export const SENTINEL_RECORD: MemberRecord = Object.freeze({
  member: ZERO_32,
  next: FIELD_MAX,
  lists: 0n,
  escrowKey: ZERO_32,
});

/** The sentinel `(0, q - 1)` brackets every member in `[1, q - 2]` strictly. */
export function checkMember(member: Bytes32): Bytes32 {
  const value = checkedBytes<Bytes32>(member, 32, "member");
  if (bytesToBigInt(value) === 0n || bytesToBigInt(value) >= bytesToBigInt(FIELD_MAX))
    invalid("MemberOutOfRange");
  return value;
}

export function memberRecordHash(record: MemberRecord): Bytes32 {
  return poseidon([
    checkedBytes<Bytes32>(record.member, 32, "record member"),
    checkedBytes<Bytes32>(record.next, 32, "record next"),
    u64Field(record.lists, "lists"),
    checkedBytes<Bytes32>(record.escrowKey, 32, "record escrow key"),
  ]);
}

/** The root `leaf` folds to along `path`, Rust `QuadPath::root`. */
export function quadPathRoot(path: QuadPath, leaf: Bytes32): Bytes32 {
  checkedIndex(path.index);
  if (path.siblings.length !== QUAD_HEIGHT) invalid("PathHeight");
  let node = leaf;
  path.siblings.forEach((siblings, level) => {
    if (siblings.length !== QUAD_ARITY - 1) invalid("PathArity");
    const digit = (path.index >>> (2 * level)) & 3;
    const children = siblings.map((sibling) => checkedBytes<Bytes32>(sibling, 32, "sibling"));
    children.splice(digit, 0, node);
    node = poseidon(children);
  });
  return node;
}

/** The member's record under `root`, `undefined` for an absent member, Rust `RecordOpening::verify`. */
export function verifyRecordOpening(
  opening: RecordOpening,
  root: Bytes32,
  member: Bytes32,
): MemberRecord | undefined {
  checkMember(member);
  const leaf = opening.kind === "present" ? opening.record : opening.low;
  if (opening.kind === "present" ? !equal(leaf.member, member) : !brackets(leaf, member))
    invalid("NotBracketed");
  if (!equal(quadPathRoot(opening.path, memberRecordHash(leaf)), root)) invalid("RootMismatch");
  return opening.kind === "present" ? opening.record : undefined;
}

/** Rust `EscrowedRecord`. */
export interface EscrowedRecord {
  readonly record: MemberRecord;
  readonly path: QuadPath;
  readonly sealed: RingSealedKey;
  /** What the escrow key binds beside the nullifier key. */
  readonly ctHash: Bytes32;
}

/** A member's record, or the low record bracketing its absence, read under one root, Rust `MemberOpeningRead`. */
export class MemberOpeningRead {
  readonly opening: RingMemberOpening;

  private constructor(opening: RingMemberOpening) {
    this.opening = opening;
    Object.freeze(this);
  }

  /** `member`'s opening under `root`, refused unless its path reaches the root. */
  static verify(opening: RingMemberOpening, root: Bytes32, member: Bytes32): MemberOpeningRead {
    verifyRecordOpening(opening, root, member);
    return new MemberOpeningRead(opening);
  }

  /** `undefined` for an absent member. */
  record(): MemberRecord | undefined {
    return this.opening.kind === "present" ? this.opening.record : undefined;
  }

  listed(list: ListId): boolean {
    return ((this.record()?.lists ?? 0n) & recordBit(list)) !== 0n;
  }

  /** `undefined` unless the record's escrow key binds `nullifierPk` to the sealed secret. */
  escrowed(nullifierPk: Bytes32): EscrowedRecord | undefined {
    const { opening } = this;
    // An absent member's opening carries the low record, its key belongs to another member.
    if (opening.kind !== "present" || opening.sealedKey === undefined) return undefined;
    const sealed = opening.sealedKey;
    if (
      !equal(
        escrowKeyHash({ nullifierPk, ciphertext: sealed.ciphertext }),
        opening.record.escrowKey,
      )
    )
      return undefined;
    return Object.freeze({
      record: opening.record,
      path: opening.path,
      sealed,
      ctHash: hashBytes(sealed.ciphertext) as Bytes32,
    });
  }
}

/** Refuses an owner whose record escrows no key for `nullifierPk`, Rust `OwnerRead::escrowed`. */
export function ownerEscrowed(
  owner: Bytes32,
  read: MemberOpeningRead | undefined,
  nullifierPk: Bytes32,
): EscrowedRecord {
  const escrowed = read?.escrowed(nullifierPk);
  if (escrowed === undefined)
    throw new RingError("RING_UNREGISTERED_OUTPUT_KEY", { details: { owner: bytesKey(owner) } });
  return escrowed;
}

/** `Poseidon(nullifier_pk, hash_bytes(ciphertext))`. */
export function escrowKeyHash(key: EscrowKey): Bytes32 {
  return poseidon([
    checkedBytes<Bytes32>(key.nullifierPk, 32, "nullifier pk"),
    hashBytes(checkedBytes<Bytes32>(key.ciphertext, 32, "ciphertext")) as Bytes32,
  ]);
}

/** The escrow write of a registered key, it sets the escrow bit and the key together. */
export function escrowEntry(member: Bytes32, key: EscrowKey): QueueEntry {
  const bit = recordBit(ListId.escrow);
  return Object.freeze({
    member: checkMember(member),
    mask: bit,
    value: bit,
    escrowKey: escrowKeyHash(key),
  });
}

/** `Poseidon(CRQW, member, mask, value, escrow_key)`. */
export function queueEntryHash(entry: QueueEntry): Bytes32 {
  return poseidon([
    domainField(RingDomain.queueWrite),
    checkedBytes<Bytes32>(entry.member, 32, "entry member"),
    u64Field(entry.mask, "mask"),
    u64Field(entry.value, "value"),
    checkedBytes<Bytes32>(entry.escrowKey, 32, "entry escrow key"),
  ]);
}

/** `chain(p) = Poseidon(chain(p - 1), entry_p)` from `chain(-1) = 0`. */
export function queueChain(previous: Bytes32, entry: QueueEntry): Bytes32 {
  return poseidon([checkedBytes<Bytes32>(previous, 32, "chain"), queueEntryHash(entry)]);
}

/**
 * Replays `writes` from the registry state the indexer served, each step against the
 * running root as the apply circuit checks it, Rust `RecordTree::apply`.
 */
export function replayRecordWrites(
  input: Readonly<{
    oldRoot: Bytes32;
    oldNextIndex: number;
    chainStart: Bytes32;
    writes: readonly RecordWriteProofInput[];
  }>,
): ApplyProofInputs {
  let root = checkedBytes<Bytes32>(input.oldRoot, 32, "old root");
  let nextIndex = checkedNextIndex(input.oldNextIndex);
  let chain = checkedBytes<Bytes32>(input.chainStart, 32, "chain start");
  for (const write of input.writes) {
    checkEntry(write.entry);
    [root, nextIndex] = replayWrite(write, root, nextIndex);
    chain = queueChain(chain, write.entry);
  }
  return Object.freeze({
    oldRoot: copy(input.oldRoot),
    newRoot: root,
    oldNextIndex: input.oldNextIndex,
    newNextIndex: nextIndex,
    chainStart: copy(input.chainStart),
    chainEnd: chain,
    writes: Object.freeze([...input.writes]),
  });
}

/** Rust `ApplyProofInputs::statement`. */
export function applyRecordsStatement(inputs: ApplyProofInputs): ApplyRecordsStatement {
  return Object.freeze({
    oldRoot: inputs.oldRoot,
    newRoot: inputs.newRoot,
    oldNextIndex: inputs.oldNextIndex,
    newNextIndex: inputs.newNextIndex,
    chainStart: inputs.chainStart,
    chainEnd: inputs.chainEnd,
    count: BigInt(inputs.writes.length),
  });
}

/** List bits outside the mask keep their value, a registered key is final. */
function writtenRecord(record: MemberRecord, entry: QueueEntry): MemberRecord {
  return Object.freeze({
    ...record,
    lists: (record.lists & ~entry.mask & U64_MAX) | entry.value,
    escrowKey: equal(record.escrowKey, ZERO_32) ? entry.escrowKey : record.escrowKey,
  });
}

function replayWrite(
  write: RecordWriteProofInput,
  root: Bytes32,
  nextIndex: number,
): readonly [Bytes32, number] {
  const { entry } = write;
  if (write.exists) {
    const record: MemberRecord = {
      member: entry.member,
      next: write.oldNext,
      lists: write.oldLists,
      escrowKey: write.oldEscrow,
    };
    if (!equal(quadPathRoot(write.slot, memberRecordHash(record)), root)) invalid("RootMismatch");
    return [quadPathRoot(write.slot, memberRecordHash(writtenRecord(record, entry))), nextIndex];
  }
  const { low } = write;
  if (
    !brackets(low, entry.member) ||
    !equal(write.oldNext, low.next) ||
    write.oldLists !== 0n ||
    !equal(write.oldEscrow, ZERO_32)
  )
    invalid("NotBracketed");
  if (!equal(quadPathRoot(write.lowPath, memberRecordHash(low)), root)) invalid("RootMismatch");
  const inserted = writtenRecord(
    { member: entry.member, next: low.next, lists: 0n, escrowKey: ZERO_32 },
    entry,
  );
  // An empty record is never inserted, the write proves the absence and keeps the root.
  if (inserted.lists === 0n && equal(inserted.escrowKey, ZERO_32)) {
    // The circuit range-checks a no-op's slot and nothing else.
    checkedIndex(write.slot.index);
    return [root, nextIndex];
  }
  if (nextIndex >= CAPACITY) throw new RingError("RING_REGISTRY_FULL");
  if (write.slot.index !== nextIndex) invalid("SlotIndex");
  const relinked = quadPathRoot(write.lowPath, memberRecordHash({ ...low, next: entry.member }));
  if (!equal(quadPathRoot(write.slot, ZERO_32), relinked)) invalid("RootMismatch");
  return [quadPathRoot(write.slot, memberRecordHash(inserted)), nextIndex + 1];
}

/** An entry the program never queues fails before the first write. */
function checkEntry(entry: QueueEntry): void {
  checkMember(entry.member);
  checkedU64(entry.mask, "mask");
  if ((checkedU64(entry.value, "value") & ~entry.mask) !== 0n) invalid("ValueOutsideMask");
}

function brackets(record: MemberRecord, member: Bytes32): boolean {
  const value = bytesToBigInt(member);
  return bytesToBigInt(record.member) < value && value < bytesToBigInt(record.next);
}

function checkedIndex(index: number): void {
  if (!Number.isInteger(index) || index < 0 || index >= CAPACITY) invalid("IndexOutOfRange");
}

function checkedNextIndex(index: number): number {
  if (!Number.isInteger(index) || index < 1 || index > CAPACITY) invalid("IndexOutOfRange");
  return index;
}

function u64Field(value: bigint, name: string): Bytes32 {
  return bigIntBytes(checkedU64(value, name)) as Bytes32;
}

function checkedU64(value: bigint, name: string): bigint {
  if (typeof value !== "bigint" || value < 0n || value > U64_MAX)
    throw new RingError("RING_MEMBER_REGISTRY_INVALID", { details: { reason: "U64", name } });
  return value;
}

function invalid(reason: string): never {
  throw new RingError("RING_MEMBER_REGISTRY_INVALID", { details: { reason } });
}
