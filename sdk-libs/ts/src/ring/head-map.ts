// Each leaf binds a member to its successor pointer and current record nullifier.

import type { Bytes32 } from "../interface/types.js";
import { bytesToBigInt, poseidon } from "../transaction/internal.js";
import { equalBytes } from "../wallet/internal.js";
import { RingError } from "./error.js";

/** Matches the circuit height and the on-chain root. */
export const HEAD_MAP_HEIGHT = 40;
export const HEAD_MAP_CAPACITY = 1n << 40n;
const FIELD_ORDER = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function invalid(reason: string): never {
  throw new RingError("RING_HEAD_MAP_INVALID", { details: { reason } });
}

export function checkedHeadMapField(field: Uint8Array): Bytes32 {
  if (
    !(field instanceof Uint8Array) ||
    field.length !== 32 ||
    bytesToBigInt(field) >= FIELD_ORDER
  ) {
    return invalid("field");
  }
  return field as Bytes32;
}

function checkedIndex(index: bigint): void {
  if (typeof index !== "bigint" || index < 0n || index >= HEAD_MAP_CAPACITY) invalid("index");
}

/** BN254 scalar field order minus one, the sentinel high member closing the list. */
export const HEAD_MAP_FIELD_MAX = Uint8Array.from([
  0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
  0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x00,
]) as Bytes32;

/** Root of the sentinel-only tree, a fresh ring's head-map root. */
export const HEAD_MAP_EMPTY_ROOT = Uint8Array.from([
  3, 167, 83, 205, 18, 179, 81, 32, 16, 112, 166, 41, 197, 155, 154, 22, 44, 83, 161, 253, 51, 161,
  56, 203, 214, 190, 129, 75, 252, 254, 152, 14,
]) as Bytes32;

const EMPTY_LEAF = new Uint8Array(32) as Bytes32;

/** The leaf preimage binding a member to its successor pointer and current nullifier. */
export function headMapLeaf(member: Bytes32, next: Bytes32, nullifier: Bytes32): Bytes32 {
  return poseidon([member, next, nullifier].map(checkedHeadMapField));
}

/** Poseidon empty-subtree hashes, index 0 is the empty leaf, index 40 the empty root. */
export function headMapZeroBytes(): Bytes32[] {
  const zeros: Bytes32[] = [new Uint8Array(EMPTY_LEAF) as Bytes32];
  let previous: Bytes32 = EMPTY_LEAF;
  for (let level = 1; level <= HEAD_MAP_HEIGHT; level += 1) {
    previous = poseidon([previous, previous]);
    zeros.push(previous);
  }
  return zeros;
}

/** Reduces the leaf up its sibling path to a root, the index bit is LSB-first per level. */
export function headMapRootFromProof(
  leaf: Bytes32,
  index: bigint,
  proof: readonly Bytes32[],
): Bytes32 {
  checkedIndex(index);
  checkedHeadMapField(leaf);
  if (proof.length !== HEAD_MAP_HEIGHT) invalid("proofLength");
  let node = leaf;
  let idx = index;
  for (const sibling of proof) {
    checkedHeadMapField(sibling);
    node = (idx & 1n) === 0n ? poseidon([node, sibling]) : poseidon([sibling, node]);
    idx >>= 1n;
  }
  return node;
}

/** Supplies predecessor and append paths for a new member's head proof. */
export interface HeadMapInsertProofInput {
  root: Bytes32;
  appendIndex: bigint;
  member: Bytes32;
  genesis: Bytes32;
  lowMember: Bytes32;
  lowNext: Bytes32;
  lowNullifier: Bytes32;
  lowIndex: bigint;
  lowProof: readonly Bytes32[];
  newProof: readonly Bytes32[];
}

/** Verifies a member insertion off its low element and empty slot, returning the advanced root. */
export function verifyHeadMapInsert(witness: HeadMapInsertProofInput): Bytes32 {
  checkedIndex(witness.appendIndex);
  checkedIndex(witness.lowIndex);
  checkedHeadMapField(witness.root);
  if (witness.appendIndex === 0n || witness.lowIndex >= witness.appendIndex) invalid("appendIndex");
  if (witness.lowProof.length !== HEAD_MAP_HEIGHT || witness.newProof.length !== HEAD_MAP_HEIGHT) {
    invalid("proofLength");
  }
  const member = bytesToBigInt(witness.member);
  // 1. Strict predecessor order proves member absence under the supplied root.
  if (!(bytesToBigInt(witness.lowMember) < member && member < bytesToBigInt(witness.lowNext))) {
    invalid("memberRange");
  }
  const lowOld = headMapLeaf(witness.lowMember, witness.lowNext, witness.lowNullifier);
  if (!equalBytes(headMapRootFromProof(lowOld, witness.lowIndex, witness.lowProof), witness.root)) {
    invalid("lowRoot");
  }
  // 2. Splice the predecessor before checking the append path.
  const lowNew = headMapLeaf(witness.lowMember, witness.member, witness.lowNullifier);
  const spliced = headMapRootFromProof(lowNew, witness.lowIndex, witness.lowProof);
  // 3. The intermediate root must authenticate an empty append slot.
  if (
    !equalBytes(headMapRootFromProof(EMPTY_LEAF, witness.appendIndex, witness.newProof), spliced)
  ) {
    invalid("occupiedAppendSlot");
  }
  const memberLeaf = headMapLeaf(witness.member, witness.lowNext, witness.genesis);
  return headMapRootFromProof(memberLeaf, witness.appendIndex, witness.newProof);
}

/** Supplies the current member path for a spend-head replacement proof. */
export interface HeadMapTransferProofInput {
  root: Bytes32;
  member: Bytes32;
  next: Bytes32;
  spent: Bytes32;
  successor: Bytes32;
  index: bigint;
  proof: readonly Bytes32[];
}

/** Verifies the member's leaf holds `spent` under `root`, returning the root after `successor`. */
export function verifyHeadMapTransfer(witness: HeadMapTransferProofInput): Bytes32 {
  checkedIndex(witness.index);
  checkedHeadMapField(witness.root);
  if (
    bytesToBigInt(witness.member) === 0n ||
    bytesToBigInt(witness.member) >= bytesToBigInt(witness.next)
  )
    invalid("memberRange");
  if (witness.proof.length !== HEAD_MAP_HEIGHT) {
    invalid("proofLength");
  }
  const spent = headMapLeaf(witness.member, witness.next, witness.spent);
  if (!equalBytes(headMapRootFromProof(spent, witness.index, witness.proof), witness.root)) {
    invalid("headRoot");
  }
  const successor = headMapLeaf(witness.member, witness.next, witness.successor);
  return headMapRootFromProof(successor, witness.index, witness.proof);
}
