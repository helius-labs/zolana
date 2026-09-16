import { BN254_SCALAR_ORDER } from "../hasher/index.js";
import { HEAD_MAP_CAPACITY, HEAD_MAP_HEIGHT } from "../interface/head-map.js";
import type { Bytes32 } from "../interface/types.js";
import { bigIntBytes, bytesToBigInt, poseidon } from "../transaction/internal.js";
import { equalBytes } from "../wallet/internal.js";
import { RingError } from "./error.js";

export { HEAD_MAP_CAPACITY, HEAD_MAP_HEIGHT };

/** @internal The sentinel high member closing the list. */
export const HEAD_MAP_FIELD_MAX = bigIntBytes(BN254_SCALAR_ORDER - 1n) as Bytes32;

/** @internal Root of the sentinel-only tree, a fresh ring's head-map root. */
export const HEAD_MAP_EMPTY_ROOT = Uint8Array.from([
  3, 167, 83, 205, 18, 179, 81, 32, 16, 112, 166, 41, 197, 155, 154, 22, 44, 83, 161, 253, 51, 161,
  56, 203, 214, 190, 129, 75, 252, 254, 152, 14,
]) as Bytes32;

const EMPTY_LEAF = new Uint8Array(32) as Bytes32;

/** Commits one member's current record nullifier and ordered successor. */
export interface HeadMapLeaf {
  readonly member: Bytes32;
  readonly next: Bytes32;
  readonly nullifier: Bytes32;
}

/** Authenticates a leaf at its indexed tree position. */
export interface HeadMapPath {
  readonly leaf: Bytes32;
  readonly index: bigint;
  readonly proof: readonly Bytes32[];
}

/** Proves member absence and insertion after its ordered predecessor. */
export interface HeadMapInsertProofInput {
  readonly root: Bytes32;
  readonly appendIndex: bigint;
  readonly member: Bytes32;
  readonly genesis: Bytes32;
  readonly lowMember: Bytes32;
  readonly lowNext: Bytes32;
  readonly lowNullifier: Bytes32;
  readonly lowIndex: bigint;
  readonly lowProof: readonly Bytes32[];
  readonly newProof: readonly Bytes32[];
}

/** Replaces one authenticated member head without changing the member order. */
export interface HeadMapTransferProofInput {
  readonly root: Bytes32;
  readonly member: Bytes32;
  readonly next: Bytes32;
  readonly spent: Bytes32;
  readonly successor: Bytes32;
  readonly index: bigint;
  readonly proof: readonly Bytes32[];
}

export function checkedHeadMapField(field: Uint8Array): Bytes32 {
  if (
    !(field instanceof Uint8Array) ||
    field.length !== 32 ||
    bytesToBigInt(field) >= BN254_SCALAR_ORDER
  ) {
    return invalid("field");
  }
  return field as Bytes32;
}

export function headMapLeaf(leaf: HeadMapLeaf): Bytes32 {
  return poseidon([leaf.member, leaf.next, leaf.nullifier].map(checkedHeadMapField));
}

/** @internal Poseidon empty-subtree hashes, index 0 is the empty leaf, index 40 the empty root. */
export function headMapZeroBytes(): Bytes32[] {
  const zeros: Bytes32[] = [new Uint8Array(EMPTY_LEAF) as Bytes32];
  let previous: Bytes32 = EMPTY_LEAF;
  for (let level = 1; level <= HEAD_MAP_HEIGHT; level += 1) {
    previous = poseidon([previous, previous]);
    zeros.push(previous);
  }
  return zeros;
}

/** Index bits are consumed LSB-first per level. */
export function headMapRootFromProof(path: HeadMapPath): Bytes32 {
  checkedIndex(path.index);
  checkedHeadMapField(path.leaf);
  if (path.proof.length !== HEAD_MAP_HEIGHT) invalid("proofLength");
  let node = path.leaf;
  let idx = path.index;
  for (const sibling of path.proof) {
    checkedHeadMapField(sibling);
    node = (idx & 1n) === 0n ? poseidon([node, sibling]) : poseidon([sibling, node]);
    idx >>= 1n;
  }
  return node;
}

export function verifyHeadMapInsert(input: HeadMapInsertProofInput): Bytes32 {
  checkedIndex(input.appendIndex);
  checkedIndex(input.lowIndex);
  checkedHeadMapField(input.root);
  if (input.appendIndex === 0n || input.lowIndex >= input.appendIndex) invalid("appendIndex");
  if (input.lowProof.length !== HEAD_MAP_HEIGHT || input.newProof.length !== HEAD_MAP_HEIGHT) {
    invalid("proofLength");
  }
  const member = bytesToBigInt(input.member);
  // Strict predecessor order proves absence.
  if (!(bytesToBigInt(input.lowMember) < member && member < bytesToBigInt(input.lowNext))) {
    invalid("memberRange");
  }
  const low = { member: input.lowMember, nullifier: input.lowNullifier };
  const lowPath = { index: input.lowIndex, proof: input.lowProof };
  const lowOld = headMapLeaf({ ...low, next: input.lowNext });
  if (!equalBytes(headMapRootFromProof({ leaf: lowOld, ...lowPath }), input.root)) {
    invalid("lowRoot");
  }
  const lowNew = headMapLeaf({ ...low, next: input.member });
  const spliced = headMapRootFromProof({ leaf: lowNew, ...lowPath });
  const newPath = { index: input.appendIndex, proof: input.newProof };
  // The append slot must be empty under the spliced root.
  if (!equalBytes(headMapRootFromProof({ leaf: EMPTY_LEAF, ...newPath }), spliced)) {
    invalid("occupiedAppendSlot");
  }
  const memberLeaf = headMapLeaf({
    member: input.member,
    next: input.lowNext,
    nullifier: input.genesis,
  });
  return headMapRootFromProof({ leaf: memberLeaf, ...newPath });
}

export function verifyHeadMapTransfer(input: HeadMapTransferProofInput): Bytes32 {
  checkedIndex(input.index);
  checkedHeadMapField(input.root);
  if (
    bytesToBigInt(input.member) === 0n ||
    bytesToBigInt(input.member) >= bytesToBigInt(input.next)
  )
    invalid("memberRange");
  if (input.proof.length !== HEAD_MAP_HEIGHT) {
    invalid("proofLength");
  }
  const path = { index: input.index, proof: input.proof };
  const spent = headMapLeaf({ member: input.member, next: input.next, nullifier: input.spent });
  if (!equalBytes(headMapRootFromProof({ leaf: spent, ...path }), input.root)) {
    invalid("headRoot");
  }
  const successor = headMapLeaf({
    member: input.member,
    next: input.next,
    nullifier: input.successor,
  });
  return headMapRootFromProof({ leaf: successor, ...path });
}

function checkedIndex(index: bigint): void {
  if (typeof index !== "bigint" || index < 0n || index >= HEAD_MAP_CAPACITY) invalid("index");
}

function invalid(reason: string): never {
  throw new RingError("RING_HEAD_MAP_INVALID", { details: { reason } });
}
