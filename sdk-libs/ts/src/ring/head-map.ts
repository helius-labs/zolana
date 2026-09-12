// The member-keyed indexed tree behind the compressed velocity rail, mirroring
// the Rust `zolana_ring_head_map` reference and the Go circuit: the leaf is
// Poseidon(member, next, nullifier) and the root advances with the on-chain
// root. Photon maintains the tree and serves witnesses, the client verifies
// them here before proving.

import type { Bytes32 } from "../interface/types.js";
import { bytesToBigInt, poseidon } from "../transaction/internal.js";
import { equalBytes } from "../wallet/internal.js";

/** Matches the circuit height and the on-chain root. */
export const HEAD_MAP_HEIGHT = 40;

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
  return poseidon([member, next, nullifier]);
}

/** Poseidon empty-subtree hashes, index 0 is the empty leaf, index 40 the empty root. */
export function headMapZeroBytes(): Bytes32[] {
  const zeros: Bytes32[] = [EMPTY_LEAF];
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
  let node = leaf;
  let idx = index;
  for (const sibling of proof) {
    node = (idx & 1n) === 0n ? poseidon([node, sibling]) : poseidon([sibling, node]);
    idx >>= 1n;
  }
  return node;
}

export interface HeadMapInsertWitness {
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
export function verifyHeadMapInsert(witness: HeadMapInsertWitness): Bytes32 {
  if (witness.lowProof.length !== HEAD_MAP_HEIGHT || witness.newProof.length !== HEAD_MAP_HEIGHT) {
    throw new Error("head map: proof length");
  }
  const member = bytesToBigInt(witness.member);
  // Strict order proves the member absent between the low element and its successor.
  if (!(bytesToBigInt(witness.lowMember) < member && member < bytesToBigInt(witness.lowNext))) {
    throw new Error("head map: member out of range");
  }
  const lowOld = headMapLeaf(witness.lowMember, witness.lowNext, witness.lowNullifier);
  if (!equalBytes(headMapRootFromProof(lowOld, witness.lowIndex, witness.lowProof), witness.root)) {
    throw new Error("head map: low element root mismatch");
  }
  const lowNew = headMapLeaf(witness.lowMember, witness.member, witness.lowNullifier);
  const spliced = headMapRootFromProof(lowNew, witness.lowIndex, witness.lowProof);
  // A non-empty append slot would overwrite a live member.
  if (!equalBytes(headMapRootFromProof(EMPTY_LEAF, witness.appendIndex, witness.newProof), spliced)) {
    throw new Error("head map: append slot occupied");
  }
  const memberLeaf = headMapLeaf(witness.member, witness.lowNext, witness.genesis);
  return headMapRootFromProof(memberLeaf, witness.appendIndex, witness.newProof);
}

export interface HeadMapTransferWitness {
  root: Bytes32;
  member: Bytes32;
  next: Bytes32;
  spent: Bytes32;
  successor: Bytes32;
  index: bigint;
  proof: readonly Bytes32[];
}

/** Verifies the member's leaf holds `spent` under `root`, returning the root after `successor`. */
export function verifyHeadMapTransfer(witness: HeadMapTransferWitness): Bytes32 {
  if (witness.proof.length !== HEAD_MAP_HEIGHT) {
    throw new Error("head map: proof length");
  }
  const spent = headMapLeaf(witness.member, witness.next, witness.spent);
  if (!equalBytes(headMapRootFromProof(spent, witness.index, witness.proof), witness.root)) {
    throw new Error("head map: head root mismatch");
  }
  const successor = headMapLeaf(witness.member, witness.next, witness.successor);
  return headMapRootFromProof(successor, witness.index, witness.proof);
}
