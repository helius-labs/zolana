import { BN254_SCALAR_ORDER } from "../hasher/index.js";
import { KEY_REGISTRY_CAPACITY, KEY_REGISTRY_HEIGHT } from "../interface/key-registry.js";
import type { Bytes32 } from "../interface/types.js";
import { bigIntBytes, bytesToBigInt, poseidon } from "../transaction/internal.js";
import { equalBytes } from "../wallet/internal.js";
import { RingError } from "./error.js";

export { KEY_REGISTRY_CAPACITY, KEY_REGISTRY_HEIGHT };

/** @internal The sentinel high member closing the list. */
export const KEY_REGISTRY_FIELD_MAX = bigIntBytes(BN254_SCALAR_ORDER - 1n) as Bytes32;

/** @internal Root of the sentinel-only tree, a fresh ring's key registry root. */
export const KEY_REGISTRY_EMPTY_ROOT = Uint8Array.from([
  3, 167, 83, 205, 18, 179, 81, 32, 16, 112, 166, 41, 197, 155, 154, 22, 44, 83, 161, 253, 51, 161,
  56, 203, 214, 190, 129, 75, 252, 254, 152, 14,
]) as Bytes32;

const EMPTY_LEAF = new Uint8Array(32) as Bytes32;

export interface KeyRegistryLeaf {
  readonly member: Bytes32;
  readonly next: Bytes32;
  readonly key: Bytes32;
}

/** Authenticates a leaf at its indexed tree position. */
export interface KeyRegistryPath {
  readonly leaf: Bytes32;
  readonly index: bigint;
  readonly proof: readonly Bytes32[];
}

/** Proves member absence and insertion after its ordered predecessor. */
export interface KeyRegistryInsertProofInput {
  readonly root: Bytes32;
  readonly appendIndex: bigint;
  readonly member: Bytes32;
  readonly key: Bytes32;
  readonly lowMember: Bytes32;
  readonly lowNext: Bytes32;
  readonly lowKey: Bytes32;
  readonly lowIndex: bigint;
  readonly lowProof: readonly Bytes32[];
  readonly newProof: readonly Bytes32[];
}

export function checkedRegistryField(field: Uint8Array): Bytes32 {
  if (
    !(field instanceof Uint8Array) ||
    field.length !== 32 ||
    bytesToBigInt(field) >= BN254_SCALAR_ORDER
  ) {
    return invalid("field");
  }
  return field as Bytes32;
}

export function keyRegistryLeaf(leaf: KeyRegistryLeaf): Bytes32 {
  return poseidon([leaf.member, leaf.next, leaf.key].map(checkedRegistryField));
}

/** @internal Poseidon empty-subtree hashes, index 0 is the empty leaf, index 40 the empty root. */
export function keyRegistryZeroBytes(): Bytes32[] {
  const zeros: Bytes32[] = [new Uint8Array(EMPTY_LEAF) as Bytes32];
  let previous: Bytes32 = EMPTY_LEAF;
  for (let level = 1; level <= KEY_REGISTRY_HEIGHT; level += 1) {
    previous = poseidon([previous, previous]);
    zeros.push(previous);
  }
  return zeros;
}

/** Index bits are consumed LSB-first per level. */
export function keyRegistryRootFromProof(path: KeyRegistryPath): Bytes32 {
  checkedIndex(path.index);
  checkedRegistryField(path.leaf);
  if (path.proof.length !== KEY_REGISTRY_HEIGHT) invalid("proofLength");
  let node = path.leaf;
  let idx = path.index;
  for (const sibling of path.proof) {
    checkedRegistryField(sibling);
    node = (idx & 1n) === 0n ? poseidon([node, sibling]) : poseidon([sibling, node]);
    idx >>= 1n;
  }
  return node;
}

export function verifyKeyRegistryInsert(input: KeyRegistryInsertProofInput): Bytes32 {
  checkedIndex(input.appendIndex);
  checkedIndex(input.lowIndex);
  checkedRegistryField(input.root);
  if (input.appendIndex === 0n || input.lowIndex >= input.appendIndex) invalid("appendIndex");
  if (
    input.lowProof.length !== KEY_REGISTRY_HEIGHT ||
    input.newProof.length !== KEY_REGISTRY_HEIGHT
  ) {
    invalid("proofLength");
  }
  const member = bytesToBigInt(input.member);
  // Strict predecessor order proves absence.
  if (!(bytesToBigInt(input.lowMember) < member && member < bytesToBigInt(input.lowNext))) {
    invalid("memberRange");
  }
  const low = { member: input.lowMember, key: input.lowKey };
  const lowPath = { index: input.lowIndex, proof: input.lowProof };
  const lowOld = keyRegistryLeaf({ ...low, next: input.lowNext });
  if (!equalBytes(keyRegistryRootFromProof({ leaf: lowOld, ...lowPath }), input.root)) {
    invalid("lowRoot");
  }
  const lowNew = keyRegistryLeaf({ ...low, next: input.member });
  const spliced = keyRegistryRootFromProof({ leaf: lowNew, ...lowPath });
  const newPath = { index: input.appendIndex, proof: input.newProof };
  // The append slot must be empty under the spliced root.
  if (!equalBytes(keyRegistryRootFromProof({ leaf: EMPTY_LEAF, ...newPath }), spliced)) {
    invalid("occupiedAppendSlot");
  }
  const memberLeaf = keyRegistryLeaf({
    member: input.member,
    next: input.lowNext,
    key: input.key,
  });
  return keyRegistryRootFromProof({ leaf: memberLeaf, ...newPath });
}

function checkedIndex(index: bigint): void {
  if (typeof index !== "bigint" || index < 0n || index >= KEY_REGISTRY_CAPACITY) invalid("index");
}

function invalid(reason: string): never {
  throw new RingError("RING_KEY_REGISTRY_INVALID", { details: { reason } });
}
