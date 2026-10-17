import type {
  MemberRecord,
  MemberRegistryPath,
  MemberOpening,
  MemberUpdate,
  RecordUpdateWitness,
} from "../interface/member-registry.js";
export type {
  MemberRecord,
  MemberRegistryPath,
  MemberOpening,
  MemberUpdate,
  RecordUpdateWitness,
} from "../interface/member-registry.js";
import { BN254_SCALAR_ORDER } from "../hasher/index.js";
import { MEMBER_REGISTRY_CAPACITY, MEMBER_REGISTRY_HEIGHT } from "../interface/member-registry.js";
import type { Bytes32 } from "../interface/types.js";
import {
  bigIntBytes,
  bytesToBigInt,
  poseidon,
  hashChain,
  ZERO_32,
  U64_MAX,
} from "../transaction/internal.js";
import { equalBytes } from "../wallet/internal.js";
import { RingError } from "./error.js";

export { MEMBER_REGISTRY_CAPACITY, MEMBER_REGISTRY_HEIGHT };
export const MAX_MEMBER_BATCH = 16;
export const MEMBER_REGISTRY_FIELD_MAX = bigIntBytes(BN254_SCALAR_ORDER - 1n) as Bytes32;
export const MEMBER_REGISTRY_EMPTY_ROOT = Uint8Array.from([
  0x27, 0x47, 0x2d, 0x6d, 0x13, 0x03, 0x74, 0x8e, 0x81, 0x79, 0x95, 0x7c, 0xa7, 0xc4, 0x14, 0x99,
  0xa1, 0x35, 0x16, 0xf1, 0x56, 0x08, 0x8e, 0x45, 0x50, 0xb9, 0x69, 0xf2, 0x50, 0x9a, 0xf2, 0x1c,
]) as Bytes32;

export function checkedRegistryField(field: Uint8Array): Bytes32 {
  if (
    !(field instanceof Uint8Array) ||
    field.length !== 32 ||
    bytesToBigInt(field) >= BN254_SCALAR_ORDER
  )
    return invalid("field");
  return field as Bytes32;
}
export function memberRegistryLeaf(record: MemberRecord): Bytes32 {
  if (typeof record.lists !== "bigint" || record.lists < 0n || record.lists > U64_MAX)
    invalid("lists");
  return poseidon(
    [record.member, record.next, bigIntBytes(record.lists), record.escrowKey].map(
      checkedRegistryField,
    ),
  );
}
export function memberRegistryZeroBytes(): Bytes32[] {
  const zeros: Bytes32[] = [new Uint8Array(32) as Bytes32];
  for (let i = 0; i < MEMBER_REGISTRY_HEIGHT; i++) {
    const prev = zeros[i]!;
    zeros.push(poseidon([prev, prev]));
  }
  return zeros;
}
export function memberRegistryRootFromProof(path: MemberRegistryPath): Bytes32 {
  checkedIndex(path.index);
  checkedRegistryField(path.leaf);
  if (path.proof.length !== MEMBER_REGISTRY_HEIGHT) invalid("pathLength");
  let node = path.leaf,
    index = path.index;
  for (const sibling of path.proof) {
    checkedRegistryField(sibling);
    node = (index & 1n) === 0n ? poseidon([node, sibling]) : poseidon([sibling, node]);
    index >>= 1n;
  }
  return node;
}
export function verifyMemberOpening(
  root: Bytes32,
  member: Bytes32,
  opening: MemberOpening,
): Readonly<{ lists: bigint; escrowKey: Bytes32 }> {
  checkedRegistryField(member);
  checkedRegistryField(root);
  if (bytesToBigInt(member) === 0n || bytesToBigInt(member) >= BN254_SCALAR_ORDER - 1n)
    invalid("member");
  const record = opening.present ? opening.record : opening.low;
  if (
    opening.present
      ? !equalBytes(record.member, member) || opening.index === 0n
      : !(
          bytesToBigInt(record.member) < bytesToBigInt(member) &&
          bytesToBigInt(member) < bytesToBigInt(record.next)
        )
  )
    invalid("memberRange");
  if (
    !equalBytes(
      memberRegistryRootFromProof({
        leaf: memberRegistryLeaf(record),
        index: opening.index,
        proof: opening.path,
      }),
      root,
    )
  )
    invalid("root");
  return opening.present
    ? { lists: record.lists, escrowKey: record.escrowKey }
    : { lists: 0n, escrowKey: ZERO_32 };
}

/** Updates authenticated paths as a batch changes their shared ancestors. */
export class MemberRegistryOverlay {
  readonly #baseIndex: bigint;
  readonly #appendPath: readonly Bytes32[];
  readonly #appendNodes: readonly Bytes32[];
  readonly #nodes = new Map<string, Bytes32>();
  constructor(root: Bytes32, nextIndex: bigint, appendPath: readonly Bytes32[]) {
    if (
      nextIndex === 0n ||
      !equalBytes(
        memberRegistryRootFromProof({ leaf: ZERO_32, index: nextIndex, proof: appendPath }),
        root,
      )
    )
      invalid("appendPath");
    this.#baseIndex = nextIndex;
    this.#appendPath = appendPath;
    const nodes: Bytes32[] = [];
    let node = ZERO_32,
      index = nextIndex;
    for (const sibling of appendPath) {
      nodes.push(node);
      node = (index & 1n) === 0n ? poseidon([node, sibling]) : poseidon([sibling, node]);
      index >>= 1n;
    }
    nodes.push(node);
    this.#appendNodes = nodes;
  }
  path(index: bigint, base?: readonly Bytes32[]): readonly Bytes32[] {
    checkedIndex(index);
    if (
      (base !== undefined && base.length !== MEMBER_REGISTRY_HEIGHT) ||
      (base === undefined && index < this.#baseIndex)
    )
      invalid("basePath");
    const zeros = memberRegistryZeroBytes();
    return Array.from({ length: MEMBER_REGISTRY_HEIGHT }, (_, level) => {
      const shift = BigInt(level),
        sibling = (index >> shift) ^ 1n;
      return (
        this.#nodes.get(`${level}:${sibling}`) ??
        (base !== undefined
          ? base[level]!
          : sibling === this.#baseIndex >> shift
            ? this.#appendNodes[level]!
            : sibling << shift >= this.#baseIndex
              ? zeros[level]!
              : this.#appendPath[level]!)
      );
    });
  }
  write(index: bigint, leaf: Bytes32, path: readonly Bytes32[]): Bytes32 {
    memberRegistryRootFromProof({ leaf, index, proof: path });
    let node = leaf,
      position = index;
    path.forEach((sibling, level) => {
      this.#nodes.set(`${level}:${position}`, node);
      node = (position & 1n) === 0n ? poseidon([node, sibling]) : poseidon([sibling, node]);
      position >>= 1n;
    });
    this.#nodes.set(`${MEMBER_REGISTRY_HEIGHT}:0`, node);
    return node;
  }
}

/** Applies one authenticated rewrite or insertion; callers retain its witness for proving. */
export function updateMemberRecord(
  input: Readonly<{
    root: Bytes32;
    nextIndex: bigint;
    member: Bytes32;
    opening: MemberOpening;
    lists: bigint;
    escrowKey: Bytes32;
    overlay: MemberRegistryOverlay;
  }>,
): Readonly<{ root: Bytes32; item: MemberUpdate; update: RecordUpdateWitness }> {
  const { member, opening, overlay } = input;
  const before = verifyMemberOpening(input.root, member, opening);
  const index = opening.present ? opening.index : input.nextIndex;
  const item: MemberUpdate = {
    member,
    oldLists: before.lists,
    oldEscrowKey: before.escrowKey,
    lists: input.lists,
    escrowKey: input.escrowKey,
    index,
  };
  const low = opening.present ? null : opening.low;
  let path: readonly Bytes32[], next: Bytes32, lowPath: readonly Bytes32[];
  if (low === null) {
    path = overlay.path(index, opening.path);
    next = opening.present ? opening.record.next : ZERO_32;
    lowPath = Array.from({ length: MEMBER_REGISTRY_HEIGHT }, () => ZERO_32);
  } else {
    lowPath = overlay.path(opening.index, opening.path);
    next = low.next;
    const spliced = overlay.write(
      opening.index,
      memberRegistryLeaf({ ...low, next: member }),
      lowPath,
    );
    path = overlay.path(index);
    if (!equalBytes(memberRegistryRootFromProof({ leaf: ZERO_32, index, proof: path }), spliced))
      invalid("occupiedAppendSlot");
  }
  const root = overlay.write(
    index,
    memberRegistryLeaf({ member, next, lists: input.lists, escrowKey: input.escrowKey }),
    path,
  );
  return {
    root,
    item,
    update: {
      exists: opening.present,
      next,
      index,
      path,
      lowMember: low?.member ?? ZERO_32,
      lowNext: low?.next ?? ZERO_32,
      lowLists: low?.lists ?? 0n,
      lowEscrow: low?.escrowKey ?? ZERO_32,
      lowIndex: low === null ? 0n : opening.index,
      lowPath,
    },
  };
}
export function updateMembersPublicInputHash(
  oldRoot: Bytes32,
  newRoot: Bytes32,
  items: readonly MemberUpdate[],
): Bytes32 {
  if (items.length === 0 || items.length > MAX_MEMBER_BATCH) invalid("batchLength");
  const fields: Bytes32[] = [bigIntBytes(BigInt(items.length)) as Bytes32];
  let previous = 0n;
  for (const item of items) {
    const member = bytesToBigInt(checkedRegistryField(item.member));
    if (member <= previous) invalid("memberOrder");
    previous = member;
    checkedIndex(item.index);
    memberRegistryLeaf({
      member: item.member,
      next: ZERO_32,
      lists: item.oldLists,
      escrowKey: item.oldEscrowKey,
    });
    memberRegistryLeaf({
      member: item.member,
      next: ZERO_32,
      lists: item.lists,
      escrowKey: item.escrowKey,
    });
    fields.push(
      item.member,
      bigIntBytes(item.oldLists) as Bytes32,
      item.oldEscrowKey,
      bigIntBytes(item.lists) as Bytes32,
      item.escrowKey,
      bigIntBytes(item.index) as Bytes32,
    );
  }
  while (fields.length < 1 + MAX_MEMBER_BATCH * 6) fields.push(ZERO_32);
  return hashChain([
    checkedRegistryField(oldRoot),
    checkedRegistryField(newRoot),
    hashChain(fields),
  ]);
}
function checkedIndex(index: bigint): void {
  if (typeof index !== "bigint" || index < 0n || index >= MEMBER_REGISTRY_CAPACITY)
    invalid("index");
}
function invalid(reason: string): never {
  throw new RingError("RING_MEMBER_REGISTRY_INVALID", { details: { reason } });
}

export interface MemberRegistryInsertProofInput {
  readonly root: Bytes32;
  readonly appendIndex: bigint;
  readonly member: Bytes32;
  readonly lists: bigint;
  readonly escrowKey: Bytes32;
  readonly lowMember: Bytes32;
  readonly lowNext: Bytes32;
  readonly lowLists: bigint;
  readonly lowEscrowKey: Bytes32;
  readonly lowIndex: bigint;
  readonly lowProof: readonly Bytes32[];
  readonly newProof: readonly Bytes32[];
}
export function verifyMemberRegistryInsert(input: MemberRegistryInsertProofInput): Bytes32 {
  if (input.appendIndex === 0n || input.lowIndex >= input.appendIndex) invalid("appendIndex");
  const low = {
    member: input.lowMember,
    next: input.lowNext,
    lists: input.lowLists,
    escrowKey: input.lowEscrowKey,
  };
  verifyMemberOpening(input.root, input.member, {
    present: false,
    low,
    index: input.lowIndex,
    path: input.lowProof,
  });
  const spliced = memberRegistryRootFromProof({
    leaf: memberRegistryLeaf({ ...low, next: input.member }),
    index: input.lowIndex,
    proof: input.lowProof,
  });
  if (
    !equalBytes(
      memberRegistryRootFromProof({
        leaf: ZERO_32,
        index: input.appendIndex,
        proof: input.newProof,
      }),
      spliced,
    )
  )
    invalid("occupiedAppendSlot");
  return memberRegistryRootFromProof({
    leaf: memberRegistryLeaf({
      member: input.member,
      next: input.lowNext,
      lists: input.lists,
      escrowKey: input.escrowKey,
    }),
    index: input.appendIndex,
    proof: input.newProof,
  });
}
