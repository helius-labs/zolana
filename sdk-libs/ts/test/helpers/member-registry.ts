import { poseidon } from "../../src/transaction/internal.js";
import { X25519PublicKey } from "../../src/keypair/x25519.js";
import type { RingMemberRecordResponse } from "../../src/client/ports.js";
import { Writer } from "../../src/interface/internal.js";
import type { Bytes32 } from "../../src/interface/types.js";
import type { NullifierKey } from "../../src/keypair/nullifier-key.js";

import { RING_MEMBER_REGISTRY_ROOT_HISTORY } from "../../src/ring/codecs.js";
import {
  MEMBER_REGISTRY_EMPTY_ROOT,
  MEMBER_REGISTRY_FIELD_MAX,
  memberRegistryLeaf,
  memberRegistryZeroBytes,
  verifyMemberRegistryInsert,
} from "../../src/ring/member-registry-tree.js";
import { registeredKeyHash, sealNullifierKey } from "../../src/ring/member-registry.js";

const ZERO = new Uint8Array(32) as Bytes32;

/** The sentinel-only registry and the insertion of `member` at slot 1. */
export function firstInsertion(member: Bytes32) {
  const zeros = memberRegistryZeroBytes();
  return {
    lowMember: ZERO,
    lowNext: MEMBER_REGISTRY_FIELD_MAX,
    lowKeyHash: ZERO,
    lowIndex: 0n,
    lowProof: zeros.slice(0, 20),
    newProof: [
      memberRegistryLeaf({ member: ZERO, next: member, lists: 0n, escrowKey: ZERO }),
      ...zeros.slice(1, 20),
    ],
  };
}

/** Rust `MemberRegistryRoot` bytes, `root` sits in `history` at `cursor`. */
export function memberRegistryRootData(
  input: Readonly<{
    root: Bytes32;
    nextIndex: bigint;
    bump: number;
    cursor?: number;
    history?: readonly Bytes32[];
  }>,
): Uint8Array {
  const cursor = input.cursor ?? 0;
  const writer = new Writer()
    .u8(9, "discriminator")
    .u64(input.nextIndex, "nextIndex")
    .u8(input.bump, "bump")
    .u8(cursor, "historyCursor");
  for (let slot = 0; slot < RING_MEMBER_REGISTRY_ROOT_HISTORY; slot++) {
    writer.bytes(slot === cursor ? input.root : (input.history?.[slot] ?? ZERO));
  }
  return writer.finish();
}

/** A registry holding `member`'s key alone, the indexer entry opens it under the new root. */
export function oneMemberRegistry(
  input: Readonly<{ member: Bytes32; nullifierKey: NullifierKey; auditor: X25519PublicKey }>,
): Readonly<{ root: Bytes32; entry: RingMemberRecordResponse }> {
  const insertion = firstInsertion(input.member);
  const envelope = sealNullifierKey(input.nullifierKey, input.auditor);
  envelope.ephemeralSecret.fill(0);
  const root = verifyMemberRegistryInsert({
    root: MEMBER_REGISTRY_EMPTY_ROOT,
    appendIndex: 1n,
    member: input.member,
    lists: 0n,
    escrowKey: registeredKeyHash({
      nullifierPublicKey: envelope.nullifierPublicKey,
      ciphertext: envelope.sealed.ciphertext,
    }),
    lowMember: insertion.lowMember,
    lowNext: insertion.lowNext,
    lowLists: 0n,
    lowEscrowKey: insertion.lowKeyHash,
    lowIndex: insertion.lowIndex,
    lowProof: insertion.lowProof,
    newProof: insertion.newProof,
  });
  return {
    root,
    entry: {
      context: { slot: 1n, blockTime: 1n },
      root,
      nextIndex: 2n,
      rootIndex: 1,
      present: true,
      record: {
        member: input.member,
        next: MEMBER_REGISTRY_FIELD_MAX,
        lists: 0n,
        escrowKey: registeredKeyHash({
          nullifierPublicKey: envelope.nullifierPublicKey,
          ciphertext: envelope.sealed.ciphertext,
        }),
        ephemeralPublicKey: envelope.sealed.ephemeralPublicKey,
        ciphertext: envelope.sealed.ciphertext,
      },
      low: null,
      index: 1n,
      path: insertion.newProof,
    },
  };
}

export function emptyMemberRecord(): RingMemberRecordResponse {
  return {
    context: { slot: 1n, blockTime: 1n },
    root: MEMBER_REGISTRY_EMPTY_ROOT,
    rootIndex: 0,
    nextIndex: 1n,
    present: false,
    record: null,
    index: 0n,
    path: [],
    low: {
      member: ZERO,
      next: MEMBER_REGISTRY_FIELD_MAX,
      lists: 0n,
      escrowKey: ZERO,
      index: 0n,
      path: memberRegistryZeroBytes().slice(0, 20),
    },
  };
}
export function emptyRegistryTip() {
  const zeros = memberRegistryZeroBytes();
  return {
    context: { slot: 1n, blockTime: 1n },
    root: MEMBER_REGISTRY_EMPTY_ROOT,
    rootIndex: 0,
    nextIndex: 1n,
    appendPath: [
      memberRegistryLeaf({
        member: ZERO,
        next: MEMBER_REGISTRY_FIELD_MAX,
        lists: 0n,
        escrowKey: ZERO,
      }),
      ...zeros.slice(1, 20),
    ],
  };
}

/** Independent sparse reference tree for authenticated member reads. */
export function registryFixture(
  records: readonly Readonly<{
    member: Bytes32;
    lists: bigint;
    escrowKey?: Bytes32;
    sealed?: Readonly<{ ephemeralPublicKey: X25519PublicKey; ciphertext: Bytes32 }>;
  }>[] = [],
) {
  const sorted = [...records].sort((a, b) => Buffer.compare(a.member, b.member));
  const rows = [{ member: ZERO, lists: 0n, escrowKey: ZERO }, ...sorted].map((row, index) => ({
    ...row,
    escrowKey: row.escrowKey ?? ZERO,
    next: sorted[index]?.member ?? MEMBER_REGISTRY_FIELD_MAX,
  }));
  const zeros = memberRegistryZeroBytes();
  const layers: Array<Map<number, Bytes32>> = [
    new Map(rows.map((row, index) => [index, memberRegistryLeaf(row)])),
  ];
  for (let level = 0; level < 20; level++) {
    const before = layers[level]!,
      after = new Map<number, Bytes32>();
    for (const index of before.keys()) {
      const parent = Math.floor(index / 2);
      after.set(
        parent,
        poseidon([
          before.get(parent * 2) ?? zeros[level]!,
          before.get(parent * 2 + 1) ?? zeros[level]!,
        ]),
      );
    }
    layers.push(after);
  }
  const root = layers[20]!.get(0)!;
  const path = (index: number) =>
    Array.from(
      { length: 20 },
      (_, level) => layers[level]!.get(Math.floor(index / 2 ** level) ^ 1) ?? zeros[level]!,
    );
  const tip = {
    context: { slot: 1n, blockTime: 1n },
    root,
    rootIndex: 0,
    nextIndex: BigInt(rows.length),
    appendPath: path(rows.length),
  };
  const read = (member: Bytes32): RingMemberRecordResponse => {
    const index = rows.findIndex((row) => Buffer.compare(row.member, member) === 0);
    const common = { context: tip.context, root, rootIndex: 0, nextIndex: tip.nextIndex };
    if (index > 0) {
      const row = rows[index]!,
        sealed = sorted[index - 1]?.sealed;
      return {
        ...common,
        present: true,
        index: BigInt(index),
        path: path(index),
        record: {
          ...row,
          ephemeralPublicKey: sealed?.ephemeralPublicKey ?? null,
          ciphertext: sealed?.ciphertext ?? null,
        },
        low: null,
      };
    }
    const lowIndex = rows.findIndex(
      (row) => Buffer.compare(row.member, member) < 0 && Buffer.compare(member, row.next) < 0,
    );
    if (lowIndex < 0) throw new Error("member outside reference registry");
    return {
      ...common,
      present: false,
      index: 0n,
      path: [],
      record: null,
      low: { ...rows[lowIndex]!, index: BigInt(lowIndex), path: path(lowIndex) },
    };
  };
  return { root, tip, read };
}
