import type { RingMemberOpening, RingSealedKey } from "../../src/client/ports.js";
import {
  QUAD_ARITY,
  QUAD_HEIGHT,
  type MemberRecord,
  type QuadPath,
} from "../../src/interface/member-registry.js";
import type { Bytes32 } from "../../src/interface/types.js";
import { FIELD_MAX, memberRecordHash } from "../../src/ring/member-registry.js";
import { ZERO_32, bytesToBigInt, poseidon } from "../../src/transaction/internal.js";

/** One record the fixture holds, its key escrow served beside it when `sealed` is set. */
export interface FixtureRecord {
  readonly member: Bytes32;
  readonly lists: bigint;
  readonly escrowKey?: Bytes32;
  readonly sealed?: RingSealedKey;
}

/** An independent sparse 4-ary record tree, leaf 0 the sentinel and the members in key order after it. */
export function recordTree(records: readonly FixtureRecord[] = []) {
  const sorted = [...records].sort((a, b) =>
    bytesToBigInt(a.member) < bytesToBigInt(b.member) ? -1 : 1,
  );
  const rows: MemberRecord[] = [
    { member: ZERO_32, lists: 0n, escrowKey: ZERO_32, next: sorted[0]?.member ?? FIELD_MAX },
    ...sorted.map((record, index) => ({
      member: record.member,
      lists: record.lists,
      escrowKey: record.escrowKey ?? ZERO_32,
      next: sorted[index + 1]?.member ?? FIELD_MAX,
    })),
  ];
  const zeros = [ZERO_32];
  for (let level = 0; level < QUAD_HEIGHT; level += 1) {
    const below = zeros[level] ?? ZERO_32;
    zeros.push(poseidon([below, below, below, below]));
  }
  const layers: Map<number, Bytes32>[] = [
    new Map(rows.map((row, index) => [index, memberRecordHash(row)])),
  ];
  for (let level = 0; level < QUAD_HEIGHT; level += 1) {
    const below = layers[level] ?? new Map<number, Bytes32>();
    const above = new Map<number, Bytes32>();
    for (const index of below.keys()) {
      const parent = index >> 2;
      if (above.has(parent)) continue;
      const children = Array.from(
        { length: QUAD_ARITY },
        (_, child) => below.get(parent * QUAD_ARITY + child) ?? zeros[level] ?? ZERO_32,
      );
      above.set(parent, poseidon(children));
    }
    layers.push(above);
  }
  const root = layers[QUAD_HEIGHT]?.get(0) ?? ZERO_32;
  const path = (index: number): QuadPath => ({
    index,
    siblings: Array.from({ length: QUAD_HEIGHT }, (_, level) => {
      const node = index >> (2 * level);
      const parent = node >> 2;
      return Array.from({ length: QUAD_ARITY }, (_, child) => parent * QUAD_ARITY + child)
        .filter((sibling) => sibling !== node)
        .map((sibling) => layers[level]?.get(sibling) ?? zeros[level] ?? ZERO_32);
    }),
  });
  const opening = (member: Bytes32): RingMemberOpening => {
    const index = rows.findIndex(
      (row, at) => at > 0 && bytesToBigInt(row.member) === bytesToBigInt(member),
    );
    const record = rows[index];
    if (index > 0 && record !== undefined) {
      const sealed = sorted[index - 1]?.sealed;
      return {
        kind: "present",
        record,
        path: path(index),
        ...(sealed === undefined ? {} : { sealedKey: sealed }),
      };
    }
    const value = bytesToBigInt(member);
    const lowIndex = rows.findIndex(
      (row) => bytesToBigInt(row.member) < value && value < bytesToBigInt(row.next),
    );
    const low = rows[lowIndex];
    if (low === undefined) throw new Error("member outside the fixture registry");
    return { kind: "absent", low, path: path(lowIndex) };
  };
  return { root, nextIndex: rows.length, rows, path, opening };
}
