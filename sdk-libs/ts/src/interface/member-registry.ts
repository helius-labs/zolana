import type { Bytes32 } from "./types.js";
/** Rust `MEMBER_REGISTRY_HEIGHT`, the circuit and the on-chain root share it. */
export const MEMBER_REGISTRY_HEIGHT = 20;
export const MEMBER_REGISTRY_CAPACITY = 1n << BigInt(MEMBER_REGISTRY_HEIGHT);

/** Eligibility for the fixed policy proof. The proof authenticates every index. */
export function shareMemberSubtree(indices: readonly bigint[]): boolean {
  let prefix: bigint | undefined;
  for (const index of indices) {
    if (typeof index !== "bigint" || index < 0n || index >= MEMBER_REGISTRY_CAPACITY) return false;
    const current = index >> 3n;
    if (prefix !== undefined && current !== prefix) return false;
    prefix = current;
  }
  return true;
}

export interface MemberRecord {
  readonly member: Bytes32;
  readonly next: Bytes32;
  readonly lists: bigint;
  readonly escrowKey: Bytes32;
}
export interface MemberRegistryPath {
  readonly leaf: Bytes32;
  readonly index: bigint;
  readonly proof: readonly Bytes32[];
}
export type MemberOpening =
  | Readonly<{ present: true; record: MemberRecord; index: bigint; path: readonly Bytes32[] }>
  | Readonly<{ present: false; low: MemberRecord; index: bigint; path: readonly Bytes32[] }>;
export interface MemberUpdate {
  readonly member: Bytes32;
  readonly oldLists: bigint;
  readonly oldEscrowKey: Bytes32;
  readonly lists: bigint;
  readonly escrowKey: Bytes32;
  readonly index: bigint;
}
export interface RecordUpdateWitness {
  readonly exists: boolean;
  readonly next: Bytes32;
  readonly index: bigint;
  readonly path: readonly Bytes32[];
  readonly lowMember: Bytes32;
  readonly lowNext: Bytes32;
  readonly lowLists: bigint;
  readonly lowEscrow: Bytes32;
  readonly lowIndex: bigint;
  readonly lowPath: readonly Bytes32[];
}
