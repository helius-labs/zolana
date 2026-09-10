import { type Address, type Signature } from "@solana/kit";
import { expect, vi } from "vitest";

import type { MerkleProof, NonInclusionProof, RpcAccount } from "../../src/client/rpc.js";
import { SHIELDED_POOL_PROGRAM_ID } from "../../src/interface/program.js";
import type { Bytes32 } from "../../src/interface/types.js";
import {
  RingListNamespace,
  encodeListEntry,
  type EntryState,
  type ListEntry,
  type ListId,
  type Member,
} from "../../src/ring/policy.js";
import type { IndexedShieldedTransaction } from "../../src/transaction/instructions/transact.js";

import { transactionsPage } from "./clients.js";
import { filled, treeAccount } from "./tree-account.js";

export interface Lineage {
  readonly spenders: readonly IndexedShieldedTransaction[];
  readonly live: ListEntry;
  readonly utxoHash: Bytes32;
  readonly nullifier: Bytes32;
  readonly address: Bytes32;
}

/** One version per state, each spending the previous, the first spends the address. */
export function lineage(
  input: Readonly<{
    namespace: Address;
    tree: Address;
    treeId?: number;
    listId: ListId;
    member: Member;
    states: readonly EntryState[];
  }>,
): Lineage {
  const namespace = RingListNamespace.of(input.namespace, input.treeId ?? 0);
  const address = namespace.entryAddress(input);
  let spent = address;
  const spenders: IndexedShieldedTransaction[] = [];
  let last: Readonly<{ entry: ListEntry; utxoHash: Bytes32; nullifier: Bytes32 }> | undefined;
  input.states.forEach((state, version) => {
    const entry: ListEntry = {
      listId: input.listId,
      member: input.member,
      state,
      version: BigInt(version),
      contentHash: filled(0) as Bytes32,
      blinding: filled(version + 1) as Bytes32,
    };
    const hashes = namespace.entryHashes(entry);
    spenders.push({
      slot: 5n,
      txSignature: String(version).repeat(87) as Signature,
      outputSlots: [
        {
          viewTag: filled(0) as Bytes32,
          outputContext: { hash: hashes.utxoHash, tree: input.tree, leafIndex: BigInt(version) },
          payload: encodeListEntry(entry),
        },
      ],
      messages: [],
      nullifiers: [spent],
      proofless: false,
    });
    spent = hashes.nullifier;
    last = { entry, utxoHash: hashes.utxoHash, nullifier: hashes.nullifier };
  });
  if (last === undefined) throw new Error("a lineage needs one state");
  return {
    spenders,
    live: last.entry,
    utxoHash: last.utxoHash,
    nullifier: last.nullifier,
    address,
  };
}

export interface HistoryRoot {
  readonly value: Bytes32;
  readonly index: number;
}

/** Mirrors the Rust `ProofRpc` fake, every leaf answered under the root at its position. */
export function entryProofReads(
  options: Readonly<{
    tree: Address;
    spenders?: readonly IndexedShieldedTransaction[];
    stateRoots?: readonly HistoryRoot[];
    nullifierRoots?: readonly HistoryRoot[];
    account?: boolean;
  }>,
) {
  const spenders = options.spenders ?? [];
  const stateRoots = options.stateRoots ?? [{ value: filled(1) as Bytes32, index: 3 }];
  const nullifierRoots = options.nullifierRoots ?? [{ value: filled(2) as Bytes32, index: 4 }];
  const root = (roots: readonly HistoryRoot[], position: number): HistoryRoot =>
    roots[Math.min(position, roots.length - 1)] ?? { value: filled(0) as Bytes32, index: 0 };
  const requests: Bytes32[][] = [];
  const merkle: Bytes32[][] = [];
  const nonInclusion: Bytes32[][] = [];
  const reads = {
    accounts: 0,
    requests,
    merkle,
    nonInclusion,
    getAccount: vi.fn(async (address: Address): Promise<RpcAccount | undefined> => {
      expect(address).toBe(options.tree);
      reads.accounts += 1;
      return options.account
        ? {
            owner: SHIELDED_POOL_PROGRAM_ID,
            lamports: 1n,
            data: treeAccount({ stateCursor: 4, written: 5, nullifierCursor: 6n }),
          }
        : undefined;
    }),
    getEncryptedUtxosByTags: vi.fn(async () => {
      throw new Error("unused");
    }),
    getShieldedTransactionsByNullifiers: vi.fn(
      async (request: { nullifiers: readonly Bytes32[] }) => {
        requests.push([...request.nullifiers]);
        return transactionsPage({
          transactions: spenders.filter((spender) =>
            spender.nullifiers.some((spent) =>
              request.nullifiers.some((asked) => Buffer.from(asked).equals(spent)),
            ),
          ),
          scannedThrough: new Uint8Array([1]),
        });
      },
    ),
    getMerkleProofs: vi.fn(async (tree: Address, leaves: readonly Bytes32[]) => {
      expect(tree).toBe(options.tree);
      merkle.push([...leaves]);
      return {
        context: { blockTime: 0n, slot: 0n },
        proofs: leaves.map((leaf, position): MerkleProof => {
          const history = root(stateRoots, position);
          return {
            leaf,
            merkleContext: { treeType: 0, tree: options.tree },
            path: Array.from({ length: 32 }, () => filled(position) as Bytes32),
            leafIndex: BigInt(position),
            root: history.value,
            rootSeq: 0n,
            rootIndex: history.index,
          };
        }),
      };
    }),
    getNonInclusionProofs: vi.fn(async (tree: Address, leaves: readonly Bytes32[]) => {
      expect(tree).toBe(options.tree);
      nonInclusion.push([...leaves]);
      return {
        context: { blockTime: 0n, slot: 0n },
        proofs: leaves.map((leaf, position): NonInclusionProof => {
          const history = root(nullifierRoots, position);
          return {
            leaf,
            merkleContext: { treeType: 1, tree: options.tree },
            path: Array.from({ length: 40 }, () => filled(0) as Bytes32),
            lowElement: filled(position) as Bytes32,
            lowElementIndex: BigInt(position),
            highElement: filled(0xff) as Bytes32,
            highElementIndex: BigInt(position + 1),
            root: history.value,
            rootSeq: 0n,
            rootIndex: history.index,
          };
        }),
      };
    }),
  };
  return reads;
}

/** The head roots `treeAccount({ stateCursor: 4, written: 5, nullifierCursor: 6n })` decodes to. */
export const FIXTURE_HEADS = Object.freeze({
  stateRoot: filled(0x14) as Bytes32,
  stateRootIndex: 4,
  nullifierRoot: filled(0x25) as Bytes32,
  nullifierRootIndex: 5,
});
