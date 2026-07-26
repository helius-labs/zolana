import type { Address, Bytes32 } from "@zolana/interface";
import { BN254_MODULUS_DEC } from "@zolana/transaction";

import {
  IndexedMerkleTree,
  MerkleTree,
  poseidonHasher,
} from "../../../merkle-tree/src/index.js";
import type { SpendProof } from "../../src/rpc.js";

const STATE_TREE_HEIGHT = 32;
const NULLIFIER_TREE_HEIGHT = 40;

function modulusMinusOne(): Bytes32 {
  const value = BigInt(BN254_MODULUS_DEC) - 1n;
  const bytes = new Uint8Array(32);
  let remaining = value;
  for (let index = 31; index >= 0; index -= 1) {
    bytes[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return bytes as Bytes32;
}

/// In-process Poseidon trees that produce spend proofs the transfer circuits
/// accept. Mirrors `sdk-libs/client/tests/test_indexer.rs`.
export class ProveIndexer {
  readonly #state = new MerkleTree(STATE_TREE_HEIGHT, poseidonHasher);
  readonly #nullifiers = new IndexedMerkleTree(NULLIFIER_TREE_HEIGHT, poseidonHasher, {
    highestValue: modulusMinusOne(),
  });
  readonly #leafIndex = new Map<string, bigint>();
  readonly #tree: Address;

  constructor(tree: Address) {
    this.#tree = tree;
  }

  addUtxo(utxoHash: Bytes32): void {
    const key = hex(utxoHash);
    if (this.#leafIndex.has(key)) {
      throw new Error(`utxo already indexed: ${key}`);
    }
    const index = this.#state.append(utxoHash);
    this.#leafIndex.set(key, index);
  }

  spendProof(utxoHash: Bytes32, nullifier: Bytes32): SpendProof {
    const leafIndex = this.#leafIndex.get(hex(utxoHash));
    if (leafIndex === undefined) {
      throw new Error(`utxo hash not indexed; call addUtxo first: ${hex(utxoHash)}`);
    }
    const nonInclusion = this.#nullifiers.nonInclusionProof(nullifier);
    return {
      state: {
        leaf: utxoHash,
        merkleContext: { treeType: 1, tree: this.#tree },
        path: this.#state.proof(leafIndex),
        leafIndex,
        root: this.#state.root(),
        rootSeq: 0n,
        rootIndex: 0,
      },
      nullifier: {
        leaf: nullifier,
        merkleContext: { treeType: 2, tree: this.#tree },
        path: nonInclusion.merkleProof,
        lowElement: nonInclusion.leafLowerRangeValue,
        lowElementIndex: nonInclusion.leafIndex,
        highElement: nonInclusion.leafHigherRangeValue,
        // Matches `sdk-libs/client/tests/test_indexer.rs`.
        highElementIndex: 0n,
        root: nonInclusion.root,
        rootSeq: 0n,
        rootIndex: 0,
      },
    };
  }
}

function hex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
