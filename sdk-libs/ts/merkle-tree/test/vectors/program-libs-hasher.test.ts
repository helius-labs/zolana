import { describe, expect, it } from "vitest";

import fixture from "../../../vectors/program-libs-parity-v1.json" with { type: "json" };
import { bigintToBytes, bytes32, type Bytes32 } from "../../src/bytes.js";
import { keccakHasher, poseidonHasher, sha256Hasher } from "../../src/hashers.js";
import { IndexedMerkleTree } from "../../src/indexed.js";
import { CoreMerkleTree, type Hasher32 } from "../../src/merkle-tree.js";

function hexToBytes(hex: string): Bytes32 {
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes as Bytes32;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

// `hashers.ts` exposes only the two-input `hash` and one-input `hashBytes` a
// Merkle tree needs, so the Rust `hashv` vectors it can reach are the ones with
// one 32-byte input or two.
function reachableVectors(
  vectors: readonly { name: string; inputs: readonly string[]; hashv: string }[],
): readonly { name: string; inputs: readonly string[]; hashv: string }[] {
  return vectors.filter(
    (vector) =>
      vector.inputs.length <= 2 && vector.inputs.every((input) => input.length === 64),
  );
}

describe("program-libs/hasher/src/sha256.rs against sha256Hasher", () => {
  for (const vector of reachableVectors(fixture.hasher.sha256.vectors)) {
    it(`matches Sha256::hashv for ${vector.name}`, () => {
      const inputs = vector.inputs.map(hexToBytes);
      const [first, second] = inputs;
      if (first === undefined) return;
      const actual =
        second === undefined ? sha256Hasher.hashBytes(first) : sha256Hasher.hash(first, second);
      expect(bytesToHex(actual)).toBe(vector.hashv);
    });
  }

  it("concatenates its inputs rather than hashing them separately", () => {
    const pair = fixture.hasher.sha256.vectors.find((entry) => entry.name === "pair-one-two");
    const reversed = fixture.hasher.sha256.vectors.find(
      (entry) => entry.name === "pair-asymmetric",
    );
    expect(pair?.hashv).not.toBe(reversed?.hashv);
  });

  it("reports the Sha256BE variant that zeroes byte 0, which TypeScript does not port", () => {
    // Recorded rather than asserted against a TypeScript implementation: no SDK
    // caller reaches Sha256BE, so the port has no counterpart to compare.
    const zeros = fixture.hasher.sha256.vectors.find((entry) => entry.name === "zeros-32");
    expect(zeros?.sha256Be.slice(0, 2)).toBe("00");
    expect(zeros?.sha256Be.slice(2)).toBe(zeros?.hashv.slice(2));
  });
});

describe("program-libs/hasher/src/keccak.rs against keccakHasher", () => {
  for (const vector of reachableVectors(fixture.hasher.keccak.vectors)) {
    it(`matches Keccak::hashv for ${vector.name}`, () => {
      const inputs = vector.inputs.map(hexToBytes);
      const [first, second] = inputs;
      if (first === undefined) return;
      const actual =
        second === undefined ? keccakHasher.hashBytes(first) : keccakHasher.hash(first, second);
      expect(bytesToHex(actual)).toBe(vector.hashv);
    });
  }
});

describe("program-libs/hasher/src/lib.rs Hasher trait", () => {
  it("agrees on the 32-byte digest width", () => {
    expect(fixture.hasher.trait.hashBytes).toBe(32);
    expect(poseidonHasher.hashBytes(hexToBytes("00".repeat(32))).length).toBe(32);
    expect(sha256Hasher.hashBytes(hexToBytes("00".repeat(32))).length).toBe(32);
    expect(keccakHasher.hashBytes(hexToBytes("00".repeat(32))).length).toBe(32);
  });

  it("records the Rust ID discriminants, which the port does not carry", () => {
    // `Hasher::ID` selects a hasher in on-chain account headers. The TypeScript
    // side passes hasher objects directly and never serializes the tag, so this
    // pins the Rust values rather than comparing them.
    expect(fixture.hasher.trait.ids).toEqual({
      keccak: 2,
      poseidon: 0,
      sha256: 1,
      sha256Be: 3,
    });
  });
});

describe("program-libs/hasher/src/zero_bytes against the runtime zero column", () => {
  // The audit called `zero_bytes/*` not applicable because TypeScript computes
  // its zero column by hashing upward instead of reading a table. That is only
  // sound if the two agree, which nothing had checked.
  const cases: readonly [string, Hasher32, readonly string[]][] = [
    ["poseidon", poseidonHasher, fixture.hasher.zeroBytes.poseidon],
    ["sha256", sha256Hasher, fixture.hasher.zeroBytes.sha256],
    ["keccak", keccakHasher, fixture.hasher.zeroBytes.keccak],
  ];

  for (const [name, hasher, table] of cases) {
    it(`reproduces the full ${name} zero table by hashing upward`, () => {
      let current = bytes32(new Uint8Array(32), "zero");
      expect(bytesToHex(current)).toBe(table[0]);
      for (let level = 1; level < table.length; level += 1) {
        current = hasher.hash(current, current);
        expect(bytesToHex(current)).toBe(table[level]);
      }
    });

    it(`gives an empty ${name} tree the root the Rust table names`, () => {
      for (const height of [1, 2, 3, 8, 16]) {
        const tree = new CoreMerkleTree(height, hasher);
        expect(bytesToHex(tree.root())).toBe(table[height]);
      }
    });
  }

  it("covers the Rust table's full height", () => {
    expect(fixture.hasher.zeroBytes.maxHeight).toBe(40);
    expect(fixture.hasher.zeroBytes.poseidon).toHaveLength(41);
  });
});

describe("program-libs/hasher/src/bigint.rs against bigintToBytes", () => {
  for (const vector of fixture.hasher.bigint.vectors) {
    it(`writes ${vector.name} big-endian into 32 bytes`, () => {
      expect(bytesToHex(bigintToBytes(BigInt(vector.decimal)))).toBe(vector.be32);
    });
  }

  it("refuses a value too wide for 32 bytes, as bigint_to_be_bytes_array does", () => {
    const reject = fixture.hasher.bigint.rejects[0];
    expect(reject).toBeDefined();
    if (reject === undefined) return;
    expect(() => bigintToBytes(BigInt(reject.decimal))).toThrow();
  });
});

describe("program-libs/indexed-array against IndexedMerkleTree", () => {
  const indexed = fixture.indexedArray;

  it("uses the same highest-address sentinel", () => {
    // The TypeScript constant is a literal; this ties it to the Rust one.
    const tree = new IndexedMerkleTree(8, poseidonHasher);
    expect(bytesToHex(tree.highestValue())).toBe(
      bytesToHex(bigintToBytes(BigInt(indexed.highestAddressPlusOne))),
    );
  });

  it("builds the same linked list Rust's IndexedArray does", () => {
    const tree = new IndexedMerkleTree(16, poseidonHasher);
    for (const step of indexed.steps) {
      tree.insert(bigintToBytes(BigInt(step.append)));
    }

    const actual = [];
    for (let index = 0n; index < tree.elementCount(); index += 1n) {
      const element = tree.element(index);
      actual.push({
        index: Number(element.index),
        nextIndex: Number(element.nextIndex),
        value: BigInt(`0x${bytesToHex(element.value)}`).toString(),
      });
    }
    expect(actual).toEqual(indexed.finalElements);
  });

  it("assigns the low element and the new index Rust assigns, at every step", () => {
    const tree = new IndexedMerkleTree(16, poseidonHasher);
    for (const step of indexed.steps) {
      const newIndex = tree.insert(bigintToBytes(BigInt(step.append)));
      expect(Number(newIndex)).toBe(step.newElementIndex);
      const low = tree.element(BigInt(step.lowElementIndex));
      expect(Number(low.nextIndex)).toBe(step.newLowElementNextIndex);
    }
  });

  it("hashes an element the way IndexedElement::hash does", () => {
    // `hash` is `H(value, next_value)` over the two big-endian 32-byte values.
    const standalone = indexed.standaloneElementHash;
    const actual = poseidonHasher.hash(
      bigintToBytes(BigInt(standalone.value)),
      bigintToBytes(BigInt(standalone.nextValue)),
    );
    expect(bytesToHex(actual)).toBe(standalone.poseidon);
  });

  it("rejects a duplicate insert, as append does", () => {
    const tree = new IndexedMerkleTree(16, poseidonHasher);
    tree.insert(bigintToBytes(30n));
    expect(() => tree.insert(bigintToBytes(30n))).toThrow();
    const duplicate = indexed.rejects.find((entry) => entry.name === "append-duplicate");
    expect(duplicate?.error).toBe("The element already exists, but was expected to be absent.");
  });

  it("refuses a value at or above the sentinel", () => {
    const tree = new IndexedMerkleTree(16, poseidonHasher);
    expect(() => tree.insert(bigintToBytes(BigInt(indexed.highestAddressPlusOne)))).toThrow();
    expect(() => tree.insert(bigintToBytes(0n))).toThrow();
  });
});
