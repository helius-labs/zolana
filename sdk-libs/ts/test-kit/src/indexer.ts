import type { Bytes32, Signature } from "@zolana/interface";

import { TestKitError } from "./error.js";
import { copyOutput, type IndexedOutput, type IndexedTransaction } from "./events.js";

export class TestIndexer {
  readonly #outputs: IndexedOutput[] = [];
  readonly #nullifiers = new Set<string>();
  readonly #transactions = new Map<Signature, IndexedTransaction>();

  record(transaction: IndexedTransaction): void {
    const expectedFirstLeaf = BigInt(this.#outputs.length);
    const first = transaction.outputs[0];
    if (first !== undefined && first.leafIndex !== expectedFirstLeaf) {
      throw new TestKitError("TEST_KIT_FIXTURE", {
        details: {
          reason: "leafIndex",
          expected: expectedFirstLeaf.toString(),
          actual: first.leafIndex.toString(),
        },
      });
    }
    transaction.outputs.forEach((output, offset) => {
      const expected = expectedFirstLeaf + BigInt(offset);
      if (output.leafIndex !== expected) {
        throw new TestKitError("TEST_KIT_FIXTURE", {
          details: {
            reason: "leafIndex",
            expected: expected.toString(),
            actual: output.leafIndex.toString(),
          },
        });
      }
    });
    const snapshot = copyTransaction(transaction);
    this.#outputs.push(...snapshot.outputs.map(copyOutput));
    snapshot.nullifiers.forEach((nullifier) => this.#nullifiers.add(hex(nullifier)));
    this.#transactions.set(snapshot.signature, snapshot);
  }

  outputs(): readonly IndexedOutput[] {
    return this.#outputs.map(copyOutput);
  }

  byViewTag(tag: Bytes32): readonly IndexedOutput[] {
    const target = hex(tag);
    return this.#outputs.filter((output) => hex(output.viewTag) === target).map(copyOutput);
  }

  transaction(signature: Signature): IndexedTransaction | undefined {
    const transaction = this.#transactions.get(signature);
    return transaction && copyTransaction(transaction);
  }

  isNullifierSpent(nullifier: Bytes32): boolean {
    return this.#nullifiers.has(hex(nullifier));
  }
}

function copyTransaction(transaction: IndexedTransaction): IndexedTransaction {
  return Object.freeze({
    signature: transaction.signature,
    outputs: Object.freeze(transaction.outputs.map(copyOutput)),
    nullifiers: Object.freeze(
      transaction.nullifiers.map((value) => new Uint8Array(value) as Bytes32),
    ),
    proofless: transaction.proofless,
  });
}

function hex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
