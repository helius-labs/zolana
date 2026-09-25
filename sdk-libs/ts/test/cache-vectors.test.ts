import { address, isSignerRole, isWritableRole, type Instruction } from "@solana/kit";
import { describe, expect, it } from "vitest";

import vectors from "../../../test-vectors/cache.json" with { type: "json" };
import { getCacheAddress } from "../src/addresses.js";
import {
  bindCacheWrite,
  cachedInputFields,
  closeCacheInstruction,
  createCacheInstruction,
  decodeCache,
  emptyCachedInputFields,
} from "../src/interface/index.js";
import { encodeTransactInstructionData } from "../src/interface/codecs/index.js";
import { cachePda } from "../src/interface/pda/index.js";
import type {
  Bytes16,
  Bytes32,
  Bytes33,
  Bytes128,
  CircuitId,
  TransactInstructionData,
} from "../src/interface/types.js";

function hex(bytes: Readonly<ArrayLike<number>>): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function bytes(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value, "hex"));
}

function filled(value: number, length: number): Uint8Array {
  return new Uint8Array(length).fill(value);
}

function field(seed: number): Bytes32 {
  const value = filled(seed, 32);
  value[0] = 0;
  return value as Bytes32;
}

function accounts(instruction: Instruction) {
  return (instruction.accounts ?? []).map((account) => ({
    address: account.address,
    signer: isSignerRole(account.role),
    writable: isWritableRole(account.role),
  }));
}

type CircuitVector = (typeof vectors.transactCircuits)[number]["circuit"];

function circuit(vector: CircuitVector): CircuitId {
  const shape = {
    inputs: vector.inputs,
    outputs: vector.outputs,
    publicAssetSlots: vector.publicAssetSlots,
  };
  switch (vector.kind) {
    case "confidentialEddsa":
      return { kind: "confidentialEddsa", ...shape };
    case "confidentialEddsaCached":
    case "ringEddsaCached":
      if (vector.readBitmap === undefined || vector.writeSlots === undefined) {
        throw new Error("a cached vector names its access");
      }
      return {
        kind: vector.kind,
        ...shape,
        cacheAccess: {
          readBitmap: BigInt(vector.readBitmap),
          writeSlots: vector.writeSlots.map(([output, slot]) => ({
            output: output ?? 0,
            slot: slot ?? 0,
          })),
        },
      };
    default:
      throw new Error(`unexpected circuit ${vector.kind}`);
  }
}

function transactData(selector: CircuitId): TransactInstructionData {
  return {
    expiryUnixTs: 77n,
    txViewingPk: filled(3, 33) as Bytes33,
    salt: filled(4, 16) as Bytes16,
    interfaceTransfers: [],
    outputs: Array.from({ length: selector.outputs }, (_, index) => ({
      utxoHash: field(0x50 + index),
      ownerTag: { kind: "inline", value: field(0x60 + index) },
    })),
    messages: [],
    privateTxHash: field(5),
    circuit: selector,
    proof: {
      a: filled(6, 32) as Bytes32,
      b: filled(7, 128) as Bytes128,
      c: filled(8, 32) as Bytes32,
    },
    inputs: Array.from({ length: selector.inputs }, (_, index) => ({
      nullifierHash: field(0x10 + index),
      treeIndex: 0,
    })),
    treeContexts: [{ utxoTreeRootIndex: 9, nullifierTreeRootIndex: 10 }],
  };
}

describe("shared cache vectors", () => {
  it("builds the create cache instruction and derives its cache as Rust does", async () => {
    const vector = vectors.createCache;
    const instruction = await createCacheInstruction({
      payer: address(vector.payer),
      data: {
        writeAuthority: address(vector.writeAuthority),
        nonce: BigInt(vector.nonce),
        treeId: vector.treeId,
        expiresAt: BigInt(vector.expiresAt),
      },
    });
    expect(hex(instruction.data ?? new Uint8Array())).toBe(vector.instruction.data);
    expect(accounts(instruction)).toEqual(vector.instruction.accounts);
    expect(await cachePda(address(vector.payer), BigInt(vector.nonce))).toEqual([
      vector.cache,
      vector.bump,
    ]);
  });

  it.each(vectors.closeCache)("builds the close cache instruction as Rust does", (vector) => {
    const instruction = closeCacheInstruction({
      cache: address(vector.cache),
      rentRecipient: address(vector.rentRecipient),
      ...(vector.writer === null ? {} : { writer: address(vector.writer) }),
    });
    expect(hex(instruction.data ?? new Uint8Array())).toBe(vector.instruction.data);
    expect(accounts(instruction)).toEqual(vector.instruction.accounts);
  });

  it.each(vectors.cachePdas)("derives the cache of sponsor nonce $nonce", async (vector) => {
    const sponsor = address(vector.rentSponsor);
    expect(await cachePda(sponsor, BigInt(vector.nonce))).toEqual([vector.address, vector.bump]);
    expect(await getCacheAddress(sponsor, BigInt(vector.nonce))).toBe(vector.address);
  });

  it("decodes the cache account layout Rust writes", () => {
    const vector = vectors.cacheAccount;
    const data = bytes(vector.header + vector.utxoHashes.join(""));
    const decoded = decodeCache(data);
    expect({
      ...decoded,
      utxoHashes: decoded.utxoHashes.map(hex),
    }).toEqual({
      bump: vector.bump,
      treeId: vector.treeId,
      expiresAt: BigInt(vector.expiresAt),
      rentSponsor: vector.rentSponsor,
      writeAuthority: vector.writeAuthority,
      utxoHashes: vector.utxoHashes,
    });
  });

  it.each(vectors.cachedInputFields)("computes the cached input fields for $name", (vector) => {
    expect(
      cachedInputFields(
        BigInt(vector.readBitmap),
        vector.treeId,
        vector.slots.map(bytes),
        vector.inputCount,
      ).map(hex),
    ).toEqual(vector.fields);
  });

  it.each(vectors.emptyCachedInputFields)(
    "computes the empty selection for $inputCount inputs",
    (vector) => {
      expect(emptyCachedInputFields(vector.inputCount).map(hex)).toEqual(vector.fields);
    },
  );

  it.each(vectors.cacheWriteBindings)(
    "binds a cache write to its write slots as Rust does",
    (vector) => {
      const externalDataHash = bytes(vector.externalDataHash);
      expect(
        hex(
          bindCacheWrite(externalDataHash, {
            cache: address(vector.cache),
            writeSlots: vector.writeSlots.map(([output, slot]) => ({
              output: output ?? 0,
              slot: slot ?? 0,
            })),
          }),
        ),
      ).toBe(vector.bound);
      expect(hex(bindCacheWrite(externalDataHash))).toBe(vector.externalDataHash);
    },
  );

  it.each(vectors.transactCircuits)(
    "encodes transact data with a $circuit.kind selector as Rust does",
    (vector) => {
      expect(hex(encodeTransactInstructionData(transactData(circuit(vector.circuit))))).toBe(
        vector.data,
      );
    },
  );
});
