import { readFileSync } from "node:fs";

import { getAddressDecoder } from "@solana/kit";
import { describe, expect, it } from "vitest";

import { resolvedPublicInputHash } from "../src/client/prover/assembly.js";
import { mergePublicInputs, prepareMerge } from "../src/client/prover/merge.js";
import { bytesToBigInt } from "../src/interface/bytes.js";
import { treeAddress } from "../src/interface/pda/index.js";
import { expectedProvingKey } from "../src/interface/proving-keys.js";
import { inputTreeSlots } from "../src/interface/tree-slot.js";
import type { Address, Bytes16, Bytes32 } from "../src/interface/types.js";
import {
  NullifierKey,
  ShieldedAddress,
  ShieldedPublicKey,
  ViewingKey,
  type Bytes31,
} from "../src/keypair/index.js";
import {
  seededMergeDummyNullifier,
  seededMergeOutputBlinding,
  seededMergeOutputKey,
  seededMergePrivateTxBlinding,
} from "../src/keypair/merge/index.js";
import { Merge, ProofInputUtxo, SOL_MINT, Utxo } from "../src/transaction/index.js";
import { decodeOutputData } from "../src/transaction/serialization/codecs.js";
import {
  encodeMergeOutputData,
  encryptMergeOutput,
  readMergeOutputBody,
} from "../src/transaction/serialization/merge.js";

type Vector = Readonly<{
  viewing_secret: string;
  ring_program_id: string;
  first_nullifier: string;
  merge_seed: string;
  output_blinding: string;
  output_key: string;
  private_tx_blinding: string;
  dummy_slot_index: number;
  dummy_nullifier: string;
  output_ciphertext_salt: string;
  output_amount: number;
  output_mint: string;
  output_ciphertext: readonly string[];
  owner_pubkey: string;
  owner_pk_hash: string;
  statement: Readonly<{
    width: number;
    nullifiers: readonly string[];
    output_hash: string;
    tree_id: number;
    utxo_root: string;
    nullifier_root: string;
    output_tree_id: number;
    private_tx_hash: string;
    external_data_hash: string;
    output_ring_data_hash: string;
    ring_program_hash: string;
    nonzero_key_public_input_hash: string;
    zero_key_public_input_hash: string;
  }>;
}>;

const vector = JSON.parse(
  readFileSync(new URL("../../../test-vectors/merge_ring_v2.json", import.meta.url), "utf8"),
) as Vector;

function bytes(value: string): Uint8Array {
  return Uint8Array.from(value.match(/../g)?.map((pair) => Number.parseInt(pair, 16)) ?? []);
}

function hex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function field(value: string): bigint {
  return bytesToBigInt(bytes(value));
}

const ZERO_SECRET = new Uint8Array(31) as Bytes31;

describe("merge_ring_v2 derivations", () => {
  const firstNullifier = bytes(vector.first_nullifier) as Bytes32;
  const seed = bytes(vector.merge_seed) as Bytes32;

  it("reproduces the shared vector", () => {
    const viewingKey = ViewingKey.fromBytes(bytes(vector.viewing_secret) as Bytes32);
    expect(
      hex(viewingKey.mergeSeed(bytes(vector.ring_program_id) as Bytes32, firstNullifier)),
    ).toBe(vector.merge_seed);
    expect(hex(seededMergeOutputBlinding(seed, firstNullifier))).toBe(vector.output_blinding);
    expect(hex(seededMergeOutputKey(seed, firstNullifier))).toBe(vector.output_key);
    expect(hex(seededMergePrivateTxBlinding(seed, firstNullifier))).toBe(
      vector.private_tx_blinding,
    );
    expect(hex(seededMergeDummyNullifier(seed, firstNullifier, vector.dummy_slot_index))).toBe(
      vector.dummy_nullifier,
    );
    const ciphertext = encryptMergeOutput(
      {
        amount: BigInt(vector.output_amount),
        mint: getAddressDecoder().decode(bytes(vector.output_mint)),
      },
      seededMergeOutputKey(seed, firstNullifier),
      bytes(vector.output_ciphertext_salt) as Bytes16,
    );
    expect(ciphertext.map(hex)).toEqual(vector.output_ciphertext);
  });

  it("does not follow from secret zero", () => {
    const zero = new Uint8Array(32) as Bytes32;
    expect(hex(seededMergeOutputBlinding(zero, firstNullifier))).not.toBe(vector.output_blinding);
    expect(hex(seededMergeOutputKey(zero, firstNullifier))).not.toBe(vector.output_key);
    expect(hex(seededMergePrivateTxBlinding(zero, firstNullifier))).not.toBe(
      vector.private_tx_blinding,
    );
    expect(hex(seededMergeDummyNullifier(zero, firstNullifier, vector.dummy_slot_index))).not.toBe(
      vector.dummy_nullifier,
    );
  });

  it("orders the statement as the program does, for both keys", () => {
    const statement = vector.statement;
    const nullifiers = Array.from({ length: statement.width }, (_, index) =>
      field(statement.nullifiers[index] ?? "00"),
    );
    const slots = inputTreeSlots([
      {
        id: statement.tree_id,
        utxoRoot: bytes(statement.utxo_root) as Bytes32,
        nullifierRoot: bytes(statement.nullifier_root) as Bytes32,
      },
    ]);
    const [ciphertext0, ciphertext1, ciphertext2] = vector.output_ciphertext.map(field);
    if (ciphertext0 === undefined || ciphertext1 === undefined || ciphertext2 === undefined) {
      throw new Error("vector ciphertext");
    }
    for (const [publishedOwner, expected] of [
      [0n, statement.nonzero_key_public_input_hash],
      [field(vector.owner_pk_hash), statement.zero_key_public_input_hash],
    ] as const) {
      const publicInputs = mergePublicInputs({
        nullifiers,
        outputHash: field(statement.output_hash),
        outputTreeId: statement.output_tree_id,
        privateTxHash: field(statement.private_tx_hash),
        externalDataHash: field(statement.external_data_hash),
        binding: {
          kind: "ringV2",
          outputRingDataHash: field(statement.output_ring_data_hash),
          ringProgramId: field(statement.ring_program_hash),
          publishedOwner,
          outputCiphertextSalt: field(vector.output_ciphertext_salt),
          outputCiphertext: [ciphertext0, ciphertext1, ciphertext2],
        },
      });
      expect(resolvedPublicInputHash(publicInputs, slots).toString(16).padStart(64, "0")).toBe(
        expected,
      );
    }
  });
});

describe("merge_ring_v2 outputs", () => {
  const ring = getAddressDecoder().decode(new Uint8Array(32).fill(0x0b)) as Address;

  it("publishes as proven with the ring data hash leading, and reads back", () => {
    const salt = new Uint8Array(16).fill(1) as Bytes16;
    const ciphertext = [
      new Uint8Array(32).fill(0) as Bytes32,
      new Uint8Array(32).fill(0) as Bytes32,
      new Uint8Array(32).fill(0) as Bytes32,
    ] as const;
    const ringDataHash = new Uint8Array(32).fill(7) as Bytes32;
    const proven = encodeMergeOutputData({ salt, ciphertext, ringDataHash, ringV2: true });
    expect(decodeOutputData(proven).encoding).toBe("verifiable");
    expect(readMergeOutputBody(proven)?.ringDataHash).toEqual(ringDataHash);
    const unverified = encodeMergeOutputData({ salt, ciphertext, ringDataHash });
    expect(decodeOutputData(unverified).encoding).toBe("encrypted");
    expect(readMergeOutputBody(unverified)?.ringDataHash).toEqual(ringDataHash);
  });

  it("publishes a zero-key merge's owner under a public zero secret", () => {
    const key = NullifierKey.fromSecret(ZERO_SECRET);
    const owner = ShieldedPublicKey.fromEd25519(bytes(vector.owner_pubkey) as Bytes32);
    const viewing = ViewingKey.generate();
    const address = ShieldedAddress.fromPublicKeys(owner, key.publicKey(), viewing.publicKey());
    const utxo = new Utxo({
      owner,
      asset: SOL_MINT,
      amount: 10n,
      blinding: new Uint8Array(32).fill(1) as Bytes32,
      ringProgramId: ring,
    });
    const spend = ProofInputUtxo.fromNullifierKey(utxo, key, {}, 3);
    const seed = viewing.mergeSeed(new Uint8Array(32).fill(0x0b) as Bytes32, spend.nullifier());
    const prepared = Merge.zeroKey({
      address,
      inputs: [spend],
      seed,
      ring: { programId: ring },
      outputTreeId: 3,
    }).prepare();
    expect(prepared.rail.kind).toBe("ringV2ZeroKey");

    const assembly = prepareMerge(prepared, treeAddress(3));
    const payload = assembly.inputs.payload;
    expect(payload.ringV2?.publishedOwner).toBe(payload.ownerPublicKeyHash);
    expect(BigInt(payload.ringV2?.mergeSeed ?? 0n)).toBe(bytesToBigInt(seed));
    expect(BigInt(payload.userNullifierSecret ?? 1n)).toBe(0n);
    expect(assembly.inputs.publicInputs).toHaveLength(13);
    expect(assembly.inputs.publicInputs[8]).toBe(payload.ownerPublicKeyHash);
  });

  it("refuses a zero-key merge under another nullifier key", () => {
    const key = NullifierKey.fromSecret(new Uint8Array(31).fill(1) as Bytes31);
    const owner = ShieldedPublicKey.fromEd25519(bytes(vector.owner_pubkey) as Bytes32);
    const address = ShieldedAddress.fromPublicKeys(
      owner,
      key.publicKey(),
      ViewingKey.generate().publicKey(),
    );
    const utxo = new Utxo({
      owner,
      asset: SOL_MINT,
      amount: 10n,
      blinding: new Uint8Array(32).fill(1) as Bytes32,
      ringProgramId: ring,
    });
    expect(() =>
      Merge.zeroKey({
        address,
        inputs: [ProofInputUtxo.fromNullifierKey(utxo, key, {}, 3)],
        seed: bytes(vector.merge_seed) as Bytes32,
        ring: { programId: ring },
      }),
    ).toThrow(expect.objectContaining({ code: "TRANSACTION_MERGE_INPUT_NULLIFIER_KEY_MISMATCH" }));
  });

  it("has no proving key until the rotation pins one", () => {
    expect(() => expectedProvingKey({ circuit: "merge-ring-v2", nInputs: 8 })).toThrow(
      expect.objectContaining({ code: "INTERFACE_INVALID_SHAPE" }),
    );
  });
});
