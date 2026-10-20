import { readFileSync } from "node:fs";

import { getAddressDecoder, getAddressEncoder } from "@solana/kit";
import { afterEach, describe, expect, it, vi } from "vitest";

import { prepareMerge } from "../src/client/prover/merge.js";
import { prepareMerge as prepareMergeFlow } from "../src/flows/merge.js";
import * as mergeKeys from "../src/keypair/merge/index.js";
import * as mergeCipher from "../src/transaction/serialization/merge.js";
import { LocalShieldedKeys } from "../src/transaction/wallet/keys.js";
import { TransactionError } from "../src/transaction/error.js";
import { checked } from "../src/transaction/internal.js";
import { BN254_SCALAR_ORDER } from "../src/hasher/index.js";
import { bigIntToBytes, bytesToBigInt } from "../src/keypair/bytes.js";
import { treeAddress } from "../src/interface/pda/index.js";
import type { Address, Bytes16, Bytes32 } from "../src/interface/types.js";
import { NullifierKey, ShieldedKeypair, type Bytes31 } from "../src/keypair/index.js";
import { mergeOutputKey } from "../src/keypair/merge/index.js";
import { Merge, ProofInputUtxo, SOL_MINT, Utxo } from "../src/transaction/index.js";
import {
  EncryptedScheme,
  decodeOutputData,
  encodeOutputData,
} from "../src/transaction/serialization/codecs.js";
import {
  MERGE_OUTPUT_BODY_LENGTH,
  decryptMergeOutput,
  encodeMergeOutputData,
  encryptMergeOutput,
  readMergeOutputBody,
  splitMergeOutputBody,
  type MergeOutputCiphertext,
} from "../src/transaction/serialization/merge.js";

type MergeRecoveryVector = Readonly<{
  nullifier_secret: string;
  first_nullifier: string;
  output_key: string;
  output_ciphertext_salt: string;
  output_amount: number;
  output_mint: string;
  output_ciphertext: readonly string[];
}>;

// Produced by Rust `Merge::encrypt_fields` (sdk-libs/transaction/tests/merge.rs
// merge_output_ciphertext_matches_shared_vectors_and_decrypts_only_under_its_key).
const vector = (
  JSON.parse(
    readFileSync(new URL("../../../test-vectors/key_derivation.json", import.meta.url), "utf8"),
  ) as Readonly<{ merge_recovery: MergeRecoveryVector }>
).merge_recovery;

function bytes(value: string): Uint8Array {
  return Uint8Array.from(value.match(/../g)?.map((pair) => Number.parseInt(pair, 16)) ?? []);
}

function hex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function filled<T extends Uint8Array>(length: number, value: number): T {
  return new Uint8Array(length).fill(value) as T;
}

/** `salt || ciphertext`, the encrypted part of a merge output body. */
function encryptedBody(salt: Bytes16, ciphertext: MergeOutputCiphertext): Uint8Array {
  return Uint8Array.from([...salt, ...ciphertext.flatMap((element) => [...element])]);
}

/** The vector's nullifier key, output key, salt, and plaintext. */
function vectorInputs() {
  const nullifierKey = NullifierKey.fromSecret(bytes(vector.nullifier_secret) as Bytes31);
  const firstNullifier = bytes(vector.first_nullifier) as Bytes32;
  const key = mergeOutputKey(nullifierKey, firstNullifier);
  const salt = bytes(vector.output_ciphertext_salt) as Bytes16;
  const mint: Address = getAddressDecoder().decode(bytes(vector.output_mint));
  return {
    nullifierKey,
    firstNullifier,
    key,
    salt,
    plaintext: { amount: BigInt(vector.output_amount), mint },
  };
}

describe("merge output ciphertext", () => {
  it("rejects non-canonical aliases of every ciphertext element", () => {
    const { nullifierKey, key, salt, plaintext } = vectorInputs();
    try {
      const ciphertext = encryptMergeOutput(plaintext, key, salt);
      expect(decryptMergeOutput(encryptedBody(salt, ciphertext), key)).toEqual(plaintext);
      for (const [index, element] of ciphertext.entries()) {
        for (const value of [bytesToBigInt(element) + BN254_SCALAR_ORDER, BN254_SCALAR_ORDER]) {
          const body = encryptedBody(salt, ciphertext);
          body.set(bigIntToBytes(value), salt.length + index * 32);
          expect(() => decryptMergeOutput(body, key)).toThrow(
            expect.objectContaining({
              code: "TRANSACTION_NON_CANONICAL_MERGE_CIPHERTEXT",
              details: { index },
            }),
          );
        }
      }
    } finally {
      key.fill(0);
      nullifierKey.destroy();
    }
  });

  it("reproduces the shared Rust ciphertext vector", () => {
    const { nullifierKey, key, salt, plaintext } = vectorInputs();
    try {
      expect(hex(key)).toBe(vector.output_key);
      const ciphertext = encryptMergeOutput(plaintext, key, salt);
      expect(ciphertext.map(hex)).toEqual(vector.output_ciphertext);
      expect(decryptMergeOutput(encryptedBody(salt, ciphertext), key)).toEqual(plaintext);
    } finally {
      nullifierKey.destroy();
    }
  });

  it.each([
    ["zero SOL", 0n, SOL_MINT],
    ["u64::MAX SOL", 0xffff_ffff_ffff_ffffn, SOL_MINT],
    ["an all-0xff mint", 1n, getAddressDecoder().decode(filled(32, 0xff))],
    ["an all-zero mint", 7n, getAddressDecoder().decode(new Uint8Array(32))],
  ] as const)("round-trips %s through encrypt and decrypt", (_name, amount, mint) => {
    const key = filled<Bytes32>(32, 0);
    key.set(Uint8Array.of(0x13, 0x37), 30);
    const salt = filled<Bytes16>(16, 0xa5);
    const ciphertext = encryptMergeOutput({ amount, mint }, key, salt);
    expect(ciphertext).toHaveLength(3);
    expect(decryptMergeOutput(encryptedBody(salt, ciphertext), key)).toEqual({ amount, mint });
    // A fresh salt pads the same plaintext differently.
    const resalted = encryptMergeOutput({ amount, mint }, key, filled<Bytes16>(16, 0x5a));
    expect(resalted.map(hex)).not.toEqual(ciphertext.map(hex));
  });

  it("refuses to decrypt under the key of another first nullifier", () => {
    // The Rust vector test's key: the first nullifier with its last byte + 1.
    // Under it the amount slot falls outside u64, so the first element fails.
    const { nullifierKey, firstNullifier, key, salt, plaintext } = vectorInputs();
    try {
      const otherFirst = new Uint8Array(firstNullifier) as Bytes32;
      otherFirst.set([(firstNullifier[31] ?? 0) + 1], 31);
      const otherKey = mergeOutputKey(nullifierKey, otherFirst);
      expect(hex(otherKey)).not.toBe(hex(key));
      const body = encryptedBody(salt, encryptMergeOutput(plaintext, key, salt));
      expect(() => decryptMergeOutput(body, otherKey)).toThrow(
        expect.objectContaining({
          name: "TransactionError",
          code: "TRANSACTION_INVALID_MERGE_OUTPUT_PLAINTEXT",
        }),
      );

      // Unauthenticated: a flipped bit never decrypts to the original plaintext.
      const tampered = new Uint8Array(body);
      tampered.set([(body.at(-1) ?? 0) ^ 1], body.length - 1);
      let decrypted: unknown;
      try {
        decrypted = decryptMergeOutput(tampered, key);
      } catch (error) {
        decrypted = error;
      }
      expect(decrypted).not.toEqual(plaintext);
    } finally {
      nullifierKey.destroy();
    }
  });

  it("refuses a body of the wrong length and an amount outside u64", () => {
    const { nullifierKey, key, salt, plaintext } = vectorInputs();
    try {
      const body = encryptedBody(salt, encryptMergeOutput(plaintext, key, salt));
      for (const wrong of [body.subarray(0, body.length - 1), Uint8Array.from([...body, 0])]) {
        expect(() => decryptMergeOutput(wrong, key)).toThrow(
          expect.objectContaining({ code: "TRANSACTION_INVALID_LENGTH" }),
        );
      }
      for (const amount of [-1n, 1n << 64n]) {
        expect(() => encryptMergeOutput({ ...plaintext, amount }, key, salt)).toThrow(
          expect.objectContaining({ code: "TRANSACTION_INVALID_AMOUNT" }),
        );
      }
    } finally {
      nullifierKey.destroy();
    }
  });

  it("is the ciphertext a prepared merge carries and proves", () => {
    const owner = ShieldedKeypair.generate();
    const nullifierKey = owner.nullifierKey();
    try {
      const inputs = [5n, 8n].map((amount, index) =>
        ProofInputUtxo.fromKeypair(
          new Utxo({
            owner: owner.signingPublicKey(),
            asset: SOL_MINT,
            amount,
            blinding: filled<Bytes32>(32, index + 1).fill(0, 0, 1),
          }),
          owner,
        ),
      );
      const prepared = Merge.fromKeypair(owner, inputs).prepare();
      const firstNullifier = inputs[0]?.nullifier();
      if (firstNullifier === undefined) throw new Error("merge fixture has no input");
      const salt = prepared.outputCiphertextSalt();
      const ciphertext = prepared.outputCiphertext();
      expect(
        decryptMergeOutput(
          encryptedBody(salt, ciphertext),
          mergeOutputKey(nullifierKey, firstNullifier),
        ),
      ).toEqual({ amount: 13n, mint: SOL_MINT });

      const payload = prepareMerge(prepared, treeAddress(prepared.inputTreeId)).inputs.payload;
      const mint = Uint8Array.from(getAddressEncoder().encode(SOL_MINT));
      expect(payload.mintChunks).toEqual([
        BigInt(`0x${hex(mint.subarray(0, 31))}`),
        BigInt(`0x${hex(mint.subarray(31))}`),
      ]);
      expect(payload.outputCiphertextSalt).toBe(BigInt(`0x${hex(salt)}`));
    } finally {
      nullifierKey.destroy();
      owner.destroy();
    }
  });
});

describe("merge output data", () => {
  const salt = filled<Bytes16>(16, 5);
  const ciphertext: MergeOutputCiphertext = [
    filled<Bytes32>(32, 6),
    filled<Bytes32>(32, 7),
    filled<Bytes32>(32, 8),
  ];
  const ringDataHash = filled<Bytes32>(32, 9);

  it("frames a plain merge as verifiable scheme 6 over salt and ciphertext", () => {
    const payload = encodeMergeOutputData({ salt, ciphertext });
    // borsh `VerifiablyEncrypted(Vec<u8>)`: variant 2, u32 LE length, then the blob.
    expect(Array.from(payload.subarray(0, 5))).toEqual([2, 1 + 112, 0, 0, 0]);
    expect(payload).toHaveLength(5 + 1 + 112);
    const frame = decodeOutputData(payload);
    expect(frame).toMatchObject({ encoding: "verifiable", scheme: EncryptedScheme.merge });
    expect(frame.body).toHaveLength(MERGE_OUTPUT_BODY_LENGTH);
    expect(MERGE_OUTPUT_BODY_LENGTH).toBe(112);
    expect(frame.body).toEqual(encryptedBody(salt, ciphertext));

    const split = splitMergeOutputBody(frame.body);
    expect(split?.ringDataHash).toBeUndefined();
    expect(split?.encrypted).toEqual(encryptedBody(salt, ciphertext));
  });

  it("frames a ring merge as encrypted, its body led by the output ring data hash", () => {
    const payload = encodeMergeOutputData({ salt, ciphertext, ringDataHash });
    // borsh `Encrypted(Vec<u8>)`: the ring merge proof does not bind the ciphertext.
    expect(Array.from(payload.subarray(0, 5))).toEqual([1, 1 + 144, 0, 0, 0]);
    const frame = decodeOutputData(payload);
    expect(frame).toMatchObject({ encoding: "encrypted", scheme: EncryptedScheme.merge });
    expect(frame.body).toHaveLength(144);
    expect(frame.body.subarray(0, 32)).toEqual(ringDataHash);
    expect(frame.body.subarray(32)).toEqual(encryptedBody(salt, ciphertext));

    const split = splitMergeOutputBody(frame.body);
    expect(split?.ringDataHash).toEqual(ringDataHash);
    expect(split?.encrypted).toEqual(encryptedBody(salt, ciphertext));
    // The split hash is a copy, not a view the caller could mutate the body through.
    split?.ringDataHash?.fill(0);
    expect(frame.body.subarray(0, 32)).toEqual(ringDataHash);
  });

  it("reads a merge body only under the encoding its shape is published with", () => {
    const plainBody = encryptedBody(salt, ciphertext);
    const ringBody = new Uint8Array([...ringDataHash, ...plainBody]);
    expect(readMergeOutputBody(encodeMergeOutputData({ salt, ciphertext }))).toEqual({
      encrypted: plainBody,
    });
    expect(readMergeOutputBody(encodeMergeOutputData({ salt, ciphertext, ringDataHash }))).toEqual({
      ringDataHash,
      encrypted: plainBody,
    });
    expect(
      readMergeOutputBody(encodeOutputData(EncryptedScheme.merge, ringBody, "verifiable")),
    ).toBeUndefined();
    expect(
      readMergeOutputBody(encodeOutputData(EncryptedScheme.merge, plainBody, "encrypted")),
    ).toBeUndefined();
    expect(() => encodeOutputData(EncryptedScheme.merge, plainBody, "plaintext")).toThrow(
      expect.objectContaining({ code: "TRANSACTION_BAD_DISCRIMINATOR" }),
    );
  });

  it.each([0, 32, 111, 113, 143, 145, 176])("splits no body of %i bytes", (length) => {
    expect(splitMergeOutputBody(new Uint8Array(length))).toBeUndefined();
  });

  it("refuses a salt, ciphertext element, or ring data hash of the wrong length", () => {
    expect(() => encodeMergeOutputData({ salt: filled<Bytes16>(15, 5), ciphertext })).toThrow(
      expect.objectContaining({ code: "TRANSACTION_INVALID_LENGTH" }),
    );
    expect(() =>
      encodeMergeOutputData({
        salt,
        ciphertext: [filled<Bytes32>(31, 6), filled<Bytes32>(32, 7), filled<Bytes32>(32, 8)],
      }),
    ).toThrow(expect.objectContaining({ code: "TRANSACTION_INVALID_LENGTH" }));
    expect(() =>
      encodeMergeOutputData({ salt, ciphertext, ringDataHash: filled<Bytes32>(33, 9) }),
    ).toThrow(expect.objectContaining({ code: "TRANSACTION_INVALID_LENGTH" }));
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("merge key lifetime", () => {
  function note(owner: ShieldedKeypair) {
    return ProofInputUtxo.fromKeypair(
      new Utxo({
        owner: owner.signingPublicKey(),
        asset: SOL_MINT,
        amount: 7n,
        blinding: checked<Bytes32>(new Uint8Array(32).fill(2), 32, "blinding"),
      }),
      owner,
    );
  }

  it.each(["success", "invalid owner", "cipher failure"])(
    "wipes builder keys after %s",
    (outcome) => {
      const owner = ShieldedKeypair.generate();
      const stranger = ShieldedKeypair.generate();
      const input = note(outcome === "invalid owner" ? stranger : owner);
      const returned = checked<Bytes32>(new Uint8Array(32).fill(3), 32, "key");
      vi.spyOn(mergeKeys, "mergeOutputKey").mockReturnValue(returned);
      const encrypt = mergeCipher.encryptMergeOutput;
      const used: Bytes32[] = [];
      vi.spyOn(mergeCipher, "encryptMergeOutput").mockImplementation((plaintext, key, salt) => {
        used.push(key);
        if (outcome === "cipher failure") throw new TransactionError("TRANSACTION_POSEIDON");
        return encrypt(plaintext, key, salt);
      });
      try {
        if (outcome === "success")
          expect(Merge.fromKeypair(owner, [input]).prepare().output.amount).toBe(7n);
        else expect(() => Merge.fromKeypair(owner, [input])).toThrow(TransactionError);
        expect(returned).toEqual(new Uint8Array(32));
        expect(used).toHaveLength(outcome === "invalid owner" ? 0 : 1);
        for (const key of used) expect(key).toEqual(new Uint8Array(32));
      } finally {
        owner.destroy();
        stranger.destroy();
      }
    },
  );

  it.each(["success", "malformed batch", "invalid output tree", "identity failure"])(
    "wipes key-holder merge answers after %s",
    async (outcome) => {
      const owner = ShieldedKeypair.generate();
      const keys = LocalShieldedKeys.fromKeypair(owner);
      const input = note(owner);
      const derive = keys.derive.bind(keys);
      const answers: Bytes32[] = [];
      vi.spyOn(keys, "derive").mockImplementation(async (requests) => {
        answers.push(...(await derive(requests)));
        return outcome === "malformed batch" ? [...answers, ...answers.slice(0, 1)] : answers;
      });
      if (outcome === "identity failure")
        vi.spyOn(keys, "address").mockImplementation(() => {
          throw new TransactionError("TRANSACTION_KEYS_IDENTITY_MISMATCH");
        });
      try {
        const result = prepareMergeFlow({
          keys,
          inputs: [input],
          invalidAnswers: () => new TransactionError("TRANSACTION_KEYS_BATCH_MISMATCH"),
          ...(outcome === "invalid output tree" ? { outputTreeId: -1 } : {}),
        });
        if (outcome === "success") expect((await result).output.amount).toBe(7n);
        else await expect(result).rejects.toBeInstanceOf(TransactionError);
        expect(answers.length).toBeGreaterThan(0);
        for (const key of answers) expect(key).toEqual(new Uint8Array(32));
      } finally {
        keys.destroy();
        owner.destroy();
      }
    },
  );
});
