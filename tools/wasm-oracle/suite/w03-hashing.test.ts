import { assemble } from "@zolana/client";
import type { Address, Bytes16, Bytes31, Bytes32, Bytes33 } from "@zolana/interface";
import {
  ciphertextHash,
  ownerPkFieldCompressed,
  pack33 as interfacePack33,
  pkFieldCompressed,
} from "@zolana/interface";
import { NullifierKey, type P256PublicKey, ShieldedKeypair, SigningKey, ViewingKey } from "@zolana/keypair";
import { hashField, pack33, sha256Be, splitBigEndian128 } from "@zolana/keypair/hash";
import {
  type ExternalData,
  ProofInputUtxo,
  SOL_MINT,
  SppProofInputs,
  Utxo,
  createExternalData,
  deriveBlinding,
} from "@zolana/transaction";
import fc from "fast-check";
import { afterAll, describe, expect, it } from "vitest";

import { probe, writeReport } from "./differential.js";
import { BN254_MODULUS, bigintTo32, fieldLeaf } from "./generators.js";
import { hex, oracle, outcomeOf, parseOutcome } from "./oracle.js";
// `createProofOutput` has no public export. Reaching into the built output
// rather than the source keeps every type in this file resolving through the
// same package build, so `ProofOutputUtxo` has one identity here.
import { createProofOutput } from "../../../sdk-libs/ts/transaction/dist/es/utxo.js";

/**
 * Every length from 0 to 64. `hash_field` and its neighbours take `&[u8; 32]` or
 * `&[u8; 33]`, so the lengths either side of those are where the two type
 * systems stop agreeing about what an input is.
 */
const anyLength = fc.uint8Array({ minLength: 0, maxLength: 64 });

/** Weighted towards 32 bytes so value comparison gets a real share of the budget. */
const around32 = fc.oneof(
  { arbitrary: fieldLeaf, weight: 5 },
  { arbitrary: anyLength, weight: 5 },
);

/** Weighted towards 33 bytes with a valid SEC1 prefix. */
const around33 = fc.oneof(
  {
    arbitrary: fc
      .record({ prefix: fc.constantFrom(0x02, 0x03), x: fieldLeaf })
      .map(({ prefix, x }) => Uint8Array.of(prefix, ...x)),
    weight: 5,
  },
  {
    arbitrary: fc
      .record({ prefix: fc.integer({ min: 0, max: 255 }), x: fieldLeaf })
      .map(({ prefix, x }) => Uint8Array.of(prefix, ...x)),
    weight: 2,
  },
  { arbitrary: anyLength, weight: 3 },
);

const I64_MIN = -(1n << 63n);
const I64_MAX = (1n << 63n) - 1n;

/** Integers around the `i64` ends and around the field modulus. */
const signedAmount = fc.oneof(
  { arbitrary: fc.bigInt({ min: I64_MIN, max: I64_MAX }), weight: 5 },
  {
    arbitrary: fc.constantFrom(
      0n,
      1n,
      -1n,
      I64_MIN,
      I64_MIN - 1n,
      I64_MAX,
      I64_MAX + 1n,
      BN254_MODULUS - 1n,
      BN254_MODULUS,
      BN254_MODULUS + 1n,
    ),
    weight: 4,
  },
  { arbitrary: fc.bigInt({ min: -(1n << 200n), max: 1n << 200n }), weight: 1 },
);

describe("W-03 hashing and field encoding", () => {
  afterAll(() => {
    writeReport("w03-hashing");
  });

  it("hash_field", () => {
    const summary = probe<Uint8Array>({
      rustSymbol: "sdk-libs/keypair/src/hash.rs::hash_field",
      arbitrary: around32,
      rust: (value) => parseOutcome(oracle.hash_field(hex(value))),
      typescript: (value) => outcomeOf(() => hex(hashField(value))),
      render: (value) => ({ valueHex: hex(value), length: value.length }),
    });
    // Acceptance check on the wrapper: `hash_field(&[u8; 32])` cannot take a
    // short input, so a wrapper that padded instead of rejecting would report
    // agreement here.
    expect(summary.divergences.length).toBeGreaterThan(0);
  });

  it("split_be_128", () => {
    const summary = probe<Uint8Array>({
      rustSymbol: "sdk-libs/keypair/src/hash.rs::split_be_128",
      arbitrary: around32,
      rust: (value) => parseOutcome(oracle.split_be_128(hex(value))),
      typescript: (value) => outcomeOf(() => splitBigEndian128(value).map(hex)),
      render: (value) => ({ valueHex: hex(value), length: value.length }),
    });
    expect(summary.cases).toBeGreaterThan(0);
  });

  it("sha256_be", () => {
    const summary = probe<Uint8Array>({
      rustSymbol: "sdk-libs/keypair/src/hash.rs::sha256_be",
      arbitrary: anyLength,
      rust: (value) => parseOutcome(oracle.sha256_be(hex(value))),
      typescript: (value) => outcomeOf(() => hex(sha256Be(value))),
      render: (value) => ({ preimageHex: hex(value), length: value.length }),
    });
    expect(summary.cases).toBeGreaterThan(0);
  });

  it("pk_field_compressed", () => {
    const summary = probe<Uint8Array>({
      rustSymbol: "program-libs/interface/src/merge_utils.rs::pk_field_compressed",
      arbitrary: around33,
      rust: (value) => parseOutcome(oracle.pk_field_compressed(hex(value))),
      typescript: (value) => outcomeOf(() => hex(pkFieldCompressed(value))),
      render: (value) => ({ compressedHex: hex(value), length: value.length }),
    });
    expect(summary.cases).toBeGreaterThan(0);
  });

  it("owner_pk_field_compressed", () => {
    const summary = probe<Uint8Array>({
      rustSymbol: "program-libs/interface/src/merge_utils.rs::owner_pk_field_compressed",
      arbitrary: around33,
      rust: (value) => parseOutcome(oracle.owner_pk_field_compressed(hex(value))),
      typescript: (value) => outcomeOf(() => hex(ownerPkFieldCompressed(value))),
      render: (value) => ({ compressedHex: hex(value), length: value.length }),
    });
    expect(summary.cases).toBeGreaterThan(0);
  });

  it("pack33 through @zolana/interface", () => {
    const summary = probe<Uint8Array>({
      rustSymbol: "program-libs/interface/src/merge_utils.rs::pack33",
      arbitrary: around33,
      rust: (value) => parseOutcome(oracle.pack33(hex(value))),
      typescript: (value) => outcomeOf(() => interfacePack33(value).map(hex)),
      render: (value) => ({ bytesHex: hex(value), length: value.length }),
    });
    expect(summary.cases).toBeGreaterThan(0);
  });

  it("pack33 through @zolana/keypair", () => {
    const summary = probe<Uint8Array>({
      rustSymbol: "sdk-libs/keypair/src/hash.rs::pack33",
      arbitrary: around33,
      rust: (value) => parseOutcome(oracle.pack33(hex(value))),
      typescript: (value) => outcomeOf(() => pack33(value).map(hex)),
      render: (value) => ({ bytesHex: hex(value), length: value.length }),
    });
    expect(summary.cases).toBeGreaterThan(0);
  });

  it("ciphertext_hash", () => {
    const summary = probe<Uint8Array>({
      rustSymbol: "program-libs/interface/src/merge_utils.rs::ciphertext_hash",
      arbitrary: fc.uint8Array({ minLength: 0, maxLength: 200 }),
      rust: (value) => parseOutcome(oracle.ciphertext_hash(hex(value))),
      typescript: (value) => outcomeOf(() => hex(ciphertextHash(value))),
      render: (value) => ({ ciphertextHex: hex(value), length: value.length }),
    });
    expect(summary.cases).toBeGreaterThan(0);
  });

  it("asset_field", () => {
    const summary = probe<Uint8Array>({
      rustSymbol:
        "sdk-libs/transaction/src/instructions/transact/spp_proof_inputs.rs::asset_field",
      arbitrary: around32,
      rust: (value) => parseOutcome(oracle.asset_field(hex(value))),
      typescript: (value) => outcomeOf(() => hex(hashField(value))),
      render: (value) => ({ addressHex: hex(value), length: value.length }),
    });
    expect(summary.cases).toBeGreaterThan(0);
  });

  it("signed_to_field through the assembled public SOL amount", () => {
    const summary = probe<bigint>({
      rustSymbol:
        "sdk-libs/transaction/src/instructions/transact/spp_proof_inputs.rs::signed_to_field",
      arbitrary: signedAmount,
      rust: (value) => parseOutcome(oracle.signed_to_field(value.toString())),
      typescript: (value) =>
        outcomeOf(() => hex(bigintTo32(assembledPublicSolAmount(value)))),
      render: (value) => ({ publicSolAmount: value.toString() }),
      cases: 250,
    });
    // Acceptance check on the wrapper: `signed_to_field(i64)` cannot take
    // `i64::MAX + 1`, so a wrapper that reduced modulo the field instead of
    // rejecting would report agreement here.
    expect(summary.divergences.length).toBeGreaterThan(0);
  });

  it("records which route to signed_to_field checks the amount and which does not", () => {
    const base = baseProofInputs();
    const overRange = (1n << 63n) + 1n;
    expect(parseOutcome(oracle.signed_to_field(overRange.toString())).arm).toBe("err");
    // Built through the factory, the amount reaches the check inside the hash.
    expect(() =>
      createExternalData({ ...base.factoryInput, publicSolAmount: overRange }).hash(),
    ).toThrow(/TRANSACTION_INVALID_AMOUNT/);
    // Spread from a factory result, it does not: the factory's `hash` closes
    // over the snapshot it captured, so it keeps hashing the old amount while
    // `assemble` maps the new one.
    expect(assembledPublicSolAmount(overRange)).toBe(overRange % BN254_MODULUS);
  });
});

/**
 * Runs `assemble` with one varying public SOL amount and returns the field it
 * put in the prover payload.
 *
 * The external data is a factory result with the amount replaced. Nothing here
 * is mocked: the factory's `hash` closes over the snapshot it captured, so a
 * replaced amount never reaches the check that lives inside that hash.
 */
function assembledPublicSolAmount(publicSolAmount: bigint): bigint {
  const base = baseProofInputs();
  const externalData: ExternalData = { ...base.externalData, publicSolAmount };
  const proofInputs = new SppProofInputs({
    payerPublicKeyHash: base.payerPublicKeyHash,
    inputUtxos: base.inputUtxos,
    outputs: base.outputs,
    externalData,
  });
  const assembled = assemble(proofInputs, base.spendProofs);
  return assembled.proverInputs.payload.publicSolAmount as bigint;
}

interface AssemblyBase {
  readonly payerPublicKeyHash: Bytes32;
  readonly inputUtxos: readonly ProofInputUtxo[];
  readonly outputs: readonly ReturnType<typeof createProofOutput>[];
  readonly externalData: ExternalData;
  readonly factoryInput: Parameters<typeof createExternalData>[0];
  readonly spendProofs: readonly Parameters<typeof assemble>[1][number][];
}

let cachedBase: AssemblyBase | undefined;

/** One deterministic eddsa-rail transfer, reused across every amount. */
function baseProofInputs(): AssemblyBase {
  if (cachedBase) return cachedBase;
  const signing = SigningKey.fromEd25519Bytes(new Uint8Array(32).fill(7) as Bytes32);
  const nullifierKey = NullifierKey.fromSigningKey(signing);
  const keypair = ShieldedKeypair.fromKeys(
    signing,
    nullifierKey,
    ViewingKey.fromSeed(new Uint8Array(32).fill(9) as Bytes32, 0),
  );
  const blindingSeed = new Uint8Array(31).fill(11) as Bytes31;
  const inputUtxos = [
    new ProofInputUtxo({
      utxo: new Utxo({
        owner: keypair.signingPublicKey(),
        asset: SOL_MINT,
        amount: 100n,
        blinding: deriveBlinding(blindingSeed, 0),
      }),
      nullifierKey,
    }),
    ProofInputUtxo.dummy(deriveBlinding(blindingSeed, 1)),
  ];
  const outputs = [
    createProofOutput({
      ownerAddress: keypair.shieldedAddress(),
      ownerTag: keypair.signingPublicKey().confidentialViewTag(),
      asset: SOL_MINT,
      amount: 100n,
      blinding: deriveBlinding(blindingSeed, 64),
    }),
    createProofOutput({
      ownerTag: new Uint8Array(32).fill(3) as Bytes32,
      asset: SOL_MINT,
      amount: 0n,
      blinding: deriveBlinding(blindingSeed, 65),
    }),
  ];
  const resolvedOwnerTags = outputs.map((output) => {
    if (output.ownerTag === undefined) throw new Error("output lacks an owner tag");
    return output.ownerTag;
  });
  const factoryInput: Parameters<typeof createExternalData>[0] = {
    instructionDiscriminator: 0,
    expiryUnixTs: 0n,
    relayerFee: 0,
    publicSolAmount: 0n,
    userSolAccount: base58(new Uint8Array(32).fill(13)),
    userSplToken: SOL_MINT,
    splTokenInterface: SOL_MINT,
    txViewingPublicKey: {
      toBytes: () => new Uint8Array(33).fill(2) as Bytes33,
    } as P256PublicKey,
    salt: new Uint8Array(16).fill(5) as Bytes16,
    outputs: outputs.map((output, index) => ({
      utxoHash: output.hash(),
      ownerTag: { kind: "inline" as const, value: resolvedOwnerTags[index] as Bytes32 },
    })),
    resolvedOwnerTags,
    messages: [],
  };
  const externalData = createExternalData(factoryInput);
  const proofInputs = new SppProofInputs({
    payerPublicKeyHash: fieldBytes(17),
    inputUtxos,
    outputs,
    externalData,
  });
  const tree = base58(new Uint8Array(32).fill(19));
  const spendProofs = proofInputs.inputContexts().map((context, index) => ({
    state: {
      leaf: context.utxoHash,
      merkleContext: { treeType: 1, tree },
      path: Array.from({ length: 32 }, () => fieldBytes(23 + index)),
      leafIndex: BigInt(index),
      root: fieldBytes(29),
      rootSeq: 1n,
      rootIndex: 2 + index,
    },
    nullifier: {
      leaf: context.nullifier,
      merkleContext: { treeType: 2, tree },
      path: Array.from({ length: 40 }, () => fieldBytes(31 + index)),
      lowElement: fieldBytes(37),
      lowElementIndex: 0n,
      highElement: fieldBytes(41),
      highElementIndex: 1n,
      root: fieldBytes(43),
      rootSeq: 1n,
      rootIndex: 3 + index,
    },
  })) as AssemblyBase["spendProofs"];
  cachedBase = {
    payerPublicKeyHash: fieldBytes(17),
    inputUtxos,
    outputs,
    externalData,
    factoryInput,
    spendProofs,
  };
  return cachedBase;
}

/** 32 bytes that are always a valid field element. */
function fieldBytes(value: number): Bytes32 {
  const bytes = new Uint8Array(32).fill(value);
  bytes[0] = 0;
  return bytes as Bytes32;
}

const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58(value: Uint8Array): Address {
  const digits = [0];
  for (const byte of value) {
    let carry = byte;
    for (let index = 0; index < digits.length; index += 1) {
      const next = (digits[index] ?? 0) * 256 + carry;
      digits[index] = next % 58;
      carry = Math.floor(next / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  let output = "";
  for (const byte of value) {
    if (byte !== 0) break;
    output += "1";
  }
  for (let index = digits.length - 1; index >= 0; index -= 1) {
    output += BASE58.charAt(digits[index] ?? 0);
  }
  return output as Address;
}
