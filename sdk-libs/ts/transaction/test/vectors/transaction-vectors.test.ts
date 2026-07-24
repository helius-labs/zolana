import type { Bytes16, Bytes31, Bytes32, Bytes64 } from "@zolana/interface";
import type { TransactProof } from "@zolana/interface";
import { NullifierKey, ShieldedKeypair, SigningKey, ViewingKey } from "@zolana/keypair";
import { describe, expect, it } from "vitest";

import {
  AssetRegistry,
  Data,
  ProofInputUtxo,
  SOL_MINT,
  TransactionError,
  Utxo,
  canonicalShape,
  deriveBlinding,
  resolveShape,
} from "../../src/index.js";
import { createExternalData } from "../../src/instructions/transact.js";
import { bytesToBigInt, encodeAddress, hashField, sha256Be } from "../../src/internal.js";
import { createProofOutput } from "../../src/utxo.js";
import { decodeData, encodeData } from "../../src/serialization/codecs.js";
import { addressForAssetField } from "../../src/wallet/asset.js";
import { fixtureArray, fixtureObject, fixtureString, hexBytes, readFixture } from "../fixture.js";

function hex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function load(path: string): Readonly<Record<string, unknown>> {
  return readFixture(path, fixtureObject);
}

function section(
  fixture: Readonly<Record<string, unknown>>,
  key: "inputs" | "expected",
): Readonly<Record<string, unknown>> {
  return fixtureObject(fixture[key], `fixture ${key}`);
}

function fixedKeypair(inputs: Readonly<Record<string, unknown>>): Readonly<{
  keypair: ShieldedKeypair;
  nullifierKey: NullifierKey;
}> {
  const signing = SigningKey.fromBytes(
    hexBytes(fixtureString(inputs, "signingSecretBytes")) as Bytes32,
  );
  const nullifierKey = NullifierKey.fromSigningKey(signing);
  const viewing = ViewingKey.fromSeed(
    hexBytes(fixtureString(inputs, "viewingSeedBytes")) as Bytes32,
    0,
  );
  return {
    keypair: ShieldedKeypair.fromKeys(signing, nullifierKey, viewing),
    nullifierKey,
  };
}

function transactionErrorCode(action: () => unknown): string {
  try {
    action();
  } catch (error) {
    if (error instanceof TransactionError) return error.code;
    throw error;
  }
  throw new Error("expected transaction error");
}

describe("manifest-verified Rust transaction vectors", () => {
  it("matches canonical Data bytes, accessors, and malformed errors", () => {
    const fixture = load("transaction/data-v1.json");
    const inputs = section(fixture, "inputs");
    const expected = section(fixture, "expected");
    const records = fixtureArray(inputs, "records").map((entry) => {
      const record = fixtureObject(entry, "data record");
      const tag = fixtureString(record, "tag");
      const kind = tag === "ZoneData" ? "zoneData" : tag === "UtxoData" ? "utxoData" : "memo";
      return { kind, bytes: hexBytes(fixtureString(record, "bytes")) } as const;
    });
    const data = new Data(records);
    const bytes = encodeData(data);

    expect(hex(bytes)).toBe(fixtureString(expected, "wincodeBytes"));
    expect(decodeData(bytes).zoneData()).toEqual(data.zoneData());
    expect(decodeData(bytes).utxoData()).toEqual(data.utxoData());
    expect(decodeData(bytes).memo()).toEqual(data.memo());
    expect(hex(data.zoneData() ?? new Uint8Array())).toBe(
      fixtureString(fixtureObject(expected.accessors), "zoneDataBytes"),
    );
    expect(hex(data.utxoData() ?? new Uint8Array())).toBe(
      fixtureString(fixtureObject(expected.accessors), "utxoDataBytes"),
    );
    expect(hex(data.memo() ?? new Uint8Array())).toBe(
      fixtureString(fixtureObject(expected.accessors), "memoBytes"),
    );
    expect(() => decodeData(bytes.slice(0, -1))).toThrow(TransactionError);
    expect(() => decodeData(Uint8Array.from([...bytes, 0]))).toThrow(TransactionError);
    expect(
      () =>
        new Data([
          { kind: "memo", bytes: Uint8Array.of(1) },
          { kind: "memo", bytes: Uint8Array.of(2) },
        ]),
    ).toThrow(expect.objectContaining({ code: "TRANSACTION_DUPLICATE_DATA_RECORD" }));
    expect(
      () =>
        new Data([
          { kind: "memo", bytes: Uint8Array.of(1) },
          { kind: "zoneData", bytes: Uint8Array.of(2) },
        ]),
    ).toThrow(expect.objectContaining({ code: "TRANSACTION_NON_CANONICAL_DATA_ORDER" }));
  });

  it("matches UTXO hashes, nullifiers, proof fields, and blindings", () => {
    const fixture = load("transaction/utxo-v1.json");
    const inputs = section(fixture, "inputs");
    const expected = section(fixture, "expected");
    const { keypair, nullifierKey } = fixedKeypair(inputs);
    const value = fixtureObject(inputs.utxo, "fixture UTXO");
    const blinding = hexBytes(fixtureString(value, "blindingBytes")) as Bytes31;
    const dataHash = hexBytes(fixtureString(inputs, "dataHashBytes")) as Bytes32;
    const utxo = new Utxo({
      owner: keypair.signingPublicKey(),
      asset: encodeAddress(hexBytes(fixtureString(value, "assetBytes"))),
      amount: BigInt(fixtureString(value, "amount")),
      blinding,
      data: new Data([
        { kind: "utxo", bytes: Uint8Array.of(1, 2, 3) },
        { kind: "memo", bytes: new TextEncoder().encode("hello") },
      ]),
    });
    const proof = new ProofInputUtxo({ utxo, nullifierKey, dataHash });

    expect(
      hex(deriveBlinding(hexBytes(fixtureString(inputs, "blindingSeedBytes")) as Bytes31, 0)),
    ).toBe(fixtureString(value, "blindingBytes"));
    expect(hex(keypair.shieldedAddress().ownerHash())).toBe(
      fixtureString(fixtureObject(expected.proofInput), "ownerHashBytes"),
    );
    expect(hex(proof.hash())).toBe(fixtureString(expected, "utxoHashBytes"));
    expect(hex(proof.nullifier())).toBe(fixtureString(expected, "nullifierBytes"));
    expect(
      () =>
        new Utxo({
          owner: keypair.signingPublicKey(),
          asset: SOL_MINT,
          amount: 1n,
          blinding,
          data: new Data([{ kind: "zoneData", bytes: Uint8Array.of(1) }]),
        }),
    ).toThrow("TRANSACTION_MISSING_ZONE_PROGRAM_ID");
  });

  it("matches shape, external-data, and proof-input hashes", () => {
    const fixture = load("transaction/transact-v1.json");
    const inputs = section(fixture, "inputs");
    const expected = section(fixture, "expected");
    const externalExpected = fixtureObject(expected.externalData);
    const { keypair, nullifierKey } = fixedKeypair(inputs);
    const blindingSeed = new Uint8Array(31).fill(11) as Bytes31;
    const input = new ProofInputUtxo({
      utxo: new Utxo({
        owner: keypair.signingPublicKey(),
        asset: SOL_MINT,
        amount: 100n,
        blinding: deriveBlinding(blindingSeed, 0),
      }),
      nullifierKey,
    });
    const output = createProofOutput({
      owner: keypair.shieldedAddress(),
      ownerTag: keypair.signingPublicKey().confidentialViewTag(),
      asset: SOL_MINT,
      amount: 100n,
      blinding: deriveBlinding(blindingSeed, 1),
    });
    const txViewing = ViewingKey.fromSeed(
      hexBytes(fixtureString(inputs, "txViewingSeedBytes")) as Bytes32,
      0,
    );
    const external = createExternalData({
      instructionDiscriminator: 0,
      expiryUnixTs: 0xffff_ffff_ffff_ffffn,
      relayerFee: 0,
      publicSolAmount: -5n,
      userSolAccount: encodeAddress(new Uint8Array(32).fill(21)),
      userSplToken: SOL_MINT,
      splTokenInterface: SOL_MINT,
      dataHash: new Uint8Array(32).fill(22) as Bytes32,
      zoneDataHash: new Uint8Array(32).fill(23) as Bytes32,
      txViewingPublicKey: txViewing.publicKey(),
      salt: hexBytes(fixtureString(inputs, "saltBytes")) as Bytes16,
      outputs: [],
      resolvedOwnerTags: [],
      messages: [],
    });

    for (const entry of fixtureArray(expected, "shapeCases")) {
      const value = fixtureObject(entry, "shape case");
      expect(
        canonicalShape(
          Number(fixtureString(value, "requestedInputs")),
          Number(fixtureString(value, "requestedOutputs")),
        ),
      ).toEqual({
        inputs: Number(fixtureString(value, "shapeInputs")),
        outputs: Number(fixtureString(value, "shapeOutputs")),
      });
    }
    expect(hex(external.hash())).toBe(fixtureString(externalExpected, "hashBytes"));
    expect(hex(txViewing.publicKey().toBytes())).toBe(
      fixtureString(externalExpected, "txViewingPkBytes"),
    );
    expect(hex(input.hash())).toBe(
      fixtureString(
        fixtureObject(fixtureArray(fixtureObject(expected.proofInputs), "inputContexts")[0]),
        "utxoHashBytes",
      ),
    );
    expect(hex(output.hash())).not.toBe(hex(input.hash()));
    expect(() => canonicalShape(9, 9)).toThrow("TRANSACTION_UNSUPPORTED_SHAPE");
    expect(() => resolveShape(2, 1, { inputs: 1, outputs: 1 })).toThrow(
      "TRANSACTION_TOO_MANY_INPUTS",
    );
  });

  it("matches asset mappings, field lookup, and typed conflicts", () => {
    const fixture = load("transaction/asset-v1.json");
    const inputs = section(fixture, "inputs");
    const expected = section(fixture, "expected");
    const entry = fixtureObject(fixtureArray(inputs, "entries")[0]);
    const mint = encodeAddress(hexBytes(fixtureString(entry, "mintBytes")));
    const registry = new AssetRegistry([[BigInt(fixtureString(entry, "assetId")), mint]]);
    const field = hashField(hexBytes(fixtureString(entry, "mintBytes")));

    expect(registry.resolve(2n)).toBe(mint);
    expect(registry.assetId(mint)).toBe(2n);
    expect(hex(field)).toBe(fixtureString(expected, "assetFieldBytes"));
    expect(addressForAssetField(registry, field)).toBe(mint);
    expect(
      transactionErrorCode(() => {
        registry.insert(1n, encodeAddress(new Uint8Array(32).fill(32)));
      }),
    ).toBe("TRANSACTION_RESERVED_ASSET_ID");
    expect(
      transactionErrorCode(() => {
        registry.insert(2n, encodeAddress(new Uint8Array(32).fill(33)));
      }),
    ).toBe("TRANSACTION_DUPLICATE_ASSET_ID");
    expect(
      transactionErrorCode(() => {
        registry.insert(3n, mint);
      }),
    ).toBe("TRANSACTION_DUPLICATE_MINT");
    expect(transactionErrorCode(() => registry.resolve(999n))).toBe("TRANSACTION_UNKNOWN_ASSET");
    expect(
      transactionErrorCode(() => registry.assetId(encodeAddress(new Uint8Array(32).fill(34)))),
    ).toBe("TRANSACTION_UNKNOWN_MINT");
  });

  it("replays values/errors and shared client proof boundaries", () => {
    const values = load("transaction/values-and-errors-v1.json");
    const valuesInputs = section(values, "inputs");
    const valuesExpected = section(values, "expected");
    expect(
      canonicalShape(
        Number(fixtureString(valuesInputs, "inputs")),
        Number(fixtureString(valuesInputs, "outputs")),
      ),
    ).toEqual({
      inputs: Number(fixtureString(fixtureObject(valuesExpected.shape), "inputs")),
      outputs: Number(fixtureString(fixtureObject(valuesExpected.shape), "outputs")),
    });
    expect(new Data([{ kind: "memo", bytes: Uint8Array.of(4) }]).memo()).toEqual(
      hexBytes(fixtureString(fixtureObject(valuesExpected.canonicalData), "memoBytes")),
    );
    expect(() => canonicalShape(99, 99)).toThrow("TRANSACTION_UNSUPPORTED_SHAPE");
    expect(
      () =>
        new Data([
          { kind: "memo", bytes: Uint8Array.of(4) },
          { kind: "memo", bytes: Uint8Array.of(5) },
        ]),
    ).toThrow("TRANSACTION_DUPLICATE_DATA_RECORD");
    const proofInput = load("client/proof-input-v1.json");
    const proofInputInputs = section(proofInput, "inputs");
    const proofInputExpected = section(proofInput, "expected");
    const dummy = ProofInputUtxo.dummy(
      hexBytes(fixtureString(proofInputInputs, "dummyBlindingBytes")) as Bytes31,
    );
    expect(dummy.isDummy()).toBe(true);
    expect(dummy.utxo.owner.isZero()).toBe(true);
    const reconstructedDummy = new ProofInputUtxo({
      utxo: new Utxo({
        owner: dummy.utxo.owner,
        asset: dummy.utxo.asset,
        amount: dummy.utxo.amount,
        blinding: dummy.utxo.blinding,
      }),
      nullifierKey: dummy.nullifierKey,
    });
    expect(reconstructedDummy.isDummy()).toBe(true);
    expect(reconstructedDummy.hash()).toEqual(dummy.hash());
    expect(hex(dummy.nullifier())).toBe(fixtureString(proofInputExpected, "nullifierBytes"));
    expect(bytesToBigInt(new Uint8Array(32).fill(9))).toBe(
      BigInt(fixtureString(proofInputExpected, "utxoTreeRoot")),
    );
    expect(bytesToBigInt(new Uint8Array(32).fill(10))).toBe(
      BigInt(fixtureString(proofInputExpected, "nullifierTreeRoot")),
    );

    const compression = load("client/proof-result-compression-v1.json");
    const compressedExpected = section(compression, "expected");
    const proof: TransactProof = {
      rail: "p256",
      a: hexBytes(fixtureString(compressedExpected, "aBytes")) as Bytes32,
      b: hexBytes(fixtureString(compressedExpected, "bBytes")) as Bytes64,
      c: hexBytes(fixtureString(compressedExpected, "cBytes")) as Bytes32,
      commitment: hexBytes(fixtureString(compressedExpected, "commitmentBytes")) as Bytes32,
      commitmentPok: hexBytes(fixtureString(compressedExpected, "commitmentPokBytes")) as Bytes32,
    };
    const copied: TransactProof = {
      ...proof,
      a: new Uint8Array(proof.a) as Bytes32,
      b: new Uint8Array(proof.b) as Bytes64,
      c: new Uint8Array(proof.c) as Bytes32,
      commitment: new Uint8Array(proof.commitment) as Bytes32,
      commitmentPok: new Uint8Array(proof.commitmentPok) as Bytes32,
    };
    proof.a.fill(0);
    expect(hex(copied.a)).toBe(fixtureString(compressedExpected, "aBytes"));
    expect(hex(copied.b)).toBe(fixtureString(compressedExpected, "bBytes"));
    expect(hex(copied.commitment)).toBe(fixtureString(compressedExpected, "commitmentBytes"));
    expect(hex(copied.commitmentPok)).toBe(fixtureString(compressedExpected, "commitmentPokBytes"));
    const transact = load("transaction/transact-v1.json");
    const transactInputs = section(transact, "inputs");
    const transactExpected = section(transact, "expected");
    expect(hex(sha256Be(hexBytes(fixtureString(transactInputs, "payerBytes"))))).toBe(
      fixtureString(fixtureObject(transactExpected.proofInputs), "payerPubkeyHashBytes"),
    );
  });
});
