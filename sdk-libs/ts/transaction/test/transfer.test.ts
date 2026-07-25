import type { Address, Bytes16, Bytes31, Bytes32 } from "@zolana/interface";
import { NullifierKey, ShieldedKeypair, SigningKey, ViewingKey } from "@zolana/keypair";
import { describe, expect, it, vi } from "vitest";

import {
  AssetRegistry,
  ConfidentialTransfer,
  Data,
  ProofInputUtxo,
  SOL_MINT,
  SppProofInputs,
  Utxo,
  deriveBlinding,
} from "../src/index.js";
import {
  ConfidentialSplit,
  Merge,
  MergeZone,
  PreparedMerge,
  prepareZoneAuthority,
  validateMergeZoneInputs,
} from "../src/instructions/builders.js";
import { createExternalData } from "../src/instructions/transact.js";
import { encodeAddress } from "../src/internal.js";
import { createProofOutput } from "../src/utxo.js";
import {
  EncryptedScheme,
  encodeOutputData,
  encodeSplitBundle,
  encryptConfidential,
  encryptSplit,
} from "../src/serialization/index.js";
import { fixtureArray, fixtureObject, fixtureString, hexBytes, readFixture } from "./fixture.js";

function hex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function load(name: string): Readonly<Record<string, unknown>> {
  return readFixture(`transaction/${name}-v1.json`, fixtureObject);
}

function section(
  fixture: Readonly<Record<string, unknown>>,
  key: "inputs" | "expected",
): Readonly<Record<string, unknown>> {
  return fixtureObject(fixture[key], `fixture ${key}`);
}

function owner(inputs: Readonly<Record<string, unknown>>): Readonly<{
  keypair: ShieldedKeypair;
  nullifier: NullifierKey;
}> {
  const signing = SigningKey.fromBytes(
    hexBytes(fixtureString(inputs, "signingSecretBytes")) as Bytes32,
  );
  const nullifier = NullifierKey.fromSigningKey(signing);
  return {
    keypair: ShieldedKeypair.fromKeys(
      signing,
      nullifier,
      ViewingKey.fromSeed(hexBytes(fixtureString(inputs, "viewingSeedBytes")) as Bytes32, 0),
    ),
    nullifier,
  };
}

function recipient(): ShieldedKeypair {
  const secret = new Uint8Array(32);
  secret[31] = 12;
  const signing = SigningKey.fromBytes(secret as Bytes32);
  return ShieldedKeypair.fromKeys(
    signing,
    NullifierKey.fromSigningKey(signing),
    ViewingKey.fromSeed(new Uint8Array(32).fill(13) as Bytes32, 0),
  );
}

function fixedInput(
  sender: ReturnType<typeof owner>,
  amount: bigint,
  asset: Address,
  seed: Bytes31,
  position: number,
  zone?: Readonly<{ programId: Address; dataHash: Bytes32 }>,
): ProofInputUtxo {
  return new ProofInputUtxo({
    utxo: new Utxo({
      owner: sender.keypair.signingPublicKey(),
      asset,
      amount,
      blinding: deriveBlinding(seed, position),
      ...(zone === undefined ? {} : { zoneProgramId: zone.programId }),
    }),
    nullifierKey: sender.nullifier,
    ...(zone === undefined ? {} : { zoneDataHash: zone.dataHash }),
  });
}

function proofInputs(inputUtxos: readonly ProofInputUtxo[]): SppProofInputs {
  const ownerTag = new Uint8Array(32).fill(21) as Bytes32;
  const outputs = [0, 1].map((position) =>
    createProofOutput({
      asset: SOL_MINT,
      amount: 0n,
      blinding: new Uint8Array(31).fill(position) as Bytes31,
      ownerTag,
    }),
  );
  return new SppProofInputs({
    payerPublicKeyHash: new Uint8Array(32) as Bytes32,
    inputUtxos,
    outputs,
    externalData: createExternalData({
      instructionDiscriminator: 0,
      expiryUnixTs: 0n,
      relayerFee: 0,
      userSolAccount: SOL_MINT,
      userSplToken: SOL_MINT,
      splTokenInterface: SOL_MINT,
      txViewingPublicKey: ViewingKey.fromSeed(
        new Uint8Array(32).fill(22) as Bytes32,
        0,
      ).publicKey(),
      salt: new Uint8Array(16) as Bytes16,
      outputs: outputs.map((output) => ({
        utxoHash: output.hash(),
        ownerTag: { kind: "inline", value: ownerTag },
      })),
      resolvedOwnerTags: outputs.map(() => ownerTag),
      messages: [],
    }),
  });
}

function inputFor(signing: SigningKey, position: number): ProofInputUtxo {
  return new ProofInputUtxo({
    utxo: new Utxo({
      owner: signing.publicKey(),
      asset: SOL_MINT,
      amount: 10n,
      blinding: new Uint8Array(31).fill(position + 1) as Bytes31,
    }),
    nullifierKey: NullifierKey.fromSigningKey(signing),
  });
}

function withRandom<T>(bytes: Bytes31, action: () => T): T {
  const mock = vi.spyOn(globalThis.crypto, "getRandomValues").mockImplementation((array) => {
    new Uint8Array(array.buffer, array.byteOffset, array.byteLength).set(bytes);
    return array;
  });
  try {
    return action();
  } finally {
    mock.mockRestore();
  }
}

describe("manifest-verified transaction builders", () => {
  it("copies external-data output tags and nested bytes", () => {
    const ownerTag = new Uint8Array(32).fill(1) as Bytes32;
    const outputData = Uint8Array.of(2);
    const messageData = Uint8Array.of(3);
    const external = createExternalData({
      instructionDiscriminator: 0,
      expiryUnixTs: 0n,
      relayerFee: 0,
      userSolAccount: SOL_MINT,
      userSplToken: SOL_MINT,
      splTokenInterface: SOL_MINT,
      txViewingPublicKey: ViewingKey.fromSeed(new Uint8Array(32).fill(4) as Bytes32, 0).publicKey(),
      salt: new Uint8Array(16) as Bytes16,
      outputs: [
        {
          utxoHash: new Uint8Array(32).fill(5) as Bytes32,
          ownerTag: { kind: "inline", value: ownerTag },
          data: outputData,
        },
      ],
      resolvedOwnerTags: [ownerTag],
      messages: [{ viewTag: new Uint8Array(32).fill(6) as Bytes32, data: messageData }],
    });
    const hash = external.hash();

    ownerTag.fill(0xff);
    outputData.fill(0xff);
    messageData.fill(0xff);

    expect(external.hash()).toEqual(hash);
    expect(external.outputs[0]?.ownerTag).toEqual({
      kind: "inline",
      value: new Uint8Array(32).fill(1),
    });
    expect(external.outputs[0]?.data).toEqual(Uint8Array.of(2));
    expect(external.messages[0]?.data).toEqual(Uint8Array.of(3));
  });

  it("accepts a P256 signature for mixed inputs without changing transaction fields", () => {
    const p256 = SigningKey.fromBytes(new Uint8Array(32).fill(1) as Bytes32);
    const ed25519 = SigningKey.fromEd25519Bytes(new Uint8Array(32).fill(2) as Bytes32);
    const p256Input = inputFor(p256, 0);
    const ed25519Input = inputFor(ed25519, 1);
    const inputs = proofInputs([ed25519Input, p256Input]);
    const ownerTags = inputs.externalData.resolvedOwnerTags.map((tag) => new Uint8Array(tag));
    const wireOwnerTags = inputs.externalData.outputs.map((output) => output.ownerTag);
    const messageHash = inputs.messageHash();
    const compact = p256.sign(messageHash);
    const r = compact.slice(0, 32) as Bytes32;
    const s = compact.slice(32) as Bytes32;

    expect(inputs.p256Signature()).toBeUndefined();
    inputs.applyP256Signature({ publicKey: p256.publicKey().p256(), r, s });

    expect(inputs.inputUtxos).toEqual([ed25519Input, p256Input]);
    expect(inputs.externalData.resolvedOwnerTags).toEqual(ownerTags);
    expect(inputs.externalData.outputs.map((output) => output.ownerTag)).toEqual(wireOwnerTags);
    expect(inputs.p256Signature()).toEqual({
      publicKey: p256.publicKey().p256(),
      r: compact.slice(0, 32),
      s: compact.slice(32),
    });
    r.fill(0);
    s.fill(0);
    expect(inputs.p256Signature()?.r).toEqual(compact.slice(0, 32));
    expect(inputs.p256Signature()?.s).toEqual(compact.slice(32));
  });

  it("retains P256 rail signature and owner validation for mixed and homogeneous inputs", () => {
    const p256 = SigningKey.fromBytes(new Uint8Array(32).fill(3) as Bytes32);
    const otherP256 = SigningKey.fromBytes(new Uint8Array(32).fill(4) as Bytes32);
    const ed25519 = SigningKey.fromEd25519Bytes(new Uint8Array(32).fill(5) as Bytes32);
    const p256Input = inputFor(p256, 0);
    const ed25519Input = inputFor(ed25519, 1);
    const signature = p256.sign(proofInputs([p256Input, ed25519Input]).messageHash());
    const valid = {
      publicKey: p256.publicKey().p256(),
      r: signature.slice(0, 32) as Bytes32,
      s: signature.slice(32) as Bytes32,
    };

    expect(proofInputs([p256Input, ed25519Input]).p256Signature()).toBeUndefined();
    expect(() => {
      proofInputs([p256Input, ed25519Input]).applyP256Signature({
        ...valid,
        publicKey: otherP256.publicKey().p256(),
      });
    }).toThrow(expect.objectContaining({ code: "TRANSACTION_SIGNATURE_OWNER_MISMATCH" }));
    expect(() => {
      proofInputs([ed25519Input, ed25519Input]).applyP256Signature(valid);
    }).toThrow(expect.objectContaining({ code: "TRANSACTION_SIGNER_NOT_P256" }));
    expect(() => {
      proofInputs([p256Input, p256Input]).applyP256Signature({
        ...valid,
        r: new Uint8Array(31) as Bytes32,
      });
    }).toThrow(expect.objectContaining({ code: "TRANSACTION_INVALID_LENGTH" }));
    expect(() => {
      proofInputs([p256Input, p256Input]).applyP256Signature({
        ...valid,
        s: new Uint8Array(33) as Bytes32,
      });
    }).toThrow(expect.objectContaining({ code: "TRANSACTION_INVALID_LENGTH" }));

    const homogeneous = proofInputs([p256Input, p256Input]);
    const homogeneousSignature = p256.sign(homogeneous.messageHash());
    homogeneous.applyP256Signature({
      publicKey: p256.publicKey().p256(),
      r: homogeneousSignature.slice(0, 32) as Bytes32,
      s: homogeneousSignature.slice(32) as Bytes32,
    });
    expect(homogeneous.p256Signature()).toEqual({
      publicKey: p256.publicKey().p256(),
      r: homogeneousSignature.slice(0, 32),
      s: homogeneousSignature.slice(32),
    });
  });

  it("matches transfer outputs, wire payloads, hashes, conservation, and errors", () => {
    const fixture = load("transfer");
    const inputs = section(fixture, "inputs");
    const expected = section(fixture, "expected");
    const sender = owner(inputs);
    const receiver = recipient();
    const seed = hexBytes(fixtureString(inputs, "blindingSeedBytes")) as Bytes31;
    const mint = encodeAddress(hexBytes(fixtureString(inputs, "splMintBytes")));
    const registry = new AssetRegistry([[2n, mint]]);
    const spends = [
      fixedInput(sender, BigInt(fixtureString(inputs, "solInputAmount")), SOL_MINT, seed, 0),
      fixedInput(sender, BigInt(fixtureString(inputs, "splInputAmount")), mint, seed, 1),
    ];
    const transfer = withRandom(
      seed,
      () =>
        new ConfidentialTransfer(
          sender.keypair.shieldedAddress(),
          spends,
          encodeAddress(hexBytes(fixtureString(inputs, "payerBytes"))),
        ),
    );
    transfer.send(
      receiver.shieldedAddress(),
      SOL_MINT,
      BigInt(fixtureString(inputs, "recipientAmount")),
    );
    const prepared = transfer.prepare();
    const expectedOutputs = fixtureArray(expected, "outputs").map((entry) =>
      fixtureObject(entry, "transfer output"),
    );

    expect(prepared.shape).toEqual({
      inputs: Number(fixtureString(fixtureObject(expected.shape), "inputs")),
      outputs: Number(fixtureString(fixtureObject(expected.shape), "outputs")),
    });
    prepared.outputs.forEach((output, index) => {
      const value = expectedOutputs[index];
      if (!value) throw new Error("missing fixture output");
      expect(output.amount).toBe(BigInt(fixtureString(value, "amount")));
      expect(hex(output.blinding)).toBe(fixtureString(value, "blindingBytes"));
      expect(hex(output.ownerHash())).toBe(fixtureString(value, "ownerHashBytes"));
      expect(hex(output.hash())).toBe(fixtureString(value, "utxoHashBytes"));
    });
    expect(prepared.outputs.reduce((sum, output) => sum + output.amount, 0n)).toBe(
      BigInt(fixtureString(expected, "conservedAmount")),
    );
    expect(hex(prepared.firstNullifier)).toBe(fixtureString(expected, "firstNullifierBytes"));

    const tx = ViewingKey.fromSeed(
      hexBytes(fixtureString(inputs, "txViewingSeedBytes")) as Bytes32,
      0,
    );
    const salt = hexBytes(fixtureString(inputs, "saltBytes")) as Bytes16;
    const payload = prepared.outputs.map((output, index) => {
      const target = index < 2 ? sender.keypair : receiver;
      return {
        viewTag: target.shieldedAddress().confidentialViewTag(),
        data: encodeOutputData(
          EncryptedScheme.confidential,
          encryptConfidential(
            tx,
            target.viewingPublicKey(),
            {
              assetId: registry.assetId(output.asset),
              amount: output.amount,
              blinding: output.blinding,
              data: output.data,
            },
            salt,
            index,
          ),
          "encrypted",
        ),
      };
    });
    const proof = prepared.finalize({
      txViewingPublicKey: tx.publicKey(),
      salt,
      payload,
    });
    const wireOutputs = fixtureArray(expected, "wireOutputs").map((entry) =>
      fixtureObject(entry, "wire output"),
    );
    proof.externalData.outputs.forEach((output, index) => {
      const wire = wireOutputs[index];
      if (!wire) throw new Error("missing wire fixture");
      expect(hex(output.utxoHash)).toBe(fixtureString(wire, "utxoHashBytes"));
      expect(hex(output.data ?? new Uint8Array())).toBe(fixtureString(wire, "dataBytes"));
    });
    expect(proof.externalData.resolvedOwnerTags.map(hex)).toEqual(
      fixtureArray(expected, "resolvedOwnerTagBytes"),
    );
    expect(hex(proof.externalData.hash())).toBe(fixtureString(expected, "externalDataHashBytes"));
    expect(hex(proof.messageHash())).toBe(fixtureString(expected, "messageHashBytes"));
    const firstSpend = spends[0];
    if (!firstSpend) throw new Error("fixture input missing");

    const insufficient = withRandom(
      seed,
      () => new ConfidentialTransfer(sender.keypair.shieldedAddress(), [firstSpend], SOL_MINT),
    );
    insufficient.send(receiver.shieldedAddress(), mint, 1n);
    expect(() => insufficient.prepare()).toThrow(
      expect.objectContaining({ code: "TRANSACTION_INSUFFICIENT_BALANCE" }),
    );
    const withdrawal = withRandom(
      seed,
      () => new ConfidentialTransfer(sender.keypair.shieldedAddress(), [firstSpend], SOL_MINT),
    );
    withdrawal.withdraw(SOL_MINT, 1n, { kind: "sol", recipient: SOL_MINT });
    expect(() => {
      withdrawal.withdraw(SOL_MINT, 1n, { kind: "sol", recipient: SOL_MINT });
    }).toThrow(expect.objectContaining({ code: "TRANSACTION_WITHDRAWAL_ALREADY_SET" }));
  });

  it("matches split bytes, padded outputs, hashes, and validation", () => {
    const fixture = load("split");
    const inputs = section(fixture, "inputs");
    const expected = section(fixture, "expected");
    const sender = owner(inputs);
    const seed = hexBytes(fixtureString(inputs, "blindingSeedBytes")) as Bytes31;
    const spend = fixedInput(
      sender,
      BigInt(fixtureString(inputs, "inputAmount")),
      SOL_MINT,
      seed,
      0,
    );
    const split = withRandom(
      seed,
      () =>
        new ConfidentialSplit({
          owner: sender.keypair.shieldedAddress(),
          input: spend,
          asset: SOL_MINT,
          numOutputs: Number(fixtureString(inputs, "partCount")),
          perOutputAmount: BigInt(fixtureString(inputs, "partAmount")),
          payer: encodeAddress(new Uint8Array(32).fill(27)),
        }),
    );
    const prepared = split.prepare();
    expect(prepared.asset).toBe(SOL_MINT);
    const expectedOutputs = fixtureArray(expected, "outputs").map((entry) =>
      fixtureObject(entry, "split output"),
    );
    expect(hex(encodeSplitBundle(prepared.bundlePlaintext(new AssetRegistry())))).toBe(
      fixtureString(expected, "bundleWincodeBytes"),
    );
    prepared.outputs.forEach((output, index) => {
      const value = expectedOutputs[index];
      if (!value) throw new Error("missing split output fixture");
      expect(output.amount).toBe(BigInt(fixtureString(value, "amount")));
      expect(hex(output.blinding)).toBe(fixtureString(value, "blindingBytes"));
      expect(hex(output.hash())).toBe(
        fixtureString(fixtureObject(fixtureArray(expected, "wireOutputs")[index]), "utxoHashBytes"),
      );
    });
    expect(prepared.outputs.reduce((sum, output) => sum + output.amount, 0n)).toBe(
      BigInt(fixtureString(expected, "conservedAmount")),
    );
    const tx = ViewingKey.fromSeed(
      hexBytes(fixtureString(inputs, "txViewingSeedBytes")) as Bytes32,
      0,
    );
    const salt = hexBytes(fixtureString(inputs, "saltBytes")) as Bytes16;
    const bundle = encodeSplitBundle(prepared.bundlePlaintext(new AssetRegistry()));
    const proof = prepared.finalize({
      txViewingPublicKey: tx.publicKey(),
      salt,
      payload: {
        viewTag: sender.keypair.shieldedAddress().confidentialViewTag(),
        data: encodeOutputData(
          EncryptedScheme.split,
          encryptSplit(tx, sender.keypair.viewingPublicKey(), bundle, salt, 0),
          "encrypted",
        ),
      },
    });
    expect(hex(proof.externalData.hash())).toBe(fixtureString(expected, "externalDataHashBytes"));
    proof.externalData.outputs.forEach((output, index) => {
      const wire = fixtureObject(fixtureArray(expected, "wireOutputs")[index]);
      expect(hex(output.utxoHash)).toBe(fixtureString(wire, "utxoHashBytes"));
      expect(output.data === undefined ? null : hex(output.data)).toBe(wire.dataBytes);
    });
    expect(
      () =>
        new ConfidentialSplit({
          owner: sender.keypair.shieldedAddress(),
          input: spend,
          asset: SOL_MINT,
          numOutputs: 1,
          perOutputAmount: 96n,
          payer: SOL_MINT,
        }),
    ).toThrow(expect.objectContaining({ code: "TRANSACTION_SPLIT_INVALID_PART_COUNT" }));
    expect(
      () =>
        new ConfidentialSplit({
          owner: sender.keypair.shieldedAddress(),
          input: spend,
          asset: SOL_MINT,
          numOutputs: 3,
          perOutputAmount: 31n,
          payer: SOL_MINT,
        }),
    ).toThrow(expect.objectContaining({ code: "TRANSACTION_SPLIT_AMOUNT_MISMATCH" }));
  });

  it("matches merge contexts and zone-bound hashes", () => {
    const mergeFixture = load("merge");
    const mergeInputs = section(mergeFixture, "inputs");
    const mergeExpected = section(mergeFixture, "expected");
    const sender = owner(mergeInputs);
    const seed = hexBytes(fixtureString(mergeInputs, "blindingSeedBytes")) as Bytes31;
    const real = fixtureArray(mergeInputs, "realInputAmounts").map((amount, index) => {
      if (typeof amount !== "string") throw new Error("merge amount must be a string");
      return fixedInput(sender, BigInt(amount), SOL_MINT, seed, index);
    });
    const prepared = new PreparedMerge({
      inputs: [
        ...real,
        ...Array.from({ length: 6 }, (_, index) =>
          ProofInputUtxo.dummy(deriveBlinding(seed, index + 2)),
        ),
      ],
      output: createProofOutput({
        ownerAddress: sender.keypair.shieldedAddress(),
        asset: SOL_MINT,
        amount: 30n,
        blinding: deriveBlinding(seed, 2),
      }),
      expiryUnixTs: 0xffff_ffff_ffff_ffffn,
      signingPublicKey: sender.keypair.signingPublicKey(),
      userViewingPublicKey: sender.keypair.viewingPublicKey(),
      txViewingSecret: hexBytes(fixtureString(mergeInputs, "txViewingSecretBytes")) as Bytes32,
    });
    expect(prepared.inputs).toHaveLength(Number(fixtureString(mergeExpected, "inputCount")));
    expect(prepared.inputs.filter((input) => input.isDummy())).toHaveLength(
      Number(fixtureString(mergeExpected, "dummyCount")),
    );
    expect(hex(prepared.output.hash())).toBe(fixtureString(mergeExpected, "outputHashBytes"));
    prepared.inputUtxoHashes().forEach((context, index) => {
      const value = fixtureObject(fixtureArray(mergeExpected, "inputContexts")[index]);
      expect(hex(context.utxoHash)).toBe(fixtureString(value, "utxoHashBytes"));
      expect(hex(context.nullifier)).toBe(fixtureString(value, "nullifierBytes"));
    });
    expect(() => new Merge(sender.keypair, [])).toThrow(
      expect.objectContaining({ code: "TRANSACTION_NO_INPUTS" }),
    );
    expect(new Merge(sender.keypair, real).withExpiry(123n).prepare().expiryUnixTs).toBe(123n);
    const firstReal = real[0];
    if (!firstReal) throw new Error("missing real merge input");
    const mismatchedNullifier = new ProofInputUtxo({
      utxo: firstReal.utxo,
      nullifierKey: NullifierKey.fromSecret(new Uint8Array(31).fill(9) as Bytes31),
    });
    expect(() => new Merge(sender.keypair, [mismatchedNullifier])).toThrow(
      expect.objectContaining({ code: "TRANSACTION_MERGE_INPUT_NULLIFIER_KEY_MISMATCH" }),
    );
    const foreignSecret = new Uint8Array(32);
    foreignSecret[31] = 12;
    const foreignSigning = SigningKey.fromBytes(foreignSecret as Bytes32);
    const foreignInput = new ProofInputUtxo({
      utxo: new Utxo({
        owner: foreignSigning.publicKey(),
        asset: SOL_MINT,
        amount: 10n,
        blinding: deriveBlinding(seed, 0),
      }),
      nullifierKey: NullifierKey.fromSigningKey(foreignSigning),
    });
    expect(() => new Merge(sender.keypair, [foreignInput])).toThrow(
      expect.objectContaining({ code: "TRANSACTION_MERGE_INPUT_OWNER_MISMATCH" }),
    );

    const zoneFixture = load("zone");
    const zoneInputs = section(zoneFixture, "inputs");
    const zoneExpected = section(zoneFixture, "expected");
    const zoneSender = owner(zoneInputs);
    const zone = encodeAddress(hexBytes(fixtureString(zoneInputs, "zoneProgramIdBytes")));
    const zoneSpend = fixedInput(zoneSender, 50n, SOL_MINT, seed, 0, {
      programId: zone,
      dataHash: hexBytes(fixtureString(zoneInputs, "inputZoneDataHashBytes")) as Bytes32,
    });
    const zoneOutput = createProofOutput({
      ownerAddress: zoneSender.keypair.shieldedAddress(),
      asset: SOL_MINT,
      amount: 50n,
      blinding: deriveBlinding(seed, 1),
      zoneProgramId: zone,
      zoneDataHash: hexBytes(fixtureString(zoneInputs, "outputZoneDataHashBytes")) as Bytes32,
    });
    expect(hex(zoneSpend.hash())).toBe(
      fixtureString(fixtureObject(zoneExpected.inputContext), "utxoHashBytes"),
    );
    expect(hex(zoneSpend.nullifier())).toBe(
      fixtureString(fixtureObject(zoneExpected.inputContext), "nullifierBytes"),
    );
    expect(hex(zoneOutput.hash())).toBe(fixtureString(zoneExpected, "outputHashBytes"));
    const preparedZone = new MergeZone(
      zoneSender.keypair,
      [zoneSpend],
      zone,
      hexBytes(fixtureString(zoneInputs, "outputZoneDataHashBytes")) as Bytes32,
    ).prepare();
    expect(preparedZone.inputs).toHaveLength(8);
    expect(preparedZone.inputs.filter((input) => input.isDummy())).toHaveLength(7);
    expect(preparedZone.output.amount).toBe(50n);
    expect(preparedZone.output.zoneProgramId).toBe(zone);
    expect(preparedZone.output.zoneDataHash).toEqual(
      hexBytes(fixtureString(zoneInputs, "outputZoneDataHashBytes")),
    );
    expect(
      new MergeZone(zoneSender.keypair, [zoneSpend], zone).withExpiry(456n).prepare().expiryUnixTs,
    ).toBe(456n);
    const zoneDataSpend = new ProofInputUtxo({
      utxo: new Utxo({
        owner: zoneSender.keypair.signingPublicKey(),
        asset: SOL_MINT,
        amount: 50n,
        blinding: deriveBlinding(seed, 0),
        zoneProgramId: zone,
        data: new Data([
          { kind: "zoneData", bytes: Uint8Array.of(1) },
          { kind: "memo", bytes: Uint8Array.of(2) },
        ]),
      }),
      nullifierKey: zoneSender.nullifier,
      zoneDataHash: hexBytes(fixtureString(zoneInputs, "inputZoneDataHashBytes")) as Bytes32,
    });
    expect(() => new MergeZone(zoneSender.keypair, [zoneDataSpend], zone)).not.toThrow();
    expect(preparedZone.inputUtxoHashes()).toEqual([
      {
        index: 0,
        utxoHash: zoneSpend.hash(),
        nullifier: zoneSpend.nullifier(),
      },
    ]);
    expect(() => {
      validateMergeZoneInputs([fixedInput(zoneSender, 50n, SOL_MINT, seed, 0)], zone);
    }).toThrow(expect.objectContaining({ code: "TRANSACTION_MERGE_INPUT_ZONE_MISMATCH" }));
    expect(
      () =>
        new MergeZone(zoneSender.keypair, [fixedInput(zoneSender, 50n, SOL_MINT, seed, 0)], zone),
    ).toThrow(expect.objectContaining({ code: "TRANSACTION_MERGE_INPUT_ZONE_MISMATCH" }));
  });

  // Rust names a zone-bound merge input and a data-carrying one separately, so
  // folding both into one code loses which rule the caller broke.
  it("names the zone binding and the attached data as separate merge rejections", () => {
    const sender = owner(section(load("merge"), "inputs"));
    const seed = new Uint8Array(31).fill(4) as Bytes31;
    const zone = encodeAddress(new Uint8Array(32).fill(9));
    const spend = (
      overrides: Readonly<{ zoneProgramId?: Address; data?: Data; zoneDataHash?: Bytes32 }>,
    ): ProofInputUtxo =>
      new ProofInputUtxo({
        utxo: new Utxo({
          owner: sender.keypair.signingPublicKey(),
          asset: SOL_MINT,
          amount: 10n,
          blinding: deriveBlinding(seed, 0),
          zoneProgramId: overrides.zoneProgramId,
          data: overrides.data,
        }),
        nullifierKey: sender.nullifier,
        zoneDataHash: overrides.zoneDataHash,
      });

    expect(() => new Merge(sender.keypair, [spend({ zoneProgramId: zone })])).toThrow(
      expect.objectContaining({ code: "TRANSACTION_MERGE_INPUT_ZONE_MISMATCH" }),
    );
    for (const overrides of [
      { data: new Data([{ kind: "utxoData" as const, bytes: Uint8Array.of(1) }]) },
      { zoneDataHash: new Uint8Array(32).fill(6) as Bytes32 },
    ]) {
      expect(() => new Merge(sender.keypair, [spend(overrides)])).toThrow(
        expect.objectContaining({ code: "TRANSACTION_MERGE_INPUT_HAS_DATA" }),
      );
    }
  });

  // Split proves ownership from the nullifier secret behind `ownerHash`, so each
  // of these inputs is unprovable and Rust names its own rejection for each.
  it("names each split input the owner cannot open", () => {
    const sender = owner(section(load("split"), "inputs"));
    const seed = new Uint8Array(31).fill(4) as Bytes31;
    const build = (input: ProofInputUtxo): (() => ConfidentialSplit) => {
      return () =>
        new ConfidentialSplit({
          owner: sender.keypair.shieldedAddress(),
          input,
          asset: SOL_MINT,
          numOutputs: 2,
          perOutputAmount: 5n,
          payer: SOL_MINT,
        });
    };
    const utxo = new Utxo({
      owner: sender.keypair.signingPublicKey(),
      asset: SOL_MINT,
      amount: 10n,
      blinding: deriveBlinding(seed, 0),
    });

    expect(build(ProofInputUtxo.dummy(deriveBlinding(seed, 1)))).toThrow(
      expect.objectContaining({ code: "TRANSACTION_SPLIT_INPUT_IS_DUMMY" }),
    );

    const foreignSecret = new Uint8Array(32);
    foreignSecret[31] = 12;
    const foreign = SigningKey.fromBytes(foreignSecret as Bytes32);
    expect(
      build(
        new ProofInputUtxo({
          utxo: new Utxo({
            owner: foreign.publicKey(),
            asset: SOL_MINT,
            amount: 10n,
            blinding: deriveBlinding(seed, 0),
          }),
          nullifierKey: NullifierKey.fromSigningKey(foreign),
        }),
      ),
    ).toThrow(expect.objectContaining({ code: "TRANSACTION_SPLIT_INPUT_OWNER_MISMATCH" }));

    expect(
      build(
        new ProofInputUtxo({
          utxo,
          nullifierKey: NullifierKey.fromSecret(new Uint8Array(31).fill(9) as Bytes31),
        }),
      ),
    ).toThrow(expect.objectContaining({ code: "TRANSACTION_SPLIT_INPUT_NULLIFIER_KEY_MISMATCH" }));
  });

  // The zone program signs a zone-authority transact, not the UTXO owners, so
  // the zone binding is what keeps their value inside the policy zone.
  it("pins a zone-authority transact to a nonzero zone and refuses an outgoing leg", () => {
    const sender = owner(section(load("zone"), "inputs"));
    const seed = new Uint8Array(31).fill(4) as Bytes31;
    const zone = encodeAddress(new Uint8Array(32).fill(9));
    const zoned = (zoneProgramId?: Address): ProofInputUtxo =>
      new ProofInputUtxo({
        utxo: new Utxo({
          owner: sender.keypair.signingPublicKey(),
          asset: SOL_MINT,
          amount: 10n,
          blinding: deriveBlinding(seed, 0),
          zoneProgramId,
        }),
        nullifierKey: sender.nullifier,
      });
    const output = (zoneProgramId?: Address) =>
      createProofOutput({
        ownerAddress: sender.keypair.shieldedAddress(),
        asset: SOL_MINT,
        amount: 10n,
        blinding: deriveBlinding(seed, 1),
        zoneProgramId,
      });
    const payerPublicKeyHash = new Uint8Array(32).fill(3) as Bytes32;
    const prepare = (overrides: Partial<Parameters<typeof prepareZoneAuthority>[0]>) =>
      prepareZoneAuthority({
        inputs: [zoned(zone)],
        outputs: [output(zone)],
        zoneProgramId: zone,
        payerPublicKeyHash,
        ...overrides,
      });

    expect(prepare({}).zoneProgramId).toBe(zone);
    expect(prepare({}).inputUtxoHashes()).toHaveLength(1);

    expect(() => prepare({ zoneProgramId: SOL_MINT })).toThrow(
      expect.objectContaining({ code: "TRANSACTION_MISSING_ZONE_AUTHORITY_PROGRAM_ID" }),
    );
    for (const stray of [undefined, encodeAddress(new Uint8Array(32).fill(8))]) {
      expect(() => prepare({ inputs: [zoned(stray)] })).toThrow(
        expect.objectContaining({ code: "TRANSACTION_ZONE_AUTHORITY_INPUT_ZONE_MISMATCH" }),
      );
      expect(() => prepare({ outputs: [output(stray)] })).toThrow(
        expect.objectContaining({ code: "TRANSACTION_ZONE_AUTHORITY_OUTPUT_ZONE_MISMATCH" }),
      );
    }
    for (const publicAmounts of [{ sol: -10n }, { spl: -10n }]) {
      expect(() => prepare({ publicAmounts })).toThrow(
        expect.objectContaining({ code: "TRANSACTION_ZONE_AUTHORITY_WITHDRAWAL_NOT_ALLOWED" }),
      );
    }
    // Paying value into the zone is gated by neither the program nor the
    // circuit, so the authority rail must be able to build it.
    expect(prepare({ publicAmounts: { sol: 10n } }).publicAmounts).toEqual({ sol: 10n });
  });
});
