import type { Address, Bytes16, Bytes31, Bytes32 } from "@zolana/interface";
import { NullifierKey, ShieldedKeypair, SigningKey, ViewingKey } from "@zolana/keypair";
import { describe, expect, it } from "vitest";

import { AssetRegistry, Data, SOL_MINT, Utxo, deriveBlinding } from "../src/index.js";
import { decodeAddress, hashField } from "../src/internal.js";
import {
  EncryptedScheme,
  anonymousRecipientUtxo,
  confidentialPlaintextFromUtxo,
  decodeAnonymousRecipient,
  decodeAnonymousSender,
  decodeMerge,
  decodeOutputData,
  decodePlaintextTransfer,
  decodeProofless,
  decodeSplitBundle,
  decryptConfidential,
  decryptMerge,
  encodeAnonymousRecipient,
  encodeAnonymousSender,
  encodeConfidential,
  encodeMerge,
  encodeOutputData,
  encodePlaintextTransfer,
  encodeProofless,
  encodeSplitBundle,
  encryptedSchemeFromByte,
  encryptAnonymous,
  encryptConfidential,
  encryptMerge,
  encryptSplit,
  mergePlaintextFromUtxo,
  mergeUtxo,
} from "../src/serialization/index.js";
import { decodeSplitEncrypted, encodeSplitEncrypted } from "../src/serialization/codecs.js";
import { fixtureArray, fixtureObject, fixtureString, hexBytes, readFixture } from "./fixture.js";

function hex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function load(): Readonly<Record<string, unknown>> {
  return readFixture("transaction/serialization-v1.json", fixtureObject);
}

function section(
  fixture: Readonly<Record<string, unknown>>,
  key: "inputs" | "expected",
): Readonly<Record<string, unknown>> {
  return fixtureObject(fixture[key], `fixture ${key}`);
}

function keys(inputs: Readonly<Record<string, unknown>>): Readonly<{
  keypair: ShieldedKeypair;
  recipient: ShieldedKeypair;
  recipientViewing: ViewingKey;
  tx: ViewingKey;
  viewing: ViewingKey;
}> {
  const signing = SigningKey.fromBytes(
    hexBytes(fixtureString(inputs, "signingSecretBytes")) as Bytes32,
  );
  const viewing = ViewingKey.fromSeed(
    hexBytes(fixtureString(inputs, "viewingSeedBytes")) as Bytes32,
    0,
  );
  const keypair = ShieldedKeypair.fromKeys(signing, NullifierKey.fromSigningKey(signing), viewing);
  const recipientSecret = new Uint8Array(32);
  recipientSecret[31] = 12;
  const recipientSigning = SigningKey.fromBytes(recipientSecret as Bytes32);
  const recipientViewing = ViewingKey.fromSeed(new Uint8Array(32).fill(13) as Bytes32, 0);
  return {
    keypair,
    recipient: ShieldedKeypair.fromKeys(
      recipientSigning,
      NullifierKey.fromSigningKey(recipientSigning),
      recipientViewing,
    ),
    recipientViewing,
    tx: ViewingKey.fromSeed(hexBytes(fixtureString(inputs, "txViewingSeedBytes")) as Bytes32, 0),
    viewing,
  };
}

describe("manifest-verified transaction serialization", () => {
  it("matches every plaintext family and exact encrypted envelope", () => {
    const fixture = load();
    const inputs = section(fixture, "inputs");
    const families = fixtureObject(section(fixture, "expected").families, "fixture families");
    const { keypair, recipient, recipientViewing, tx } = keys(inputs);
    const data = new Data([{ kind: "memo", bytes: new TextEncoder().encode("codec") }]);
    const seed = hexBytes(fixtureString(inputs, "blindingSeedBytes")) as Bytes31;
    const salt = hexBytes(fixtureString(inputs, "saltBytes")) as Bytes16;

    const confidential = {
      assetId: 1n,
      amount: 55n,
      blinding: deriveBlinding(seed, 1),
      data,
    };
    const confidentialExpected = fixtureObject(families.confidential);
    const confidentialBytes = encodeConfidential(confidential);
    const confidentialBody = encryptConfidential(
      tx,
      recipient.viewingPublicKey(),
      confidential,
      salt,
      0,
    );
    expect(hex(confidentialBytes)).toBe(fixtureString(confidentialExpected, "wincodeBytes"));
    expect(hex(confidentialBody)).toBe(fixtureString(confidentialExpected, "encryptedBodyBytes"));
    expect(hex(encodeOutputData(EncryptedScheme.confidential, confidentialBody, "encrypted"))).toBe(
      fixtureString(confidentialExpected, "envelopeBorshBytes"),
    );
    expect(
      decryptConfidential(recipientViewing, tx.publicKey(), confidentialBody, salt, 0),
    ).toMatchObject({ assetId: 1n, amount: 55n });

    const anonymousRecipient = {
      ownerPublicKey: recipient.signingPublicKey(),
      senderPublicKey: keypair.viewingPublicKey(),
      assetId: 1n,
      amount: 19n,
      blinding: deriveBlinding(seed, 2),
      data,
    };
    const recipientExpected = fixtureObject(families.anonymousRecipient);
    const recipientBytes = encodeAnonymousRecipient(anonymousRecipient);
    const recipientBody = encryptAnonymous(
      tx,
      recipient.viewingPublicKey(),
      recipientBytes,
      salt,
      1,
    );
    expect(hex(recipientBytes)).toBe(fixtureString(recipientExpected, "wincodeBytes"));
    expect(hex(recipientBody)).toBe(fixtureString(recipientExpected, "encryptedBodyBytes"));
    expect(
      hex(encodeOutputData(EncryptedScheme.anonymousRecipient, recipientBody, "encrypted")),
    ).toBe(fixtureString(recipientExpected, "envelopeBorshBytes"));
    expect(decodeAnonymousRecipient(recipientBytes)).toMatchObject({
      assetId: 1n,
      amount: 19n,
    });
    expect(
      anonymousRecipientUtxo(
        {
          ...anonymousRecipient,
          data: new Data([{ kind: "utxoData", bytes: Uint8Array.of(1) }]),
        },
        new AssetRegistry(),
      ).data.utxoData(),
    ).toEqual(Uint8Array.of(1));
    const zoneProgramId = "SysvarRent111111111111111111111111111111111" as Address;
    expect(
      anonymousRecipientUtxo(
        {
          ...anonymousRecipient,
          data: new Data([{ kind: "zoneData", bytes: Uint8Array.of(2) }]),
        },
        new AssetRegistry(),
        zoneProgramId,
      ).zoneProgramId,
    ).toBe(zoneProgramId);

    const anonymousSender = {
      ownerPublicKey: keypair.signingPublicKey(),
      splAssetId: 0n,
      splAmount: 0n,
      solAmount: 36n,
      blindingSeed: seed,
      recipientViewingPublicKeys: [recipient.viewingPublicKey()],
      splData: new Data(),
      solData: data,
    };
    const senderExpected = fixtureObject(families.anonymousSender);
    const senderBytes = encodeAnonymousSender(anonymousSender);
    const senderBody = encryptAnonymous(tx, keypair.viewingPublicKey(), senderBytes, salt, 2);
    expect(hex(senderBytes)).toBe(fixtureString(senderExpected, "wincodeBytes"));
    expect(hex(senderBody)).toBe(fixtureString(senderExpected, "encryptedBodyBytes"));
    expect(hex(encodeOutputData(EncryptedScheme.anonymousSender, senderBody, "encrypted"))).toBe(
      fixtureString(senderExpected, "envelopeBorshBytes"),
    );
    expect(decodeAnonymousSender(senderBytes)).toMatchObject({
      splAmount: 0n,
      solAmount: 36n,
    });

    const split = {
      ownerPublicKey: keypair.signingPublicKey(),
      numOutputs: 3,
      assetId: 1n,
      assetAmount: 12n,
      blindingSeed: seed,
      data,
    };
    const splitExpected = fixtureObject(families.split);
    const splitBytes = encodeSplitBundle(split);
    const splitBody = encryptSplit(tx, keypair.viewingPublicKey(), splitBytes, salt, 3);
    expect(hex(splitBytes)).toBe(fixtureString(splitExpected, "wincodeBytes"));
    expect(hex(splitBody)).toBe(fixtureString(splitExpected, "encryptedBodyBytes"));
    expect(hex(encodeOutputData(EncryptedScheme.split, splitBody, "encrypted"))).toBe(
      fixtureString(splitExpected, "envelopeBorshBytes"),
    );
    expect(decodeSplitBundle(encodeSplitBundle(split))).toMatchObject({
      numOutputs: 3,
      assetAmount: 12n,
    });

    const plaintext = {
      typePrefix: 4,
      blindingSeed: seed,
      sender: {
        ownerPublicKey: keypair.signingPublicKey(),
        spl: { amount: 7n, assetId: 1n },
        solAmount: 8n,
        splData: new Data(),
        solData: data,
      },
      recipientSlots: [
        {
          ownerPublicKey: recipient.signingPublicKey(),
          assetId: 1n,
          amount: 9n,
          data,
        },
      ],
    };
    const plaintextExpected = fixtureObject(families.plaintextTransfer);
    const plaintextBytes = encodePlaintextTransfer(plaintext);
    expect(hex(plaintextBytes)).toBe(fixtureString(plaintextExpected, "wincodeBytes"));
    expect(
      hex(encodeOutputData(EncryptedScheme.plaintextTransfer, plaintextBytes, "plaintext")),
    ).toBe(fixtureString(plaintextExpected, "envelopeBorshBytes"));
    expect(decodePlaintextTransfer(plaintextBytes, 4)).toMatchObject({
      sender: { spl: { amount: 7n }, solAmount: 8n },
    });
  });

  it("matches proofless, merge, and split-encrypted fixed layouts", () => {
    const fixture = load();
    const inputs = section(fixture, "inputs");
    const families = fixtureObject(section(fixture, "expected").families);
    const { keypair, tx, viewing } = keys(inputs);
    const seed = hexBytes(fixtureString(inputs, "blindingSeedBytes")) as Bytes31;
    const proofless = encodeProofless({
      owner: keypair.shieldedAddress().ownerHash(),
      blinding: deriveBlinding(seed, 4),
      asset: SOL_MINT,
      amount: 33n,
    });
    const prooflessExpected = fixtureObject(families.proofless);
    expect(hex(proofless)).toBe(fixtureString(prooflessExpected, "borshBytes"));
    const decoded = decodeProofless(proofless);
    expect(decoded).toMatchObject({ asset: SOL_MINT, amount: 33n });
    const framed = encodeOutputData(EncryptedScheme.proofless, proofless, "plaintext");
    expect(hex(framed)).toBe(fixtureString(prooflessExpected, "envelopeBorshBytes"));
    expect(decodeOutputData(framed)).toMatchObject({
      scheme: EncryptedScheme.proofless,
      encoding: "plaintext",
    });

    const merge = {
      amount: 77n,
      assetField: hashField(decodeAddress(SOL_MINT)),
      blinding: deriveBlinding(seed, 3),
    };
    const mergeExpected = fixtureObject(families.merge);
    const mergeBytes = encodeMerge(merge);
    const mergeCiphertext = encryptMerge(tx, keypair.viewingPublicKey(), merge);
    expect(hex(mergeBytes)).toBe(fixtureString(mergeExpected, "fixedBytes"));
    expect(hex(mergeCiphertext)).toBe(fixtureString(mergeExpected, "encryptedBodyBytes"));
    expect(hex(encodeOutputData(EncryptedScheme.merge, mergeCiphertext, "verifiable"))).toBe(
      fixtureString(mergeExpected, "envelopeBorshBytes"),
    );
    expect(decodeMerge(encodeMerge(merge))).toEqual(merge);
    expect(decryptMerge(viewing, mergeCiphertext)).toEqual(merge);
    const assets = new AssetRegistry();
    const mergeOutput = mergeUtxo(
      merge,
      keypair.signingPublicKey(),
      assets,
      "SysvarRent111111111111111111111111111111111" as Address,
    );
    expect(mergeOutput.zoneProgramId).toBe("SysvarRent111111111111111111111111111111111");
    expect(mergePlaintextFromUtxo(mergeOutput, keypair.signingPublicKey())).toEqual(merge);
    expect(
      confidentialPlaintextFromUtxo(
        new Utxo({
          owner: keypair.signingPublicKey(),
          asset: SOL_MINT,
          amount: 55n,
          blinding: deriveBlinding(seed, 1),
          data: new Data(),
        }),
        keypair.signingPublicKey(),
        assets,
      ),
    ).toMatchObject({ assetId: 1n, amount: 55n });

    const splitEncryptedExpected = fixtureObject(families.splitEncrypted);
    const splitEncrypted = encodeSplitEncrypted({
      typePrefix: 2,
      txViewingPublicKey: tx.publicKey(),
      salt: hexBytes(fixtureString(inputs, "saltBytes")) as Bytes16,
      ciphertext: Uint8Array.of(1, 2, 3, 4, 5),
    });
    expect(hex(splitEncrypted)).toBe(fixtureString(splitEncryptedExpected, "wincodeBytes"));
    expect(decodeSplitEncrypted(splitEncrypted).ciphertext).toEqual(Uint8Array.of(1, 2, 3, 4, 5));
  });

  it("rejects every malformed fixture family", () => {
    const fixture = load();
    const { recipientViewing, tx } = keys(section(fixture, "inputs"));
    const expected = section(fixture, "expected");
    const schemes = fixtureArray(expected, "schemes").map((entry) => {
      const value = fixtureObject(entry, "scheme");
      return Number(fixtureString(value, "byte"));
    });
    expect(schemes).toEqual([0, 1, 2, 3, 5, 6, 7]);
    expect(() => decodeOutputData(Uint8Array.of(4, 0, 0, 0, 0))).toThrow();
    expect(() => encryptedSchemeFromByte(4)).toThrow(
      expect.objectContaining({
        code: "TRANSACTION_BAD_DISCRIMINATOR",
        details: { byte: 4 },
      }),
    );
    expect(() =>
      encodeOutputData(EncryptedScheme.confidential, Uint8Array.of(1), "plaintext"),
    ).toThrow(expect.objectContaining({ code: "TRANSACTION_BAD_DISCRIMINATOR" }));
    expect(() => decodeOutputData(Uint8Array.of(0, 1, 0, 0, 0, 3))).toThrow(
      expect.objectContaining({ code: "TRANSACTION_BAD_DISCRIMINATOR" }),
    );
    expect(() => decodeOutputData(Uint8Array.of(0, 0, 0, 0, 0))).toThrow(
      expect.objectContaining({
        code: "TRANSACTION_INVALID_LENGTH",
        details: { field: "encryptedOutput", expectedMinimum: 1, actual: 0 },
      }),
    );
    const plaintext = hexBytes(
      fixtureString(
        fixtureObject(fixtureObject(expected.families).plaintextTransfer),
        "wincodeBytes",
      ),
    );
    plaintext[0] = 0xff;
    expect(() => decodePlaintextTransfer(plaintext, 4)).toThrow(
      expect.objectContaining({ code: "TRANSACTION_BAD_DISCRIMINATOR" }),
    );
    const merge = hexBytes(
      fixtureString(fixtureObject(fixtureObject(expected.families).merge), "fixedBytes"),
    );
    expect(() => decodeMerge(merge.slice(0, -1))).toThrow(
      expect.objectContaining({ code: "TRANSACTION_INVALID_LENGTH" }),
    );
    const proofless = hexBytes(
      fixtureString(fixtureObject(fixtureObject(expected.families).proofless), "borshBytes"),
    );
    expect(() => decodeProofless(proofless.slice(0, -1))).toThrow();
    expect(() =>
      decryptConfidential(
        recipientViewing,
        tx.publicKey(),
        new Uint8Array(49),
        new Uint8Array(16) as Bytes16,
        0,
      ),
    ).toThrow();
  });
});
