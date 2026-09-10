import { describe, expect, it } from "vitest";

import type { Address, Bytes16, Bytes32 } from "../../src/interface/index.js";
import { ShieldedKeypair, SigningKey, ViewingKey } from "../../src/keypair/index.js";
import {
  AssetRegistry,
  Data,
  SOL_MINT,
  Utxo,
  outputBlindingSeed,
  transactOutputBlinding,
} from "../../src/transaction/index.js";
import {
  EncryptedScheme,
  anonymousRecipientUtxo,
  anonymousSenderUtxos,
  confidentialPlaintextFromUtxo,
  decodeAnonymousRecipient,
  decodeAnonymousSender,
  decodeConfidential,
  decodeOutputData,
  decodePlaintextTransfer,
  decodeProofless,
  decodeSplitBundle,
  decryptAnonymous,
  decryptConfidential,
  decryptSplit,
  encodeAnonymousRecipient,
  encodeAnonymousSender,
  encodeConfidential,
  encodeOutputData,
  encodePlaintextTransfer,
  encodeProofless,
  encodeSplitBundle,
  encryptedSchemeFromByte,
  encryptAnonymous,
  encryptConfidential,
  encryptSplit,
  plaintextTransferUtxos,
  splitBundleUtxos,
} from "../../src/transaction/serialization/index.js";
import {
  decodeSplitEncrypted,
  encodeSplitEncrypted,
} from "../../src/transaction/serialization/codecs.js";
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
  const signing = SigningKey.fromP256Bytes(
    hexBytes(fixtureString(inputs, "signingSecretBytes")) as Bytes32,
  );
  const viewing = ViewingKey.fromBytes(
    hexBytes(fixtureString(inputs, "viewingSecretBytes")) as Bytes32,
  );
  const keypair = ShieldedKeypair.withViewingKey(signing, viewing);
  const recipientSigning = SigningKey.fromP256Bytes(
    hexBytes(fixtureString(inputs, "recipientSigningSecretBytes")) as Bytes32,
  );
  const recipientViewing = ViewingKey.fromBytes(
    hexBytes(fixtureString(inputs, "recipientViewingSecretBytes")) as Bytes32,
  );
  return {
    keypair,
    recipient: ShieldedKeypair.withViewingKey(recipientSigning, recipientViewing),
    recipientViewing,
    tx: ViewingKey.fromBytes(hexBytes(fixtureString(inputs, "txViewingSecretBytes")) as Bytes32),
    viewing,
  };
}

/**
 * The transact blinding family the fixture's slots are blinded with: every
 * output slot `i` carries `TXOB(firstNullifier, outputSeed, i)` where the
 * output seed is `TXOS(firstNullifier, blindingSeedBytes)`. The
 * seed-disclosing plaintexts publish the DERIVED output seed, never the root.
 */
function slotBlindings(inputs: Readonly<Record<string, unknown>>): Readonly<{
  firstNullifier: Bytes32;
  outputSeed: Bytes32;
  blinding(slot: number): Bytes32;
}> {
  const seed = hexBytes(fixtureString(inputs, "blindingSeedBytes")) as Bytes32;
  const firstNullifier = hexBytes(fixtureString(inputs, "firstNullifierBytes")) as Bytes32;
  const outputSeed = outputBlindingSeed(firstNullifier, seed);
  return {
    firstNullifier,
    outputSeed,
    blinding: (slot: number): Bytes32 => transactOutputBlinding(firstNullifier, outputSeed, slot),
  };
}

/** The `wincodeBytes`, `encryptedBodyBytes`, and `envelopeBorshBytes` goldens of one family. */
function family(
  families: Readonly<Record<string, unknown>>,
  name: string,
): Readonly<Record<string, unknown>> {
  return fixtureObject(families[name], `family ${name}`);
}

describe("manifest-verified transaction serialization", () => {
  it("encodes and opens every active plaintext family", () => {
    const fixture = load();
    const inputs = section(fixture, "inputs");
    const families = fixtureObject(section(fixture, "expected").families);
    const { keypair, recipient, recipientViewing, tx } = keys(inputs);
    const data = new Data([{ kind: "memo", bytes: new TextEncoder().encode("codec") }]);
    const { firstNullifier, outputSeed, blinding } = slotBlindings(inputs);
    const salt = hexBytes(fixtureString(inputs, "saltBytes")) as Bytes16;
    const assets = new AssetRegistry();

    const confidential = {
      assetId: 1n,
      amount: 55n,
      blinding: blinding(1),
      data,
    };
    const confidentialBytes = encodeConfidential(confidential);
    const confidentialExpected = family(families, "confidential");
    expect(hex(confidentialBytes)).toBe(fixtureString(confidentialExpected, "wincodeBytes"));
    expect(decodeConfidential(confidentialBytes)).toEqual(confidential);
    const confidentialBody = encryptConfidential(
      tx,
      recipient.viewingPublicKey(),
      confidential,
      salt,
      0,
    );
    expect(hex(confidentialBody)).toBe(fixtureString(confidentialExpected, "encryptedBodyBytes"));
    const confidentialEnvelope = encodeOutputData(
      EncryptedScheme.confidential,
      confidentialBody,
      "encrypted",
    );
    expect(hex(confidentialEnvelope)).toBe(
      fixtureString(confidentialExpected, "envelopeBorshBytes"),
    );
    expect(decodeOutputData(confidentialEnvelope)).toMatchObject({
      scheme: EncryptedScheme.confidential,
      encoding: "encrypted",
    });
    expect(
      decryptConfidential(recipientViewing, tx.publicKey(), confidentialBody, salt, 0),
    ).toEqual(confidential);

    const anonymousRecipient = {
      ownerPublicKey: recipient.signingPublicKey(),
      senderPublicKey: keypair.viewingPublicKey(),
      assetId: 1n,
      amount: 19n,
      blinding: blinding(2),
      data,
    };
    const recipientBytes = encodeAnonymousRecipient(anonymousRecipient);
    const recipientExpected = family(families, "anonymousRecipient");
    expect(hex(recipientBytes)).toBe(fixtureString(recipientExpected, "wincodeBytes"));
    const recipientBody = encryptAnonymous(
      tx,
      recipient.viewingPublicKey(),
      recipientBytes,
      salt,
      1,
    );
    expect(hex(recipientBody)).toBe(fixtureString(recipientExpected, "encryptedBodyBytes"));
    expect(
      hex(encodeOutputData(EncryptedScheme.anonymousRecipient, recipientBody, "encrypted")),
    ).toBe(fixtureString(recipientExpected, "envelopeBorshBytes"));
    expect(
      decodeAnonymousRecipient(
        decryptAnonymous(recipientViewing, tx.publicKey(), recipientBody, salt, 1),
      ),
    ).toEqual(anonymousRecipient);
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
    const ringProgramId = "SysvarRent111111111111111111111111111111111" as Address;
    expect(
      anonymousRecipientUtxo(
        {
          ...anonymousRecipient,
          data: new Data([{ kind: "ringData", bytes: Uint8Array.of(2) }]),
        },
        new AssetRegistry(),
        ringProgramId,
      ).ringProgramId,
    ).toBe(ringProgramId);

    const anonymousSender = {
      ownerPublicKey: keypair.signingPublicKey(),
      splAssetId: 0n,
      splAmount: 0n,
      solAmount: 36n,
      blindingSeed: outputSeed,
      recipientViewingPublicKeys: [recipient.viewingPublicKey()],
      splData: new Data(),
      solData: data,
    };
    const senderBytes = encodeAnonymousSender(anonymousSender);
    const senderExpected = family(families, "anonymousSender");
    expect(hex(senderBytes)).toBe(fixtureString(senderExpected, "wincodeBytes"));
    const senderBody = encryptAnonymous(tx, keypair.viewingPublicKey(), senderBytes, salt, 2);
    expect(hex(senderBody)).toBe(fixtureString(senderExpected, "encryptedBodyBytes"));
    expect(hex(encodeOutputData(EncryptedScheme.anonymousSender, senderBody, "encrypted"))).toBe(
      fixtureString(senderExpected, "envelopeBorshBytes"),
    );
    const decodedSender = decodeAnonymousSender(
      decryptAnonymous(keypair.viewingKey(), tx.publicKey(), senderBody, salt, 2),
    );
    expect(decodedSender).toEqual(anonymousSender);
    expect(decodeAnonymousSender(senderBytes)).toMatchObject({
      splAmount: 0n,
      solAmount: 36n,
    });
    // The disclosed seed plus the first nullifier recovers the SOL change
    // blinding at its fixed slot, 1.
    expect(
      anonymousSenderUtxos(decodedSender, assets, SOL_MINT, firstNullifier).map(
        (utxo) => utxo.blinding,
      ),
    ).toEqual([blinding(1)]);

    const split = {
      ownerPublicKey: keypair.signingPublicKey(),
      numOutputs: 3,
      assetId: 1n,
      assetAmount: 12n,
      blindingSeed: outputSeed,
      data,
    };
    const splitBytes = encodeSplitBundle(split);
    const splitExpected = family(families, "split");
    expect(hex(splitBytes)).toBe(fixtureString(splitExpected, "wincodeBytes"));
    const splitBody = encryptSplit(tx, keypair.viewingPublicKey(), splitBytes, salt, 3);
    expect(hex(splitBody)).toBe(fixtureString(splitExpected, "encryptedBodyBytes"));
    expect(hex(encodeOutputData(EncryptedScheme.split, splitBody, "encrypted"))).toBe(
      fixtureString(splitExpected, "envelopeBorshBytes"),
    );
    const decodedSplit = decodeSplitBundle(
      decryptSplit(keypair.viewingKey(), tx.publicKey(), splitBody, salt, 3),
    );
    expect(decodedSplit).toEqual(split);
    expect(decodeSplitBundle(encodeSplitBundle(split))).toMatchObject({
      numOutputs: 3,
      assetAmount: 12n,
    });
    expect(
      splitBundleUtxos(decodedSplit, assets, firstNullifier).map((utxo) => utxo.blinding),
    ).toEqual([blinding(0), blinding(1), blinding(2)]);

    const plaintext = {
      typePrefix: 4,
      blindingSeed: outputSeed,
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
    const plaintextBytes = encodePlaintextTransfer(plaintext);
    const plaintextExpected = family(families, "plaintextTransfer");
    expect(hex(plaintextBytes)).toBe(fixtureString(plaintextExpected, "wincodeBytes"));
    const plaintextEnvelope = encodeOutputData(
      EncryptedScheme.plaintextTransfer,
      plaintextBytes,
      "plaintext",
    );
    expect(hex(plaintextEnvelope)).toBe(fixtureString(plaintextExpected, "envelopeBorshBytes"));
    expect(decodeOutputData(plaintextEnvelope)).toMatchObject({
      scheme: EncryptedScheme.plaintextTransfer,
      encoding: "plaintext",
    });
    const decodedPlaintext = decodePlaintextTransfer(plaintextBytes, 4);
    expect(decodedPlaintext).toMatchObject({
      sender: { spl: { amount: 7n }, solAmount: 8n },
    });
    // SPL change at slot 0, SOL change at slot 1, the first recipient at slot 2.
    expect(
      plaintextTransferUtxos(decodedPlaintext, assets, SOL_MINT, firstNullifier).map(
        (utxo) => utxo.blinding,
      ),
    ).toEqual([blinding(0), blinding(1), blinding(2)]);
  });

  it("matches proofless and split-encrypted fixed layouts", () => {
    const fixture = load();
    const inputs = section(fixture, "inputs");
    const families = fixtureObject(section(fixture, "expected").families);
    const { keypair, tx } = keys(inputs);
    const { blinding } = slotBlindings(inputs);
    const proofless = encodeProofless({
      owner: keypair.shieldedAddress().ownerHash(),
      blinding: blinding(4),
      asset: SOL_MINT,
      amount: 33n,
    });
    expect(proofless).toHaveLength(110);
    const prooflessExpected = family(families, "proofless");
    expect(hex(proofless)).toBe(fixtureString(prooflessExpected, "borshBytes"));
    const decoded = decodeProofless(proofless);
    expect(decoded).toMatchObject({ asset: SOL_MINT, amount: 33n });
    const framed = encodeOutputData(EncryptedScheme.proofless, proofless, "plaintext");
    expect(hex(framed)).toBe(fixtureString(prooflessExpected, "envelopeBorshBytes"));
    expect(decodeOutputData(framed)).toMatchObject({
      scheme: EncryptedScheme.proofless,
      encoding: "plaintext",
    });

    const assets = new AssetRegistry();
    expect(
      confidentialPlaintextFromUtxo(
        new Utxo({
          owner: keypair.signingPublicKey(),
          asset: SOL_MINT,
          amount: 55n,
          blinding: blinding(1),
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

  /**
   * A published anonymous slot is attacker-chosen bytes, so the category the
   * reader sorts a malformed body into is part of the protocol. Each expected
   * code below is the category Rust produced for the same input, read from
   * `AnonymousTransferRecipientPlaintext::{serialize,deserialize}` at the
   * frozen revision: wincode's `ReadError` and `WriteError` both land in
   * `TransactionError::{Deserialize,Serialize}`
   * (`sdk-libs/transaction/src/error.rs:250-260`), and `Data::validate` runs
   * inside `serialize` (`serialization/anonymous.rs:29-38`).
   */
  it("sorts a malformed anonymous body into the category Rust does", () => {
    const fixture = load();
    const { keypair, recipient } = keys(section(fixture, "inputs"));
    const { outputSeed, blinding } = slotBlindings(section(fixture, "inputs"));
    const plaintext = {
      ownerPublicKey: recipient.signingPublicKey(),
      senderPublicKey: keypair.viewingPublicKey(),
      assetId: 1n,
      amount: 19n,
      blinding: blinding(2),
      data: new Data([{ kind: "memo", bytes: new TextEncoder().encode("hi") }]),
    };
    const bytes = encodeAnonymousRecipient(plaintext);

    // Rust: Deserialize("Trailing bytes remain after deserialization"). The
    // finer TypeScript code is recorded as deliberate and widened to the
    // deserialize family by the oracle's category map.
    expect(() => decodeAnonymousRecipient(new Uint8Array([...bytes, 0]))).toThrow(
      expect.objectContaining({ code: "TRANSACTION_TRAILING_BYTES" }),
    );

    for (const truncated of [bytes.slice(0, -1), new Uint8Array()]) {
      expect(() => decodeAnonymousRecipient(truncated)).toThrow(
        expect.objectContaining({ code: "TRANSACTION_DESERIALIZE" }),
      );
    }

    // The record tag sits after owner (34), sender (33), asset id (8),
    // amount (8), blinding (32) and the record count (1).
    const badTag = new Uint8Array(bytes);
    const tagOffset = 34 + 33 + 8 + 8 + 32 + 1;
    expect(badTag[tagOffset]).toBe(3);
    badTag[tagOffset] = 9;
    expect(() => decodeAnonymousRecipient(badTag)).toThrow(
      expect.objectContaining({
        code: "TRANSACTION_DESERIALIZE",
        details: { field: "dataRecordTag", tag: 9 },
      }),
    );

    // Rust: Serialize("Sequence length would overflow length encoding
    // scheme: u8"), not the output-count refusal.
    expect(() =>
      encodeAnonymousSender({
        ownerPublicKey: keypair.signingPublicKey(),
        splAssetId: 0n,
        splAmount: 0n,
        solAmount: 1n,
        blindingSeed: outputSeed,
        recipientViewingPublicKeys: Array.from({ length: 256 }, () => recipient.viewingPublicKey()),
        splData: new Data(),
        solData: new Data(),
      }),
    ).toThrow(
      expect.objectContaining({
        code: "TRANSACTION_SERIALIZE",
        details: { field: "recipientViewingPublicKeys", maximum: 0xff, actual: 256 },
      }),
    );
  });

  /**
   * Rust reaches the cipher through `?` on every rail (`anonymous.rs:135-143`,
   * `:175-179`; `confidential.rs:139-147`), so a key or cipher failure arrives
   * as `TransactionError::Keypair`. The trigger below is a destroyed key
   * because a typed TypeScript caller cannot build the off-curve key that
   * reaches Rust's own refusal; the category the caller sees is the point.
   */
  it("reports a cipher failure in Rust's category on every rail", () => {
    const fixture = load();
    const inputs = section(fixture, "inputs");
    const { recipient, tx } = keys(inputs);
    const salt = hexBytes(fixtureString(inputs, "saltBytes")) as Bytes16;
    const { blinding } = slotBlindings(inputs);
    const spent = ViewingKey.fromBytes(
      hexBytes(fixtureString(inputs, "viewingSecretBytes")) as Bytes32,
    );
    const recipientPublicKey = recipient.viewingPublicKey();
    const txPublicKey = tx.publicKey();
    spent.destroy();

    const calls = [
      () => encryptAnonymous(spent, recipientPublicKey, Uint8Array.of(1, 2, 3), salt, 0),
      () => encryptSplit(spent, recipientPublicKey, Uint8Array.of(1, 2, 3), salt, 0),
      () => decryptAnonymous(spent, txPublicKey, Uint8Array.of(1, 2, 3), salt, 0),
      () => decryptSplit(spent, txPublicKey, Uint8Array.of(1, 2, 3), salt, 0),
      () =>
        encryptConfidential(
          spent,
          recipientPublicKey,
          { assetId: 1n, amount: 55n, blinding: blinding(1), data: new Data() },
          salt,
          0,
        ),
    ];
    for (const call of calls) {
      expect(call).toThrow(
        expect.objectContaining({
          name: "TransactionError",
          code: "TRANSACTION_KEYPAIR",
          details: { keypair: "KEYPAIR_INVALID_SECRET_KEY" },
        }),
      );
    }
  });

  it("rejects every malformed fixture family", () => {
    const fixture = load();
    const inputs = section(fixture, "inputs");
    const { keypair, recipientViewing, tx } = keys(inputs);
    const expected = section(fixture, "expected");
    const schemes = fixtureArray(expected, "schemes").map((entry) => {
      const value = fixtureObject(entry, "scheme");
      return Number(fixtureString(value, "byte"));
    });
    expect(schemes).toEqual([0, 1, 2, 3, 4, 5, 6, 7, 8]);
    expect(() => decodeOutputData(Uint8Array.of(4, 0, 0, 0, 0))).toThrow();
    expect(() => encryptedSchemeFromByte(9)).toThrow(
      expect.objectContaining({
        code: "TRANSACTION_BAD_DISCRIMINATOR",
        details: { byte: 9 },
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
    const plaintext = encodePlaintextTransfer({
      typePrefix: 4,
      blindingSeed: new Uint8Array(32) as Bytes32,
      recipientSlots: [],
    });
    plaintext[0] = 0xff;
    expect(() => decodePlaintextTransfer(plaintext, 4)).toThrow(
      expect.objectContaining({ code: "TRANSACTION_BAD_DISCRIMINATOR" }),
    );
    const proofless = encodeProofless({
      owner: keypair.shieldedAddress().ownerHash(),
      blinding: slotBlindings(inputs).blinding(4),
      asset: SOL_MINT,
      amount: 33n,
    });
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
