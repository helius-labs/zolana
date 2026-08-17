import { describe, expect, it } from "vitest";

import type { Address, Bytes16, Bytes32 } from "../../src/interface/index.js";
import { ShieldedKeypair, SigningKey, ViewingKey } from "../../src/keypair/index.js";
import {
  AssetRegistry,
  Data,
  SOL_MINT,
  Utxo,
  deriveBlinding,
} from "../../src/transaction/index.js";
import {
  EncryptedScheme,
  anonymousRecipientUtxo,
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
  const signing = SigningKey.fromBytes(
    hexBytes(fixtureString(inputs, "signingSecretBytes")) as Bytes32,
  );
  const viewing = ViewingKey.fromSeed(
    hexBytes(fixtureString(inputs, "viewingSeedBytes")) as Bytes32,
    0,
  );
  const keypair = ShieldedKeypair.withViewingKey(signing, viewing);
  const recipientSecret = new Uint8Array(32);
  recipientSecret[31] = 12;
  const recipientSigning = SigningKey.fromBytes(recipientSecret as Bytes32);
  const recipientViewing = ViewingKey.fromSeed(new Uint8Array(32).fill(13) as Bytes32, 0);
  return {
    keypair,
    recipient: ShieldedKeypair.withViewingKey(recipientSigning, recipientViewing),
    recipientViewing,
    tx: ViewingKey.fromSeed(hexBytes(fixtureString(inputs, "txViewingSeedBytes")) as Bytes32, 0),
    viewing,
  };
}

describe("manifest-verified transaction serialization", () => {
  it("encodes and opens every active plaintext family", () => {
    const fixture = load();
    const inputs = section(fixture, "inputs");
    const { keypair, recipient, recipientViewing, tx } = keys(inputs);
    const data = new Data([{ kind: "memo", bytes: new TextEncoder().encode("codec") }]);
    const seed = hexBytes(fixtureString(inputs, "blindingSeedBytes")) as Bytes32;
    const salt = hexBytes(fixtureString(inputs, "saltBytes")) as Bytes16;

    const confidential = {
      assetId: 1n,
      amount: 55n,
      blinding: deriveBlinding(seed, 1),
      data,
    };
    const confidentialBytes = encodeConfidential(confidential);
    expect(decodeConfidential(confidentialBytes)).toEqual(confidential);
    const confidentialBody = encryptConfidential(
      tx,
      recipient.viewingPublicKey(),
      confidential,
      salt,
      0,
    );
    expect(
      decodeOutputData(
        encodeOutputData(EncryptedScheme.confidential, confidentialBody, "encrypted"),
      ),
    ).toMatchObject({ scheme: EncryptedScheme.confidential, encoding: "encrypted" });
    expect(
      decryptConfidential(recipientViewing, tx.publicKey(), confidentialBody, salt, 0),
    ).toEqual(confidential);

    const anonymousRecipient = {
      ownerPublicKey: recipient.signingPublicKey(),
      senderPublicKey: keypair.viewingPublicKey(),
      assetId: 1n,
      amount: 19n,
      blinding: deriveBlinding(seed, 2),
      data,
    };
    const recipientBytes = encodeAnonymousRecipient(anonymousRecipient);
    const recipientBody = encryptAnonymous(
      tx,
      recipient.viewingPublicKey(),
      recipientBytes,
      salt,
      1,
    );
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
    const senderBytes = encodeAnonymousSender(anonymousSender);
    const senderBody = encryptAnonymous(tx, keypair.viewingPublicKey(), senderBytes, salt, 2);
    expect(
      decodeAnonymousSender(
        decryptAnonymous(keypair.viewingKey(), tx.publicKey(), senderBody, salt, 2),
      ),
    ).toEqual(anonymousSender);
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
    const splitBytes = encodeSplitBundle(split);
    const splitBody = encryptSplit(tx, keypair.viewingPublicKey(), splitBytes, salt, 3);
    expect(
      decodeSplitBundle(decryptSplit(keypair.viewingKey(), tx.publicKey(), splitBody, salt, 3)),
    ).toEqual(split);
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
    const plaintextBytes = encodePlaintextTransfer(plaintext);
    expect(
      decodeOutputData(
        encodeOutputData(EncryptedScheme.plaintextTransfer, plaintextBytes, "plaintext"),
      ),
    ).toMatchObject({ scheme: EncryptedScheme.plaintextTransfer, encoding: "plaintext" });
    expect(decodePlaintextTransfer(plaintextBytes, 4)).toMatchObject({
      sender: { spl: { amount: 7n }, solAmount: 8n },
    });
  });

  it("matches proofless and split-encrypted fixed layouts", () => {
    const fixture = load();
    const inputs = section(fixture, "inputs");
    const families = fixtureObject(section(fixture, "expected").families);
    const { keypair, tx } = keys(inputs);
    const seed = hexBytes(fixtureString(inputs, "blindingSeedBytes")) as Bytes32;
    const proofless = encodeProofless({
      owner: keypair.shieldedAddress().ownerHash(),
      blinding: deriveBlinding(seed, 4),
      asset: SOL_MINT,
      amount: 33n,
    });
    expect(proofless).toHaveLength(110);
    const decoded = decodeProofless(proofless);
    expect(decoded).toMatchObject({ asset: SOL_MINT, amount: 33n });
    const framed = encodeOutputData(EncryptedScheme.proofless, proofless, "plaintext");
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
    const seed = hexBytes(
      fixtureString(section(fixture, "inputs"), "blindingSeedBytes"),
    ) as Bytes32;
    const plaintext = {
      ownerPublicKey: recipient.signingPublicKey(),
      senderPublicKey: keypair.viewingPublicKey(),
      assetId: 1n,
      amount: 19n,
      blinding: deriveBlinding(seed, 2),
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
        blindingSeed: seed,
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
    const seed = hexBytes(fixtureString(inputs, "blindingSeedBytes")) as Bytes32;
    const spent = ViewingKey.fromSeed(
      hexBytes(fixtureString(inputs, "viewingSeedBytes")) as Bytes32,
      0,
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
          { assetId: 1n, amount: 55n, blinding: deriveBlinding(seed, 1), data: new Data() },
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
      blinding: deriveBlinding(hexBytes(fixtureString(inputs, "blindingSeedBytes")) as Bytes32, 4),
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
