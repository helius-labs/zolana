import { X25519PublicKey, X25519Keypair } from "../src/keypair/x25519.js";
import { readFileSync } from "node:fs";
import { wireDecoder } from "../src/interface/decode.js";
import { SOLANA_OWNER_TAG, hashBytes, initializePoseidon } from "../src/hasher/index.js";
import { describe, expect, it } from "vitest";
import { address, type Signature } from "@solana/kit";

import { poseidon } from "../src/keypair/poseidon.js";
import { ShieldedKeypair } from "../src/keypair/shielded.js";
import { ViewingKey } from "../src/keypair/viewing-key.js";
import { inputTreeSlots, treeIdField, treeSlotsHashChain } from "../src/interface/tree-slot.js";
import { addressBytes, encodeBase58 } from "../src/interface/internal.js";
import { treeAddress } from "../src/interface/pda/index.js";
import { UTXO_DOMAIN } from "../src/interface/program.js";
import type { Bytes16, Bytes32, Bytes33 } from "../src/interface/types.js";
import {
  auditPublicInputHash,
  policyPublicInputHash,
  auditSharedSecret,
  AUDITOR_MESSAGE_LENGTH,
  auditDisclosureLength,
  auditorMessageData,
  decodeAnonymousAuditDisclosure,
  decryptTransactionViewingSecret,
  encodeAnonymousAuditDisclosure,
  encryptTransactionViewingSecret,
  openAuditOutputDisclosure,
  openAnonymousAuditDisclosure,
  parseAuditorMessage,
  symmetricAuditApply,
  type AnonymousAuditDisclosure,
  type AnonymousOutputOpening,
  type AuditOutputOpening,
} from "../src/keypair/audit.js";
import { bigIntToBytes } from "../src/keypair/bytes.js";
import { auditRing, auditRingTransaction } from "../src/ring/audit.js";
import { recoverRingMemberNotes } from "../src/ring/recover.js";
import { Utxo } from "../src/transaction/utxo.js";
import { ringAuditReader, transactionsPage } from "./helpers/clients.js";
import { AssetRegistry, SOL_ASSET_ID, SOL_MINT } from "../src/transaction/asset.js";
import {
  bytesToBigInt,
  commitmentPoseidon,
  rightAlign,
  ZERO_32,
} from "../src/transaction/internal.js";
import { Data } from "../src/transaction/data.js";
import {
  EncryptedScheme,
  RING_ANONYMOUS_PLAINTEXT_LENGTH,
  encodeOutputData,
  encodeRingAnonymous,
  encryptConfidential,
  ringAnonymousBodyHash,
} from "../src/transaction/serialization/codecs.js";
import type { IndexedShieldedTransaction } from "../src/transaction/instructions/transact.js";

function hex(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value, "hex"));
}

// Vectors from custom-rings/sdk/tests/go_vectors.rs.
const TX_SK = hex("001013121514171619181b1a1d1c1f1e010003020504070609080b0a0d0c0f4e") as Bytes32;
const EPH_SK = hex("01232021262724252a2b28292e2f2c2d32333031363734353a3b38393e3f3c3d") as Bytes32;
const AUDITOR_SK = hex(
  "01323130373635343b3a39383f3e3d3c23222120272625242b2a29282f2e2d2c",
) as Bytes32;
const EPH_PK = hex("048ea960e4e1b72cdec9a6e7d86ae28cd04edb4b5c07266d3c32d9133c8ebaa966") as Bytes33;
const AUDITOR_PK = hex(
  "04708c2645c705baaf44f2ab947574174f9280df58be6fc2f6f2e8881b78a3115a",
) as Bytes33;
const DH = hex("464b33b122dc1346a6012199742d7e14b2ee6436589c454a579fdda24feec92c") as Bytes32;
const SHARED_SECRET = hex(
  "2590b2b949a2f87b9201e4d065167ea9282c4bd06a32e888e24e33c5bddae54f",
) as Bytes32;
const CIPHERTEXT = hex(
  "da94f616e95702bdea89178dd9c4547393ebce9d47e67d0cac1533f13b678b90",
) as Bytes32;

// Fixture from custom-rings/program/src/instructions/transact.rs.
const TX_PK = hex("043632fe89228ea5215eea45a56704f569e3929868a8573363d015e39609f0eb63") as Bytes33;
const PRIVATE_TX_HASH = hex(
  "0000000000000000000000000000000000000000000000000000000000abcdef",
) as Bytes32;
const ZERO_DISCLOSURE = Array.from({ length: 36 }, () => new Uint8Array(32) as Bytes32);

const PAD_KEY = Uint8Array.from({ length: 32 }, (_, index) => 0x40 ^ index) as Bytes32;
const PAD_SALT = Uint8Array.from({ length: 16 }, (_, index) => index + 1) as Bytes16;

describe("ring audit encryption", () => {
  it("matches the Go vectors", () => {
    const ephemeral = X25519Keypair.fromBytes(EPH_SK);
    const auditor = X25519PublicKey.fromBytes(AUDITOR_PK);
    expect(ephemeral.publicKey().toBytes()).toEqual(EPH_PK);
    expect(X25519Keypair.fromBytes(AUDITOR_SK).publicKey().toBytes()).toEqual(AUDITOR_PK);
    const dh = ephemeral.ecdh(auditor);
    expect(dh).toEqual(DH);
    expect(auditSharedSecret(dh, ephemeral.publicKey(), auditor)).toEqual(SHARED_SECRET);
    const message = {
      ephemeralPublicKey: ephemeral.publicKey(),
      ciphertext: CIPHERTEXT,
      disclosure: ZERO_DISCLOSURE,
    };
    expect(decryptTransactionViewingSecret(X25519Keypair.fromBytes(AUDITOR_SK), message)).toEqual(
      TX_SK,
    );
  });

  it("round-trips under a fresh ephemeral key and publishes the complete audit message", () => {
    const auditor = X25519Keypair.generate();
    const encrypted = encryptTransactionViewingSecret(TX_SK, auditor.publicKey());
    expect(decryptTransactionViewingSecret(auditor, encrypted.message)).toEqual(TX_SK);
    const data = auditorMessageData(encrypted.message, auditor.publicKey());
    expect(data.viewTag).toEqual(auditor.publicKey().u());
    expect(data.data).toHaveLength(AUDITOR_MESSAGE_LENGTH);
    const parsed = parseAuditorMessage(data.data);
    expect(parsed.ciphertext).toEqual(encrypted.message.ciphertext);
    expect(parsed.ephemeralPublicKey.toBytes()).toEqual(
      encrypted.message.ephemeralPublicKey.toBytes(),
    );
  });

  /** The prover requests the Go tests prove, every value a wallet publishes derived here from the secrets they carry. */
  function goRequest(name: string): Record<string, unknown> {
    const decoder = wireDecoder((path) => new Error(`invalid fixture ${path}`));
    return decoder.record(
      JSON.parse(
        readFileSync(
          new URL(`../../../prover/server/prover/custom_ring/testdata/${name}`, import.meta.url),
          "utf8",
        ),
      ),
      name,
    );
  }

  function fixtureBytes(value: unknown, length: number): Uint8Array {
    if (typeof value !== "string" || !/^0x(?:[0-9a-f]{2})+$/u.test(value))
      throw new Error("invalid fixture hex");
    const decoded = hex(value.slice(2));
    if (decoded.length !== length) throw new Error("invalid fixture byte length");
    return decoded;
  }

  const fixtureField = (value: unknown): Bytes32 => fixtureBytes(value, 32) as Bytes32;

  function fixtureCount(value: unknown): number {
    if (typeof value !== "number" || !Number.isInteger(value) || value < 1 || value > 4)
      throw new Error("invalid fixture slot count");
    return value;
  }

  function fixtureOpening(value: unknown): AuditOutputOpening {
    const decoder = wireDecoder((path) => new Error(`invalid fixture ${path}`));
    const opening = decoder.record(value, "opening");
    return {
      domain: fixtureField(opening["domain"]),
      treeId: fixtureField(opening["treeId"]),
      ownerHash: fixtureField(opening["ownerHash"]),
      asset: fixtureField(opening["asset"]),
      amount: fixtureField(opening["amount"]),
      blinding: fixtureField(opening["blinding"]),
      dataHash: fixtureField(opening["dataHash"]),
      ringDataHash: fixtureField(opening["ringDataHash"]),
      ringProgramId: fixtureField(opening["ringProgramId"]),
    };
  }

  /** The envelope the request's secrets seal, the auditor key is the bare u coordinate on the wire. */
  function fixtureEnvelope(
    wire: Record<string, unknown>,
    disclosure: Parameters<typeof encryptTransactionViewingSecret>[2],
  ): Readonly<{
    txViewingPublicKey: X25519PublicKey;
    auditorPublicKey: X25519PublicKey;
    message: Parameters<typeof auditPublicInputHash>[0]["message"];
  }> {
    const txSecret = fixtureField(wire["txViewingSk"]);
    const ephemeral = X25519Keypair.fromBytes(fixtureField(wire["ephSk"]));
    const auditorPublicKey = X25519PublicKey.fromBytes(
      Uint8Array.of(4, ...fixtureBytes(wire["auditorPk"], 32)),
    );
    const dh = ephemeral.ecdh(auditorPublicKey);
    const shared = auditSharedSecret(dh, ephemeral.publicKey(), auditorPublicKey);
    const txViewingPublicKey = X25519Keypair.fromBytes(txSecret).publicKey();
    const sealed = encryptTransactionViewingSecret(txSecret, auditorPublicKey, disclosure);
    return {
      txViewingPublicKey,
      auditorPublicKey,
      message: {
        ephemeralPublicKey: ephemeral.publicKey(),
        ciphertext: symmetricAuditApply(shared, txSecret) as Bytes32,
        disclosure: sealed.message.disclosure,
      },
    };
  }

  it("hashes the base statement of the Go `custom-ring-base` request with a zero body chain", () => {
    const wire = goRequest("custom-ring-base.json");
    const decoder = wireDecoder((path) => new Error(`invalid fixture ${path}`));
    const salt = fixtureBytes(wire["salt"], 16) as Bytes16;
    const outputs = decoder.list(wire["outputs"], "outputs").map(fixtureOpening);
    const nOut = fixtureCount(wire["nOut"]);
    const envelope = fixtureEnvelope(wire, { salt, outputs });
    const input = {
      ...envelope,
      privateTxHash: fixtureField(wire["privateTxHash"]),
      outputHashes: outputs.slice(0, nOut).map(auditOpeningHash),
      salt,
    };
    expect(auditPublicInputHash(input)).toEqual(fixtureField(wire["publicInputHash"]));
    expect(auditPublicInputHash({ ...input, outputBodyHashes: [ZERO_32] })).toEqual(
      fixtureField(wire["publicInputHash"]),
    );
    expect(
      auditPublicInputHash({ ...input, outputBodyHashes: [filled(1) as Bytes32] }),
    ).not.toEqual(fixtureField(wire["publicInputHash"]));
  });

  it("extends the audit chain like the member-registry policy transcript", () => {
    const filled = (value: number): Bytes32 => new Uint8Array(32).fill(value) as Bytes32;
    const field = (value: bigint): Bytes32 => bigIntToBytes(value, 32) as Bytes32;
    const tail = (treeSlotsChain: Bytes32): Uint8Array =>
      [
        filled(0x2a),
        treeSlotsChain,
        treeIdField(9),
        filled(8),
        filled(10),
        field(1n),
        field(1n),
        filled(0x0b),
        filled(0x0c),
      ].reduce<Uint8Array>(
        (chain, element) => poseidon([chain, element]),
        auditPublicInputHash(base),
      );
    const treeSlots = [
      { id: 9, utxoRoot: filled(6), nullifierRoot: filled(7) },
      { id: 1, utxoRoot: filled(4), nullifierRoot: filled(5) },
      { id: 2, utxoRoot: filled(2), nullifierRoot: filled(3) },
    ];
    const base = {
      privateTxHash: PRIVATE_TX_HASH,
      txViewingPublicKey: X25519PublicKey.fromBytes(TX_PK),
      auditorPublicKey: X25519PublicKey.fromBytes(AUDITOR_PK),
      message: {
        ephemeralPublicKey: X25519PublicKey.fromBytes(EPH_PK),
        ciphertext: CIPHERTEXT,
        disclosure: ZERO_DISCLOSURE,
      },
      outputHashes: [new Uint8Array(32) as Bytes32],
      salt: new Uint8Array(16) as Bytes16,
    };
    const input = {
      ...base,
      policyHash: filled(0x2a),
      treeSlots,
      addressTreeId: 9,
      ringId: filled(8),
      namespaceOwnerHash: filled(10),
      approvalRequired: true,
      memberRegistryRoot: filled(0x0b),
      keyEscrow: true,
      foreignRoot: filled(0x0c),
    };
    expect(policyPublicInputHash(input)).toEqual(
      tail(treeSlotsHashChain(inputTreeSlots(treeSlots))),
    );
    expect(policyPublicInputHash({ ...input, foreignRoot: filled(0) })).not.toEqual(
      policyPublicInputHash(input),
    );
  });

  it("reconstructs the statement of the Go `custom-ring-base` anonymous request from its secrets", () => {
    const wire = goRequest("custom-ring-base-anonymous.json");
    const decoder = wireDecoder((path) => new Error(`invalid fixture ${path}`));
    const salt = fixtureBytes(wire["salt"], 16) as Bytes16;
    const nOut = fixtureCount(wire["nOut"]);
    const nIn = fixtureCount(wire["nIn"]);
    const notes = decoder.list(wire["anonymousOutputs"], "anonymousOutputs").map((value) => {
      const note = decoder.record(value, "note");
      return {
        ...fixtureOpening({ ...note, ownerHash: "0x" + "00".repeat(32) }),
        ownerHash: poseidon([
          fixtureField(note["ownerPkHash"]),
          fixtureField(note["nullifierPk"]),
        ]) as Bytes32,
        nullifierPk: fixtureField(note["nullifierPk"]),
      };
    });
    const inputs = decoder.list(wire["inputs"], "inputs").map((value) => {
      const note = decoder.record(value, "note");
      return {
        treeId: Number(bytesToBigInt(fixtureField(note["treeId"]))),
        amount: bytesToBigInt(fixtureField(note["amount"])),
        asset: fixtureField(note["asset"]),
        blinding: fixtureField(note["blinding"]),
      };
    });
    const recipients = decoder
      .list(wire["recipients"], "recipients")
      .map((value) => fixtureBytes(value, 33));
    const viewingKeys = decoder
      .list(wire["recipientViewingKeys"], "recipientViewingKeys")
      .map((value) => fixtureBytes(value, 33) as Bytes33);
    const delivery = decoder.record(wire["delivery"], "delivery");
    const bodies = decoder
      .list(delivery["outputs"], "delivery.outputs")
      .map((value) =>
        fixtureBytes(decoder.record(value, "slot")["ciphertext"], RING_ANONYMOUS_PLAINTEXT_LENGTH),
      );
    const disclosure: AnonymousAuditDisclosure = {
      sender: fixtureBytes(wire["sender"], 33).slice(1) as Bytes32,
      inputs: inputs.slice(0, nIn),
      outputs: notes.slice(0, nOut).map((note, index) => ({
        identityTag: recipients[index]![0]!,
        identityKey: recipients[index]!.slice(1) as Bytes32,
        nullifierPublicKey: note.nullifierPk,
        viewingPublicKey: viewingKeys[index]!,
      })),
    };
    const envelope = fixtureEnvelope(wire, { salt, anonymous: disclosure });
    const input = {
      ...envelope,
      privateTxHash: fixtureField(wire["privateTxHash"]),
      outputHashes: notes.slice(0, nOut).map(auditOpeningHash),
      outputBodyHashes: bodies.slice(0, nOut).map(ringAnonymousBodyHash),
      salt,
      anonymous: true,
    };
    const expected = fixtureField(wire["publicInputHash"]);
    expect(auditPublicInputHash(input)).toEqual(expected);
    expect(auditPublicInputHash({ ...input, anonymous: false })).not.toEqual(expected);
    expect(auditPublicInputHash({ ...input, outputBodyHashes: [ZERO_32] })).not.toEqual(expected);
  });

  it("masks each disclosure field with a pad no other pad derives", () => {
    const auditor = X25519Keypair.generate();
    const zero = new Uint8Array(32) as Bytes32;
    const blank: AuditOutputOpening = {
      domain: zero,
      treeId: zero,
      ownerHash: zero,
      asset: zero,
      amount: zero,
      blinding: zero,
      dataHash: zero,
      ringDataHash: zero,
      ringProgramId: zero,
    };
    const pad = encryptTransactionViewingSecret(PAD_KEY, auditor.publicKey(), {
      salt: PAD_SALT,
      outputs: [blank, blank, blank, blank],
    }).message.disclosure;
    expect(pad).toHaveLength(36);
    expect(new Set(pad.map((mask) => Buffer.from(mask).toString("hex"))).size).toBe(36);
    pad.slice(1).forEach((mask, index) => {
      expect(mask).not.toEqual(poseidon([pad[index]!, bigIntToBytes(BigInt(index + 1), 32)]));
    });
    const opened = openAuditOutputDisclosure(PAD_KEY, PAD_SALT, pad);
    expect(opened).toHaveLength(4);
    for (const opening of opened) expect(opening).toEqual(blank);
  });

  it("witnesses the canonical 32-byte X25519 coordinate", () => {
    const auditor = X25519PublicKey.fromBytes(AUDITOR_PK);
    expect(auditor.u()).toHaveLength(32);
    expect(auditor.toBytes()[0]).toBe(4);
    expect(auditor.u()).toEqual(auditor.toBytes().subarray(1));
  });
});

await initializePoseidon();

describe("ring audit outputs", () => {
  const auditor = X25519Keypair.generate();
  const tx = ViewingKey.generate();
  const viewTag = new Uint8Array(32).fill(0x77) as Bytes32;
  const blinding = new Uint8Array(32).fill(6) as Bytes32;

  function transaction(
    input: Readonly<{ amount: bigint; committedAmount?: bigint }>,
  ): IndexedShieldedTransaction {
    const salt = new Uint8Array(16) as Bytes16;
    const opening = auditOpening(input.committedAmount ?? input.amount, blinding);
    const encrypted = encryptTransactionViewingSecret(tx.secretBytes(), auditor.publicKey(), {
      salt,
      outputs: [opening],
    });
    const message = auditorMessageData(encrypted.message, auditor.publicKey());
    return {
      slot: 1n,
      txSignature: "sig" as Signature,
      txViewingPublicKey: tx.publicKey(),
      salt,
      outputSlots: [
        {
          viewTag,
          outputContext: {
            hash: auditOpeningHash(opening),
            tree: address("11111111111111111111111111111111"),
            leafIndex: 0n,
          },
          payload: encodeOutputData(
            EncryptedScheme.confidential,
            encryptConfidential(
              tx,
              tx.publicKey(),
              { assetId: SOL_ASSET_ID, amount: input.amount, blinding, data: new Data() },
              salt,
              0,
            ),
            "encrypted",
          ),
        },
      ],
      messages: [message],
      nullifiers: [],
      proofless: false,
    };
  }

  const audit = (transaction: IndexedShieldedTransaction) =>
    auditRingTransaction({ auditor, transaction, assets: new AssetRegistry() });

  it("opens the slot the transaction key seals", () => {
    const audited = audit(transaction({ amount: 5n }));
    expect(audited.outputs.map((output) => output.amount)).toEqual([5n]);
    expect(audited.payloadErrors).toEqual([]);
  });

  it("retains verified disclosure when recipient plaintext disagrees", () => {
    const audited = audit(transaction({ amount: 5n, committedAmount: 0n }));
    expect(audited.outputs).toEqual([]);
    expect(audited.payloadErrors).toEqual([{ slotIndex: 0, kind: "openingMismatch" }]);
    expect(audited.outputOpenings[0]?.amount).toEqual(ZERO_32);
  });
});

function auditOpening(amount: bigint, blinding: Bytes32): AuditOutputOpening {
  return Object.freeze({
    domain: rightAlign(Uint8Array.of(UTXO_DOMAIN)),
    treeId: treeIdField(0),
    ownerHash: ZERO_32,
    asset: hashBytes(addressBytes(SOL_MINT)) as Bytes32,
    amount: rightAlign(bigIntToBytes(amount, 8)),
    blinding,
    dataHash: ZERO_32,
    ringDataHash: ZERO_32,
    ringProgramId: ZERO_32,
  });
}

function auditOpeningHash(opening: AuditOutputOpening): Bytes32 {
  return commitmentPoseidon([
    opening.domain,
    opening.treeId,
    opening.asset,
    opening.amount,
    opening.dataHash,
    commitmentPoseidon([opening.ringDataHash, opening.ringProgramId]),
    commitmentPoseidon([opening.ownerHash, opening.blinding]),
  ]);
}

describe("anonymous ring audit", () => {
  const RING = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
  const auditor = X25519Keypair.generate();
  const tx = ViewingKey.generate();
  const member = ShieldedKeypair.generate();
  const source = member.shieldedAddress();
  const salt = new Uint8Array(16).fill(5) as Bytes16;
  const blinding = filled(7, 0) as Bytes32;
  const solAsset = hashBytes(addressBytes(SOL_MINT)) as Bytes32;
  const utxo = new Utxo({
    owner: source.signingPublicKey,
    asset: SOL_MINT,
    amount: 42n,
    blinding,
    ringProgramId: RING,
  });
  const commitment = utxo.hash(source.nullifierPublicKey, 0);
  const pairU = X25519Keypair.fromBytes(EPH_SK).publicKey().u();
  const recipient: AnonymousOutputOpening = Object.freeze({
    identityTag: SOLANA_OWNER_TAG,
    identityKey: source.confidentialViewTag() as Bytes32,
    nullifierPublicKey: source.nullifierPublicKey,
    viewingPublicKey: source.viewingPublicKey.toBytes(),
  });
  const dummy: AnonymousOutputOpening = Object.freeze({
    identityTag: 0,
    identityKey: ZERO_32,
    nullifierPublicKey: ZERO_32,
    viewingPublicKey: new Uint8Array(33) as Bytes33,
  });
  const disclosure: AnonymousAuditDisclosure = Object.freeze({
    sender: filled(3) as Bytes32,
    inputs: [
      { treeId: 4, amount: 9n, asset: solAsset, blinding: filled(6, 0) as Bytes32 },
      { treeId: 0, amount: 0n, asset: ZERO_32, blinding: ZERO_32 },
    ],
    outputs: [recipient, dummy],
  });
  const shape = { anonymous: true, inputs: 2, outputs: 2 };

  function transaction(opening = disclosure): IndexedShieldedTransaction {
    const encrypted = encryptTransactionViewingSecret(tx.secretBytes(), auditor.publicKey(), {
      salt,
      anonymous: opening,
    });
    const body = tx.sealAnonymousOutput(
      source.viewingPublicKey,
      encodeRingAnonymous({ assetAddress: SOL_MINT, amount: 42n, blinding, pairU }),
      salt,
      0,
    );
    const padding = new Uint8Array(RING_ANONYMOUS_PLAINTEXT_LENGTH).fill(0xd0);
    return {
      slot: 1n,
      txSignature: "1".repeat(87) as Signature,
      eventIndex: 0,
      txViewingPublicKey: tx.publicKey(),
      salt,
      ringProgramId: RING,
      outputSlots: [
        {
          viewTag: ZERO_32,
          outputContext: { hash: commitment, tree: treeAddress(0), treeId: 0, leafIndex: 0n },
          payload: encodeOutputData(EncryptedScheme.ringAnonymous, body, "encrypted"),
        },
        {
          viewTag: ZERO_32,
          outputContext: {
            hash: filled(9) as Bytes32,
            tree: treeAddress(0),
            treeId: 0,
            leafIndex: 1n,
          },
          payload: encodeOutputData(EncryptedScheme.ringAnonymous, padding, "encrypted"),
        },
      ],
      messages: [auditorMessageData(encrypted.message, auditor.publicKey())],
      nullifiers: [filled(1) as Bytes32, filled(2) as Bytes32],
      proofless: false,
    };
  }

  it("seals a 2x2 disclosure into sixteen chunks and opens it with the same stream", () => {
    expect(auditDisclosureLength(shape)).toBe(16);
    expect(auditDisclosureLength({ anonymous: true, inputs: 3, outputs: 4 })).toBe(27);
    expect(auditDisclosureLength({ anonymous: false, inputs: 0, outputs: 1 })).toBe(36);
    expect(auditDisclosureLength({ anonymous: true, inputs: 0, outputs: 2 })).toBeUndefined();
    expect(auditDisclosureLength({ anonymous: true, inputs: 5, outputs: 2 })).toBe(25);
    expect(auditDisclosureLength({ anonymous: true, inputs: 13, outputs: 2 })).toBeUndefined();
    const message = transaction().messages[0]!;
    expect(message.data).toHaveLength(65 + 32 * 16);
    const parsed = parseAuditorMessage(message.data, shape);
    expect(openAnonymousAuditDisclosure(tx.secretBytes(), salt, parsed.disclosure, shape)).toEqual(
      disclosure,
    );
    // The fixed non-anonymous length and a neighbouring shape are both refused.
    expect(() => parseAuditorMessage(message.data)).toThrow();
    expect(() =>
      parseAuditorMessage(message.data, { anonymous: true, inputs: 1, outputs: 2 }),
    ).toThrow();
    expect(() =>
      openAnonymousAuditDisclosure(tx.secretBytes(), salt, parsed.disclosure, {
        anonymous: true,
        inputs: 1,
        outputs: 2,
      }),
    ).toThrow(RangeError);
    expect(() =>
      openAnonymousAuditDisclosure(tx.secretBytes(), salt, parsed.disclosure, {
        ...shape,
        anonymous: false,
      }),
    ).toThrow(RangeError);
  });

  it("rejects nonzero slot padding and a foreign sender tag", () => {
    const plaintext = encodeAnonymousAuditDisclosure(disclosure);
    expect(plaintext).toHaveLength(62 + 2 * 93 + 2 * 124);
    expect(decodeAnonymousAuditDisclosure(plaintext, shape)).toEqual(disclosure);
    for (const [index, value] of [
      [33, 1],
      [0, 0x50],
      [62 + 74, 1],
      [62 + 2 * 93 + 98, 1],
    ] as const) {
      const corrupted = plaintext.slice();
      corrupted[index] = value;
      expect(() => decodeAnonymousAuditDisclosure(corrupted, shape)).toThrow(RangeError);
    }
    expect(() => decodeAnonymousAuditDisclosure(plaintext.subarray(1), shape)).toThrow(RangeError);
  });

  it("opens the proven body under the recipient stream and rebuilds the real commitment", () => {
    const audited = auditRingTransaction({
      auditor,
      transaction: transaction(),
      assets: new AssetRegistry(),
      mode: "anonymous",
    });
    expect(audited.anonymous).toEqual({
      sender: encodeBase58(filled(3)),
      inputs: [{ treeId: 4, amount: 9n, asset: solAsset }],
      recipients: [
        {
          slotIndex: 0,
          identityTag: SOLANA_OWNER_TAG,
          identityKey: source.confidentialViewTag(),
          nullifierPk: source.nullifierPublicKey,
          amount: 42n,
          asset: solAsset,
        },
      ],
    });
    expect(audited.outputs).toHaveLength(1);
    expect(audited.outputs[0]?.amount).toBe(42n);
    expect(audited.outputs[0]?.ringProgramId).toBe(RING);
    expect(audited.outputs[0]?.ownerTag).toEqual(source.confidentialViewTag());
    expect(audited.outputs[0]?.recipientViewingPublicKey.equals(source.viewingPublicKey)).toBe(
      true,
    );
    expect(audited.outputOpenings[0]?.ownerHash).toEqual(source.ownerHash());
    expect(auditOpeningHash(audited.outputOpenings[0]!)).toEqual(commitment);
    expect(audited.outputOpenings[1]?.ownerHash).toEqual(ZERO_32);
    expect(audited.payloadErrors).toEqual([]);
    expect(audited.outputs[0]?.asset).toBe(SOL_MINT);
    expect(audited.outputs[0]?.blinding).toEqual(blinding);
  });

  it("refuses a real body the disclosed viewing key does not open", () => {
    const valid = transaction();
    const slot = valid.outputSlots[0]!;
    // Frame header 6 bytes, then the scheme byte, the blinding sits at body offset 40.
    const frame = slot.payload.slice();
    const flipped = 6 + 1 + 40;
    frame[flipped] = (frame[flipped] ?? 0) ^ 1;
    expect(() =>
      auditRingTransaction({
        auditor,
        assets: new AssetRegistry(),
        mode: "anonymous",
        transaction: {
          ...valid,
          outputSlots: [{ ...slot, payload: frame }, valid.outputSlots[1]!],
        },
      }),
    ).toThrow("RING_AUDIT_OUTPUT_MISMATCH");
  });

  it("reports a pair hint outside the X25519 encoding beside the stored output", () => {
    const encrypted = encryptTransactionViewingSecret(tx.secretBytes(), auditor.publicKey(), {
      salt,
      anonymous: disclosure,
    });
    const valid = transaction();
    const body = tx.sealAnonymousOutput(
      source.viewingPublicKey,
      encodeRingAnonymous({
        assetAddress: SOL_MINT,
        amount: 42n,
        blinding,
        pairU: new Uint8Array(32).fill(0xff) as Bytes32,
      }),
      salt,
      0,
    );
    const audited = auditRingTransaction({
      auditor,
      assets: new AssetRegistry(),
      mode: "anonymous",
      transaction: {
        ...valid,
        outputSlots: [
          {
            ...valid.outputSlots[0]!,
            payload: encodeOutputData(EncryptedScheme.ringAnonymous, body, "encrypted"),
          },
          valid.outputSlots[1]!,
        ],
        messages: [auditorMessageData(encrypted.message, auditor.publicKey())],
      },
    });
    expect(audited.outputs.map((output) => output.amount)).toEqual([42n]);
    expect(audited.payloadErrors).toEqual([{ slotIndex: 0, kind: "pairHint" }]);
  });

  it("fails closed without the anonymous mode, on a wrong commitment and without a tree id", () => {
    const valid = transaction();
    const assets = new AssetRegistry();
    expect(() => auditRingTransaction({ auditor, transaction: valid, assets })).toThrow(
      "RING_AUDIT_MESSAGE",
    );
    const slot = valid.outputSlots[0]!;
    const flipped = filled(0) as Bytes32;
    flipped.set(commitment);
    flipped[31] = (flipped[31] ?? 0) ^ 1;
    expect(() =>
      auditRingTransaction({
        auditor,
        assets,
        mode: "anonymous",
        transaction: {
          ...valid,
          outputSlots: [
            { ...slot, outputContext: { ...slot.outputContext, hash: flipped } },
            valid.outputSlots[1]!,
          ],
        },
      }),
    ).toThrow("RING_AUDIT_OUTPUT_MISMATCH");
    const { treeId: _, ...withoutTreeId } = slot.outputContext;
    expect(() =>
      auditRingTransaction({
        auditor,
        assets,
        mode: "anonymous",
        transaction: {
          ...valid,
          outputSlots: [{ ...slot, outputContext: withoutTreeId }, valid.outputSlots[1]!],
        },
      }),
    ).toThrow("RING_AUDIT_OUTPUT_MISMATCH");
  });

  it("retains a zero-value input whose blinding distinguishes it from padding", () => {
    const audited = auditRingTransaction({
      auditor,
      assets: new AssetRegistry(),
      mode: "anonymous",
      transaction: transaction({
        ...disclosure,
        inputs: [
          { treeId: 0, amount: 0n, asset: ZERO_32, blinding },
          { treeId: 0, amount: 0n, asset: ZERO_32, blinding: ZERO_32 },
        ],
      }),
    });
    expect(audited.anonymous?.inputs).toEqual([{ treeId: 0, amount: 0n, asset: ZERO_32 }]);
  });

  it("recovers the member's note from an anonymous transaction", async () => {
    const indexed = transaction();
    const client = {
      ...ringAuditReader({
        getShieldedTransactionsByTags: async (input) =>
          transactionsPage(input.ringProgramId === undefined ? { transactions: [indexed] } : {}),
      }),
      getShieldedTransactionsByNullifiers: async () => transactionsPage(),
    };
    const recovered = await recoverRingMemberNotes({
      client,
      ringProgramId: RING,
      auditor,
      source,
      nullifierKey: member.nullifierKey(),
      assets: new AssetRegistry(),
      mode: "anonymous",
      resolveTreeId: () => 0,
      origin: {
        ringInvoked: async () => true,
        confirmedTransaction: async (transaction: IndexedShieldedTransaction) => transaction,
      },
    });
    expect(recovered.notes.map((note) => note.utxo.amount)).toEqual([42n]);
    expect(recovered.notes[0]?.outputContext.hash).toEqual(commitment);
    expect(recovered.unopened).toEqual([]);
    // Another member sees the transaction but owns none of its notes.
    const other = ShieldedKeypair.generate();
    const none = await recoverRingMemberNotes({
      client,
      ringProgramId: RING,
      auditor,
      source: other.shieldedAddress(),
      nullifierKey: other.nullifierKey(),
      assets: new AssetRegistry(),
      mode: "anonymous",
      resolveTreeId: () => 0,
      origin: {
        ringInvoked: async () => true,
        confirmedTransaction: async (transaction: IndexedShieldedTransaction) => transaction,
      },
    });
    expect(none.notes).toEqual([]);
    expect(none.unopened).toEqual([]);
  });

  it("completes recovery at the page cap when Photon reports a terminal frontier", async () => {
    const indexed = transaction();
    let taggedReads = 0;
    const client = {
      ...ringAuditReader({
        getShieldedTransactionsByTags: async (request) => {
          if (request.ringProgramId !== undefined) return transactionsPage();
          taggedReads++;
          return transactionsPage({
            transactions: [indexed],
            nextCursor: Uint8Array.of(1),
            scannedThrough: Uint8Array.of(2),
          });
        },
      }),
      getShieldedTransactionsByNullifiers: async () => transactionsPage(),
    };
    const recovered = await recoverRingMemberNotes({
      client,
      ringProgramId: RING,
      auditor,
      source,
      nullifierKey: member.nullifierKey(),
      assets: new AssetRegistry(),
      mode: "anonymous",
      resolveTreeId: () => 0,
      maxPages: 1,
      origin: {
        ringInvoked: async () => true,
        confirmedTransaction: async (record: IndexedShieldedTransaction) => record,
      },
    });
    expect(taggedReads).toBe(1);
    expect(recovered.notes.map((note) => note.utxo.amount)).toEqual([42n]);
    expect(recovered.unopened).toEqual([]);
  });

  it("rejects invalid scan bounds before returning an empty audit", async () => {
    const client = ringAuditReader({
      getShieldedTransactionsByTags: async () => {
        throw new Error("invalid bounds reached the indexer");
      },
    });
    for (const limits of [
      { maxPages: 0 },
      { maxPages: -1 },
      { maxPages: 1.5 },
      { pageSize: 0 },
      { pageSize: -1 },
      { pageSize: Number.POSITIVE_INFINITY },
    ]) {
      await expect(
        auditRing({ client, auditor, ringProgramId: RING, assets: new AssetRegistry(), ...limits }),
      ).rejects.toThrow("RING_RPC");
    }
  });
});

function filled(byte: number, first = byte): Uint8Array {
  const bytes = new Uint8Array(32).fill(byte);
  bytes[0] = first;
  return bytes;
}
