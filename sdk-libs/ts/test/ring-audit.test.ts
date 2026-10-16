import { X25519PublicKey, X25519Secret } from "../src/keypair/x25519.js";
import { hashBytes, initializePoseidon } from "../src/hasher/index.js";
import { describe, expect, it } from "vitest";
import { address, type Signature } from "@solana/kit";

import { poseidon } from "../src/keypair/poseidon.js";
import { P256PublicKey } from "../src/keypair/public-key.js";
import { ViewingKey } from "../src/keypair/viewing-key.js";
import { inputTreeSlots, treeIdField, treeSlotsHashChain } from "../src/interface/tree-slot.js";
import { addressBytes } from "../src/interface/internal.js";
import { UTXO_DOMAIN } from "../src/interface/program.js";
import type { Bytes16, Bytes32, Bytes33 } from "../src/interface/types.js";
import {
  auditPublicInputHash,
  policyPublicInputHash,
  auditSharedSecret,
  AUDITOR_MESSAGE_LENGTH,
  auditorMessageData,
  decryptTransactionViewingSecret,
  encryptTransactionViewingSecret,
  openAuditOutputDisclosure,
  parseAuditorMessage,
  type AuditOutputOpening,
} from "../src/keypair/audit.js";
import { bigIntToBytes } from "../src/keypair/bytes.js";
import { auditRingTransaction } from "../src/ring/audit.js";
import { AssetRegistry, SOL_ASSET_ID, SOL_MINT } from "../src/transaction/asset.js";
import { commitmentPoseidon, rightAlign, ZERO_32 } from "../src/transaction/internal.js";
import { Data } from "../src/transaction/data.js";
import {
  EncryptedScheme,
  encodeOutputData,
  encryptConfidential,
} from "../src/transaction/serialization/codecs.js";
import type { IndexedShieldedTransaction } from "../src/transaction/instructions/transact.js";

function hex(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value, "hex"));
}

// Vectors from custom-rings/sdk/tests/go_vectors.rs.
const TX_SK = hex("011013121514171619181b1a1d1c1f1e010003020504070609080b0a0d0c0f0e") as Bytes32;
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
  "02417a38002f02b2af3e7b938032a1d317e6350831c55a9d3a91e9520feb2314",
) as Bytes32;

// Fixture from custom-rings/program/src/instructions/transact.rs.
const TX_PK = hex("0268737cf1d852483220d399b5321261d5e9e90d8214dc62b4f7e4d0fee955c5d5") as Bytes33;
const PRIVATE_TX_HASH = hex(
  "0000000000000000000000000000000000000000000000000000000000abcdef",
) as Bytes32;
const PUBLIC_INPUT_HASH = hex("00b0332f42b187eee22269f9110350982cbe4637fcafd65cb0c6465994efd8c6");
const ZERO_DISCLOSURE = Array.from({ length: 36 }, () => new Uint8Array(32) as Bytes32);

const PAD_KEY = Uint8Array.from({ length: 32 }, (_, index) => 0x40 ^ index) as Bytes32;
const PAD_SALT = Uint8Array.from({ length: 16 }, (_, index) => index + 1) as Bytes16;

describe("ring audit encryption", () => {
  it("matches the Go vectors", () => {
    const ephemeral = X25519Secret.fromBytes(EPH_SK);
    const auditor = X25519PublicKey.fromBytes(AUDITOR_PK);
    expect(ephemeral.publicKey().toBytes()).toEqual(EPH_PK);
    expect(X25519Secret.fromBytes(AUDITOR_SK).publicKey().toBytes()).toEqual(AUDITOR_PK);
    const dh = ephemeral.ecdh(auditor);
    expect(dh).toEqual(DH);
    expect(auditSharedSecret(dh, ephemeral.publicKey(), auditor)).toEqual(SHARED_SECRET);
    const message = {
      ephemeralPublicKey: ephemeral.publicKey(),
      ciphertext: CIPHERTEXT,
      disclosure: ZERO_DISCLOSURE,
    };
    expect(decryptTransactionViewingSecret(X25519Secret.fromBytes(AUDITOR_SK), message)).toEqual(
      TX_SK,
    );
  });

  it("round-trips under a fresh ephemeral key and publishes the complete audit message", () => {
    const auditor = X25519Secret.generate();
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

  it("hashes the audit statement like Rust `CustomRingBasePublicInput::hash`", () => {
    expect(
      Buffer.from(
        auditPublicInputHash({
          privateTxHash: PRIVATE_TX_HASH,
          txViewingPublicKey: P256PublicKey.fromBytes(TX_PK),
          auditorPublicKey: X25519PublicKey.fromBytes(AUDITOR_PK),
          message: {
            ephemeralPublicKey: X25519PublicKey.fromBytes(EPH_PK),
            ciphertext: CIPHERTEXT,
            disclosure: ZERO_DISCLOSURE,
          },
          outputHashes: [new Uint8Array(32) as Bytes32],
          salt: new Uint8Array(16) as Bytes16,
        }),
      ).toString("hex"),
    ).toBe(Buffer.from(PUBLIC_INPUT_HASH).toString("hex"));
  });

  it("extends the audit chain like Go `TestNonzeroRevocationTailVector`", () => {
    const filled = (value: number): Bytes32 => new Uint8Array(32).fill(value) as Bytes32;
    const field = (value: bigint): Bytes32 => bigIntToBytes(value, 32) as Bytes32;
    const revocationTargets = Array.from({ length: 10 }, () => new Uint8Array(32) as Bytes32);
    revocationTargets[0] = field(0x42n);
    revocationTargets[1] = filled(0x11);
    // Fact 1 reads slot 2, fact 0 slot 0.
    const revocationTreeIndexes = [0, 2, 0, 0, 0, 0, 0, 0, 0, 0];
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
        field(2n << 3n),
        ...revocationTargets,
      ].reduce((chain, element) => poseidon([chain, element]), PUBLIC_INPUT_HASH);
    expect(Buffer.from(tail(filled(6))).toString("hex")).toBe(
      "291b8807a42057a0d42bba0cd70ab8717d589a0002ac45f71b64df66b6d5af79",
    );
    const treeSlots = [
      { id: 9, utxoRoot: filled(6), nullifierRoot: filled(7) },
      { id: 1, utxoRoot: filled(4), nullifierRoot: filled(5) },
      { id: 2, utxoRoot: filled(2), nullifierRoot: filled(3) },
    ];
    const input = {
      privateTxHash: PRIVATE_TX_HASH,
      txViewingPublicKey: P256PublicKey.fromBytes(TX_PK),
      auditorPublicKey: X25519PublicKey.fromBytes(AUDITOR_PK),
      message: {
        ephemeralPublicKey: X25519PublicKey.fromBytes(EPH_PK),
        ciphertext: CIPHERTEXT,
        disclosure: ZERO_DISCLOSURE,
      },
      outputHashes: [new Uint8Array(32) as Bytes32],
      salt: new Uint8Array(16) as Bytes16,
      policyHash: filled(0x2a),
      treeSlots,
      addressTreeId: 9,
      ringId: filled(8),
      namespaceOwnerHash: filled(10),
      approvalRequired: true,
      keyRegistryRoot: filled(0x0b),
      revocationTargets,
      revocationTreeIndexes,
    };
    expect(policyPublicInputHash(input)).toEqual(
      tail(treeSlotsHashChain(inputTreeSlots(treeSlots))),
    );
    expect(() =>
      policyPublicInputHash({ ...input, revocationTreeIndexes: [8, 0, 0, 0, 0, 0, 0, 0, 0, 0] }),
    ).toThrow(RangeError);
  });

  it("masks each disclosure field with the chained two-input Poseidon pad", () => {
    const auditor = X25519Secret.generate();
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
    pad.slice(1).forEach((mask, index) => {
      expect(mask).toEqual(poseidon([pad[index]!, bigIntToBytes(BigInt(index + 1), 32)]));
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
  const auditor = X25519Secret.generate();
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
    expect(audited.undecryptableSlots).toHaveLength(0);
  });

  it("rejects recipient plaintext that disagrees with the proof-bound output", () => {
    expect(() => audit(transaction({ amount: 5n, committedAmount: 0n }))).toThrow(
      "RING_AUDIT_OUTPUT_MISMATCH",
    );
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
