import { describe, expect, it } from "vitest";

import { P256PublicKey } from "../src/keypair/public-key.js";
import { ViewingKey } from "../src/keypair/viewing-key.js";
import type { Bytes32, Bytes33 } from "../src/interface/types.js";
import {
  customRingPublicInputHash,
  auditSharedSecret,
  auditorMessageData,
  decryptTransactionViewingSecret,
  encryptTransactionViewingSecret,
  parseAuditorMessage,
} from "../src/keypair/audit.js";

function hex(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value, "hex"));
}

// Vectors from custom-rings/sdk/tests/go_vectors.rs.
const TX_SK = hex("011013121514171619181b1a1d1c1f1e010003020504070609080b0a0d0c0f0e") as Bytes32;
const EPH_SK = hex("01232021262724252a2b28292e2f2c2d32333031363734353a3b38393e3f3c3d") as Bytes32;
const AUDITOR_SK = hex(
  "01323130373635343b3a39383f3e3d3c23222120272625242b2a29282f2e2d2c",
) as Bytes32;
const EPH_PK = hex("038bd43dcdaea72a1db879b1ca6faac09593fd17893d22eeef926b5c1c245a133c") as Bytes33;
const AUDITOR_PK = hex(
  "039dc51b59006b13f143944d4e432db7c032241ceb3698a6cc0cdabadf29b71dec",
) as Bytes33;
const DH = hex("0adc4a9b4fc9112518acab2c346559372e9a5c2a9d8b93fb1b7650ea1edd4823") as Bytes32;
const SHARED_SECRET = hex(
  "009926f6e6fefd31699816632ef553197a3695424ddd9589e3d074518c40d605",
) as Bytes32;
const CIPHERTEXT = hex(
  "6de7c18c3c3676ca517647a25df33a7150ace3e07b410bc296fac11b1355382b",
) as Bytes32;

// Fixture from custom-rings/program/src/instructions/transact.rs.
const TX_PK = hex("0268737cf1d852483220d399b5321261d5e9e90d8214dc62b4f7e4d0fee955c5d5") as Bytes33;
const PRIVATE_TX_HASH = hex(
  "0000000000000000000000000000000000000000000000000000000000abcdef",
) as Bytes32;
const PUBLIC_INPUT_HASH = hex("18bf7563a64675c110ae7d408b973c98005afac6d06b8ae177f4435d7e6e020b");

describe("ring audit encryption", () => {
  it("matches the Go vectors", () => {
    const ephemeral = ViewingKey.fromBytes(EPH_SK);
    const auditor = P256PublicKey.fromBytes(AUDITOR_PK);
    expect(ephemeral.publicKey().toBytes()).toEqual(EPH_PK);
    expect(ViewingKey.fromBytes(AUDITOR_SK).publicKey().toBytes()).toEqual(AUDITOR_PK);
    const dh = ephemeral.ecdh(auditor);
    expect(dh).toEqual(DH);
    expect(auditSharedSecret(dh, ephemeral.publicKey(), auditor)).toEqual(SHARED_SECRET);
    const message = {
      ephemeralPublicKey: ephemeral.publicKey(),
      ciphertext: CIPHERTEXT,
    };
    expect(decryptTransactionViewingSecret(ViewingKey.fromBytes(AUDITOR_SK), message)).toEqual(
      TX_SK,
    );
  });

  it("round-trips under a fresh ephemeral key and publishes a 65-byte message", () => {
    const auditor = ViewingKey.generate();
    const encrypted = encryptTransactionViewingSecret(TX_SK, auditor.publicKey());
    expect(decryptTransactionViewingSecret(auditor, encrypted.message)).toEqual(TX_SK);
    const data = auditorMessageData(encrypted.message, auditor.publicKey());
    expect(data.viewTag).toEqual(auditor.publicKey().x());
    expect(data.data).toHaveLength(65);
    const parsed = parseAuditorMessage(data.data);
    expect(parsed.ciphertext).toEqual(encrypted.message.ciphertext);
    expect(parsed.ephemeralPublicKey.toBytes()).toEqual(
      encrypted.message.ephemeralPublicKey.toBytes(),
    );
  });

  it("hashes the public input like the ring program", () => {
    expect(
      customRingPublicInputHash({
        privateTxHash: PRIVATE_TX_HASH,
        txViewingPublicKey: P256PublicKey.fromBytes(TX_PK),
        auditorPublicKey: P256PublicKey.fromBytes(AUDITOR_PK),
        message: {
          ephemeralPublicKey: P256PublicKey.fromBytes(EPH_PK),
          ciphertext: CIPHERTEXT,
        },
      }),
    ).toEqual(PUBLIC_INPUT_HASH);
  });

  it("decompresses the auditor key to the 65-byte point the circuit witnesses", () => {
    const auditor = P256PublicKey.fromBytes(AUDITOR_PK);
    const uncompressed = auditor.toUncompressed();
    expect(uncompressed).toHaveLength(65);
    expect(uncompressed[0]).toBe(4);
    expect(uncompressed.subarray(1, 33)).toEqual(auditor.x());
    expect(P256PublicKey.fromUncompressed(uncompressed).equals(auditor)).toBe(true);
  });
});
