import { ed25519 } from "@noble/curves/ed25519.js";
import {
  AccountRole,
  address,
  getAddressDecoder,
  getAddressEncoder,
  getBase58Decoder,
  getProgramDerivedAddress,
  type MessagePartialSigner,
} from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import { ringDepositInstruction } from "../src/interface/instructions/index.js";
import { DepositAsset, InstructionTag } from "../src/interface/index.js";
import type { Bytes16, Bytes32, Bytes33 } from "../src/interface/types.js";
import {
  RING_CREATE_CONFIG_COMPUTE_UNIT_LIMIT,
  createRingConfigInstruction,
  initSppRingConfigInstruction,
  ringTransactInstruction,
} from "../src/ring/instructions.js";
import { decodeRingProgramConfig } from "../src/ring/codecs.js";
import { setRingAuthorityInstruction } from "../src/ring/config.js";
import { getProtocolConfigAddress } from "../src/addresses.js";
import { passkeyReader } from "../src/ring/passkey.js";
import {
  checkedReaderKey,
  decodeReadAccessRecord,
  grantReadAccessInstruction,
  parseReaderKey,
  readerKeyBytes,
  readerKeyEquals,
  readerKeyFromBytes,
  readerKeyToString,
  readAccessRecordAddress,
  revokeReadAccessInstruction,
  type ReaderKey,
} from "../src/ring/reader.js";
import { P_CONST_SEC1, P_DERIVE_SEC1, P_PDA_SEC1 } from "../src/keypair/derivation.js";
import { sha256 } from "../src/interface/internal.js";
import { P256PublicKey } from "../src/keypair/public-key.js";
import {
  RingReadRequest,
  RingRpc,
  auditorKeyAttestation,
  messageSignerReader,
  ringReadAttestation,
} from "../src/ring/rpc.js";
import { decodeOutputData } from "../src/transaction/serialization/codecs.js";
import {
  decodeRingDepositOutput,
  decodeRingDepositPlaintext,
  encodeRingDepositPlaintext,
} from "../src/transaction/serialization/ring-deposit.js";

function hex(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value, "hex"));
}

function filled(byte: number, length: number): Uint8Array {
  return new Uint8Array(length).fill(byte);
}

function addressOf(byte: number) {
  return getAddressDecoder().decode(filled(byte, 32));
}

// Byte strings from custom-rings/sdk/tests/instruction_builders.rs.
const RING = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
const PAYER = address("k7FaK87WHGVXzkaoHb7CdVPgkKDQhZ29VLDeBVbDfYn");
const TREE = address("2RJD1KnDRGEkvuFfAGrJ7PD28LRE9LRDjZznDywagzmr");
const OUTPUT_TREE = address("2VDW9dFE1ZXz4zWAbaBDQFynNVdRpQ73HyfSHMzBSL6Z");
const RING_AUTH = address("AtyqWdns8uYfWdpLhWJRN9DxRdpwB6Zaa33k66TAkwFx");
const RING_CONFIG = address("CXJhGzAcN4NYaapjRqiTzmnRBTmtUL52Zg4ooG2PtMfP");
const SPP = address("sppXZU59VoYodv9Accs4hHNTjYiuYmDFyFVjUjPxFsG");
const SYSTEM = address("11111111111111111111111111111111");
const SOL_INTERFACE = address("GGk4JbLExpASWVCAtAVdxZ65BCQsj8WN5TsL6v8Dd1c8");

describe("ring deposit", () => {
  it("encodes the plaintext like Rust wincode", () => {
    const plaintext = {
      blinding: filled(9, 32) as Bytes32,
      memo: Uint8Array.of(104, 105),
      ringData: new Uint8Array(),
    };
    const encoded = encodeRingDepositPlaintext(plaintext);
    expect(Buffer.from(encoded).toString("hex")).toBe(
      "09090909090909090909090909090909090909090909090909090909090909090001020068690000",
    );
    expect(decodeRingDepositPlaintext(encoded)).toEqual(plaintext);
  });

  it("builds the instruction Rust `Deposit` builds", async () => {
    const instruction = await ringDepositInstruction({
      ringProgramId: RING,
      tree: TREE,
      depositor: PAYER,
      deposits: [
        {
          asset: DepositAsset.sol(),
          viewTag: filled(31, 32) as Bytes32,
          ownerUtxoHash: filled(32, 32) as Bytes32,
          amount: 7_000_000n,
          ringDataHash: filled(33, 32) as Bytes32,
          encrypted: {
            txViewingPublicKey: filled(3, 33) as Bytes33,
            salt: filled(34, 16) as Bytes16,
            ciphertext: Uint8Array.of(35, 36, 37),
          },
        },
      ],
    });
    expect(instruction.programAddress).toBe(RING);
    expect(instruction.accounts?.map((meta) => [meta.address, meta.role])).toEqual([
      [TREE, AccountRole.WRITABLE],
      [PAYER, AccountRole.WRITABLE_SIGNER],
      [RING_AUTH, AccountRole.READONLY],
      [SPP, AccountRole.READONLY],
      [SYSTEM, AccountRole.READONLY],
      [SOL_INTERFACE, AccountRole.WRITABLE],
    ]);
    expect(instruction.data?.[0]).toBe(InstructionTag.ringDeposit);
    expect(Buffer.from(instruction.data ?? []).toString("hex")).toBe(
      "0e010001001f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f2020202020202020202020202020202020202020202020202020202020202020c0cf6a0000000000002121212121212121212121212121212121212121212121212121212121212121030303030303030303030303030303030303030303030303030303030303030303222222222222222222222222222222220300232425",
    );
  });

  it("decodes the output the shielded pool publishes", () => {
    const frame = decodeOutputData(
      hex(
        "01c20000000820202020202020202020202020202020202020202020202020202020202020200000000000000000000000000000000000000000000000000000000000000000c0cf6a00000000000084b11dbd52858fa19dbddb423ed67907afb971aad086c9e365fcf9baa9bd066021212121212121212121212121212121212121212121212121212121212121210303030303030303030303030303030303030303030303030303030303030303032222222222222222222222222222222203000000232425",
      ),
    );
    expect(frame.encoding).toBe("encrypted");
    expect(frame.scheme).toBe(8);
    const output = decodeRingDepositOutput(frame.body);
    expect(output.ownerUtxoHash).toEqual(filled(32, 32));
    expect(output.asset).toBe(SYSTEM);
    expect(output.amount).toBe(7_000_000n);
    expect(output.dataHash).toBeUndefined();
    expect(output.ringProgramId).toBe(RING);
    expect(output.ringDataHash).toEqual(filled(33, 32));
    expect(output.encrypted.txViewingPublicKey).toEqual(filled(3, 33));
    expect(output.encrypted.salt).toEqual(filled(34, 16));
    expect(output.encrypted.ciphertext).toEqual(Uint8Array.of(35, 36, 37));
  });
});

describe("ring config", () => {
  const AUTHORITY = addressOf(12);
  const AUDITOR = P256PublicKey.fromBytes(hex(P256_HEX) as Bytes33);

  it("builds create config like Rust `CreateConfig`", async () => {
    const instruction = await createRingConfigInstruction({
      ringProgramId: RING,
      payer: PAYER,
      authority: AUTHORITY,
      auditorPublicKey: AUDITOR,
    });
    const [programData] = await getProgramDerivedAddress({
      programAddress: address("BPFLoaderUpgradeab1e11111111111111111111111"),
      seeds: [getAddressEncoder().encode(RING)],
    });
    expect(instruction.programAddress).toBe(RING);
    expect(instruction.accounts?.map((meta) => [meta.address, meta.role])).toEqual([
      [PAYER, AccountRole.WRITABLE_SIGNER],
      [AUTHORITY, AccountRole.READONLY_SIGNER],
      [RING_CONFIG, AccountRole.WRITABLE],
      [SYSTEM, AccountRole.READONLY],
      [RING, AccountRole.READONLY],
      [programData, AccountRole.READONLY],
    ]);
    expect(Buffer.from(instruction.data ?? []).toString("hex")).toBe(`01${P256_HEX}`);
    expect(RING_CREATE_CONFIG_COMPUTE_UNIT_LIMIT).toBe(50_000);
  });

  it("refuses a reserved auditor key like Rust `CreateConfig`", async () => {
    for (const reserved of [P_CONST_SEC1, P_DERIVE_SEC1, P_PDA_SEC1]) {
      await expect(
        createRingConfigInstruction({
          ringProgramId: RING,
          payer: PAYER,
          authority: AUTHORITY,
          auditorPublicKey: P256PublicKey.fromBytes(reserved as Bytes33),
        }),
      ).rejects.toMatchObject({ code: "RING_RESERVED_AUDITOR_KEY" });
    }
  });

  it("builds init SPP ring config like Rust `InitSppRingConfig`", async () => {
    const instruction = await initSppRingConfigInstruction({
      ringProgramId: RING,
      payer: PAYER,
      authority: AUTHORITY,
    });
    expect(instruction.accounts?.map((meta) => [meta.address, meta.role])).toEqual([
      [PAYER, AccountRole.WRITABLE_SIGNER],
      [AUTHORITY, AccountRole.READONLY_SIGNER],
      [RING_CONFIG, AccountRole.READONLY],
      [await getProtocolConfigAddress(), AccountRole.READONLY],
      [RING_AUTH, AccountRole.WRITABLE],
      [SYSTEM, AccountRole.READONLY],
      [SPP, AccountRole.READONLY],
    ]);
    expect(instruction.data).toEqual(Uint8Array.of(2));
  });

  it("decodes the config account and rejects another layout", () => {
    const data = Uint8Array.from([1, ...filled(12, 32), ...hex(P256_HEX), 254]);
    const config = decodeRingProgramConfig(data);
    expect(config.authority).toBe(AUTHORITY);
    expect(config.auditorPublicKey.equals(AUDITOR)).toBe(true);
    expect(config.bump).toBe(254);
    expect(() => decodeRingProgramConfig(data.subarray(1))).toThrow("RING_CONFIG_INVALID");
    expect(() => decodeRingProgramConfig(Uint8Array.from([2, ...data.subarray(1)]))).toThrow(
      "RING_CONFIG_INVALID",
    );
  });

  it("builds the authority handover like Rust `SetAuthority`", async () => {
    const handover = await setRingAuthorityInstruction({
      ringProgramId: RING,
      authority: AUTHORITY,
      newAuthority: PAYER,
    });
    expect(handover.programAddress).toBe(RING);
    expect(handover.accounts?.map((meta) => [meta.address, meta.role])).toEqual([
      [AUTHORITY, AccountRole.READONLY_SIGNER],
      [PAYER, AccountRole.READONLY_SIGNER],
      [RING_CONFIG, AccountRole.WRITABLE],
    ]);
    expect(Buffer.from(handover.data ?? []).toString("hex")).toBe("06");
  });
});

describe("ring status", () => {
  it("reads the three states and both keys", async () => {
    const wire = {
      jsonrpc: "2.0",
      id: 1,
      result: {
        ringProgramId: addressOf(7),
        state: "foreignAuditor",
        auditorPubkey: Buffer.from(hex(P256_HEX)).toString("base64"),
        auditorViewTag: addressOf(21),
        configAuditorPubkey: Buffer.from(hex(P256_HEX)).toString("base64"),
        servicePubkey: addressOf(22),
      },
    };
    const fetch = (async () => new Response(JSON.stringify(wire))) as typeof globalThis.fetch;

    const status = await new RingRpc("http://ring.example", { fetch }).ringStatus(addressOf(7));

    expect(status.state).toBe("foreignAuditor");
    expect(status.configAuditorPublicKey?.toBytes()).toEqual(hex(P256_HEX));
    expect(status.servicePublicKey).toBe(addressOf(22));
  });

  it("leaves the config key absent before a ring is initialized", async () => {
    const fetch = (async () =>
      new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          result: {
            ringProgramId: addressOf(7),
            state: "uninitialized",
            auditorPubkey: Buffer.from(hex(P256_HEX)).toString("base64"),
            auditorViewTag: addressOf(21),
            servicePubkey: addressOf(22),
          },
        }),
      )) as typeof globalThis.fetch;

    const status = await new RingRpc("http://ring.example", { fetch }).ringStatus(addressOf(7));

    expect(status.state).toBe("uninitialized");
    expect(status.configAuditorPublicKey).toBeUndefined();
  });
});

describe("ring deposits", () => {
  const queue = (results: readonly unknown[]) => {
    const bodies: Record<string, unknown>[] = [];
    let call = 0;
    const fetch = (async (_input: URL | string, init?: RequestInit) => {
      bodies.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
      return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: results[call++] }));
    }) as typeof globalThis.fetch;
    return { bodies, fetch };
  };
  const deposit = (byte: number, slot: number) => ({
    signature: String(byte).repeat(87),
    slot,
    depositor: addressOf(byte),
    asset: "11111111111111111111111111111111",
    amount: byte,
  });

  it("pages the ring history until the cursor is absent", async () => {
    const { bodies, fetch } = queue([
      { deposits: [deposit(1, 9)], cursor: "AQID", oldestSlot: 9 },
      { deposits: [deposit(2, 4)], oldestSlot: 4 },
    ]);
    const rpc = new RingRpc("http://ring.example", { fetch });

    const first = await rpc.ringDeposits({ ringProgramId: addressOf(7), limit: 20 });
    expect(first.deposits).toHaveLength(1);
    expect(first.deposits[0]).toEqual({
      signature: "1".repeat(87),
      slot: 9n,
      depositor: addressOf(1),
      asset: "11111111111111111111111111111111",
      amount: 1n,
    });
    expect(first.cursor).toEqual(Uint8Array.of(1, 2, 3));
    expect(first.oldestSlot).toBe(9n);

    const second = await rpc.ringDeposits({
      ringProgramId: addressOf(7),
      cursor: first.cursor as Uint8Array,
    });
    expect(second.deposits[0]?.slot).toBe(4n);
    expect(second.cursor).toBeUndefined();
    expect(second.oldestSlot).toBe(4n);

    expect(bodies[0]?.["params"]).toEqual({ ringProgramId: addressOf(7), limit: 20 });
    expect(bodies[1]?.["params"]).toEqual({ ringProgramId: addressOf(7), cursor: "AQID" });
  });

  it("keeps a cursor over a page whose signatures held no deposit", async () => {
    const { fetch } = queue([{ deposits: [], cursor: "BAUG", oldestSlot: 12 }]);

    const page = await new RingRpc("http://ring.example", { fetch }).ringDeposits({
      ringProgramId: addressOf(7),
    });

    expect(page.deposits).toEqual([]);
    expect(page.cursor).toEqual(Uint8Array.of(4, 5, 6));
    expect(page.oldestSlot).toBe(12n);
  });

  it("leaves the oldest slot absent when the page examined nothing", async () => {
    const { fetch } = queue([{ deposits: [] }]);

    const page = await new RingRpc("http://ring.example", { fetch }).ringDeposits({
      ringProgramId: addressOf(7),
    });

    expect(page.cursor).toBeUndefined();
    expect(page.oldestSlot).toBeUndefined();
  });
});

describe("ring transact", () => {
  it("appends the settlement accounts of a public withdrawal", async () => {
    const recipient = addressOf(31);
    const instruction = await ringTransactInstruction({
      ringProgramId: RING,
      payer: PAYER,
      inputTree: TREE,
      outputTree: OUTPUT_TREE,
      proof: Uint8Array.from([
        ...filled(51, 32),
        ...filled(52, 64),
        ...filled(53, 32),
        ...filled(54, 32),
        ...filled(55, 32),
      ]),
      withdrawal: { kind: "sol", recipient },
      data: {
        expiryUnixTs: 0xffff_ffff_ffff_ffffn,
        privateTxHash: filled(41, 32) as Bytes32,
        circuit: { kind: "ringEddsa", inputs: 2, outputs: 3, publicAssetSlots: 3 },
        txViewingPk: filled(3, 33) as Bytes33,
        salt: filled(42, 16) as Bytes16,
        proof: {
          a: filled(43, 32) as Bytes32,
          b: filled(44, 64) as never,
          c: filled(45, 32) as Bytes32,
        },
        inputs: [],
        interfaceTransfers: [],
        outputs: [],
        messages: [],
      },
    });

    // Without these the pool cannot settle and the ring cannot pay an address.
    const tail = instruction.accounts?.slice(-2).map((meta) => meta.address);
    expect(tail).toEqual([SOL_INTERFACE, recipient]);
  });

  it("wraps the pool's account list and data like Rust `CustomRingTransact`", async () => {
    const instruction = await ringTransactInstruction({
      ringProgramId: RING,
      payer: PAYER,
      inputTree: TREE,
      outputTree: OUTPUT_TREE,
      proof: Uint8Array.from([
        ...filled(51, 32),
        ...filled(52, 64),
        ...filled(53, 32),
        ...filled(54, 32),
        ...filled(55, 32),
      ]),
      data: {
        expiryUnixTs: 0xffff_ffff_ffff_ffffn,
        privateTxHash: filled(41, 32) as Bytes32,
        circuit: { kind: "ringEddsa", inputs: 2, outputs: 3, publicAssetSlots: 3 },
        txViewingPk: filled(3, 33) as Bytes33,
        salt: filled(42, 16) as Bytes16,
        proof: {
          a: filled(43, 32) as Bytes32,
          b: filled(44, 64) as never,
          c: filled(45, 32) as Bytes32,
        },
        inputs: [],
        interfaceTransfers: [],
        outputs: [],
        messages: [],
      },
    });
    expect(instruction.programAddress).toBe(RING);
    expect(instruction.accounts?.map((meta) => [meta.address, meta.role])).toEqual([
      [PAYER, AccountRole.WRITABLE_SIGNER],
      [RING_CONFIG, AccountRole.READONLY],
      [PAYER, AccountRole.WRITABLE_SIGNER],
      [TREE, AccountRole.WRITABLE],
      [OUTPUT_TREE, AccountRole.WRITABLE],
      [SPP, AccountRole.READONLY],
      [SYSTEM, AccountRole.READONLY],
      [RING_AUTH, AccountRole.READONLY],
    ]);
    expect(Buffer.from(instruction.data ?? []).toString("hex")).toBe(
      "03333333333333333333333333333333333333333333333333333333333333333334343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434353535353535353535353535353535353535353535353535353535353535353536363636363636363636363636363636363636363636363636363636363636363737373737373737373737373737373737373737373737373737373737373737ffffffffffffffff292929292929292929292929292929292929292929292929292929292929292901000203030303030303030303030303030303030303030303030303030303030303030303032a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d000000000000",
    );
  });
});

// The P-256 key of the scalar [46; 32], its record printed by the Rust builders.
const P256_HEX = "02039b852db622408abe58a18c0f056631a6ca4b2cfeec198aae25017cad09d4e8";

describe("ring reader delegation", () => {
  const AUTHORITY = addressOf(12);
  const P256_UNCOMPRESSED =
    "04039b852db622408abe58a18c0f056631a6ca4b2cfeec198aae25017cad09d4e8e208b616e0dc5775a5d840775d38dafd4676da34100215e8be857bed2ba4ac30";
  // Rust `reader()`, the ed25519 key of the seed [23; 32].
  const ED25519 = address("4MfyR4G3NWfVRDWo6iNAHDBZqWMgwZX6FNtMqEW3a9JT");
  const KEYS = [
    {
      key: ED25519 as ReaderKey,
      record: address("Btd87zUBTFhLjF6ZKUTdpXgVAGmrXYHhsKpSdCtUFE2p"),
      bytes: `01${Buffer.from(ed25519.getPublicKey(filled(23, 32))).toString("hex")}00`,
    },
    {
      key: P256PublicKey.fromBytes(hex(P256_HEX) as Bytes33) as ReaderKey,
      record: address("HNpuU7MthQAioAdziSbVyS7YaHABC7e8b36PU6yFQ78D"),
      bytes: `00${P256_HEX}`,
    },
  ];

  it("encodes both key kinds and derives the record like Rust `ReaderKey`", async () => {
    for (const { key, record, bytes } of KEYS) {
      expect(Buffer.from(readerKeyBytes(key)).toString("hex")).toBe(bytes);
      expect(await readAccessRecordAddress(RING, key)).toBe(record);
      expect(readerKeyEquals(parseReaderKey(readerKeyToString(key)), key)).toBe(true);
      expect(readerKeyEquals(readerKeyFromBytes(hex(bytes)), key)).toBe(true);
    }
    expect(P256PublicKey.fromUncompressed(hex(P256_UNCOMPRESSED)).toBytes()).toEqual(hex(P256_HEX));
  });

  it("refuses keys that cannot sign a read like Rust `ReaderKey`", () => {
    const weak = new Uint8Array(32);
    weak[0] = 1;
    expect(() => checkedReaderKey(getAddressDecoder().decode(weak))).toThrow("RING_READER_KEY");
    weak[31] = 0x80;
    expect(() => checkedReaderKey(getAddressDecoder().decode(weak))).toThrow("RING_READER_KEY");
    const noncanonical = filled(0xff, 32);
    noncanonical[0] = 0xee;
    noncanonical[31] = 0x7f;
    expect(() => checkedReaderKey(getAddressDecoder().decode(noncanonical))).toThrow(
      "RING_READER_KEY",
    );
    const mixedTorsion = ed25519.Point.BASE.add(
      ed25519.Point.fromBytes(Uint8Array.of(...new Uint8Array(31), 0x80)),
    ).toBytes();
    expect(() => checkedReaderKey(getAddressDecoder().decode(mixedTorsion))).toThrow(
      "RING_READER_KEY",
    );
    for (const reserved of [P_CONST_SEC1, P_DERIVE_SEC1, P_PDA_SEC1]) {
      expect(() => checkedReaderKey(P256PublicKey.fromBytes(reserved as Bytes33))).toThrow(
        "RING_READER_KEY",
      );
    }
    const scheme = hex(`01${"17".repeat(32)}00`);
    scheme[0] = 2;
    expect(() => readerKeyFromBytes(scheme)).toThrow("RING_READER_KEY");
    expect(() => parseReaderKey("not-a-key")).toThrow("RING_READER_KEY");
    expect(() => parseReaderKey("04".repeat(33))).toThrow("RING_READER_KEY");
  });

  it("builds grant and revoke like Rust `GrantReadAccess` and `RevokeReadAccess`", async () => {
    for (const { key, record, bytes } of KEYS) {
      const grant = await grantReadAccessInstruction({
        ringProgramId: RING,
        payer: PAYER,
        authority: AUTHORITY,
        reader: key,
      });
      expect(grant.programAddress).toBe(RING);
      expect(grant.accounts?.map((meta) => [meta.address, meta.role])).toEqual([
        [PAYER, AccountRole.WRITABLE_SIGNER],
        [AUTHORITY, AccountRole.READONLY_SIGNER],
        [RING_CONFIG, AccountRole.READONLY],
        [record, AccountRole.WRITABLE],
        [SYSTEM, AccountRole.READONLY],
      ]);
      expect(Buffer.from(grant.data ?? []).toString("hex")).toBe(`04${bytes}`);

      const revoke = await revokeReadAccessInstruction({
        ringProgramId: RING,
        authority: AUTHORITY,
        reader: key,
        rentRecipient: PAYER,
      });
      expect(revoke.accounts?.map((meta) => [meta.address, meta.role])).toEqual([
        [AUTHORITY, AccountRole.READONLY_SIGNER],
        [RING_CONFIG, AccountRole.READONLY],
        [record, AccountRole.WRITABLE],
        [PAYER, AccountRole.WRITABLE],
      ]);
      expect(Buffer.from(revoke.data ?? []).toString("hex")).toBe(`05${bytes}`);
    }
  });

  it("decodes the record the program writes and rejects anything else", () => {
    for (const { key, bytes } of KEYS) {
      const record = decodeReadAccessRecord(Uint8Array.from([2, ...hex(bytes), 254]));
      expect(readerKeyEquals(record.reader, key)).toBe(true);
      expect(record.bump).toBe(254);
    }
    expect(() => decodeReadAccessRecord(Uint8Array.from([1, ...filled(23, 34), 254]))).toThrow(
      "RING_READ_ACCESS_RECORD_INVALID",
    );
    expect(() => decodeReadAccessRecord(filled(2, 35))).toThrow("RING_READ_ACCESS_RECORD_INVALID");
  });
});

describe("ring passkey", () => {
  it("signs through WebAuthn with the attestation hash as challenge", async () => {
    const passkey = {
      credentialId: filled(9, 16),
      publicKey: P256PublicKey.fromBytes(
        hex("02039b852db622408abe58a18c0f056631a6ca4b2cfeec198aae25017cad09d4e8") as Bytes33,
      ),
    };
    let seen: PublicKeyCredentialRequestOptions | undefined;
    const navigatorStub = {
      credentials: {
        get: (options: CredentialRequestOptions) => {
          seen = options.publicKey;
          return Promise.resolve({
            response: {
              signature: filled(1, 70).buffer,
              authenticatorData: filled(2, 37).buffer,
              clientDataJSON: filled(3, 80).buffer,
            },
          });
        },
      },
    };
    vi.stubGlobal("navigator", navigatorStub);
    try {
      const message = filled(7, 40);
      const reader = passkeyReader(passkey);
      expect(reader.reader).toEqual(readerKeyBytes(passkey.publicKey));
      expect(reader.reader).toHaveLength(34);
      const signed = await reader.sign(message);
      expect(new Uint8Array(seen?.challenge as ArrayBuffer)).toEqual(sha256(message));
      expect(seen?.userVerification).toBe("required");
      expect(new Uint8Array(seen?.allowCredentials?.[0]?.id as ArrayBuffer)).toEqual(
        passkey.credentialId,
      );
      expect(signed).toEqual({
        signature: filled(1, 70),
        authenticatorData: filled(2, 37),
        clientDataJSON: filled(3, 80),
      });
    } finally {
      vi.unstubAllGlobals();
    }
  });
});

describe("ring read attestation", () => {
  it("matches the Rust `read_attestation_is_stable` vector", () => {
    const message = ringReadAttestation({
      ringProgramId: addressOf(7),
      timestamp: 1_700_000_000n,
      nonce: filled(4, 32) as Bytes32,
      cursor: Uint8Array.of(1, 2, 3),
      limit: 5n,
    });
    expect(new TextDecoder().decode(message)).toBe(
      "zolana/ring-rpc-read/v1\nring: US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx\ntimestamp: 1700000000\nnonce: BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=\nlimit: 5\ncursor: AQID",
    );
  });

  it("omits limit and cursor as 0 and empty", () => {
    const message = ringReadAttestation({
      ringProgramId: addressOf(7),
      timestamp: 1n,
      nonce: filled(4, 32) as Bytes32,
    });
    expect(new TextDecoder().decode(message)).toBe(
      "zolana/ring-rpc-read/v1\nring: US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx\ntimestamp: 1\nnonce: BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=\nlimit: 0\ncursor: ",
    );
  });

  it("bounds the cursor and the limit like Rust `ReadRequest`", () => {
    const request = RingReadRequest.read(addressOf(7));
    expect(() => request.withCursor(new Uint8Array())).toThrow("RING_READ_CURSOR");
    expect(() => request.withCursor(new Uint8Array(257))).toThrow("RING_READ_CURSOR");
    expect(() => request.withLimit(0n)).toThrow("RING_READ_LIMIT");
    expect(() => request.withLimit(101n)).toThrow("RING_READ_LIMIT");
    expect(request.withCursor(new Uint8Array(256)).withLimit(100n)).toBe(request);
  });
});

describe("ring read request", () => {
  it("sends the tagged reader key and the signature over the attestation", async () => {
    const signerAddress = getAddressDecoder().decode(ed25519.getPublicKey(filled(7, 32)));
    const seen: Uint8Array[] = [];
    const signer = {
      address: signerAddress,
      signMessages: (messages: readonly { content: Uint8Array }[]) => {
        seen.push(...messages.map((message) => message.content));
        return Promise.resolve(messages.map(() => ({ [signerAddress]: filled(5, 64) })));
      },
    } as unknown as MessagePartialSigner;
    const reader = messageSignerReader(signer);
    expect(reader.reader).toEqual(readerKeyBytes(signerAddress));
    expect(reader.reader[0]).toBe(1);
    expect(reader.reader[33]).toBe(0);

    const bodies: Record<string, unknown>[] = [];
    const fetch = (async (_input: URL | string, init?: RequestInit) => {
      bodies.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
      return new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          result: {
            context: { blockTime: 1_700_000_000, slot: 9 },
            value: {
              items: [
                {
                  slot: 8,
                  txSignature: "1".repeat(87),
                  txViewingPk: Buffer.from(hex(P256_HEX)).toString("base64"),
                  outputs: [
                    {
                      slotIndex: 1,
                      recipientViewingPk: Buffer.from(hex(P256_HEX)).toString("base64"),
                      ownerTag: addressOf(11),
                      asset: "11111111111111111111111111111111",
                      amount: 7,
                      ringProgramId: RING,
                    },
                  ],
                  undecryptableSlots: [0],
                  nullifiers: [addressOf(3)],
                  signers: [addressOf(11)],
                  withdrawals: [],
                },
              ],
              skipped: [{ slot: 7, txSignature: "2".repeat(87), reason: "invalidAuditData" }],
              cursor: "AQID",
            },
          },
        }),
      );
    }) as typeof globalThis.fetch;
    const page = await new RingRpc("http://ring.example", { fetch }).getDecryptedTransactions({
      ringProgramId: addressOf(7),
      signer: reader,
      cursor: Uint8Array.of(1, 2, 3),
      limit: 5n,
      timestamp: 1_700_000_000n,
    });
    expect(page.slot).toBe(9n);
    expect(page.blockTime).toBe(1_700_000_000n);
    expect(page.cursor).toEqual(Uint8Array.of(1, 2, 3));
    expect(page.skipped).toEqual([
      { slot: 7n, signature: "2".repeat(87), reason: "invalidAuditData" },
    ]);
    const item = page.items[0];
    expect(item?.slot).toBe(8n);
    expect(item?.txViewingPublicKey.toBytes()).toEqual(hex(P256_HEX));
    expect(item?.undecryptableSlots).toEqual([0]);
    expect(item?.nullifiers).toEqual([filled(3, 32)]);
    expect(item?.outputs[0]).toMatchObject({
      slotIndex: 1,
      asset: "11111111111111111111111111111111",
      amount: 7n,
      ringProgramId: RING,
    });
    expect(item?.outputs[0]?.ownerTag).toEqual(filled(11, 32));
    expect(item?.signers).toEqual([addressOf(11)]);
    expect(item?.withdrawals).toEqual([]);
    const params = bodies[0]?.["params"] as Record<string, unknown>;
    expect(Object.keys(params).sort()).toEqual(["auth", "cursor", "limit", "ringProgramId"]);
    const auth = params["auth"] as Record<string, unknown>;
    expect(Object.keys(auth).sort()).toEqual(["nonce", "reader", "signature", "timestamp"]);
    expect(auth["reader"]).toBe(Buffer.from(readerKeyBytes(signerAddress)).toString("base64"));
    expect(auth["signature"]).toBe(Buffer.from(filled(5, 64)).toString("base64"));
    expect(auth["timestamp"]).toBe(1_700_000_000);
    const nonce = Buffer.from(auth["nonce"] as string, "base64");
    expect(nonce).toHaveLength(32);
    expect(params["ringProgramId"]).toBe(addressOf(7));
    expect(params["cursor"]).toBe("AQID");
    expect(params["limit"]).toBe(5);
    expect(new TextDecoder().decode(seen[0])).toBe(
      new TextDecoder().decode(
        ringReadAttestation({
          ringProgramId: addressOf(7),
          timestamp: 1_700_000_000n,
          nonce: Uint8Array.from(nonce) as Bytes32,
          cursor: Uint8Array.of(1, 2, 3),
          limit: 5n,
        }),
      ),
    );
  });

  it("reads the owner tag and the signers of every output", async () => {
    const signerAddress = getAddressDecoder().decode(ed25519.getPublicKey(filled(9, 32)));
    const reader = messageSignerReader({
      address: signerAddress,
      signMessages: (messages: readonly { content: Uint8Array }[]) =>
        Promise.resolve(messages.map(() => ({ [signerAddress]: filled(5, 64) }))),
    } as unknown as MessagePartialSigner);
    const fetch = (async () =>
      new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          result: {
            context: { blockTime: 1_700_000_000, slot: 9 },
            value: {
              items: [
                {
                  slot: 8,
                  txSignature: "1".repeat(87),
                  txViewingPk: Buffer.from(hex(P256_HEX)).toString("base64"),
                  outputs: [
                    {
                      slotIndex: 0,
                      recipientViewingPk: Buffer.from(hex(P256_HEX)).toString("base64"),
                      ownerTag: addressOf(11),
                      asset: "11111111111111111111111111111111",
                      amount: 7,
                    },
                  ],
                  undecryptableSlots: [],
                  nullifiers: [],
                  signers: [addressOf(11), addressOf(12)],
                  withdrawals: [],
                },
              ],
              skipped: [],
            },
          },
        }),
      )) as typeof globalThis.fetch;

    const page = await new RingRpc("http://ring.example", { fetch }).getDecryptedTransactions({
      ringProgramId: addressOf(7),
      signer: reader,
    });

    expect(page.items[0]?.outputs[0]?.ownerTag).toEqual(filled(11, 32));
    expect(page.items[0]?.signers).toEqual([addressOf(11), addressOf(12)]);
  });

  const withdrawalPage = (withdrawals: readonly Record<string, unknown>[]) =>
    (async () =>
      new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          result: {
            context: { blockTime: 1_700_000_000, slot: 9 },
            value: {
              items: [
                {
                  slot: 8,
                  txSignature: "1".repeat(87),
                  txViewingPk: Buffer.from(hex(P256_HEX)).toString("base64"),
                  outputs: [],
                  undecryptableSlots: [],
                  nullifiers: [],
                  signers: [],
                  withdrawals,
                },
              ],
              skipped: [],
            },
          },
        }),
      )) as typeof globalThis.fetch;

  const anyReader = () => {
    const signerAddress = getAddressDecoder().decode(ed25519.getPublicKey(filled(9, 32)));
    return messageSignerReader({
      address: signerAddress,
      signMessages: (messages: readonly { content: Uint8Array }[]) =>
        Promise.resolve(messages.map(() => ({ [signerAddress]: filled(5, 64) }))),
    } as unknown as MessagePartialSigner);
  };

  it("reads the withdrawal asset of an SPL leg and a SOL leg", async () => {
    const solMint = address("So11111111111111111111111111111111111111112");
    const fetch = withdrawalPage([
      { recipient: addressOf(31), asset: addressOf(13), amount: 5 },
      { recipient: addressOf(32), asset: solMint, amount: 6 },
    ]);

    const page = await new RingRpc("http://ring.example", { fetch }).getDecryptedTransactions({
      ringProgramId: addressOf(7),
      signer: anyReader(),
    });

    expect(page.items[0]?.withdrawals).toEqual([
      { recipient: addressOf(31), asset: addressOf(13), amount: 5n },
      { recipient: addressOf(32), asset: solMint, amount: 6n },
    ]);
  });

  it("sends a passkey assertion under camelCase keys", async () => {
    const bodies: Record<string, unknown>[] = [];
    const fetch = (async (_input: URL | string, init?: RequestInit) => {
      bodies.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
      return new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          result: { context: { blockTime: 0, slot: 1 }, value: { items: [], skipped: [] } },
        }),
      );
    }) as typeof globalThis.fetch;
    const signer = {
      reader: readerKeyBytes(P256PublicKey.fromBytes(hex(P256_HEX) as Bytes33)),
      sign: () =>
        Promise.resolve({
          signature: filled(1, 70),
          authenticatorData: filled(2, 37),
          clientDataJSON: filled(3, 80),
        }),
    };
    const page = await new RingRpc("http://ring.example", { fetch }).getDecryptedTransactions({
      ringProgramId: addressOf(7),
      signer,
    });
    expect(page.cursor).toBeUndefined();
    const params = bodies[0]?.["params"] as Record<string, unknown>;
    expect(Object.keys(params).sort()).toEqual(["auth", "ringProgramId"]);
    const auth = params["auth"] as Record<string, unknown>;
    expect(Object.keys(auth).sort()).toEqual([
      "nonce",
      "reader",
      "signature",
      "timestamp",
      "webauthn",
    ]);
    expect(auth["webauthn"]).toEqual({
      authenticatorData: Buffer.from(filled(2, 37)).toString("base64"),
      clientDataJson: Buffer.from(filled(3, 80)).toString("base64"),
    });
  });

  it("verifies the auditor key attestation before trusting the key", async () => {
    const serviceSecret = filled(9, 32);
    const servicePublicKey = getAddressDecoder().decode(ed25519.getPublicKey(serviceSecret));
    const auditor = P256PublicKey.fromBytes(hex(P256_HEX) as Bytes33);
    const attestation = auditorKeyAttestation(RING, auditor);
    expect(attestation.subarray(0, 26)).toEqual(
      new TextEncoder().encode("zolana/ring-auditor-key/v1"),
    );
    expect(attestation).toHaveLength(26 + 32 + 33);
    const respond = (signature: Uint8Array) =>
      (async () =>
        new Response(
          JSON.stringify({
            jsonrpc: "2.0",
            id: 1,
            result: {
              ringProgramId: RING,
              auditorPubkey: Buffer.from(auditor.toBytes()).toString("base64"),
              auditorViewTag: getAddressDecoder().decode(auditor.x()),
              servicePubkey: servicePublicKey,
              signature: getBase58Decoder().decode(signature),
            },
          }),
        )) as typeof globalThis.fetch;
    const key = await new RingRpc("http://ring.example", {
      fetch: respond(ed25519.sign(attestation, serviceSecret)),
    }).createAuditorKey(RING);
    expect(key.auditorPublicKey.equals(auditor)).toBe(true);
    expect(key.auditorViewTag).toEqual(auditor.x());
    expect(key.servicePublicKey).toBe(servicePublicKey);
    await expect(
      new RingRpc("http://ring.example", { fetch: respond(filled(1, 64)) }).createAuditorKey(RING),
    ).rejects.toMatchObject({ code: "RING_RPC" });
  });
});
