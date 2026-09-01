import { ed25519 } from "@noble/curves/ed25519.js";
import {
  AccountRole,
  address,
  getAddressDecoder,
  getAddressEncoder,
  getBase58Decoder,
  getProgramDerivedAddress,
  generateKeyPairSigner,
  type MessagePartialSigner,
} from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import {
  ringDepositInstruction,
  ringTransactAccounts,
} from "../src/interface/instructions/index.js";
import {
  DepositAsset,
  InstructionTag,
  SHIELDED_POOL_CPI_AUTHORITY,
} from "../src/interface/index.js";
import {
  TransactWithdrawal,
  type Bytes16,
  type Bytes64,
  type Bytes32,
  type Bytes33,
  type Signature,
} from "../src/interface/types.js";
import {
  RING_CREATE_CONFIG_COMPUTE_UNIT_LIMIT,
  createRingConfigInstruction,
  initSppRingConfigInstruction,
  ringLookupTableAddresses,
  ringSettlementStatics,
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
import { addressBytes, sha256 } from "../src/interface/internal.js";
import { P256PublicKey } from "../src/keypair/public-key.js";
import {
  RingReadRequest,
  RingRpc,
  type SignedAuditorKeyRequest,
  type SignedRingRead,
  auditorKeyAttestation,
  auditorKeyRequestAttestation,
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

function signatureOf(byte: number) {
  return getBase58Decoder().decode(filled(byte, 64));
}

function capturingFetch(result: unknown): {
  fetch: typeof globalThis.fetch;
  bodies: Record<string, unknown>[];
} {
  const bodies: Record<string, unknown>[] = [];
  const fetch = (async (_input: URL | string, init?: RequestInit) => {
    bodies.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result }), {
      headers: { "content-type": "application/json" },
    });
  }) as typeof globalThis.fetch;
  return { fetch, bodies };
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
const JSON_HEADERS = { headers: { "content-type": "application/json" } };
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

describe("ring transact settlement", () => {
  it("appends the SPL withdrawal group Rust `append_interface_transfer_accounts` appends", () => {
    const mint = addressOf(41);
    const splTokenInterface = addressOf(42);
    const recipientTokenAccount = addressOf(43);
    const tokenProgram = addressOf(44);
    const pool = ringTransactAccounts({
      payer: PAYER,
      inputTree: TREE,
      outputTree: OUTPUT_TREE,
      ringAuth: RING_AUTH,
      withdrawal: TransactWithdrawal.spl({
        mint,
        splTokenInterface,
        recipientTokenAccount,
        tokenProgram,
      }),
    });
    expect(pool.slice(-5).map((meta) => [meta.address, meta.role])).toEqual([
      [SHIELDED_POOL_CPI_AUTHORITY, AccountRole.READONLY],
      [mint, AccountRole.READONLY],
      [splTokenInterface, AccountRole.WRITABLE],
      [recipientTokenAccount, AccountRole.WRITABLE],
      [tokenProgram, AccountRole.READONLY],
    ]);
  });

  it("appends non-payer owner signers as readonly signers", () => {
    const owner = addressOf(45);
    const pool = ringTransactAccounts({
      payer: PAYER,
      inputTree: TREE,
      outputTree: OUTPUT_TREE,
      ringAuth: RING_AUTH,
      ownerSigners: [owner],
    });
    expect(pool.map((meta) => [meta.address, meta.role])).toContainEqual([
      owner,
      AccountRole.READONLY_SIGNER,
    ]);
  });

  it("adds the settlement statics to a new table without requiring them at fetch", async () => {
    const required = await ringLookupTableAddresses({ ringProgramId: RING, tree: TREE });
    for (const address of ringSettlementStatics()) {
      expect(required).not.toContain(address);
    }
    expect(ringSettlementStatics()).toContain(SHIELDED_POOL_CPI_AUTHORITY);
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
  it("reads the state and the config key", async () => {
    const wire = {
      jsonrpc: "2.0",
      id: 1,
      result: {
        ringProgramId: addressOf(7),
        state: "foreignAuditor",
        configAuditorPubkey: Buffer.from(hex(P256_HEX)).toString("base64"),
        servicePubkey: addressOf(22),
      },
    };
    const fetch = (async () =>
      new Response(JSON.stringify(wire), JSON_HEADERS)) as typeof globalThis.fetch;

    const status = await new RingRpc("http://ring.example", {
      fetch,
      allowInsecureHttp: true,
    }).ringStatus(addressOf(7));

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
            servicePubkey: addressOf(22),
          },
        }),
        JSON_HEADERS,
      )) as typeof globalThis.fetch;

    const status = await new RingRpc("http://ring.example", {
      fetch,
      allowInsecureHttp: true,
    }).ringStatus(addressOf(7));

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
      return new Response(
        JSON.stringify({ jsonrpc: "2.0", id: 1, result: results[call++] }),
        JSON_HEADERS,
      );
    }) as typeof globalThis.fetch;
    return { bodies, fetch };
  };
  const deposit = (byte: number, slot: number) => ({
    signature: signatureOf(byte),
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
    const rpc = new RingRpc("http://ring.example", { fetch, allowInsecureHttp: true });

    const first = await rpc.ringDeposits({ ringProgramId: addressOf(7), limit: 20 });
    expect(first.deposits).toHaveLength(1);
    expect(first.deposits[0]).toEqual({
      signature: signatureOf(1),
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

    const page = await new RingRpc("http://ring.example", {
      fetch,
      allowInsecureHttp: true,
    }).ringDeposits({
      ringProgramId: addressOf(7),
    });

    expect(page.deposits).toEqual([]);
    expect(page.cursor).toEqual(Uint8Array.of(4, 5, 6));
    expect(page.oldestSlot).toBe(12n);
  });

  it("leaves the oldest slot absent when the page examined nothing", async () => {
    const { fetch } = queue([{ deposits: [] }]);

    const page = await new RingRpc("http://ring.example", {
      fetch,
      allowInsecureHttp: true,
    }).ringDeposits({
      ringProgramId: addressOf(7),
    });

    expect(page.cursor).toBeUndefined();
    expect(page.oldestSlot).toBeUndefined();
  });
});

describe("signed ring request validation", () => {
  const READER = readerKeyBytes(
    checkedReaderKey(getAddressDecoder().decode(ed25519.getPublicKey(filled(5, 32)))),
  );
  const WEBAUTHN = {
    signature: filled(1, 70),
    authenticatorData: filled(2, 37),
    clientDataJSON: filled(3, 12),
  };

  function signedRead(overrides: Partial<SignedRingRead> = {}): SignedRingRead {
    return {
      ringProgramId: RING,
      reader: READER,
      timestamp: 1n,
      nonce: filled(7, 32) as Bytes32,
      signature: filled(1, 64),
      ...overrides,
    };
  }

  function signedAuditorKey(
    overrides: Partial<SignedAuditorKeyRequest> = {},
  ): SignedAuditorKeyRequest {
    return {
      ringProgramId: RING,
      authority: PAYER,
      genesisHash: filled(2, 32) as Bytes32,
      timestamp: 1n,
      nonce: filled(3, 32) as Bytes32,
      signature: filled(4, 64) as Bytes64,
      ...overrides,
    };
  }

  function offlineRpc(): Readonly<{ rpc: RingRpc; fetch: ReturnType<typeof vi.fn> }> {
    const fetch = vi.fn<typeof globalThis.fetch>();
    return {
      rpc: new RingRpc("http://ring.example", {
        fetch,
        allowInsecureHttp: true,
      }),
      fetch,
    };
  }

  const readCases: readonly [string, Readonly<Record<string, unknown>>, string][] = [
    ["a malformed ring program id", { ringProgramId: "not-base58!" }, "RING_RPC"],
    ["a short reader key", { reader: filled(1, 33) }, "RING_READER_KEY"],
    ["an invalid P256 reader key", { reader: new Uint8Array(34) }, "RING_READER_KEY"],
    ["a short nonce", { nonce: filled(7, 31) }, "RING_RPC"],
    ["a since without a slot", { since: { signature: signatureOf(2) } }, "RING_READ_SINCE"],
    [
      "a since with a numeric slot",
      { since: { slot: 3, signature: signatureOf(2) } },
      "RING_READ_SINCE",
    ],
    ["a zero limit", { limit: 0n }, "RING_READ_LIMIT"],
    ["a limit over the page cap", { limit: 101n }, "RING_READ_LIMIT"],
    ["a negative timestamp", { timestamp: -1n }, "RING_RPC"],
    ["a timestamp past the safe range", { timestamp: 1n << 53n }, "RING_RPC"],
    ["a short ed25519 signature", { signature: filled(1, 63) }, "RING_RPC"],
    ["a null signature", { signature: null }, "RING_RPC"],
    ["an extra field", { extra: true }, "RING_RPC"],
    [
      "an empty webauthn signature",
      { signature: { ...WEBAUTHN, signature: new Uint8Array(0) } },
      "RING_RPC",
    ],
    [
      "short webauthn authenticator data",
      { signature: { ...WEBAUTHN, authenticatorData: filled(2, 36) } },
      "RING_RPC",
    ],
    [
      "empty webauthn client data",
      { signature: { ...WEBAUTHN, clientDataJSON: new Uint8Array(0) } },
      "RING_RPC",
    ],
  ];

  it.each(readCases)(
    "rejects a read with %s before any network call",
    async (_name, overrides, code) => {
      const { rpc, fetch } = offlineRpc();
      await expect(
        Reflect.apply(rpc.readSigned, rpc, [{ ...signedRead(), ...overrides }]),
      ).rejects.toMatchObject({ code });
      expect(fetch).not.toHaveBeenCalled();
    },
  );

  const auditorCases: readonly [string, Readonly<Record<string, unknown>>, string][] = [
    ["a malformed ring program id", { ringProgramId: "nope" }, "RING_RPC"],
    ["a malformed authority", { authority: "nope" }, "RING_RPC"],
    ["a short genesis hash", { genesisHash: filled(2, 31) }, "RING_RPC"],
    ["a short nonce", { nonce: filled(3, 31) }, "RING_RPC"],
    ["a short signature", { signature: filled(4, 63) }, "RING_RPC"],
    ["a timestamp past the safe range", { timestamp: 1n << 53n }, "RING_RPC"],
    ["an extra field", { extra: true }, "RING_RPC"],
  ];

  it.each(auditorCases)(
    "rejects an auditor key request with %s before any network call",
    async (_name, overrides, code) => {
      const { rpc, fetch } = offlineRpc();
      await expect(
        Reflect.apply(rpc.createAuditorKeySigned, rpc, [{ ...signedAuditorKey(), ...overrides }]),
      ).rejects.toMatchObject({ code });
      expect(fetch).not.toHaveBeenCalled();
    },
  );

  it("rejects non-object signed requests through Ring errors", async () => {
    const { rpc, fetch } = offlineRpc();
    await expect(Reflect.apply(rpc.readSigned, rpc, [null])).rejects.toMatchObject({
      code: "RING_RPC",
    });
    await expect(Reflect.apply(rpc.createAuditorKeySigned, rpc, [null])).rejects.toMatchObject({
      code: "RING_RPC",
    });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("requires signed fields to be own properties", async () => {
    const { rpc, fetch } = offlineRpc();
    await expect(
      Reflect.apply(rpc.readSigned, rpc, [Object.create(signedRead())]),
    ).rejects.toMatchObject({ code: "RING_RPC" });
    await expect(
      Reflect.apply(rpc.createAuditorKeySigned, rpc, [Object.create(signedAuditorKey())]),
    ).rejects.toMatchObject({ code: "RING_RPC" });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("accepts a well-formed signed read and a webauthn signature", async () => {
    const { fetch } = capturingFetch({
      context: { slot: 1, blockTime: 1 },
      value: { items: [], skipped: [] },
    });
    const rpc = new RingRpc("http://ring.example", { fetch, allowInsecureHttp: true });
    await rpc.readSigned(signedRead());
    await rpc.readSigned(signedRead({ signature: WEBAUTHN }));
  });
});

describe("ring rpc response validation", () => {
  const rpcWith = (result: unknown) => {
    const fetch = (async () =>
      new Response(
        JSON.stringify({ jsonrpc: "2.0", id: 1, result }),
        JSON_HEADERS,
      )) as typeof globalThis.fetch;
    return new RingRpc("http://ring.example", { fetch, allowInsecureHttp: true });
  };

  it("rejects a malformed service address", async () => {
    await expect(
      rpcWith({
        ringProgramId: addressOf(7),
        state: "uninitialized",
        servicePubkey: "not-base58!",
      }).ringStatus(addressOf(7)),
    ).rejects.toMatchObject({ code: "RING_RPC", details: { path: "result.servicePubkey" } });
  });

  it("rejects a malformed deposit signature and depositor", async () => {
    const base = { slot: 1, asset: SYSTEM, amount: 1 };
    await expect(
      rpcWith({
        deposits: [{ ...base, depositor: addressOf(1), signature: "1".repeat(87) }],
      }).ringDeposits({ ringProgramId: addressOf(7) }),
    ).rejects.toMatchObject({ code: "RING_RPC", details: { path: "deposits.signature" } });
    await expect(
      rpcWith({
        deposits: [{ ...base, depositor: "tooShort", signature: signatureOf(1) }],
      }).ringDeposits({ ringProgramId: addressOf(7) }),
    ).rejects.toMatchObject({ code: "RING_RPC", details: { path: "deposits.depositor" } });
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

  it("appends the owner signers as readonly signers after the payer", async () => {
    const owner = addressOf(33);
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
      ownerSigners: [owner],
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

    const signers = (instruction.accounts ?? []).filter(
      (meta) =>
        meta.role === AccountRole.WRITABLE_SIGNER || meta.role === AccountRole.READONLY_SIGNER,
    );
    // The payer signs twice, the ring's own account list and the wrapped pool list.
    expect(signers.map((meta) => meta.address)).toEqual([PAYER, PAYER, owner]);
    expect(signers[2]?.role).toBe(AccountRole.READONLY_SIGNER);
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
      since: {
        slot: 3n,
        signature:
          "2AXDGYSE4f2sz7tvMMzyHvUfcoJmxudvdhBcmiUSo6ijwfYmfZYsKRxboQMPh3R4kUhXRVdtSXFXMheka4Rc4P2" as Signature,
      },
      limit: 5n,
    });
    expect(new TextDecoder().decode(message)).toBe(
      "zolana/ring-rpc-read/v1\nring: US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx\ntimestamp: 1700000000\nnonce: BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=\nlimit: 5\nsince: 3:2AXDGYSE4f2sz7tvMMzyHvUfcoJmxudvdhBcmiUSo6ijwfYmfZYsKRxboQMPh3R4kUhXRVdtSXFXMheka4Rc4P2",
    );
  });

  it("matches the Rust `auditor_key_request_attestation_is_stable` vector", () => {
    const message = auditorKeyRequestAttestation({
      genesisHash: filled(9, 32) as Bytes32,
      ringProgramId: addressOf(5),
      timestamp: 1_700_000_000n,
      nonce: filled(7, 32) as Bytes32,
    });
    expect(new TextDecoder().decode(message)).toBe(
      "zolana/ring-rpc-auditor-key-request/v1\ngenesis: cGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN\nring: LbUiWL3xVV8hTFYBVdbTNrpDo41NKS6o3LHHuDzjfcY\ntimestamp: 1700000000\nnonce: BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=",
    );
  });

  it("omits limit and since as 0 and empty", () => {
    const message = ringReadAttestation({
      ringProgramId: addressOf(7),
      timestamp: 1n,
      nonce: filled(4, 32) as Bytes32,
    });
    expect(new TextDecoder().decode(message)).toBe(
      "zolana/ring-rpc-read/v1\nring: US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx\ntimestamp: 1\nnonce: BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=\nlimit: 0\nsince: ",
    );
  });

  it("bounds the since shape and the limit like Rust `ReadRequest`", () => {
    const malformedSince: unknown = {
      slot: 3,
      signature:
        "2AXDGYSE4f2sz7tvMMzyHvUfcoJmxudvdhBcmiUSo6ijwfYmfZYsKRxboQMPh3R4kUhXRVdtSXFXMheka4Rc4P2",
    };
    const request = RingReadRequest.read(addressOf(7));
    expect(() =>
      request.withSince(malformedSince as Parameters<typeof request.withSince>[0]),
    ).toThrow("RING_READ_SINCE");
    expect(() => request.withLimit(0n)).toThrow("RING_READ_LIMIT");
    expect(() => request.withLimit(101n)).toThrow("RING_READ_LIMIT");
    expect(
      request
        .withSince({
          slot: 3n,
          signature:
            "2AXDGYSE4f2sz7tvMMzyHvUfcoJmxudvdhBcmiUSo6ijwfYmfZYsKRxboQMPh3R4kUhXRVdtSXFXMheka4Rc4P2" as Signature,
        })
        .withLimit(100n),
    ).toBe(request);
  });
});

describe("ring read request", () => {
  it("sends the tagged reader key and the signature over the attestation", async () => {
    const delegate = await generateKeyPairSigner();
    const signerAddress = delegate.address;
    const seen: Uint8Array[] = [];
    const returnedSignatures: Uint8Array[] = [];
    const signer = {
      address: signerAddress,
      signMessages: async (messages) => {
        seen.push(...messages.map((message) => message.content));
        const signatures = await delegate.signMessages(messages);
        returnedSignatures.push(
          ...signatures.map((signature) => new Uint8Array(signature[signerAddress]!)),
        );
        return signatures;
      },
    } satisfies MessagePartialSigner;
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
                  txSignature: signatureOf(1),
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
              skipped: [{ slot: 7, txSignature: signatureOf(2), reason: "invalidAuditData" }],
              next: { slot: 4, signature: signatureOf(2) },
            },
          },
        }),
        JSON_HEADERS,
      );
    }) as typeof globalThis.fetch;
    const page = await new RingRpc("http://ring.example", {
      fetch,
      allowInsecureHttp: true,
    }).getDecryptedTransactions({
      ringProgramId: addressOf(7),
      signer: reader,
      since: {
        slot: 3n,
        signature:
          "2AXDGYSE4f2sz7tvMMzyHvUfcoJmxudvdhBcmiUSo6ijwfYmfZYsKRxboQMPh3R4kUhXRVdtSXFXMheka4Rc4P2" as Signature,
      },
      limit: 5n,
      timestamp: 1_700_000_000n,
    });
    expect(page.slot).toBe(9n);
    expect(page.blockTime).toBe(1_700_000_000n);
    expect(page.next).toEqual({ slot: 4n, signature: signatureOf(2) });
    expect(page.skipped).toEqual([
      { slot: 7n, signature: signatureOf(2), reason: "invalidAuditData" },
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
    expect(Object.keys(params).sort()).toEqual(["auth", "limit", "ringProgramId", "since"]);
    const auth = params["auth"] as Record<string, unknown>;
    expect(Object.keys(auth).sort()).toEqual(["nonce", "reader", "signature", "timestamp"]);
    expect(auth["reader"]).toBe(Buffer.from(readerKeyBytes(signerAddress)).toString("base64"));
    expect(auth["signature"]).toBe(Buffer.from(returnedSignatures[0]!).toString("base64"));
    expect(auth["timestamp"]).toBe(1_700_000_000);
    const nonce = Buffer.from(auth["nonce"] as string, "base64");
    expect(nonce).toHaveLength(32);
    expect(params["ringProgramId"]).toBe(addressOf(7));
    expect(params["since"]).toEqual({
      slot: 3,
      signature:
        "2AXDGYSE4f2sz7tvMMzyHvUfcoJmxudvdhBcmiUSo6ijwfYmfZYsKRxboQMPh3R4kUhXRVdtSXFXMheka4Rc4P2",
    });
    expect(params["limit"]).toBe(5);
    expect(new TextDecoder().decode(seen[0])).toBe(
      new TextDecoder().decode(
        ringReadAttestation({
          ringProgramId: addressOf(7),
          timestamp: 1_700_000_000n,
          nonce: Uint8Array.from(nonce) as Bytes32,
          since: {
            slot: 3n,
            signature:
              "2AXDGYSE4f2sz7tvMMzyHvUfcoJmxudvdhBcmiUSo6ijwfYmfZYsKRxboQMPh3R4kUhXRVdtSXFXMheka4Rc4P2" as Signature,
          },
          limit: 5n,
        }),
      ),
    );
  });

  it("reads the owner tag and the signers of every output", async () => {
    const reader = messageSignerReader(await generateKeyPairSigner());
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
                  txSignature: signatureOf(1),
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
        JSON_HEADERS,
      )) as typeof globalThis.fetch;

    const page = await new RingRpc("http://ring.example", {
      fetch,
      allowInsecureHttp: true,
    }).getDecryptedTransactions({
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
                  txSignature: signatureOf(1),
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
        JSON_HEADERS,
      )) as typeof globalThis.fetch;

  const anyReader = async () => messageSignerReader(await generateKeyPairSigner());

  it("reads the withdrawal asset of an SPL leg and a SOL leg", async () => {
    const solMint = address("So11111111111111111111111111111111111111112");
    const fetch = withdrawalPage([
      { recipient: addressOf(31), asset: addressOf(13), amount: 5 },
      { recipient: addressOf(32), asset: solMint, amount: 6 },
    ]);

    const page = await new RingRpc("http://ring.example", {
      fetch,
      allowInsecureHttp: true,
    }).getDecryptedTransactions({
      ringProgramId: addressOf(7),
      signer: await anyReader(),
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
        JSON_HEADERS,
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
    const page = await new RingRpc("http://ring.example", {
      fetch,
      allowInsecureHttp: true,
    }).getDecryptedTransactions({
      ringProgramId: addressOf(7),
      signer,
    });
    expect(page.next).toBeUndefined();
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

  const serviceSecret = filled(9, 32);
  const servicePublicKey = getAddressDecoder().decode(ed25519.getPublicKey(serviceSecret));
  const auditor = P256PublicKey.fromBytes(hex(P256_HEX) as Bytes33);
  const genesisHash = filled(4, 32) as Bytes32;
  const auditorKeyResult = (signature: Uint8Array) => ({
    ringProgramId: RING,
    auditorPubkey: Buffer.from(auditor.toBytes()).toString("base64"),
    auditorViewTag: getAddressDecoder().decode(auditor.x()),
    servicePubkey: servicePublicKey,
    signature: getBase58Decoder().decode(signature),
  });

  it("refuses a plain HTTP endpoint unless the caller opts in", () => {
    expect(() => new RingRpc("http://ring.example")).toThrowError(
      expect.objectContaining({ code: "RING_RPC_CONFIG" }),
    );
    expect(() => new RingRpc("https://user:pw@ring.example")).toThrowError(
      expect.objectContaining({ code: "RING_RPC_CONFIG" }),
    );
  });

  it("keeps server error text out of the thrown details", async () => {
    const fetch = (async () =>
      new Response(
        JSON.stringify({ jsonrpc: "2.0", id: 1, error: { code: -32000, message: "secret text" } }),
        JSON_HEADERS,
      )) as typeof globalThis.fetch;
    const error = await new RingRpc("http://ring.example", { fetch, allowInsecureHttp: true })
      .ringStatus(addressOf(7))
      .then(
        () => undefined,
        (cause: unknown) => cause,
      );
    expect(error).toMatchObject({ code: "RING_RPC" });
    expect(JSON.stringify(error)).not.toContain("secret");
  });

  it("threads the request context timeout into the transport", async () => {
    const fetch = ((_input: unknown, init?: RequestInit) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => {
          reject(new Error("aborted"));
        });
      })) as typeof globalThis.fetch;
    await expect(
      new RingRpc("http://ring.example", { fetch, allowInsecureHttp: true }).ringStatus(
        addressOf(7),
        { timeoutMs: 5 },
      ),
    ).rejects.toMatchObject({ code: "RING_RPC_TRANSPORT" });
  });

  it("verifies the auditor key attestation before trusting the key", async () => {
    const attestation = auditorKeyAttestation(RING, auditor);
    expect(attestation.subarray(0, 26)).toEqual(
      new TextEncoder().encode("zolana/ring-auditor-key/v1"),
    );
    expect(attestation).toHaveLength(26 + 32 + 33);
    const authority = await generateKeyPairSigner();
    const key = await new RingRpc("http://ring.example", {
      fetch: capturingFetch(auditorKeyResult(ed25519.sign(attestation, serviceSecret))).fetch,
      allowInsecureHttp: true,
    }).createAuditorKey({ ringProgramId: RING, genesisHash, authority });
    expect(key.auditorPublicKey.equals(auditor)).toBe(true);
    expect(key.auditorViewTag).toEqual(auditor.x());
    expect(key.servicePublicKey).toBe(servicePublicKey);

    await expect(
      new RingRpc("http://ring.example", {
        fetch: capturingFetch(auditorKeyResult(filled(1, 64))).fetch,
        allowInsecureHttp: true,
      }).createAuditorKey({ ringProgramId: RING, genesisHash, authority }),
    ).rejects.toMatchObject({ code: "RING_RPC" });
  });

  it("signs the auditor key request with the authority and sends it under camelCase keys", async () => {
    const authority = await generateKeyPairSigner();
    const { fetch, bodies } = capturingFetch(
      auditorKeyResult(ed25519.sign(auditorKeyAttestation(RING, auditor), serviceSecret)),
    );
    await new RingRpc("http://ring.example", { fetch, allowInsecureHttp: true }).createAuditorKey({
      ringProgramId: RING,
      genesisHash,
      authority,
      timestamp: 1_700_000_000n,
    });

    const params = bodies[0]?.["params"] as Record<string, unknown>;
    expect(Object.keys(params).sort()).toEqual(["auth", "ringProgramId"]);
    expect(params["ringProgramId"]).toBe(RING);
    const auth = params["auth"] as Record<string, unknown>;
    expect(Object.keys(auth).sort()).toEqual([
      "authority",
      "genesisHash",
      "nonce",
      "signature",
      "timestamp",
    ]);
    expect(auth["authority"]).toBe(authority.address);
    expect(auth["genesisHash"]).toBe("GgBaCs3NCBuZN12kCJgAW63ydqohFkHEdfdEXBPzLHq");
    expect(auth["timestamp"]).toBe(1_700_000_000);
    const nonce = Uint8Array.from(Buffer.from(String(auth["nonce"]), "base64"));
    expect(nonce).toHaveLength(32);
    expect(
      ed25519.verify(
        Uint8Array.from(Buffer.from(String(auth["signature"]), "base64")),
        auditorKeyRequestAttestation({
          genesisHash,
          ringProgramId: RING,
          timestamp: 1_700_000_000n,
          nonce: nonce as Bytes32,
        }),
        addressBytes(authority.address),
      ),
    ).toBe(true);
  });
});
