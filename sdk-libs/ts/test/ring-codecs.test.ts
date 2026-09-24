import { ringDepositInstruction } from "../src/ring/deposit-instruction.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { readFileSync } from "node:fs";
import {
  AccountRole,
  address,
  getAddressDecoder,
  getAddressEncoder,
  getBase58Decoder,
  getProgramDerivedAddress,
  generateKeyPairSigner,
  type Address,
  type MessagePartialSigner,
} from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import { ringTransactAccounts } from "../src/interface/instructions/index.js";
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
} from "../src/interface/types.js";
import {
  RING_CREATE_CONFIG_COMPUTE_UNIT_LIMIT,
  RING_SET_PAUSED_COMPUTE_UNIT_LIMIT,
  createRingConfigInstruction,
  initSppRingConfigInstruction,
  ringDelegateTransactInstruction,
  ringTransactInstruction,
  type RingTransactPolicy,
} from "../src/ring/instructions.js";
import { decodeRingPolicyConfig, decodeRingProgramConfig } from "../src/ring/codecs.js";
import {
  clearRingCoSignerInstruction,
  clearRingSpendWindowInstruction,
  fetchRingCoSigner,
  fetchRingDelegate,
  fetchRingSpendWindow,
  setRingAuthorityInstruction,
  setRingCoSignerInstruction,
  setRingDelegateInstruction,
  setRingPausedInstruction,
  setRingSpendWindowInstruction,
} from "../src/ring/config.js";
import { ownedAccount } from "./helpers/ring-accounts.js";
import {
  ringCoSignerAddress,
  ringCoSignerPda,
  ringConfigAddress,
  ringDelegateAddress,
  ringDelegatePda,
  ringDepositAuditAddress,
  ringKeyRegistryRootAddress,
  nullifierPdaAddress,
  ringSpendWindowAddress,
  ringSpendWindowPda,
} from "../src/interface/pda/index.js";
import { SOL_MINT } from "../src/transaction/asset.js";
import {
  RING_COSIGN_TRANSFERS,
  RING_COSIGN_WITHDRAWALS,
  decodeRingCoSigner,
  decodeRingDelegate,
  decodeRingSpendWindow,
} from "../src/ring/codecs.js";
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
import { RING_VELOCITY_SLOTS } from "../src/client/prover/types.js";
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

/** Rust `PolicyConfig` bytes, every part past the header defaults to zero. */
function policyConfigBytes(
  parts: Readonly<{
    sources?: Uint8Array;
    ruleCount?: number;
    rules?: readonly Uint8Array[];
    inlineCount?: number;
    inlineAssets?: readonly Uint8Array[];
    inlineLimits?: readonly bigint[];
    generation?: readonly number[];
    generationSlot?: readonly number[];
  }> = {},
): Uint8Array {
  const table = (rows: readonly Uint8Array[], slots: number) =>
    Array.from({ length: slots }, (_, index) => [...(rows[index] ?? new Uint8Array(32))]).flat();
  const limits = Array.from({ length: 8 }, (_, index) => {
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, parts.inlineLimits?.[index] ?? 0n, false);
    return [...bytes];
  }).flat();
  return Uint8Array.from([
    3,
    ...filled(42, 32),
    ...filled(43, 32),
    7,
    0,
    253,
    252,
    ...filled(46, 32),
    ...(parts.sources ?? new Uint8Array(33 * 8)),
    parts.ruleCount ?? parts.rules?.length ?? 0,
    ...table(parts.rules ?? [], 16),
    parts.inlineCount ?? parts.inlineAssets?.length ?? 0,
    ...table(parts.inlineAssets ?? [], 8),
    ...limits,
    ...new Uint8Array(8),
    0,
    ...new Uint8Array(32 * 8),
    ...new Uint8Array(8 * 8),
    ...new Uint8Array(8 * 8),
    ...(parts.generation ?? new Uint8Array(4)),
    ...(parts.generationSlot ?? new Uint8Array(8)),
  ]);
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
const ADDRESS_TREE = addressOf(60);
const RING_AUTH = address("AtyqWdns8uYfWdpLhWJRN9DxRdpwB6Zaa33k66TAkwFx");
const RING_CONFIG = address("CXJhGzAcN4NYaapjRqiTzmnRBTmtUL52Zg4ooG2PtMfP");
const SPP = address("sppU489D7A4U1exNo1oeMGZtLEofq3a6o2fR7UeoWB6");
const SYSTEM = address("11111111111111111111111111111111");
const JSON_HEADERS = { headers: { "content-type": "application/json" } };
const SOL_INTERFACE = address("2iAazE9tAWcUJhNhfscRzX17Gb32Km9jJYZLGy1AnkVP");

function ringPolicyConfig() {
  return getProgramDerivedAddress({
    programAddress: RING,
    seeds: [new TextEncoder().encode("policy")],
  }).then(([address]) => address);
}

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
      [await ringConfigAddress(RING), AccountRole.READONLY],
      [await ringCoSignerAddress(RING), AccountRole.READONLY],
      [await ringCoSignerAddress(RING), AccountRole.READONLY],
      [await ringDepositAuditAddress(RING), AccountRole.READONLY],
      [await ringSpendWindowAddress(RING, SOL_MINT), AccountRole.WRITABLE],
      [TREE, AccountRole.WRITABLE],
      [PAYER, AccountRole.WRITABLE_SIGNER],
      [RING_AUTH, AccountRole.READONLY],
      [SPP, AccountRole.READONLY],
      [SYSTEM, AccountRole.READONLY],
      [SOL_INTERFACE, AccountRole.WRITABLE],
    ]);
    expect(instruction.data?.[0]).toBe(InstructionTag.ringDeposit);
    expect(Buffer.from(instruction.data ?? []).toString("hex")).toBe(
      "12010001001f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f2020202020202020202020202020202020202020202020202020202020202020c0cf6a0000000000002121212121212121212121212121212121212121212121212121212121212121030303030303030303030303030303030303030303030303030303030303030303222222222222222222222222222222220300232425",
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
  it("appends the SPL withdrawal group Rust `append_interface_transfer_accounts` appends", async () => {
    const mint = addressOf(41);
    const splTokenInterface = addressOf(42);
    const recipientTokenAccount = addressOf(43);
    const tokenProgram = addressOf(44);
    const pool = await ringTransactAccounts({
      payer: PAYER,
      inputTrees: [TREE],
      outputTree: OUTPUT_TREE,
      ringAuth: RING_AUTH,
      inputs: [],
      treeContexts: [{ utxoTreeRootIndex: 0, nullifierTreeRootIndex: 0 }],
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

  it("appends non-payer owner signers as readonly signers", async () => {
    const owner = addressOf(45);
    const pool = await ringTransactAccounts({
      payer: PAYER,
      inputTrees: [TREE],
      outputTree: OUTPUT_TREE,
      ringAuth: RING_AUTH,
      inputs: [],
      treeContexts: [{ utxoTreeRootIndex: 0, nullifierTreeRootIndex: 0 }],
      ownerSigners: [owner],
    });
    expect(pool.map((meta) => [meta.address, meta.role])).toContainEqual([
      owner,
      AccountRole.READONLY_SIGNER,
    ]);
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
      hasPolicy: true,
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
    expect(Buffer.from(instruction.data ?? []).toString("hex")).toBe(`01${P256_HEX}01`);
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
          hasPolicy: true,
        }),
      ).rejects.toMatchObject({ code: "RING_RESERVED_AUDITOR_KEY" });
    }
  });

  it("builds init SPP ring config like Rust `InitSppRingConfig`", async () => {
    const instruction = await initSppRingConfigInstruction({
      ringProgramId: RING,
      payer: PAYER,
      authority: AUTHORITY,
      hasPolicy: false,
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

  it("registers a policy ring with its policy config as the eighth read-only account", async () => {
    const instruction = await initSppRingConfigInstruction({
      ringProgramId: RING,
      payer: PAYER,
      authority: AUTHORITY,
      hasPolicy: true,
    });
    expect(instruction.accounts).toHaveLength(8);
    expect(instruction.accounts?.slice(0, 7)).toEqual(
      (
        await initSppRingConfigInstruction({
          ringProgramId: RING,
          payer: PAYER,
          authority: AUTHORITY,
          hasPolicy: false,
        })
      ).accounts,
    );
    expect(instruction.accounts?.[7]).toEqual({
      address: await ringPolicyConfig(),
      role: AccountRole.READONLY,
    });
    expect(instruction.data).toEqual(Uint8Array.of(2));
  });

  it("decodes the config account and rejects another layout", () => {
    const data = Uint8Array.from([1, ...filled(12, 32), ...hex(P256_HEX), 254, 1, 0]);
    const config = decodeRingProgramConfig(data);
    expect(config.authority).toBe(AUTHORITY);
    expect(config.auditorPublicKey.equals(AUDITOR)).toBe(true);
    expect(config.bump).toBe(254);
    expect(config.hasPolicy).toBe(true);
    expect(config.keyEscrow).toBe(false);
    // Rust `RingProgramConfig::key_escrow`, any nonzero byte reads as on.
    for (const flag of [1, 2, 0xff]) {
      expect(
        decodeRingProgramConfig(Uint8Array.from([...data.subarray(0, 68), flag])).keyEscrow,
      ).toBe(true);
    }
    expect(() => decodeRingProgramConfig(data.subarray(0, 68))).toThrow("RING_CONFIG_INVALID");
    expect(() => decodeRingProgramConfig(data.subarray(1))).toThrow("RING_CONFIG_INVALID");
    expect(() => decodeRingProgramConfig(Uint8Array.from([2, ...data.subarray(1)]))).toThrow(
      "RING_CONFIG_INVALID",
    );
  });

  it("decodes the policy config account and rejects another layout", () => {
    const data = policyConfigBytes();
    expect(data).toHaveLength(1604);
    const config = decodeRingPolicyConfig(data);
    expect(config.policyHash).toEqual(filled(42, 32));
    expect(config.addressTree).toBe(addressOf(43));
    expect(config.addressTreeId).toBe(7);
    expect(config.namespaceBump).toBe(253);
    expect(config.bump).toBe(252);
    expect(config.sources).toHaveLength(8);
    expect(config.sources.every((slot) => slot.listId === 0)).toBe(true);
    expect(config.ruleCount).toBe(0);
    expect(config.rules).toEqual([]);
    expect(config.inlineCount).toBe(0);
    expect(config.inlineAssets).toEqual([]);
    expect(config.inlineLimits).toEqual([]);
    expect(config.namespaceOwnerHash).toEqual(filled(46, 32));
    expect(config.windowSlots).toBe(0n);
    expect(config.velocity).toEqual([]);
    expect(config.generation).toBe(0);
    expect(config.generationSlot).toBe(0n);
    expect(() => decodeRingPolicyConfig(data.subarray(1))).toThrow("RING_POLICY_CONFIG_INVALID");
    expect(() => decodeRingPolicyConfig(Uint8Array.from([1, ...data.subarray(1)]))).toThrow(
      "RING_POLICY_CONFIG_INVALID",
    );
    // The 331-byte layout without the rule table and the generation.
    expect(() => decodeRingPolicyConfig(data.subarray(0, 331))).toThrow(
      "RING_POLICY_CONFIG_INVALID",
    );
  });

  it("decodes a live policy source slot", () => {
    const config = decodeRingPolicyConfig(
      policyConfigBytes({
        sources: Uint8Array.from([1, ...filled(44, 32), ...new Uint8Array(33 * 7)]),
      }),
    );
    expect(config.sources[0]).toEqual({ listId: 1, namespace: addressOf(44) });
    expect(config.sources[1]).toEqual({ listId: 0, namespace: addressOf(0) });
  });

  it("decodes a one-row rule table with an inline member and the generation", () => {
    const rule = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
    const member = filled(45, 32);
    const data = policyConfigBytes({
      rules: [rule],
      inlineAssets: [member],
      inlineLimits: [123n],
      generation: [4, 3, 2, 1],
      generationSlot: [8, 7, 6, 5, 4, 3, 2, 1],
    });
    expect(data[365]).toBe(1);
    expect(data.subarray(366, 398)).toEqual(rule);
    expect(data[878]).toBe(1);
    expect(data.subarray(879, 911)).toEqual(member);
    expect(data.subarray(1135, 1143)).toEqual(Uint8Array.from([0, 0, 0, 0, 0, 0, 0, 123]));
    expect(data.subarray(1592, 1596)).toEqual(Uint8Array.from([4, 3, 2, 1]));
    expect(data.subarray(1596)).toEqual(Uint8Array.from([8, 7, 6, 5, 4, 3, 2, 1]));
    const config = decodeRingPolicyConfig(data);
    expect(config.ruleCount).toBe(1);
    expect(config.rules).toEqual([rule]);
    expect(config.inlineCount).toBe(1);
    expect(config.inlineAssets).toEqual([member]);
    expect(config.inlineLimits).toEqual([123n]);
    expect(config.generation).toBe(0x01020304);
    expect(config.generationSlot).toBe(0x0102030405060708n);
  });

  it("decodes the Rust policy account vector", () => {
    const encoded = readFileSync(
      new URL("../../../custom-rings/sdk/tests/fixtures/policy-config.hex", import.meta.url),
      "utf8",
    );
    const config = decodeRingPolicyConfig(hex(encoded.replace(/\s/g, "")));
    expect(config.inlineLimits).toEqual([123n]);
    expect(config.generation).toBe(0x01020304);
    expect(config.generationSlot).toBe(0x0102030405060708n);
    expect(config.sources[0]).toEqual({ listId: 1, namespace: addressOf(0x11) });
    expect(config.namespaceOwnerHash).toEqual(
      hex("2cb09cab7a637278cc7157bb6780f81e5abdcc5e001eddad5279891f03f05196"),
    );
    expect(config.windowSlots).toBe(0n);
  });

  it("decodes every byte of an unsigned per-asset limit", () => {
    const limits = [0n, 123n, 0x0102030405060708n, (1n << 64n) - 1n];
    const config = decodeRingPolicyConfig(
      policyConfigBytes({
        inlineAssets: limits.map(() => filled(1, 32)),
        inlineLimits: limits,
      }),
    );
    expect(config.inlineLimits).toEqual(limits);
  });

  it("bounds the rule table by its width and refuses bytes past the counts", () => {
    const row = filled(1, 32);
    const full = decodeRingPolicyConfig(
      policyConfigBytes({
        rules: Array.from({ length: 16 }, () => row),
        inlineAssets: Array.from({ length: 8 }, () => row),
      }),
    );
    expect(full.ruleCount).toBe(16);
    expect(full.inlineCount).toBe(8);
    const refused: readonly [string, Parameters<typeof policyConfigBytes>[0]][] = [
      ["ruleCount above 16", { ruleCount: 17 }],
      ["inlineCount above 8", { inlineCount: 9 }],
      ["a rule row past ruleCount", { ruleCount: 1, rules: [row, row] }],
      ["an inline member past inlineCount", { inlineCount: 0, inlineAssets: [row] }],
      ["an inline limit past inlineCount", { inlineCount: 0, inlineLimits: [1n] }],
    ];
    for (const [name, parts] of refused) {
      expect(() => decodeRingPolicyConfig(policyConfigBytes(parts)), name).toThrow(
        "RING_POLICY_CONFIG_INVALID",
      );
    }
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

  it("builds the co-signer set and clear like Rust", async () => {
    const signer = addressOf(37);
    const set = await setRingCoSignerInstruction({
      ringProgramId: RING,
      payer: PAYER,
      authority: AUTHORITY,
      signer,
      scope: RING_COSIGN_WITHDRAWALS,
      thresholds: [{ mint: SOL_MINT, above: 10n }],
    });
    expect(set.accounts?.map((meta) => [meta.address, meta.role])).toEqual([
      [PAYER, AccountRole.WRITABLE_SIGNER],
      [AUTHORITY, AccountRole.READONLY_SIGNER],
      [RING_CONFIG, AccountRole.READONLY],
      [await ringCoSignerAddress(RING), AccountRole.WRITABLE],
      [SYSTEM, AccountRole.READONLY],
    ]);
    expect(Buffer.from(set.data ?? []).toString("hex")).toBe(
      "1b" +
        Buffer.from(addressBytes(signer, "signer")).toString("hex") +
        "0401" +
        "00".repeat(32) +
        "0a00000000000000",
    );
    const clear = await clearRingCoSignerInstruction({
      ringProgramId: RING,
      authority: AUTHORITY,
      rentRecipient: PAYER,
    });
    expect(clear.accounts?.map((meta) => [meta.address, meta.role])).toEqual([
      [AUTHORITY, AccountRole.READONLY_SIGNER],
      [RING_CONFIG, AccountRole.READONLY],
      [await ringCoSignerAddress(RING), AccountRole.WRITABLE],
      [PAYER, AccountRole.WRITABLE],
    ]);
    expect([...(clear.data ?? [])]).toEqual([21]);
    await expect(
      setRingCoSignerInstruction({
        ringProgramId: RING,
        payer: PAYER,
        authority: AUTHORITY,
        signer,
        scope: 0,
      }),
    ).rejects.toThrow("RING_CO_SIGNER_INVALID");
    await expect(
      setRingCoSignerInstruction({
        ringProgramId: RING,
        payer: PAYER,
        authority: AUTHORITY,
        signer,
        scope: RING_COSIGN_TRANSFERS,
        thresholds: [
          { mint: SOL_MINT, above: 1n },
          { mint: SOL_MINT, above: 2n },
        ],
      }),
    ).rejects.toThrow("RING_CO_SIGNER_INVALID");
  });

  it("builds the spend window set and clear like Rust", async () => {
    const mint = addressOf(60);
    const set = await setRingSpendWindowInstruction({
      ringProgramId: RING,
      payer: PAYER,
      authority: AUTHORITY,
      mint,
      windowSlots: 100n,
      withdrawalCap: 9n,
    });
    expect(set.accounts?.map((meta) => [meta.address, meta.role])).toEqual([
      [PAYER, AccountRole.WRITABLE_SIGNER],
      [AUTHORITY, AccountRole.READONLY_SIGNER],
      [RING_CONFIG, AccountRole.READONLY],
      [await ringSpendWindowAddress(RING, mint), AccountRole.WRITABLE],
      [SYSTEM, AccountRole.READONLY],
    ]);
    expect(Buffer.from(set.data ?? []).toString("hex")).toBe(
      "16" +
        Buffer.from(addressBytes(mint, "mint")).toString("hex") +
        "6400000000000000" +
        "0000000000000000" +
        "0900000000000000",
    );
    const clear = await clearRingSpendWindowInstruction({
      ringProgramId: RING,
      authority: AUTHORITY,
      mint,
      rentRecipient: PAYER,
    });
    expect(clear.accounts?.map((meta) => [meta.address, meta.role])).toEqual([
      [AUTHORITY, AccountRole.READONLY_SIGNER],
      [RING_CONFIG, AccountRole.READONLY],
      [await ringSpendWindowAddress(RING, mint), AccountRole.WRITABLE],
      [PAYER, AccountRole.WRITABLE],
    ]);
    expect(Buffer.from(clear.data ?? []).toString("hex")).toBe(
      "17" + Buffer.from(addressBytes(mint, "mint")).toString("hex"),
    );
    await expect(
      setRingSpendWindowInstruction({
        ringProgramId: RING,
        payer: PAYER,
        authority: AUTHORITY,
        mint,
        windowSlots: 0n,
      }),
    ).rejects.toThrow("RING_SPEND_WINDOW_INVALID");
  });

  it("builds the delegate set like Rust and decodes the account", async () => {
    const delegate = addressOf(47);
    const [programData] = await getProgramDerivedAddress({
      programAddress: address("BPFLoaderUpgradeab1e11111111111111111111111"),
      seeds: [getAddressEncoder().encode(RING)],
    });
    const set = await setRingDelegateInstruction({
      ringProgramId: RING,
      payer: PAYER,
      authority: AUTHORITY,
      delegate,
    });
    expect(set.accounts?.map((meta) => [meta.address, meta.role])).toEqual([
      [PAYER, AccountRole.WRITABLE_SIGNER],
      [AUTHORITY, AccountRole.READONLY_SIGNER],
      [RING_CONFIG, AccountRole.WRITABLE],
      [await ringDelegateAddress(RING), AccountRole.WRITABLE],
      [await ringKeyRegistryRootAddress(RING), AccountRole.READONLY],
      [SYSTEM, AccountRole.READONLY],
      [RING, AccountRole.READONLY],
      [programData, AccountRole.READONLY],
    ]);
    expect(Buffer.from(set.data ?? []).toString("hex")).toBe(
      "18" + Buffer.from(addressBytes(delegate, "delegate")).toString("hex"),
    );
    const data = Uint8Array.from([6, ...addressBytes(delegate, "delegate"), 254]);
    expect(decodeRingDelegate(data)).toEqual({ delegate, bump: 254 });
    expect(() => decodeRingDelegate(data.subarray(1))).toThrow("RING_DELEGATE_INVALID");
    const zeroKey = Uint8Array.from(data);
    zeroKey.fill(0, 1, 33);
    expect(() => decodeRingDelegate(zeroKey)).toThrow("RING_DELEGATE_INVALID");
  });

  it("decodes the spend window account and rejects another layout", () => {
    const mint = addressOf(60);
    const data = Uint8Array.from([
      5,
      ...addressBytes(mint, "mint"),
      100,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      7,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      9,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      176,
      4,
      0,
      0,
      0,
      0,
      0,
      0,
      1,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      2,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      251,
    ]);
    expect(decodeRingSpendWindow(data)).toEqual({
      mint,
      windowSlots: 100n,
      depositCap: 7n,
      withdrawalCap: 9n,
      windowStartSlot: 1200n,
      deposited: 1n,
      withdrawn: 2n,
      bump: 251,
    });
    expect(() => decodeRingSpendWindow(data.subarray(1))).toThrow("RING_SPEND_WINDOW_INVALID");
    const zeroWindow = Uint8Array.from(data);
    zeroWindow[33] = 0;
    expect(() => decodeRingSpendWindow(zeroWindow)).toThrow("RING_SPEND_WINDOW_INVALID");
  });

  it("decodes the co-signer account and rejects another layout", () => {
    const signer = addressOf(37);
    const row = [...addressBytes(SOL_MINT, "mint"), 10, 0, 0, 0, 0, 0, 0, 0];
    const data = Uint8Array.from([
      4,
      ...addressBytes(signer, "signer"),
      RING_COSIGN_WITHDRAWALS,
      1,
      ...row,
      ...new Uint8Array(7 * 40),
      253,
    ]);
    const cosigner = decodeRingCoSigner(data);
    expect(cosigner.signer).toBe(signer);
    expect(cosigner.scope).toBe(RING_COSIGN_WITHDRAWALS);
    expect(cosigner.bump).toBe(253);
    expect(cosigner.thresholds).toEqual([{ mint: SOL_MINT, above: 10n }]);
    expect(() => decodeRingCoSigner(data.subarray(1))).toThrow("RING_CO_SIGNER_INVALID");
    const zeroScope = Uint8Array.from(data);
    zeroScope[33] = 0;
    expect(() => decodeRingCoSigner(zeroScope)).toThrow("RING_CO_SIGNER_INVALID");
  });

  it("rejects co-signer bytes the program cannot store", () => {
    const data = Uint8Array.from([
      4,
      ...addressBytes(AUTHORITY),
      RING_COSIGN_WITHDRAWALS,
      2,
      ...addressBytes(SOL_MINT),
      10,
      ...new Uint8Array(7),
      ...addressBytes(addressOf(55)),
      20,
      ...new Uint8Array(7),
      ...new Uint8Array(6 * 40),
      253,
    ]);
    expect(decodeRingCoSigner(data).thresholds).toEqual([
      { mint: SOL_MINT, above: 10n },
      { mint: addressOf(55), above: 20n },
    ]);
    const malformed: readonly [string, (bytes: Uint8Array) => void][] = [
      [
        "zero signer",
        (bytes) => {
          bytes.fill(0, 1, 33);
        },
      ],
      [
        "zero scope",
        (bytes) => {
          bytes[33] = 0;
        },
      ],
      [
        "unsupported scope",
        (bytes) => {
          bytes[33] = 8;
        },
      ],
      [
        "nine rows",
        (bytes) => {
          bytes[34] = 9;
        },
      ],
      [
        "overflow count",
        (bytes) => {
          bytes[34] = 255;
        },
      ],
      [
        "duplicate mint",
        (bytes) => {
          bytes.copyWithin(75, 35, 67);
        },
      ],
      [
        "unused mint",
        (bytes) => {
          bytes[115] = 1;
        },
      ],
      [
        "unused amount",
        (bytes) => {
          bytes[147] = 1;
        },
      ],
      [
        "last unused amount",
        (bytes) => {
          bytes[354] = 1;
        },
      ],
    ];
    for (const [name, mutate] of malformed) {
      const invalid = new Uint8Array(data);
      mutate(invalid);
      const before = new Uint8Array(invalid);
      expect(() => decodeRingCoSigner(invalid), name).toThrow(
        expect.objectContaining({ code: "RING_CO_SIGNER_INVALID" }),
      );
      expect(invalid).toEqual(before);
    }
    const full = new Uint8Array(data);
    full[34] = 8;
    for (let slot = 2; slot < 8; slot += 1) {
      full.set(addressBytes(addressOf(55 + slot)), 35 + slot * 40);
    }
    expect(decodeRingCoSigner(full).thresholds).toHaveLength(8);
  });

  it("rejects an invalid co-signer before building the set instruction", async () => {
    for (const change of [
      { signer: SYSTEM },
      { scope: 0x1_0000_0001 },
      { scope: Number.NaN },
      { scope: 1.5 },
    ]) {
      await expect(
        setRingCoSignerInstruction({
          ringProgramId: RING,
          payer: PAYER,
          authority: AUTHORITY,
          signer: AUTHORITY,
          scope: RING_COSIGN_WITHDRAWALS,
          ...change,
        }),
      ).rejects.toMatchObject({ code: "RING_CO_SIGNER_INVALID" });
    }
  });

  it("keeps optional control absence separate from malformed state", async () => {
    const reader = (owner: Address, data: Uint8Array) => ({
      getAccount: vi.fn(async () => ownedAccount(owner, data)),
    });
    const controls = [
      {
        pda: () => ringCoSignerPda(RING),
        read: (client: ReturnType<typeof reader>) => fetchRingCoSigner(client, RING),
        code: "RING_CO_SIGNER_INVALID",
        data: (bump: number) =>
          Uint8Array.of(
            4,
            ...addressBytes(AUTHORITY),
            RING_COSIGN_TRANSFERS,
            0,
            ...new Uint8Array(8 * 40),
            bump,
          ),
      },
      {
        pda: () => ringDelegatePda(RING),
        read: (client: ReturnType<typeof reader>) => fetchRingDelegate(client, RING),
        code: "RING_DELEGATE_INVALID",
        data: (bump: number) => Uint8Array.of(6, ...addressBytes(AUTHORITY), bump),
      },
      {
        pda: () => ringSpendWindowPda(RING, SOL_MINT),
        read: (client: ReturnType<typeof reader>) => fetchRingSpendWindow(client, RING, SOL_MINT),
        code: "RING_SPEND_WINDOW_INVALID",
        data: (bump: number) =>
          Uint8Array.of(5, ...addressBytes(SOL_MINT), 100, ...new Uint8Array(47), bump),
      },
    ];
    for (const control of controls) {
      const [pda, bump] = await control.pda();
      const data = control.data(bump);
      const valid = reader(RING, data);
      await expect(control.read(valid)).resolves.toMatchObject({ bump });
      expect(valid.getAccount).toHaveBeenCalledWith(pda, undefined);
      for (const owner of [RING, SYSTEM]) {
        await expect(control.read(reader(owner, new Uint8Array()))).resolves.toBeUndefined();
      }
      const wrongDiscriminator = new Uint8Array(data);
      wrongDiscriminator[0] = 0;
      const wrongBump = new Uint8Array(data);
      wrongBump[data.length - 1] = bump ^ 1;
      for (const account of [
        reader(addressOf(9), data),
        reader(RING, data.subarray(0, data.length - 1)),
        reader(RING, wrongDiscriminator),
        reader(RING, wrongBump),
      ]) {
        await expect(control.read(account)).rejects.toMatchObject({ code: control.code });
      }
    }
    const missing = { getAccount: async () => undefined };
    await expect(fetchRingCoSigner(missing, RING)).resolves.toBeUndefined();
    await expect(fetchRingDelegate(missing, RING)).resolves.toBeUndefined();
    await expect(fetchRingSpendWindow(missing, RING, SOL_MINT)).resolves.toBeUndefined();
  });

  it("builds the pause switch like Rust `SetPaused` for both states", async () => {
    for (const paused of [true, false]) {
      const instruction = await setRingPausedInstruction({
        ringProgramId: RING,
        authority: AUTHORITY,
        paused,
      });
      expect(instruction.programAddress).toBe(RING);
      expect(instruction.accounts?.map((meta) => [meta.address, meta.role])).toEqual([
        [AUTHORITY, AccountRole.READONLY_SIGNER],
        [RING_CONFIG, AccountRole.READONLY],
        [RING_AUTH, AccountRole.WRITABLE],
        [SPP, AccountRole.READONLY],
      ]);
      expect(instruction.data).toEqual(Uint8Array.of(11, paused ? 1 : 0));
    }
    expect(RING_SET_PAUSED_COMPUTE_UNIT_LIMIT).toBe(50_000);
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

describe("ring rpc gateway", () => {
  const recording = () => {
    const calls: { url: URL; method: unknown }[] = [];
    const fetch = (async (input: URL | string, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      calls.push({ url: new URL(String(input)), method: body["method"] });
      const result =
        body["method"] === "health"
          ? { mode: "derived", servicePubkey: addressOf(22) }
          : { ringProgramId: addressOf(7), state: "uninitialized", servicePubkey: addressOf(22) };
      return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result }), JSON_HEADERS);
    }) as typeof globalThis.fetch;
    return { calls, fetch };
  };

  it("posts each method under its own path with the key and the endpoint query", async () => {
    const { calls, fetch } = recording();
    const rpc = new RingRpc("https://gateway.example/v1/zolana/ring/?tenant=alpha", {
      fetch,
      apiKey: "k+1",
    });

    await rpc.health();
    await rpc.ringStatus(addressOf(7));

    expect(calls.map(({ url }) => url.pathname)).toEqual([
      "/v1/zolana/ring/health",
      "/v1/zolana/ring/ringStatus",
    ]);
    expect(calls.map(({ method }) => method)).toEqual(["health", "ringStatus"]);
    for (const { url } of calls) {
      expect(url.searchParams.getAll("api-key")).toEqual(["k+1"]);
      expect(url.searchParams.get("tenant")).toBe("alpha");
    }
    expect(rpc.url).toBe("https://gateway.example/v1/zolana/ring/?tenant=alpha");
  });

  it("sends a key carried by the URL and keeps it off the reported URL", async () => {
    const { calls, fetch } = recording();
    const rpc = new RingRpc("https://gateway.example/v1/zolana/ring?api-key=k", { fetch });

    await rpc.health();

    expect(calls[0]?.url.searchParams.getAll("api-key")).toEqual(["k"]);
    expect(rpc.url).toBe("https://gateway.example/v1/zolana/ring");
  });

  it("leaves a caller's URL object carrying the key untouched", async () => {
    const { calls, fetch } = recording();
    const endpoint = new URL("https://gateway.example/v1/zolana/ring?api-key=k");
    const rpc = new RingRpc(endpoint, { fetch });

    await rpc.health();

    expect(endpoint.href).toBe("https://gateway.example/v1/zolana/ring?api-key=k");
    expect(rpc.url).toBe("https://gateway.example/v1/zolana/ring");
    expect(calls[0]?.url.href).toBe("https://gateway.example/v1/zolana/ring/health?api-key=k");
  });

  it.each([
    ["https://gateway.example?api-key=leak1&api-key=leak2", undefined],
    ["https://gateway.example?api-key=leak1", "leak2"],
    ["https://gateway.example", ""],
    ["https://gateway.example", "leak\nbreak"],
  ])(
    "refuses an API key that is duplicated, doubly sourced or malformed (%s, %j)",
    (url, apiKey) => {
      const error = (() => {
        try {
          new RingRpc(url, apiKey === undefined ? {} : { apiKey });
        } catch (cause) {
          return cause;
        }
        return undefined;
      })();

      expect(error).toMatchObject({ code: "RING_RPC_CONFIG", details: { field: "apiKey" } });
      expect(JSON.stringify(error)).not.toContain("leak");
    },
  );

  it("keeps the key out of a transport failure", async () => {
    const fetch = (async () =>
      new Response("upstream down", { status: 502 })) as typeof globalThis.fetch;

    const error = await new RingRpc("https://gateway.example", { fetch, apiKey: "secret-key" })
      .health()
      .then(
        () => undefined,
        (cause: unknown) => cause,
      );

    expect(error).toMatchObject({ code: "RING_RPC_TRANSPORT" });
    expect(JSON.stringify(error)).not.toContain("secret-key");
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
    ["an empty cursor", { cursor: new Uint8Array(0) }, "RING_READ_CURSOR"],
    ["an oversized cursor", { cursor: new Uint8Array(257) }, "RING_READ_CURSOR"],
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
  const customRingProof = () =>
    Uint8Array.from([
      ...filled(51, 32),
      ...filled(52, 64),
      ...filled(53, 32),
      ...filled(54, 32),
      ...filled(55, 32),
    ]);

  const transactData = () => ({
    expiryUnixTs: 0xffff_ffff_ffff_ffffn,
    privateTxHash: filled(41, 32) as Bytes32,
    circuit: { kind: "ringEddsa", inputs: 2, outputs: 3, publicAssetSlots: 3 } as const,
    txViewingPk: filled(3, 33) as Bytes33,
    salt: filled(42, 16) as Bytes16,
    proof: {
      a: filled(43, 32) as Bytes32,
      b: filled(44, 128) as never,
      c: filled(45, 32) as Bytes32,
    },
    inputs: [],
    treeContexts: [{ utxoTreeRootIndex: 0, nullifierTreeRootIndex: 0 }],
    interfaceTransfers: [],
    outputs: [],
    messages: [],
  });

  const ZERO_TARGETS = Array.from({ length: 10 }, () => filled(0, 32) as Bytes32);
  const policy = (input: Partial<RingTransactPolicy> = {}): RingTransactPolicy => ({
    trees: [ADDRESS_TREE],
    treeContexts: [{ utxoTreeRootIndex: 0, nullifierTreeRootIndex: 0 }],
    revocationTargets: ZERO_TARGETS,
    revocationTreeIndexes: Array.from({ length: 10 }, () => 0),
    ...input,
  });

  it("appends the settlement accounts of a public withdrawal", async () => {
    const recipient = addressOf(31);
    const instruction = await ringTransactInstruction({
      ringProgramId: RING,
      payer: PAYER,
      inputTrees: [TREE],
      outputTree: OUTPUT_TREE,
      policy: policy(),
      proof: customRingProof(),
      withdrawal: { kind: "sol", recipient },
      data: transactData(),
    });

    // Without these the pool cannot settle and the ring cannot pay an address.
    const tail = instruction.accounts?.slice(-2).map((meta) => meta.address);
    expect(tail).toEqual([SOL_INTERFACE, recipient]);
  });

  it("places the delegate after the co-signer, requires key escrow and refuses a public leg", async () => {
    const delegate = addressOf(47);
    const [policyConfig] = await getProgramDerivedAddress({
      programAddress: RING,
      seeds: [new TextEncoder().encode("policy")],
    });
    const escrowed = await ringDelegateTransactInstruction({
      ringProgramId: RING,
      payer: PAYER,
      delegate,
      inputTrees: [TREE],
      outputTree: OUTPUT_TREE,
      policy: policy({ keyRegistryRootIndex: 3 }),
      proof: customRingProof(),
      data: transactData(),
    });
    expect(escrowed.data?.[0]).toBe(25);
    expect(escrowed.accounts?.slice(0, 10).map((meta) => [meta.address, meta.role])).toEqual([
      [PAYER, AccountRole.WRITABLE_SIGNER],
      [RING_CONFIG, AccountRole.READONLY],
      [await ringCoSignerAddress(RING), AccountRole.READONLY],
      [await ringCoSignerAddress(RING), AccountRole.READONLY],
      [await ringDelegateAddress(RING), AccountRole.READONLY],
      [delegate, AccountRole.READONLY_SIGNER],
      [policyConfig, AccountRole.READONLY],
      [ADDRESS_TREE, AccountRole.READONLY],
      [await ringKeyRegistryRootAddress(RING), AccountRole.READONLY],
      [PAYER, AccountRole.WRITABLE_SIGNER],
    ]);
    for (const unescrowed of [undefined, policy()]) {
      await expect(
        ringDelegateTransactInstruction({
          ringProgramId: RING,
          payer: PAYER,
          delegate,
          inputTrees: [TREE],
          outputTree: OUTPUT_TREE,
          ...(unescrowed === undefined ? {} : { policy: unescrowed }),
          proof: customRingProof(),
          data: transactData(),
        }),
      ).rejects.toThrow("RING_DELEGATE_INVALID");
    }
    await expect(
      ringDelegateTransactInstruction({
        ringProgramId: RING,
        payer: PAYER,
        delegate,
        inputTrees: [TREE],
        outputTree: OUTPUT_TREE,
        policy: policy({ keyRegistryRootIndex: 3 }),
        proof: customRingProof(),
        data: { ...transactData(), interfaceTransfers: [{ kind: "solWithdrawal", amount: 1n }] },
      }),
    ).rejects.toThrow("RING_DELEGATE_PUBLIC_LEG");
    await expect(
      ringDelegateTransactInstruction({
        ringProgramId: RING,
        payer: PAYER,
        delegate,
        inputTrees: [TREE],
        outputTree: OUTPUT_TREE,
        policy: policy({ keyRegistryRootIndex: 3 }),
        approvalRequired: true,
        proof: customRingProof(),
        data: transactData(),
      }),
    ).rejects.toMatchObject({
      code: "RING_DELEGATE_INVALID",
      details: { reason: "approvalRequired" },
    });
  });

  it("places one spend window slot per public leg before the spp payer", async () => {
    const recipient = addressOf(31);
    const instruction = await ringTransactInstruction({
      ringProgramId: RING,
      payer: PAYER,
      inputTrees: [TREE],
      outputTree: OUTPUT_TREE,
      proof: customRingProof(),
      withdrawal: { kind: "sol", recipient },
      data: {
        ...transactData(),
        interfaceTransfers: [
          { kind: "solWithdrawal", amount: 6n },
          { kind: "solWithdrawal", amount: 6n },
        ],
      },
    });
    const window = await ringSpendWindowAddress(RING, SOL_MINT);
    expect(instruction.accounts?.slice(4, 7).map((meta) => [meta.address, meta.role])).toEqual([
      [window, AccountRole.WRITABLE],
      [window, AccountRole.WRITABLE],
      [PAYER, AccountRole.WRITABLE_SIGNER],
    ]);
    await expect(
      ringTransactInstruction({
        ringProgramId: RING,
        payer: PAYER,
        inputTrees: [TREE],
        outputTree: OUTPUT_TREE,
        proof: customRingProof(),
        withdrawal: { kind: "sol", recipient },
        data: {
          ...transactData(),
          interfaceTransfers: [{ kind: "splWithdrawal", amount: 1n, splInterfaceBump: 250 }],
        },
      }),
    ).rejects.toThrow("RING_BUILD_WITHDRAWAL");
  });

  it("appends the owner signers as readonly signers after the payer", async () => {
    const owner = addressOf(33);
    const instruction = await ringTransactInstruction({
      ringProgramId: RING,
      payer: PAYER,
      inputTrees: [TREE],
      outputTree: OUTPUT_TREE,
      proof: customRingProof(),
      policy: policy(),
      ownerSigners: [owner],
      data: transactData(),
    });

    const signers = (instruction.accounts ?? []).filter(
      (meta) =>
        meta.role === AccountRole.WRITABLE_SIGNER || meta.role === AccountRole.READONLY_SIGNER,
    );
    // The payer signs twice, the ring's own account list and the wrapped pool list.
    expect(signers.map((meta) => meta.address)).toEqual([PAYER, PAYER, owner]);
    expect(signers[2]?.role).toBe(AccountRole.READONLY_SIGNER);
  });

  it("wraps the pool's account list and data like Rust `CustomRingTransactIxData`", async () => {
    const [policyConfig] = await getProgramDerivedAddress({
      programAddress: RING,
      seeds: [new TextEncoder().encode("policy")],
    });
    const revocationTarget = filled(66, 32) as Bytes32;
    const instruction = await ringTransactInstruction({
      ringProgramId: RING,
      payer: PAYER,
      inputTrees: [TREE],
      outputTree: OUTPUT_TREE,
      policy: policy({ revocationTargets: [revocationTarget, ...ZERO_TARGETS.slice(1)] }),
      proof: customRingProof(),
      data: transactData(),
    });
    expect(instruction.programAddress).toBe(RING);
    expect(instruction.accounts?.map((meta) => [meta.address, meta.role])).toEqual([
      [PAYER, AccountRole.WRITABLE_SIGNER],
      [RING_CONFIG, AccountRole.READONLY],
      [await ringCoSignerAddress(RING), AccountRole.READONLY],
      [await ringCoSignerAddress(RING), AccountRole.READONLY],
      [policyConfig, AccountRole.READONLY],
      [ADDRESS_TREE, AccountRole.READONLY],
      [await nullifierPdaAddress(ADDRESS_TREE, revocationTarget), AccountRole.READONLY],
      [PAYER, AccountRole.WRITABLE_SIGNER],
      [OUTPUT_TREE, AccountRole.WRITABLE],
      [SPP, AccountRole.READONLY],
      [SYSTEM, AccountRole.READONLY],
      [RING_AUTH, AccountRole.READONLY],
      [TREE, AccountRole.WRITABLE],
    ]);
    expect(Buffer.from(instruction.data ?? []).toString("hex")).toBe(
      "03" +
        "333333333333333333333333333333333333333333333333333333333333333334343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434353535353535353535353535353535353535353535353535353535353535353536363636363636363636363636363636363636363636363636363636363636363737373737373737373737373737373737373737373737373737373737373737" +
        "01" +
        "00000000" +
        "00" +
        "00" +
        "01" +
        "42".repeat(32) +
        "00".repeat(10) +
        "ffffffffffffffff0303030303030303030303030303030303030303030303030303030303030303032a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a0000000000292929292929292929292929292929292929292929292929292929292929292901000203032b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d000100000000",
    );
  });

  it("derives each revocation PDA under its fact's policy tree", async () => {
    const targets = [
      filled(66, 32) as Bytes32,
      filled(67, 32) as Bytes32,
      ...ZERO_TARGETS.slice(2),
    ];
    const instruction = await ringTransactInstruction({
      ringProgramId: RING,
      payer: PAYER,
      inputTrees: [TREE],
      outputTree: OUTPUT_TREE,
      policy: policy({
        trees: [ADDRESS_TREE, TREE],
        treeContexts: [
          { utxoTreeRootIndex: 0x0102, nullifierTreeRootIndex: 0x0304 },
          { utxoTreeRootIndex: 0x0506, nullifierTreeRootIndex: 0x0708 },
        ],
        keyRegistryRootIndex: 9,
        revocationTargets: targets,
        revocationTreeIndexes: [1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
      }),
      proof: customRingProof(),
      data: transactData(),
    });
    expect(instruction.accounts?.slice(5, 10).map((meta) => meta.address)).toEqual([
      ADDRESS_TREE,
      TREE,
      await ringKeyRegistryRootAddress(RING),
      await nullifierPdaAddress(TREE, filled(66, 32)),
      await nullifierPdaAddress(ADDRESS_TREE, filled(67, 32)),
    ]);
    expect(Array.from((instruction.data ?? new Uint8Array()).slice(193, 204))).toEqual([
      2, 2, 1, 4, 3, 6, 5, 8, 7, 9, 0,
    ]);
    const indexes = 204 + 1 + 2 * 32;
    expect(Array.from((instruction.data ?? new Uint8Array()).slice(indexes, indexes + 10))).toEqual(
      [1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    );
    await expect(
      ringTransactInstruction({
        ringProgramId: RING,
        payer: PAYER,
        inputTrees: [TREE],
        outputTree: OUTPUT_TREE,
        policy: policy({
          revocationTargets: targets,
          revocationTreeIndexes: [1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        }),
        proof: customRingProof(),
        data: transactData(),
      }),
    ).rejects.toThrow("RING_POLICY_SHAPE_UNSUPPORTED");
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
                  spendRecords: [
                    {
                      slotIndex: 2,
                      member: addressOf(12),
                      version: "18446744073709551615",
                      window: "18446744073709551615",
                      countersCommitment: addressOf(13),
                      counters: [
                        { slot: 0, asset: addressOf(16), spent: "__U64_MAX__" },
                        { slot: 3, asset: addressOf(19), spent: 0 },
                      ],
                    },
                    {
                      slotIndex: 3,
                      member: addressOf(24),
                      version: 1,
                      window: 5,
                      countersCommitment: addressOf(25),
                    },
                  ],
                },
              ],
              skipped: [{ slot: 7, txSignature: signatureOf(2), reason: "invalidAuditData" }],
              cursor: "AQID",
            },
          },
        }).replace('"__U64_MAX__"', "18446744073709551615"),
        JSON_HEADERS,
      );
    }) as typeof globalThis.fetch;
    const page = await new RingRpc("http://ring.example", {
      fetch,
      allowInsecureHttp: true,
    }).getDecryptedTransactions({
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
    expect(item?.spendRecords).toHaveLength(2);
    const spend = item?.spendRecords[0];
    expect(spend).toMatchObject({
      slotIndex: 2,
      version: 18446744073709551615n,
      window: 18446744073709551615n,
    });
    expect(spend?.member).toEqual(filled(12, 32));
    expect(spend?.countersCommitment).toEqual(filled(13, 32));
    // The velocity counter is a full-range u64, decoded past `Number` precision.
    expect(spend?.counters).toEqual([
      { slot: 0, asset: filled(16, 32), spent: 18446744073709551615n },
      { slot: 3, asset: filled(19, 32), spent: 0n },
    ]);
    const absent = item?.spendRecords[1];
    expect(absent?.slotIndex).toBe(3);
    expect(absent?.member).toEqual(filled(24, 32));
    expect(absent?.counters).toBeUndefined();
    const params = bodies[0]?.["params"] as Record<string, unknown>;
    expect(Object.keys(params).sort()).toEqual(["auth", "cursor", "limit", "ringProgramId"]);
    const auth = params["auth"] as Record<string, unknown>;
    expect(Object.keys(auth).sort()).toEqual(["nonce", "reader", "signature", "timestamp"]);
    expect(auth["reader"]).toBe(Buffer.from(readerKeyBytes(signerAddress)).toString("base64"));
    expect(auth["signature"]).toBe(Buffer.from(returnedSignatures[0]!).toString("base64"));
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
                  spendRecords: [],
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
                  spendRecords: [],
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

  it("rejects a spend record off the protocol shape", async () => {
    const spendRecordPage = (record: Record<string, unknown>) =>
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
                    withdrawals: [],
                    spendRecords: [record],
                  },
                ],
                skipped: [],
              },
            },
          }),
          JSON_HEADERS,
        )) as typeof globalThis.fetch;
    const counter = (slot: number) => ({ slot, asset: addressOf(16 + slot), spent: 1 });
    const base = {
      slotIndex: 2,
      member: addressOf(12),
      version: 3,
      window: 5,
      countersCommitment: addressOf(13),
    };
    const malformed: readonly Record<string, unknown>[] = [
      { ...base, counters: [counter(RING_VELOCITY_SLOTS)] },
      { ...base, counters: [counter(1), counter(1)] },
      { ...base, counters: [counter(2), counter(1)] },
      { ...base, counters: [{ ...counter(0), spent: -1 }] },
      ...["18446744073709551616", "-1", "1.5"].flatMap((value) => [
        { ...base, version: value },
        { ...base, window: value },
        { ...base, counters: [{ ...counter(0), spent: value }] },
      ]),
      { ...base, counters: [{ ...counter(0), asset: signatureOf(16) }] },
      { ...base, slotIndex: 0x1_0000_0000, counters: [counter(0)] },
    ];
    for (const record of malformed) {
      await expect(
        new RingRpc("http://ring.example", {
          fetch: spendRecordPage(record),
          allowInsecureHttp: true,
        }).getDecryptedTransactions({ ringProgramId: addressOf(7), signer: await anyReader() }),
      ).rejects.toMatchObject({ code: "RING_RPC" });
    }
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
