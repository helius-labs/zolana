import { decryptRingDepositUtxo } from "../src/ring/deposit-payload.js";
import { address, AccountRole, getAddressDecoder, type Signature } from "@solana/kit";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { initializePoseidon, BN254_SCALAR_ORDER } from "../src/hasher/index.js";
import { customRingDepositProofRequest, ProverClient } from "../src/client/prover/client.js";
import type { CustomRingDepositProofRequest } from "../src/client/prover/types.js";
import { DepositAsset } from "../src/interface/types.js";
import type { Bytes16, Bytes32 } from "../src/interface/types.js";
import { ringDepositInstruction } from "../src/ring/deposit-instruction.js";
import { ringConfigPda, ringDepositAuditPda, treeAddress } from "../src/interface/pda/index.js";
import { encodeRingDepositCapsule, readRingDepositCapsule } from "../src/ring/deposit-capsule.js";
import { InstructionTag } from "../src/interface/program.js";
import { Writer, addressBytes } from "../src/interface/internal.js";
import { ViewingKey } from "../src/keypair/viewing-key.js";
import { ShieldedKeypair } from "../src/keypair/shielded.js";
import { bigIntToBytes } from "../src/keypair/bytes.js";
import { encodeRingDepositPlaintext } from "../src/transaction/serialization/ring-deposit.js";
import { ownerUtxoHash, Utxo } from "../src/transaction/utxo.js";
import { AssetRegistry, SOL_MINT } from "../src/transaction/asset.js";
import type { IndexedShieldedTransaction } from "../src/transaction/instructions/transact.js";
import { encodeOutputData, EncryptedScheme } from "../src/transaction/serialization/codecs.js";
import { mergeDummyNullifier, mergeOutputBlinding } from "../src/keypair/merge/index.js";
import { buildRingDepositTransaction } from "../src/ring/deposit.js";
import { decodeRingDepositAudit } from "../src/ring/codecs.js";
import { fetchRingDepositAudit, setRingDepositAuditInstruction } from "../src/ring/config.js";
import { initializeRingConfigInstructions } from "../src/ring/instructions.js";
import { recoverRingMemberNotes } from "../src/ring/recover.js";
import {
  openRingDepositOpening,
  ringDepositContextHash,
  ringDepositPublicInputHash,
  sealRingDepositOpenings,
} from "../src/ring/deposit-audit.js";
import { depositClient, ringAuditReader, transactionsPage } from "./helpers/clients.js";
import { ownedAccount, ringProgramConfigData } from "./helpers/ring-accounts.js";

const RING = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
const TREE = treeAddress(0);
function field(value: bigint): Bytes32 {
  return bigIntToBytes(value) as Bytes32;
}
beforeAll(initializePoseidon);

describe("deposit disclosure", () => {
  it("pins the shared Rust and Go encryption and statement vector", () => {
    const auditor = ViewingKey.fromBytes(new Uint8Array(32).fill(0x11) as Bytes32);
    const generate = vi
      .spyOn(ViewingKey, "generate")
      .mockImplementation(() => ViewingKey.fromBytes(new Uint8Array(32).fill(0x22) as Bytes32));
    const sealed = sealRingDepositOpenings(
      [
        { ownerHash: field(1n), blinding: field(3n), recipientCiphertext: Uint8Array.of(1) },
        { ownerHash: field(2n), blinding: field(4n), recipientCiphertext: Uint8Array.of(2) },
      ],
      auditor.publicKey(),
    );
    try {
      const contextHash = ringDepositContextHash(
        getAddressDecoder().decode(new Uint8Array(32).fill(0x33)),
        getAddressDecoder().decode(new Uint8Array(32).fill(0x44)),
        Uint8Array.of(18, 1, 0, 2),
      );
      expect(Buffer.from(contextHash).toString("hex")).toBe(
        "2cc6b9a5a2cb550702b5387ade744abee5e6eeb7c266415e59502e6f8acce56b",
      );
      expect(
        sealed.capsules.map((capsule) => Buffer.from(capsule.ciphertext).toString("hex")),
      ).toEqual([
        "146b393f9c81cad9bc22887e500644f69ea8293e2253f55869e88127e5483e9b12a46abadf0068bd73c83584a8e47a550e88a35558642ba87646ff0765c5e3b5",
        "74e42b590ba76cfee5c6d8e3e05e03a460e0c02c7330fd977dc4eb71e34645616f616fb39595f1ecadfdd87feffd48fb4177741341dd2d507c474094e252f89c",
      ]);
      const hash = ringDepositPublicInputHash({
        contextHash,
        ownerCommitments: [
          ownerUtxoHash(field(1n), field(3n)),
          ownerUtxoHash(field(2n), field(4n)),
        ],
        capsules: sealed.capsules,
        auditorPublicKey: auditor.publicKey(),
      });
      expect(Buffer.from(hash).toString("hex")).toBe(
        "0bc3f76e72b6d6bd1a557447da49e445dafb11e6d9168005742013130b45e030",
      );
    } finally {
      generate.mockRestore();
      sealed.ephemeralSecret.fill(0);
      auditor.destroy();
    }
  });
  it("opens every slot of one shared stream and preserves recipient ciphertext", () => {
    const auditor = ViewingKey.generate();
    const openings = Array.from({ length: 8 }, (_, index) => ({
      ownerHash: field(BigInt(index + 1)),
      blinding: field(BigInt(index + 11)),
      recipientCiphertext: Uint8Array.of(index, 9),
    }));
    const sealed = sealRingDepositOpenings(openings, auditor.publicKey());
    try {
      for (const [index, encoded] of sealed.payloads.entries()) {
        const capsule = readRingDepositCapsule(encoded);
        if (capsule === undefined) throw new Error("missing capsule");
        expect(capsule.slotIndex).toBe(index);
        expect(capsule.ephemeralPublicKey).toEqual(sealed.capsules[0]?.ephemeralPublicKey);
        expect(capsule.recipientCiphertext).toEqual(openings[index]?.recipientCiphertext);
        const opening = openings[index];
        if (opening === undefined) throw new Error("missing opening");
        const opened = openRingDepositOpening(
          capsule,
          auditor,
          ownerUtxoHash(opening.ownerHash, opening.blinding),
        );
        expect(opened.ownerHash).toEqual(openings[index]?.ownerHash);
        expect(opened.blinding).toEqual(openings[index]?.blinding);
        opened.ownerHash.fill(0);
        opened.blinding.fill(0);
        expect(() => openRingDepositOpening(capsule, auditor, field(0n))).toThrow(
          expect.objectContaining({ code: "RING_AUDIT_MESSAGE" }),
        );
      }
      expect(new Set(sealed.capsules.map((capsule) => capsule.ciphertext.join())).size).toBe(8);
      const first = sealed.capsules[0];
      if (first === undefined) throw new Error("missing capsule");
      expect(() =>
        readRingDepositCapsule(sealed.payloads[0]?.slice(0, 105) ?? new Uint8Array()),
      ).toThrow(
        expect.objectContaining({ code: "INTERFACE_CODEC", details: { field: "deposit capsule" } }),
      );
      expect(() => encodeRingDepositCapsule({ ...first, slotIndex: 8 })).toThrow(
        expect.objectContaining({ code: "INTERFACE_CODEC", details: { field: "deposit slot" } }),
      );
      expect(readRingDepositCapsule(Uint8Array.of(1, 2, 3))).toBeUndefined();
    } finally {
      sealed.ephemeralSecret.fill(0);
      auditor.destroy();
    }
  });

  it("binds the entire SPP wire, both program addresses, commitments, and ciphertext", () => {
    const auditor = ViewingKey.generate();
    const sealed = sealRingDepositOpenings(
      [{ ownerHash: field(1n), blinding: field(2n), recipientCiphertext: Uint8Array.of(3) }],
      auditor.publicKey(),
    );
    try {
      const contextHash = ringDepositContextHash(RING, TREE, Uint8Array.of(18, 1));
      expect(ringDepositContextHash(RING, TREE, Uint8Array.of(18, 2))).not.toEqual(contextHash);
      expect(ringDepositContextHash(TREE, RING, Uint8Array.of(18, 1))).not.toEqual(contextHash);
      const input = {
        contextHash,
        ownerCommitments: [ownerUtxoHash(field(1n), field(2n))],
        capsules: sealed.capsules,
        auditorPublicKey: auditor.publicKey(),
      };
      const hash = ringDepositPublicInputHash(input);
      expect(ringDepositPublicInputHash({ ...input, ownerCommitments: [field(3n)] })).not.toEqual(
        hash,
      );
      const capsule = sealed.capsules[0];
      if (capsule === undefined) throw new Error("missing capsule");
      capsule.ciphertext[0] = (capsule.ciphertext[0] ?? 0) ^ 1;
      expect(ringDepositPublicInputHash(input)).not.toEqual(hash);
      expect(() =>
        ringDepositPublicInputHash({ ...input, contextHash: field(BN254_SCALAR_ORDER) }),
      ).toThrow();
    } finally {
      sealed.ephemeralSecret.fill(0);
      auditor.destroy();
    }
  });

  it("accepts legacy recipient ciphertext and unwraps disclosed deposits", () => {
    const auditor = ViewingKey.generate();
    const envelope = ViewingKey.generate();
    const recipient = ShieldedKeypair.generate();
    const r = field(15n);
    const salt = new Uint8Array(16) as Bytes16;
    const ciphertext = envelope.encryptRingDeposit(
      recipient.viewingPublicKey(),
      encodeRingDepositPlaintext({ blinding: r, ringData: Uint8Array.of(9) }),
      salt,
    );
    const sealed = sealRingDepositOpenings(
      [
        {
          ownerHash: recipient.shieldedAddress().ownerHash(),
          blinding: r,
          recipientCiphertext: ciphertext,
        },
      ],
      auditor.publicKey(),
    );
    try {
      const output = {
        ownerUtxoHash: ownerUtxoHash(recipient.shieldedAddress().ownerHash(), r),
        asset: SOL_MINT,
        amount: 7n,
        ringProgramId: RING,
        ringDataHash: field(0n),
        encrypted: { txViewingPublicKey: envelope.publicKey().toBytes(), salt, ciphertext },
      };
      const legacy = decryptRingDepositUtxo(output, recipient, recipient.signingPublicKey());
      const capsule = sealed.payloads[0];
      if (capsule === undefined) throw new Error("missing capsule");
      const audited = decryptRingDepositUtxo(
        { ...output, encrypted: { ...output.encrypted, ciphertext: capsule } },
        recipient,
        recipient.signingPublicKey(),
      );
      expect(audited.blinding).toEqual(legacy.blinding);
      expect(audited.data).toEqual(legacy.data);
    } finally {
      sealed.ephemeralSecret.fill(0);
      envelope.destroy();
      auditor.destroy();
      recipient.destroy();
    }
  });

  it("wraps one proof around eight capsules and leaves the SPP deposit bytes intact", async () => {
    const auditor = ViewingKey.generate();
    const sealed = sealRingDepositOpenings(
      Array.from({ length: 8 }, () => ({
        ownerHash: field(1n),
        blinding: field(2n),
        recipientCiphertext: Uint8Array.of(3),
      })),
      auditor.publicKey(),
    );
    try {
      const deposits = sealed.payloads.map((ciphertext) => ({
        asset: DepositAsset.sol(),
        viewTag: field(1n),
        ownerUtxoHash: ownerUtxoHash(field(1n), field(2n)),
        amount: 1n,
        ringDataHash: field(0n),
        encrypted: {
          txViewingPublicKey: auditor.publicKey().toBytes(),
          salt: new Uint8Array(16) as Bytes16,
          ciphertext,
        },
      }));
      const input = {
        ringProgramId: RING,
        tree: TREE,
        depositor: RING,
        deposits,
      };
      const legacy = await ringDepositInstruction(input);
      const audited = await ringDepositInstruction({
        ...input,
        proof: new Uint8Array(192).fill(7),
      });
      expect(audited.data?.[0]).toBe(31);
      expect(audited.data?.slice(1, 193)).toEqual(new Uint8Array(192).fill(7));
      expect(audited.data?.[193]).toBe(0);
      expect(audited.data?.slice(194)).toEqual(legacy.data);
      expect(legacy.data?.[0]).toBe(InstructionTag.ringDeposit);
      expect(audited.accounts).toEqual(legacy.accounts);
      expect(audited.accounts?.[3]).toMatchObject({
        address: (await ringDepositAuditPda(RING))[0],
        role: AccountRole.READONLY,
      });
      await expect(
        ringDepositInstruction({
          ...input,
          proof: new Uint8Array(192),
          deposits: [...deposits, deposits[0]!],
        }),
      ).rejects.toMatchObject({ code: "INTERFACE_CODEC", details: { field: "deposit count" } });
      await expect(
        ringDepositInstruction({ ...input, proof: new Uint8Array(191) }),
      ).rejects.toMatchObject({
        code: "INTERFACE_INVALID_LENGTH",
        details: { name: "deposit proof", expected: 192, actual: 191 },
      });
      await expect(
        ringDepositInstruction({
          ...input,
          proof: new Uint8Array(192),
          deposits: [...deposits].reverse(),
        }),
      ).rejects.toMatchObject({ code: "INTERFACE_CODEC", details: { field: "deposit capsule" } });
    } finally {
      sealed.ephemeralSecret.fill(0);
      auditor.destroy();
    }
  });

  it("serializes the queued circuit contract and rejects noncanonical fields or padding", async () => {
    const auditor = ViewingKey.generate();
    const ephemeral = ViewingKey.generate();
    const input: CustomRingDepositProofRequest = {
      publicInputHash: field(1n),
      contextHash: field(2n),
      count: 1,
      ownerPkHashes: [field(3n), ...Array.from({ length: 7 }, () => field(0n))],
      nullifierPks: [field(5n), ...Array.from({ length: 7 }, () => field(0n))],
      blindings: [field(4n), ...Array.from({ length: 7 }, () => field(0n))],
      keys: Array.from({ length: 8 }, () => undefined),
      ephemeralSecret: ephemeral.secretBytes(),
      auditorPublicKey: auditor.publicKey().toUncompressed(),
    };
    try {
      expect(customRingDepositProofRequest(input)).toMatchObject({
        circuitType: "custom-ring-deposit",
        count: 1,
        ownerPkHashes: input.ownerPkHashes.map(
          (bytes) => `0x${Buffer.from(bytes).toString("hex")}`,
        ),
        nullifierPks: input.nullifierPks.map((bytes) => `0x${Buffer.from(bytes).toString("hex")}`),
        keys: Array.from({ length: 8 }, () => null),
        keyEscrow: false,
        keyRegistryRoot: `0x${"0".repeat(64)}`,
        ephSk: `0x${Buffer.from(input.ephemeralSecret).toString("hex")}`,
      });
      const invalidInputs = expect.objectContaining({ code: "CLIENT_INVALID_PROOF_INPUTS" });
      expect(() =>
        customRingDepositProofRequest({ ...input, publicInputHash: field(BN254_SCALAR_ORDER) }),
      ).toThrow(invalidInputs);
      expect(() => customRingDepositProofRequest({ ...input, count: 0 })).toThrow(invalidInputs);
      expect(() => customRingDepositProofRequest({ ...input, count: 9 })).toThrow(invalidInputs);
      expect(() => customRingDepositProofRequest({ ...input, ephemeralSecret: field(0n) })).toThrow(
        invalidInputs,
      );
      expect(() =>
        customRingDepositProofRequest({ ...input, auditorPublicKey: new Uint8Array(65) }),
      ).toThrow(invalidInputs);
      expect(() =>
        customRingDepositProofRequest({
          ...input,
          blindings: [...input.blindings.slice(0, 7), field(1n)],
        }),
      ).toThrow(invalidInputs);
      expect(() =>
        customRingDepositProofRequest({
          ...input,
          nullifierPks: [...input.nullifierPks.slice(0, 7), field(1n)],
        }),
      ).toThrow(invalidInputs);
      expect(() =>
        customRingDepositProofRequest({
          ...input,
          keys: [
            ...input.keys.slice(0, 7),
            { next: field(0n), ctHash: field(0n), index: 1n, path: [] },
          ],
        }),
      ).toThrow(invalidInputs);
      const fetch = vi.fn<typeof globalThis.fetch>(async (_url, options) => {
        expect(new Headers(options?.headers).get("X-Sync")).toBeNull();
        expect(JSON.parse(String(options?.body))).toEqual(customRingDepositProofRequest(input));
        return Response.json({
          ar: ["0x0", "0x0"],
          bs: [
            ["0x0", "0x0"],
            ["0x0", "0x0"],
          ],
          krs: ["0x0", "0x0"],
        });
      });
      const prover = new ProverClient({ url: "https://prover.example", fetch });
      await expect(prover.proveCustomRingDeposit(input)).resolves.toEqual({
        a: new Uint8Array(64),
        b: new Uint8Array(128),
        c: new Uint8Array(64),
      });
      await expect(prover.proveCustomRingDeposit({ ...input, count: 9 })).rejects.toMatchObject({
        code: "CLIENT_INVALID_PROOF_INPUTS",
      });
      expect(fetch).toHaveBeenCalledTimes(1);
      fetch.mockResolvedValueOnce(Response.json({ ar: [] }));
      await expect(prover.proveCustomRingDeposit(input)).rejects.toMatchObject({
        code: "CLIENT_PROOF_PARSE",
      });
      expect(fetch).toHaveBeenCalledTimes(2);
    } finally {
      input.ephemeralSecret.fill(0);
      ephemeral.destroy();
      auditor.destroy();
    }
  });
});

describe("deposit audit control", () => {
  it("defaults only absent or empty system-owned canonical settings to disabled", async () => {
    const [, bump] = await ringDepositAuditPda(RING);
    expect(await fetchRingDepositAudit({ getAccount: async () => undefined }, RING)).toBe(false);
    expect(
      await fetchRingDepositAudit(
        { getAccount: async () => ownedAccount(SOL_MINT, new Uint8Array()) },
        RING,
      ),
    ).toBe(false);
    expect(
      await fetchRingDepositAudit(
        { getAccount: async () => ownedAccount(RING, Uint8Array.of(8, 1, bump)) },
        RING,
      ),
    ).toBe(true);
    for (const [owner, bytes] of [
      [RING, new Uint8Array()],
      [TREE, new Uint8Array()],
      [SOL_MINT, Uint8Array.of(8, 1, bump)],
      [RING, Uint8Array.of(8, 2, bump)],
      [RING, Uint8Array.of(8, 1, bump ^ 1)],
    ] as const)
      await expect(
        fetchRingDepositAudit({ getAccount: async () => ownedAccount(owner, bytes) }, RING),
      ).rejects.toMatchObject({ code: "RING_DEPOSIT_AUDIT_INVALID" });
    expect(decodeRingDepositAudit(Uint8Array.of(8, 0, bump))).toEqual({ required: false, bump });
  });

  it("sets the control with config authority and enables it only on opt-in initialization", async () => {
    const auditor = ViewingKey.generate();
    try {
      const input = {
        ringProgramId: RING,
        payer: TREE,
        authority: RING,
        auditorPublicKey: auditor.publicKey(),
        hasPolicy: false,
      };
      expect(await initializeRingConfigInstructions(input)).toHaveLength(1);
      const enabled = await initializeRingConfigInstructions({ ...input, depositAudit: true });
      expect(enabled).toHaveLength(2);
      expect(enabled[1]).toEqual(
        await setRingDepositAuditInstruction({ ...input, required: true }),
      );
      expect(enabled[1]?.data).toEqual(Uint8Array.of(30, 1));
      expect(enabled[1]?.accounts?.map((meta) => meta.role)).toEqual([
        AccountRole.WRITABLE_SIGNER,
        AccountRole.READONLY_SIGNER,
        AccountRole.READONLY,
        AccountRole.WRITABLE,
        AccountRole.READONLY,
      ]);
    } finally {
      auditor.destroy();
    }
  });

  it.each([
    { required: false, fails: false },
    { required: true, fails: false },
    { required: true, fails: true },
  ])("honors the deposit setting and wipes proof inputs %o", async ({ required, fails }) => {
    const auditor = ViewingKey.generate();
    const recipient = ShieldedKeypair.generate();
    const [config, bump] = await ringConfigPda(RING);
    const [setting, settingBump] = await ringDepositAuditPda(RING);
    const proofInputs: CustomRingDepositProofRequest[] = [];
    const proveCustomRingDeposit = vi.fn(async (input: CustomRingDepositProofRequest) => {
      proofInputs.push(input);
      expect(input.count).toBe(1);
      expect(input.ephemeralSecret.some((byte) => byte !== 0)).toBe(true);
      if (fails) throw new Error("prover unavailable");
      return new Uint8Array(192);
    });
    try {
      const client = {
        ...depositClient({
          getAccount: async (address) =>
            address === config
              ? ownedAccount(
                  RING,
                  ringProgramConfigData({
                    authority: RING,
                    auditorPublicKey: auditor.publicKey().toBytes(),
                    bump,
                    hasPolicy: false,
                  }),
                )
              : address === setting
                ? ownedAccount(RING, Uint8Array.of(8, Number(required), settingBump))
                : undefined,
        }),
        proveCustomRingDeposit,
        getRingKeyRegistryEntry: vi.fn(async () => {
          throw new Error("escrow is off");
        }),
      };
      const building = buildRingDepositTransaction({
        client,
        ringProgramId: RING,
        feePayer: TREE,
        recipient: recipient.shieldedAddress(),
        amount: 1n,
      });
      if (fails) await expect(building).rejects.toMatchObject({ code: "RING_BUILD_DEPOSIT" });
      else await building;
      expect(proveCustomRingDeposit).toHaveBeenCalledTimes(required ? 1 : 0);
      for (const input of proofInputs) {
        expect(input.ephemeralSecret.every((byte) => byte === 0)).toBe(true);
        expect(input.blindings.every((field) => field.every((byte) => byte === 0))).toBe(true);
      }
    } finally {
      auditor.destroy();
      recipient.destroy();
    }
  });
});

describe("deposit recovery", () => {
  it("refuses a ring history truncated by the page budget", async () => {
    const auditor = ViewingKey.generate();
    const source = ShieldedKeypair.generate();
    const key = source.nullifierKey();
    const client = {
      ...ringAuditReader({
        getShieldedTransactionsByTags: async (input) =>
          transactionsPage(
            input.ringProgramId === undefined ? {} : { nextCursor: Uint8Array.of(1) },
          ),
      }),
      getShieldedTransactionsByNullifiers: async () => transactionsPage(),
    };
    try {
      await expect(
        recoverRingMemberNotes({
          client,
          ringProgramId: RING,
          auditor,
          source: source.shieldedAddress(),
          nullifierKey: key,
          assets: new AssetRegistry(),
          resolveTreeId: () => 0,
          origin: { ringInvoked: async () => true },
          maxPages: 1,
        }),
      ).rejects.toMatchObject({ code: "RING_RECOVERY_INCOMPLETE" });
    } finally {
      key.destroy();
      source.destroy();
      auditor.destroy();
    }
  });
  it("recovers disclosed deposits with committed metadata and follows their ring merges", async () => {
    const auditor = ViewingKey.generate();
    const source = ShieldedKeypair.generate();
    const address = source.shieldedAddress();
    const key = source.nullifierKey();
    const blinding = field(15n);
    const ringDataHash = field(3n);
    const utxo = new Utxo({
      owner: address.signingPublicKey,
      asset: SOL_MINT,
      amount: 7n,
      blinding,
      ringProgramId: RING,
    });
    const commitment = utxo.hash(address.nullifierPublicKey, 0, undefined, ringDataHash);
    const nullifier = utxo.nullifier(commitment, key);
    const sealed = sealRingDepositOpenings(
      [{ ownerHash: address.ownerHash(), blinding, recipientCiphertext: Uint8Array.of(3) }],
      auditor.publicKey(),
    );
    const ciphertext = sealed.payloads[0];
    if (ciphertext === undefined) throw new Error("missing capsule");
    const body = new Writer()
      .bytes(ownerUtxoHash(address.ownerHash(), blinding))
      .bytes(addressBytes(SOL_MINT))
      .u64(7n, "amount")
      .u8(0, "dataHash")
      .bytes(addressBytes(RING))
      .bytes(ringDataHash)
      .bytes(auditor.publicKey().toBytes())
      .bytes(new Uint8Array(16))
      .u32(ciphertext.length, "ciphertextLength")
      .bytes(ciphertext)
      .finish();
    const deposit: IndexedShieldedTransaction = {
      txSignature: "1".repeat(87) as Signature,
      slot: 1n,
      eventIndex: 0,
      ringProgramId: RING,
      proofless: true,
      nullifiers: [],
      messages: [],
      outputSlots: [
        {
          viewTag: field(123n),
          outputContext: { hash: commitment, tree: TREE, leafIndex: 1n },
          payload: encodeOutputData(EncryptedScheme.ringDeposit, body, "encrypted"),
        },
      ],
    };
    const malformedBody = new Uint8Array(body);
    const encryptedOffset = body.length - ciphertext.length;
    malformedBody[encryptedOffset + 42] = (malformedBody[encryptedOffset + 42] ?? 0) ^ 1;
    const malformed: IndexedShieldedTransaction = {
      ...deposit,
      outputSlots: deposit.outputSlots.map((slot) => ({
        ...slot,
        outputContext: { ...slot.outputContext, hash: field(99n) },
        payload: encodeOutputData(EncryptedScheme.ringDeposit, malformedBody, "encrypted"),
      })),
    };
    let history = [deposit, malformed];
    let spends: IndexedShieldedTransaction[] = [];
    const client = {
      ...ringAuditReader({
        getShieldedTransactionsByTags: async (input) =>
          transactionsPage({
            transactions: input.ringProgramId === RING ? history : [],
          }),
      }),
      getShieldedTransactionsByNullifiers: vi.fn(async () =>
        transactionsPage({ transactions: spends }),
      ),
    };
    const params = {
      client,
      ringProgramId: RING,
      auditor,
      source: address,
      nullifierKey: key,
      assets: new AssetRegistry(),
      resolveTreeId: (tree: typeof TREE) => (tree === TREE ? 0 : 1),
      origin: { ringInvoked: async () => true },
    };
    try {
      const result = await recoverRingMemberNotes(params);
      expect(result.unopened).toEqual([]);
      expect(result.unsupportedDeposits).toEqual([]);
      expect(result.notes).toHaveLength(1);
      expect(result.notes[0]?.nullifier).toEqual(nullifier);
      expect(result.notes[0]?.ringDataHash).toEqual(ringDataHash);
      expect(result.notes[0]?.utxo.blinding).toEqual(blinding);
      history = [
        deposit,
        {
          ...malformed,
          outputSlots: malformed.outputSlots.map((slot) => ({
            ...slot,
            viewTag: address.viewingPublicKey.x(),
          })),
        },
      ];
      expect((await recoverRingMemberNotes(params)).unsupportedDeposits).toEqual([field(99n)]);
      history = [deposit];
      const merged = new Utxo({
        owner: address.signingPublicKey,
        asset: SOL_MINT,
        amount: 7n,
        blinding: mergeOutputBlinding(key, nullifier),
        ringProgramId: RING,
      });
      const mergedHash = merged.hash(address.nullifierPublicKey, 1, undefined, ringDataHash);
      const merge: IndexedShieldedTransaction = {
        txSignature: "2".repeat(87) as Signature,
        slot: 2n,
        eventIndex: 0,
        ringProgramId: RING,
        proofless: false,
        nullifiers: [
          nullifier,
          ...Array.from({ length: 7 }, (_, index) =>
            mergeDummyNullifier(key, nullifier, index + 1),
          ),
        ],
        messages: [],
        outputSlots: [
          {
            viewTag: nullifier,
            outputContext: { hash: mergedHash, tree: treeAddress(1), leafIndex: 2n },
            payload: ringDataHash,
          },
        ],
      };
      spends = [merge];
      const successor = await recoverRingMemberNotes(params);
      expect(successor.notes).toHaveLength(1);
      expect(successor.notes[0]?.outputContext.hash).toEqual(mergedHash);
      expect(successor.unopened).toEqual([]);
      expect(successor.unsupportedDeposits).toEqual([]);
      expect(
        (await recoverRingMemberNotes({ ...params, origin: { ringInvoked: async () => false } }))
          .notes,
      ).toEqual([]);
      const slot = deposit.outputSlots[0];
      if (slot === undefined) throw new Error("missing deposit");
      slot.outputContext.hash[0] = (slot.outputContext.hash[0] ?? 0) ^ 1;
      await expect(recoverRingMemberNotes(params)).rejects.toMatchObject({
        code: "RING_AUDIT_MESSAGE",
      });
    } finally {
      sealed.ephemeralSecret.fill(0);
      key.destroy();
      auditor.destroy();
      source.destroy();
    }
  });
});
