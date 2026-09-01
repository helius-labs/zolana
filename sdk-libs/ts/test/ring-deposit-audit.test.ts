import { X25519Keypair } from "../src/keypair/x25519.js";
import { decryptRingDepositUtxo } from "../src/ring/deposit-payload.js";
import { address, AccountRole, getAddressDecoder, type Signature } from "@solana/kit";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { initializePoseidon, BN254_SCALAR_ORDER } from "../src/hasher/index.js";
import { customRingDepositProofRequest, ProverClient } from "../src/client/prover/client.js";
import { ZolanaClient } from "../src/client/client.js";
import { wireDecoder } from "../src/interface/decode.js";
import type { CustomRingDepositProofRequest } from "../src/client/prover/types.js";
import { DepositAsset } from "../src/interface/types.js";
import type { Bytes16, Bytes32, Bytes96 } from "../src/interface/types.js";
import { ringDepositInstruction } from "../src/ring/deposit-instruction.js";
import { ringConfigPda, ringDepositAuditPda, treeAddress } from "../src/interface/pda/index.js";
import { encodeRingDepositCapsule, readRingDepositCapsule } from "../src/ring/deposit-capsule.js";
import { InstructionTag } from "../src/interface/program.js";
import { Writer, addressBytes } from "../src/interface/internal.js";
import { ViewingKey } from "../src/keypair/viewing-key.js";
import { ShieldedKeypair } from "../src/keypair/shielded.js";
import { bigIntToBytes, checkedBytes } from "../src/keypair/bytes.js";
import { encodeRingDepositPlaintext } from "../src/transaction/serialization/ring-deposit.js";
import { ownerUtxoHash, Utxo } from "../src/transaction/utxo.js";
import { AssetRegistry, SOL_MINT } from "../src/transaction/asset.js";
import type { IndexedShieldedTransaction } from "../src/transaction/instructions/transact.js";
import { encodeOutputData, EncryptedScheme } from "../src/transaction/serialization/codecs.js";
import {
  mergeDummyNullifier,
  mergeOutputBlinding,
  mergeOutputKey,
} from "../src/keypair/merge/index.js";
import {
  encodeMergeOutputData,
  encryptMergeOutput,
} from "../src/transaction/serialization/merge.js";
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
import {
  chainPosition,
  depositClient,
  ringAuditReader,
  transactionsPage,
} from "./helpers/clients.js";
import { ownedAccount, ringProgramConfigData } from "./helpers/ring-accounts.js";
import { proofFor } from "./helpers/proofs.js";
import { ConfirmedDeposit } from "../src/ring/origin.js";
import { confirmedDepositTransaction } from "./helpers/confirmed-deposits.js";

const RING = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
const TREE = treeAddress(0);
function field(value: bigint): Bytes32 {
  return bigIntToBytes(value) as Bytes32;
}
beforeAll(initializePoseidon);

describe("deposit disclosure", () => {
  it("pins the shared Rust and Go encryption and statement vector", () => {
    const auditor = X25519Keypair.fromBytes(new Uint8Array(32).fill(0x11) as Bytes32);
    const generate = vi
      .spyOn(X25519Keypair, "generate")
      .mockImplementation(() => X25519Keypair.fromBytes(new Uint8Array(32).fill(0x22) as Bytes32));
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
        "006d5d4d188464de0e852c806b11ef3850cd683b977fea9bd1b9278b6461669f631350fa47a91f10cceb37738a4fefe7f88ded2f36b08fa08cb0ebba0268414424ab3ee9887da5fa32d2074fbd7155bc72723a28dacb3fd92f045649bba3cdf6",
        "588ca73e11d9094a68cc5e7c26aadac08f1bc0f41c3580bf9ddc70518b26a826aaeab0368c456598c7641706ce6de7dcdbafa8c64f3eba9526b5012da75c1a4c4fb93b88049bc84e8589460c06610c931447f57d2d4a9955f6ec638727886729",
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
        "0313e323a3870bacb7042d78648a0d01d5f5b4ddfa56ee3024bcd26207ebe4f3",
      );
    } finally {
      generate.mockRestore();
      sealed.ephemeralSecret.fill(0);
      auditor.destroy();
    }
  });
  it("opens every slot of one shared stream and preserves recipient ciphertext", () => {
    const auditor = X25519Keypair.generate();
    // Odd slots disclose an owner key like an anonymous ring.
    const openings = Array.from({ length: 8 }, (_, index) => ({
      ownerHash: field(BigInt(index + 1)),
      blinding: field(BigInt(index + 11)),
      ...(index % 2 === 0 ? {} : { ownerKey: new Uint8Array(32).fill(index) as Bytes32 }),
      recipientCiphertext: Uint8Array.of(index, 9),
    }));
    const sealed = sealRingDepositOpenings(openings, auditor.publicKey());
    const signature = "1".repeat(87) as Signature;
    const confirmed = ConfirmedDeposit.fromTransaction(
      confirmedDepositTransaction(
        RING,
        signature,
        sealed.capsules,
        openings.map((opening) => ownerUtxoHash(opening.ownerHash, opening.blinding)),
      ),
      signature,
      0,
      RING,
    );
    try {
      for (const [index, encoded] of sealed.payloads.entries()) {
        const capsule = readRingDepositCapsule(encoded);
        if (capsule === undefined) throw new Error("missing capsule");
        expect(capsule.slotIndex).toBe(index);
        expect(capsule.ephemeralPublicKey).toEqual(sealed.capsules[0]?.ephemeralPublicKey);
        expect(capsule.recipientCiphertext).toEqual(openings[index]?.recipientCiphertext);
        const opening = openings[index];
        if (opening === undefined) throw new Error("missing opening");
        const binding = confirmed[index];
        if (binding === undefined) throw new Error("missing confirmation");
        const opened = openRingDepositOpening(
          capsule,
          auditor,
          ownerUtxoHash(opening.ownerHash, opening.blinding),
          binding,
        );
        expect(opened.ownerHash).toEqual(openings[index]?.ownerHash);
        expect(opened.blinding).toEqual(openings[index]?.blinding);
        expect(opened.ownerKey).toEqual(opening.ownerKey);
        opened.ownerHash.fill(0);
        opened.blinding.fill(0);
        expect(() => openRingDepositOpening(capsule, auditor, field(0n), binding)).toThrow(
          expect.objectContaining({ code: "RING_AUDIT_MESSAGE" }),
        );
      }
      expect(new Set(sealed.capsules.map((capsule) => capsule.ciphertext.join())).size).toBe(8);
      const first = sealed.capsules[0];
      if (first === undefined) throw new Error("missing capsule");
      expect(() =>
        readRingDepositCapsule(sealed.payloads[0]?.slice(0, 137) ?? new Uint8Array()),
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
    const auditor = X25519Keypair.generate();
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
    const auditor = X25519Keypair.generate();
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
    const auditor = X25519Keypair.generate();
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
    const auditor = X25519Keypair.generate();
    const ephemeral = X25519Keypair.generate();
    const input: CustomRingDepositProofRequest = {
      publicInputHash: field(1n),
      contextHash: field(2n),
      count: 1,
      ownerPkHashes: [field(3n), ...Array.from({ length: 7 }, () => field(0n))],
      nullifierPks: [field(5n), ...Array.from({ length: 7 }, () => field(0n))],
      blindings: [field(4n), ...Array.from({ length: 7 }, () => field(0n))],
      keys: Array.from({ length: 8 }, () => undefined),
      ephemeralSecret: ephemeral.secretBytes(),
      auditorPublicKey: auditor.publicKey().u(),
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
      expect(() =>
        customRingDepositProofRequest({ ...input, auditorPublicKey: new Uint8Array(32).fill(255) }),
      ).toThrow(invalidInputs);
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
        return Response.json(proofFor(String(options?.body)));
      });
      const prover = new ProverClient({ tee: false, url: "https://prover.example", fetch });
      await expect(prover.proveCustomRingDeposit(input)).resolves.toEqual({
        a: new Uint8Array(64),
        b: new Uint8Array(128),
        c: new Uint8Array(64),
      });
      await expect(prover.proveCustomRingDeposit({ ...input, count: 9 })).rejects.toMatchObject({
        code: "CLIENT_INVALID_PROOF_INPUTS",
      });
      expect(fetch).toHaveBeenCalledTimes(1);
      fetch.mockResolvedValueOnce(
        Response.json({ ...proofFor(customRingDepositProofRequest(input)), ar: [] }),
      );
      await expect(prover.proveCustomRingDeposit(input)).rejects.toMatchObject({
        code: "CLIENT_PROOF_PARSE",
      });
      expect(fetch).toHaveBeenCalledTimes(2);
      const deposit = { ...input, keyRegistryRoot: field(17n) };
      const indexed = {
        deposit,
        registry: { ringProgramId: RING, root: field(17n), nextIndex: 2n },
      };
      const proof = {
        ...proofFor({ circuitType: "custom-ring-deposit" }),
        proofCommitment: ["0x1", "0x2"],
        proofCommitmentPok: ["0x0", "0x0"],
      };
      const indexedFetch = vi.fn<typeof globalThis.fetch>(async () =>
        Response.json({ ...proof, resolution: { trees: [], publicInputHash: "0x1" } }),
      );
      const client = new ZolanaClient({
        fetch: indexedFetch,
        indexerConfig: { requireSlot: 42n, poll: { numRetries: 1, delayMs: 0n, maxDelayMs: 0n } },
      });
      await expect(client.proveIndexedRingDeposit(indexed)).resolves.toHaveLength(192);
      expect(String(indexedFetch.mock.lastCall?.[0])).toMatch(
        /\/prove\/custom_ring_deposit\/indexed$/u,
      );
      expect(new Headers(indexedFetch.mock.lastCall?.[1]?.headers).get("X-Sync")).toBe("true");
      const wire: unknown = JSON.parse(String(indexedFetch.mock.lastCall?.[1]?.body));
      const decoder = wireDecoder(() => new Error("invalid body"));
      const body = decoder.record(wire, "body");
      expect(body["minContextSlot"]).toBe(42);
      expect(decoder.record(body["prepared"], "prepared")["keys"]).toBeUndefined();
      indexedFetch.mockResolvedValueOnce(
        Response.json({ ...proof, resolution: { trees: [], publicInputHash: "0x2" } }),
      );
      await expect(client.proveIndexedRingDeposit(indexed)).rejects.toMatchObject({
        code: "CLIENT_PROOF_PARSE",
      });
      await expect(
        client.proveIndexedRingDeposit({
          ...indexed,
          registry: { ...indexed.registry, root: field(18n) },
        }),
      ).rejects.toMatchObject({ code: "CLIENT_INVALID_PROOF_INPUTS" });
      expect(indexedFetch).toHaveBeenCalledTimes(2);
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
    const auditor = X25519Keypair.generate();
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
    const auditor = X25519Keypair.generate();
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
        proofDataSource: "client" as const,
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

describe("deposit builder ring mode", () => {
  it("refuses an anonymous ring before reading the deposit setting", async () => {
    const auditor = X25519Keypair.generate();
    const recipient = ShieldedKeypair.generate();
    const [config, bump] = await ringConfigPda(RING);
    const proveCustomRingDeposit = vi.fn();
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
                    anonymous: true,
                  }),
                )
              : undefined,
        }),
        proofDataSource: "client" as const,
        proveCustomRingDeposit,
        getRingKeyRegistryEntry: vi.fn(async () => {
          throw new Error("the mode check comes first");
        }),
      };
      await expect(
        buildRingDepositTransaction({
          client,
          ringProgramId: RING,
          feePayer: TREE,
          recipient: recipient.shieldedAddress(),
          amount: 1n,
        }),
      ).rejects.toMatchObject({ code: "RING_BUILD_DEPOSIT", causeCode: "RING_CONFIG_INVALID" });
      expect(proveCustomRingDeposit).not.toHaveBeenCalled();
    } finally {
      auditor.destroy();
      recipient.destroy();
    }
  });
});

describe("deposit recovery", () => {
  it("refuses a ring history truncated by the page budget", async () => {
    const auditor = X25519Keypair.generate();
    const source = ShieldedKeypair.generate();
    const key = source.nullifierKey();
    const client = {
      ...ringAuditReader({
        getShieldedTransactionsByTags: async (input) =>
          transactionsPage(input.ringProgramId === undefined ? {} : { next: chainPosition(1n) }),
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
    const auditor = X25519Keypair.generate();
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
    let history = [deposit];
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
      depositSource: {
        confirmedDeposits: async () =>
          ConfirmedDeposit.fromTransaction(
            confirmedDepositTransaction(RING, deposit.txSignature, sealed.capsules, [
              ownerUtxoHash(address.ownerHash(), blinding),
            ]),
            deposit.txSignature,
            0,
            RING,
          ),
      },
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
      await expect(recoverRingMemberNotes(params)).rejects.toMatchObject({
        code: "RING_AUDIT_MESSAGE",
      });
      const unsupported = await recoverRingMemberNotes({
        ...params,
        depositSource: { confirmedDeposits: async () => [] },
      });
      expect(unsupported.unsupportedDeposits).toEqual([commitment, field(99n)]);
      history = [deposit];
      const merged = new Utxo({
        owner: address.signingPublicKey,
        asset: SOL_MINT,
        amount: 7n,
        blinding: mergeOutputBlinding(key, nullifier),
        ringProgramId: RING,
      });
      const mergedHash = merged.hash(address.nullifierPublicKey, 1, undefined, ringDataHash);
      const mergeSalt = new Uint8Array(16).fill(3) as Bytes16;
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
            payload: encodeMergeOutputData({
              ringDataHash,
              salt: mergeSalt,
              ciphertext: encryptMergeOutput(
                { amount: 7n, mint: SOL_MINT },
                mergeOutputKey(key, nullifier),
                mergeSalt,
              ),
            }),
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

describe("confirmed deposit attribution", () => {
  it("opens an unknown owner only with its confirmed capsule and rejects altered or swapped bytes", () => {
    const auditor = X25519Keypair.generate();
    const signature = "1".repeat(87) as Signature;
    const ownerKey = new Uint8Array(32).fill(7) as Bytes32;
    const owners = [ownerUtxoHash(field(1n), field(2n)), ownerUtxoHash(field(3n), field(4n))];
    const sealed = sealRingDepositOpenings(
      [
        {
          ownerHash: field(1n),
          blinding: field(2n),
          ownerKey,
          recipientCiphertext: Uint8Array.of(9),
        },
        { ownerHash: field(3n), blinding: field(4n), recipientCiphertext: Uint8Array.of(8) },
      ],
      auditor.publicKey(),
    );
    try {
      const transaction = confirmedDepositTransaction(RING, signature, sealed.capsules, owners);
      const bindings = ConfirmedDeposit.fromTransaction(transaction, signature, 0, RING);
      const first = sealed.capsules[0];
      const binding = bindings[0];
      const other = bindings[1];
      if (
        first === undefined ||
        binding === undefined ||
        other === undefined ||
        owners[0] === undefined
      )
        throw new Error("missing confirmation");
      expect(openRingDepositOpening(first, auditor, owners[0], binding).ownerKey).toEqual(ownerKey);
      const forged: unknown = Object.create(ConfirmedDeposit.prototype);
      expect(ConfirmedDeposit.is(forged)).toBe(false);
      expect(ConfirmedDeposit.is(binding)).toBe(true);
      for (const offset of [0, 32, 64, 95]) {
        const ciphertext = checkedBytes<Bytes96>(first.ciphertext, 96, "deposit ciphertext");
        ciphertext[offset] = (ciphertext[offset] ?? 0) ^ 1;
        expect(() =>
          openRingDepositOpening({ ...first, ciphertext }, auditor, owners[0]!, binding),
        ).toThrow("RING_AUDIT_MESSAGE");
      }
      expect(() =>
        openRingDepositOpening(
          { ...first, recipientCiphertext: Uint8Array.of(10) },
          auditor,
          owners[0]!,
          binding,
        ),
      ).toThrow("RING_AUDIT_MESSAGE");
      expect(() => openRingDepositOpening(first, auditor, owners[0]!, other)).toThrow(
        "RING_AUDIT_MESSAGE",
      );
      expect(() => ConfirmedDeposit.fromTransaction(transaction, signature, 1, RING)).toThrow(
        "RING_ORIGIN_DECODE",
      );
      expect(() =>
        ConfirmedDeposit.fromTransaction(transaction, "2".repeat(87) as Signature, 0, RING),
      ).toThrow("RING_ORIGIN_DECODE");
      expect(() =>
        ConfirmedDeposit.fromTransaction(
          { ...transaction, meta: { ...transaction.meta, err: { InstructionError: [0, 1] } } },
          signature,
          0,
          RING,
        ),
      ).toThrow("RING_ORIGIN_DECODE");
      const source = transaction.meta.innerInstructions[0]?.instructions[0];
      if (source === undefined) throw new Error("missing source");
      const unaudited = {
        ...transaction,
        transaction: {
          ...transaction.transaction,
          message: {
            ...transaction.transaction.message,
            instructions: [{ ...source, programIdIndex: 0 }],
          },
        },
      };
      expect(ConfirmedDeposit.fromTransaction(unaudited, signature, 0, RING)).toEqual([]);
    } finally {
      sealed.ephemeralSecret.fill(0);
      auditor.destroy();
    }
  });
});
