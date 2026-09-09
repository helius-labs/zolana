import { AccountRole, generateKeyPairSigner, getAddressDecoder, type Address } from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import { SYSTEM_PROGRAM } from "../src/interface/instructions/index.js";
import { addressBytes, sha256 } from "../src/interface/internal.js";
import type { Bytes32 } from "../src/interface/types.js";
import { BPF_LOADER_UPGRADEABLE_ID, ringProgramDataAddress } from "../src/ring/config.js";
import {
  CLOCK_SYSVAR as CLOCK,
  RENT_SYSVAR as RENT,
  decodeRingProgramData,
  deployRingProgram,
  deployWithMaxDataLenInstruction,
  extendProgramInstruction,
  fetchRingProgramData,
  initializeBufferInstruction,
  ringProgramBinary,
  setUpgradeAuthorityInstruction,
  upgradeInstruction,
  verifyRingProgram,
  writeBufferInstruction,
} from "../src/ring/program.js";

import { ClientError } from "../src/client/error.js";

import { BLOCKHASH, solanaRpcReads } from "./helpers/clients.js";
import { ownedAccount } from "./helpers/ring-accounts.js";

const filled = (byte: number): Bytes32 => new Uint8Array(32).fill(byte) as Bytes32;
const addressOf = (byte: number): Address => getAddressDecoder().decode(filled(byte));
const PROGRAM = addressOf(10);
const AUTHORITY = addressOf(12);
const PAYER = addressOf(11);
const BUFFER = addressOf(13);

/** Rust `UpgradeableLoaderState::ProgramData` followed by `bytes`, padded to `capacity`. */
function programData(
  input: Readonly<{ slot: bigint; authority?: Address; bytes: Uint8Array; capacity?: number }>,
): Uint8Array {
  const data = new Uint8Array(45 + (input.capacity ?? input.bytes.length));
  data[0] = 3;
  new DataView(data.buffer).setBigUint64(4, input.slot, true);
  if (input.authority !== undefined) {
    data[12] = 1;
    data.set(addressBytes(input.authority), 13);
  }
  data.set(input.bytes, 45);
  return data;
}

describe("program data", () => {
  it("reads the slot, the authority and the deployed hash", () => {
    const bytes = Uint8Array.from({ length: 100 }, (_, index) => index);
    const decoded = decodeRingProgramData(
      programData({ slot: 7n, authority: AUTHORITY, bytes, capacity: 150 }),
    );
    expect(decoded.lastDeploySlot).toBe(7n);
    expect(decoded.upgradeAuthority).toBe(AUTHORITY);
    expect(decoded.capacity).toBe(150);
    expect(decoded.deployedHash(100)).toEqual(sha256(bytes));
    expect(decoded.deployedHash(151)).toBeUndefined();
    expect(
      decodeRingProgramData(programData({ slot: 1n, bytes })).upgradeAuthority,
    ).toBeUndefined();
    expect(() => decodeRingProgramData(new Uint8Array(44))).toThrow(
      expect.objectContaining({ code: "RING_PROGRAM_DATA_INVALID" }),
    );
    const buffer = programData({ slot: 1n, bytes });
    buffer[0] = 1;
    expect(() => decodeRingProgramData(buffer)).toThrow(
      expect.objectContaining({ code: "RING_PROGRAM_DATA_INVALID" }),
    );
  });

  it("verifies the deployed bytes and names a missing or different program", async () => {
    const binary = ringProgramBinary(Uint8Array.from({ length: 40 }, (_, index) => index));
    const dataAddress = await ringProgramDataAddress(PROGRAM);
    const accounts = new Map([
      [PROGRAM, ownedAccount(BPF_LOADER_UPGRADEABLE_ID, new Uint8Array(36))],
      [
        dataAddress,
        ownedAccount(
          BPF_LOADER_UPGRADEABLE_ID,
          programData({ slot: 3n, authority: AUTHORITY, bytes: binary.bytes }),
        ),
      ],
    ]);
    const client = { getAccount: vi.fn(async (account: Address) => accounts.get(account)) };
    await expect(verifyRingProgram(client, PROGRAM, binary)).resolves.toMatchObject({
      lastDeploySlot: 3n,
    });
    const other = ringProgramBinary(new Uint8Array(40));
    await expect(verifyRingProgram(client, PROGRAM, other)).rejects.toMatchObject({
      code: "RING_PROGRAM_MISMATCH",
    });
    accounts.delete(PROGRAM);
    await expect(fetchRingProgramData(client, PROGRAM)).resolves.toBeUndefined();
    await expect(verifyRingProgram(client, PROGRAM, binary)).rejects.toMatchObject({
      code: "RING_PROGRAM_NOT_DEPLOYED",
    });
  });
});

describe("loader instructions", () => {
  const roles = (instruction: { accounts?: readonly { address: Address; role: AccountRole }[] }) =>
    instruction.accounts?.map((meta) => [meta.address, meta.role]);

  it("encode the bincode tags and account orders of the upgradeable loader", async () => {
    const dataAddress = await ringProgramDataAddress(PROGRAM);
    const initialize = initializeBufferInstruction({ buffer: BUFFER, authority: AUTHORITY });
    expect(initialize.programAddress).toBe(BPF_LOADER_UPGRADEABLE_ID);
    expect([...(initialize.data ?? [])]).toEqual([0, 0, 0, 0]);
    expect(roles(initialize)).toEqual([
      [BUFFER, AccountRole.WRITABLE],
      [AUTHORITY, AccountRole.READONLY],
    ]);
    const write = writeBufferInstruction({
      buffer: BUFFER,
      authority: AUTHORITY,
      offset: 42,
      bytes: Uint8Array.of(1, 2, 3, 4, 5),
    });
    expect([...(write.data ?? [])]).toEqual([
      1, 0, 0, 0, 42, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5,
    ]);
    expect(roles(write)).toEqual([
      [BUFFER, AccountRole.WRITABLE],
      [AUTHORITY, AccountRole.READONLY_SIGNER],
    ]);
    const deploy = await deployWithMaxDataLenInstruction({
      payer: PAYER,
      ringProgramId: PROGRAM,
      buffer: BUFFER,
      authority: AUTHORITY,
      maxDataLen: 1_000_000,
    });
    expect([...(deploy.data ?? [])]).toEqual([2, 0, 0, 0, 0x40, 0x42, 0x0f, 0, 0, 0, 0, 0]);
    expect(roles(deploy)).toEqual([
      [PAYER, AccountRole.WRITABLE_SIGNER],
      [dataAddress, AccountRole.WRITABLE],
      [PROGRAM, AccountRole.WRITABLE],
      [BUFFER, AccountRole.WRITABLE],
      [RENT, AccountRole.READONLY],
      [CLOCK, AccountRole.READONLY],
      [SYSTEM_PROGRAM, AccountRole.READONLY],
      [AUTHORITY, AccountRole.READONLY_SIGNER],
    ]);
    const upgrade = await upgradeInstruction({
      ringProgramId: PROGRAM,
      buffer: BUFFER,
      spill: PAYER,
      authority: AUTHORITY,
    });
    expect([...(upgrade.data ?? [])]).toEqual([3, 0, 0, 0]);
    expect(roles(upgrade)).toEqual([
      [dataAddress, AccountRole.WRITABLE],
      [PROGRAM, AccountRole.WRITABLE],
      [BUFFER, AccountRole.WRITABLE],
      [PAYER, AccountRole.WRITABLE],
      [RENT, AccountRole.READONLY],
      [CLOCK, AccountRole.READONLY],
      [AUTHORITY, AccountRole.READONLY_SIGNER],
    ]);
    const renounce = await setUpgradeAuthorityInstruction({
      ringProgramId: PROGRAM,
      authority: AUTHORITY,
    });
    expect([...(renounce.data ?? [])]).toEqual([4, 0, 0, 0]);
    expect(roles(renounce)).toEqual([
      [dataAddress, AccountRole.WRITABLE],
      [AUTHORITY, AccountRole.READONLY_SIGNER],
    ]);
    const handover = await setUpgradeAuthorityInstruction({
      ringProgramId: PROGRAM,
      authority: AUTHORITY,
      newAuthority: PAYER,
    });
    expect(roles(handover)?.at(-1)).toEqual([PAYER, AccountRole.READONLY]);
  });

  it("matches solana-loader-v3-interface 6.1.0 checked extension", async () => {
    const dataAddress = await ringProgramDataAddress(PROGRAM);
    const extend = await extendProgramInstruction({
      ringProgramId: PROGRAM,
      payer: PAYER,
      authority: AUTHORITY,
      additionalBytes: 10_240,
    });
    expect([...(extend.data ?? [])]).toEqual([9, 0, 0, 0, 0, 0x28, 0, 0]);
    expect(roles(extend)).toEqual([
      [dataAddress, AccountRole.WRITABLE],
      [PROGRAM, AccountRole.WRITABLE],
      [AUTHORITY, AccountRole.WRITABLE_SIGNER],
      [SYSTEM_PROGRAM, AccountRole.READONLY],
      [PAYER, AccountRole.WRITABLE_SIGNER],
    ]);
  });
});

describe("deployment", () => {
  const binary = ringProgramBinary(Uint8Array.from({ length: 3_000 }, (_, index) => index % 251));
  const BUFFER_RENT = 7n * (37n + 3_000n);
  const DEPLOY_REQUIRED = 20_000_000n + BUFFER_RENT + 7n * 36n + 7n * (45n + 3_000n);

  async function signers() {
    const [payer, authority, program, buffer] = await Promise.all([
      generateKeyPairSigner(),
      generateKeyPairSigner(),
      generateKeyPairSigner(),
      generateKeyPairSigner(),
    ]);
    return { payer, authority, program, buffer };
  }

  interface ChainOptions {
    readonly deployed?: Readonly<{ authority?: Address; bytes: Uint8Array; capacity?: number }>;
    readonly buffer?: Readonly<{
      authority: Address;
      owner?: Address;
      size?: number;
      state?: number;
    }>;
    readonly balance?: bigint;
    readonly bufferContent?: Uint8Array;
    readonly failFirstConfirmation?: boolean;
    readonly failFirstSend?: boolean;
    readonly rejectOnChain?: boolean;
    /** The first attempt lands after its confirmation timed out. */
    readonly landLate?: boolean;
  }

  /** The program exists once a send follows the buffer content read. */
  function chain(keys: Awaited<ReturnType<typeof signers>>, options: ChainOptions = {}) {
    const sends: number[] = [];
    const rents: bigint[] = [];
    let contentRead = 0;
    let finished = false;
    let bufferCreated = options.buffer !== undefined;
    let inFlight = 0;
    let maxInFlight = 0;
    let slot = 10n;
    let confirmations = 0;
    let sendCalls = 0;
    const bufferData = () => {
      const size = options.buffer?.size ?? 37 + binary.bytes.length;
      const data = new Uint8Array(size);
      data[0] = options.buffer?.state ?? 1;
      data[4] = 1;
      data.set(addressBytes(options.buffer?.authority ?? keys.authority.address), 5);
      data.set((options.bufferContent ?? binary.bytes).subarray(0, Math.max(0, size - 37)), 37);
      return data;
    };
    const rpc = {
      getMinimumBalanceForRentExemption: (space: bigint) => ({
        send: async () => {
          rents.push(space);
          return space * 7n;
        },
      }),
      getSlot: () => ({ send: async () => (slot += 1n) }),
      getSignatureStatuses: () => ({
        send: async () => ({
          value: [
            options.landLate && confirmations === 1
              ? { err: null, confirmationStatus: "confirmed" as const, slot: 3n }
              : null,
          ],
        }),
      }),
      sendTransaction: (encoded: string) => ({
        send: async () => {
          sendCalls += 1;
          if (options.failFirstSend && sendCalls === 1) throw new Error("connection reset");
          inFlight += 1;
          maxInFlight = Math.max(maxInFlight, inFlight);
          await new Promise((resolve) => setTimeout(resolve, 1));
          inFlight -= 1;
          sends.push(Buffer.from(encoded, "base64").length);
          bufferCreated = true;
          if (contentRead > 0) finished = true;
          return "1".repeat(87);
        },
      }),
    };
    const fake = {
      sends,
      rents,
      maxInFlight: () => maxInFlight,
      getLatestBlockhash: vi.fn(async () => BLOCKHASH),
      getBalance: vi.fn(async () => options.balance ?? 1_000_000_000_000n),
      getAccount: vi.fn(async (account: Address) => {
        if (account === keys.buffer.address) {
          if (!bufferCreated) return undefined;
          contentRead += 1;
          return ownedAccount(options.buffer?.owner ?? BPF_LOADER_UPGRADEABLE_ID, bufferData());
        }
        const deployed = finished
          ? { authority: keys.authority.address, bytes: binary.bytes }
          : options.deployed;
        if (deployed === undefined) return undefined;
        if (account === keys.program.address) {
          return ownedAccount(BPF_LOADER_UPGRADEABLE_ID, new Uint8Array(36));
        }
        return ownedAccount(BPF_LOADER_UPGRADEABLE_ID, programData({ slot: 3n, ...deployed }));
      }),
      confirmTransaction: vi.fn(async () => {
        confirmations += 1;
        if (options.rejectOnChain) {
          throw new ClientError("CLIENT_RPC", {
            details: { method: "getSignatureStatuses", reason: "transaction failed" },
          });
        }
        if ((options.failFirstConfirmation || options.landLate) && confirmations === 1) {
          throw new ClientError("CLIENT_RPC", {
            details: { method: "getSignatureStatuses", reason: "signature not confirmed" },
          });
        }
        return 3n;
      }),
      solanaRpc: solanaRpcReads(rpc),
      commitment: "confirmed" as const,
    };
    return fake;
  }

  const params = (keys: Awaited<ReturnType<typeof signers>>, client: ReturnType<typeof chain>) => ({
    client,
    ringProgramId: keys.program.address,
    binary,
    payer: keys.payer,
    authority: keys.authority,
    program: keys.program,
    buffer: keys.buffer,
  });

  it("deploys through full packets, one blockhash per transaction, within the concurrency", async () => {
    const keys = await signers();
    const client = chain(keys);
    const outcome = await deployRingProgram({ ...params(keys, client), concurrency: 2 });
    expect(outcome.kind).toBe("deployed");
    expect(outcome.programData.upgradeAuthority).toBe(keys.authority.address);
    expect(client.sends.length).toBeGreaterThan(4);
    for (const size of client.sends) expect(size).toBeLessThanOrEqual(1232);
    expect(client.sends.filter((size) => size === 1232).length).toBeGreaterThanOrEqual(3);
    expect(client.getLatestBlockhash).toHaveBeenCalledTimes(client.sends.length);
    expect(client.maxInFlight()).toBeLessThanOrEqual(2);
    expect(client.rents).toEqual([37n + 3_000n, 36n, 45n + 3_000n]);
  });

  it("resends a dropped transaction under a fresh blockhash and keeps a late landing", async () => {
    const keys = await signers();
    const dropped = chain(keys, { failFirstConfirmation: true });
    await deployRingProgram(params(keys, dropped));
    expect(dropped.getLatestBlockhash).toHaveBeenCalledTimes(dropped.sends.length);
    const reset = chain(keys, { failFirstSend: true });
    await deployRingProgram(params(keys, reset));
    expect(reset.getLatestBlockhash).toHaveBeenCalledTimes(reset.sends.length + 1);
    const late = chain(keys, { landLate: true });
    await deployRingProgram(params(keys, late));
    expect(late.getLatestBlockhash).toHaveBeenCalledTimes(late.sends.length);
    await expect(
      deployRingProgram({
        ...params(keys, chain(keys, { failFirstConfirmation: true })),
        attempts: 1,
      }),
    ).rejects.toMatchObject({ code: "RING_DEPLOY_PROGRAM", causeCode: "CLIENT_RPC" });
  });

  it("stops at a transaction the chain refused without re-signing it", async () => {
    const keys = await signers();
    const refused = chain(keys, { rejectOnChain: true });
    await expect(deployRingProgram(params(keys, refused))).rejects.toMatchObject({
      code: "RING_DEPLOY_PROGRAM",
      causeCode: "CLIENT_RPC",
    });
    expect(refused.confirmTransaction).toHaveBeenCalledTimes(1);
    expect(refused.getLatestBlockhash).toHaveBeenCalledTimes(1);
  });

  it("resumes an interrupted upload and refuses a buffer it cannot own", async () => {
    const keys = await signers();
    const fresh = chain(keys);
    await deployRingProgram(params(keys, fresh));
    const resumed = chain(keys, { buffer: { authority: keys.authority.address } });
    await deployRingProgram(params(keys, resumed));
    expect(fresh.rents).toContain(37n + 3_000n);
    expect(resumed.rents).not.toContain(37n + 3_000n);
    expect(resumed.sends.length).toBeGreaterThan(0);
    const invalid: readonly NonNullable<ChainOptions["buffer"]>[] = [
      { authority: keys.payer.address },
      { authority: keys.authority.address, owner: keys.payer.address },
      { authority: keys.authority.address, size: 37 + 2_999 },
      { authority: keys.authority.address, state: 3 },
    ];
    for (const buffer of invalid) {
      const client = chain(keys, { buffer });
      await expect(deployRingProgram(params(keys, client))).rejects.toMatchObject({
        code: "RING_DEPLOY_PROGRAM",
        causeCode: "RING_PROGRAM_BUFFER_INVALID",
      });
      expect(client.sends).toHaveLength(0);
    }
  });

  it("refuses unwritten content after the upload and a short balance before it", async () => {
    const keys = await signers();
    const tampered = chain(keys, { bufferContent: new Uint8Array(binary.bytes.length) });
    await expect(deployRingProgram(params(keys, tampered))).rejects.toMatchObject({
      code: "RING_DEPLOY_PROGRAM",
      causeCode: "RING_PROGRAM_BUFFER_INVALID",
    });
    expect(tampered.sends.length).toBeGreaterThan(0);
    const poor = chain(keys, { balance: DEPLOY_REQUIRED - 1n });
    await expect(deployRingProgram(params(keys, poor))).rejects.toMatchObject({
      code: "RING_DEPLOY_PROGRAM",
      causeCode: "RING_PROGRAM_UNDERFUNDED",
    });
    expect(poor.sends).toHaveLength(0);
    await expect(
      deployRingProgram(params(keys, chain(keys, { balance: DEPLOY_REQUIRED }))),
    ).resolves.toMatchObject({ kind: "deployed" });
  });

  it("upgrades, extending in its own transaction and waiting out the extend slot", async () => {
    const keys = await signers();
    const grown = chain(keys, {
      deployed: { authority: keys.authority.address, bytes: new Uint8Array(1_000) },
    });
    await expect(deployRingProgram(params(keys, grown))).resolves.toMatchObject({
      kind: "upgraded",
    });
    expect(grown.rents).toEqual([37n + 3_000n, 45n + 1_000n, 45n + 1_000n + 10_240n]);
    const roomy = chain(keys, {
      deployed: {
        authority: keys.authority.address,
        bytes: new Uint8Array(1_000),
        capacity: 4_000,
      },
    });
    await expect(deployRingProgram(params(keys, roomy))).resolves.toMatchObject({
      kind: "upgraded",
    });
    expect(roomy.rents).toEqual([37n + 3_000n]);
    expect(grown.sends.length).toBe(roomy.sends.length + 1);
    expect(grown.getAccount.mock.calls.length).toBeGreaterThan(roomy.getAccount.mock.calls.length);
  });

  it("reports a present binary and refuses the wrong authority or keypair", async () => {
    const keys = await signers();
    const present = chain(keys, {
      deployed: { authority: keys.authority.address, bytes: binary.bytes },
    });
    await expect(deployRingProgram(params(keys, present))).resolves.toMatchObject({
      kind: "present",
    });
    expect(present.sends).toHaveLength(0);
    const foreign = chain(keys, {
      deployed: { authority: keys.payer.address, bytes: binary.bytes },
    });
    await expect(deployRingProgram(params(keys, foreign))).rejects.toMatchObject({
      code: "RING_DEPLOY_PROGRAM",
      causeCode: "RING_PROGRAM_AUTHORITY_MISMATCH",
    });
    const immutable = chain(keys, { deployed: { bytes: binary.bytes } });
    await expect(deployRingProgram(params(keys, immutable))).rejects.toMatchObject({
      code: "RING_DEPLOY_PROGRAM",
      causeCode: "RING_PROGRAM_IMMUTABLE",
    });
    const { program, ...withoutProgram } = params(keys, chain(keys));
    await expect(deployRingProgram(withoutProgram)).rejects.toMatchObject({
      code: "RING_DEPLOY_PROGRAM",
      causeCode: "RING_PROGRAM_KEYPAIR_INVALID",
    });
    expect(program.address).toBe(keys.program.address);
  });
});
