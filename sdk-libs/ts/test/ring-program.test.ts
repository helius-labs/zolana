import {
  AccountRole,
  SOLANA_ERROR__JSON_RPC__SERVER_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE,
  generateKeyPairSigner,
  decompileTransactionMessage,
  getAddressDecoder,
  getCompiledTransactionMessageDecoder,
  getSolanaErrorFromJsonRpcError,
  getTransactionDecoder,
  type Address,
} from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import { SYSTEM_PROGRAM } from "../src/interface/instructions/index.js";
import { addressBytes, sha256 } from "../src/interface/internal.js";
import type { Bytes32 } from "../src/interface/types.js";
import { ringPolicyConfigAddress } from "../src/interface/pda/index.js";
import { BPF_LOADER_UPGRADEABLE_ID, ringProgramDataAddress } from "../src/ring/config.js";
import { RING_POLICY_CONFIG_SIZE } from "../src/ring/codecs.js";
import {
  CLOCK_SYSVAR as CLOCK,
  RENT_SYSVAR as RENT,
  decodeRingProgramData,
  deployRingProgram,
  deployWithMaxDataLenInstruction,
  extendProgramInstruction,
  fetchRingProgramData,
  initializeBufferInstruction,
  RingProgramBinary,
  closeBufferInstruction,
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

function elf(length: number, byte = (index: number) => index % 251): Uint8Array {
  const bytes = Uint8Array.from({ length }, (_, index) => byte(index));
  bytes.fill(0, 0, 128);
  const view = new DataView(bytes.buffer);
  bytes.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]);
  view.setUint16(16, 3, true);
  view.setUint16(18, 263, true);
  view.setUint32(20, 1, true);
  view.setBigUint64(24, 128n, true);
  view.setBigUint64(32, 64n, true);
  view.setBigUint64(40, BigInt(length - 192), true);
  view.setUint16(52, 64, true);
  view.setUint16(54, 56, true);
  view.setUint16(56, 1, true);
  view.setUint16(58, 64, true);
  view.setUint16(60, 3, true);
  view.setUint16(62, 2, true);
  view.setUint32(64, 1, true);
  view.setUint32(68, 5, true);
  view.setBigUint64(72, 128n, true);
  view.setBigUint64(80, 128n, true);
  view.setBigUint64(96, BigInt(length - 344), true);
  view.setBigUint64(104, BigInt(length - 344), true);
  const names = new TextEncoder().encode("\0.text\0.shstrtab\0");
  const namesStart = length - 192 - names.length;
  bytes.set(names, namesStart);
  bytes.fill(0, length - 192);
  const text = length - 128;
  view.setUint32(text, 1, true);
  view.setUint32(text + 4, 1, true);
  view.setBigUint64(text + 8, 6n, true);
  view.setBigUint64(text + 16, 128n, true);
  view.setBigUint64(text + 24, 128n, true);
  view.setBigUint64(text + 32, BigInt(length - 344), true);
  const strings = length - 64;
  view.setUint32(strings, 7, true);
  view.setUint32(strings + 4, 3, true);
  view.setBigUint64(strings + 24, BigInt(namesStart), true);
  view.setBigUint64(strings + 32, BigInt(names.length), true);
  return bytes;
}

/** Rust `UpgradeableLoaderState::Program`. */
function programAccount(dataAddress: Address): Uint8Array {
  return Uint8Array.of(2, 0, 0, 0, ...addressBytes(dataAddress));
}

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

  it("rejects truncated ELF tables and bodies", () => {
    const complete = elf(512);
    for (const bytes of [
      new Uint8Array(),
      new Uint8Array(64),
      complete.subarray(0, 63),
      complete.subarray(0, 64),
      complete.subarray(0, 127),
      complete.subarray(0, complete.length - 1),
    ]) {
      expect(() => RingProgramBinary.parse(bytes)).toThrow(
        expect.objectContaining({ code: "RING_PROGRAM_BINARY_INVALID" }),
      );
    }
  });

  it("rejects ELF ranges beyond the complete artifact", () => {
    for (const field of [32, 40, 72, 96, 408, 416]) {
      const bytes = elf(512);
      new DataView(bytes.buffer).setBigUint64(field, 0xffff_ffff_ffff_ffffn, true);
      expect(() => RingProgramBinary.parse(bytes)).toThrow(
        expect.objectContaining({ code: "RING_PROGRAM_BINARY_INVALID" }),
      );
    }
  });

  it("rejects unchecked descriptors before reading accounts", async () => {
    const binary = RingProgramBinary.parse(elf(512));
    const client = { getAccount: vi.fn(async () => undefined) };
    for (const copy of [
      { bytes: new Uint8Array(512), sha256: binary.sha256, byteLength: binary.byteLength },
      { ...binary },
    ]) {
      // @ts-expect-error Unchecked binary descriptor.
      await expect(verifyRingProgram(client, PROGRAM, copy)).rejects.toMatchObject({
        code: "RING_PROGRAM_BINARY_INVALID",
      });
    }
    expect(client.getAccount).not.toHaveBeenCalled();
    expect(() => Reflect.construct(RingProgramBinary, [binary.bytes])).toThrow(
      expect.objectContaining({ code: "RING_PROGRAM_BINARY_INVALID" }),
    );
  });

  it("pins its bytes and hash against mutation through the exposed copy", () => {
    const binary = RingProgramBinary.parse(elf(512));
    const pinned = new Uint8Array(binary.sha256);
    binary.bytes.fill(0xff);
    binary.sha256.fill(0);
    expect(binary.bytes).toEqual(elf(512));
    expect(binary.sha256).toEqual(pinned);
    expect(binary.byteLength).toBe(512);
  });

  it("requires the artifact to cover every nonzero deployed byte", async () => {
    const bytes = elf(512);
    const longer = new Uint8Array(600);
    longer.set(bytes);
    longer[599] = 1;
    const dataAddress = await ringProgramDataAddress(PROGRAM);
    const client = {
      getAccount: async (account: Address) =>
        ownedAccount(
          BPF_LOADER_UPGRADEABLE_ID,
          account === PROGRAM
            ? programAccount(dataAddress)
            : programData({ slot: 3n, bytes: longer }),
        ),
    };
    await expect(
      verifyRingProgram(client, PROGRAM, RingProgramBinary.parse(bytes)),
    ).rejects.toMatchObject({ code: "RING_PROGRAM_NOT_DEPLOYED" });
    longer[599] = 0;
    await expect(
      verifyRingProgram(client, PROGRAM, RingProgramBinary.parse(bytes)),
    ).resolves.toMatchObject({ capacity: 600 });
  });

  it("verifies the deployed bytes and names a missing, different or occupied program", async () => {
    const binary = RingProgramBinary.parse(elf(512));
    const dataAddress = await ringProgramDataAddress(PROGRAM);
    const accounts = new Map([
      [PROGRAM, ownedAccount(BPF_LOADER_UPGRADEABLE_ID, programAccount(dataAddress))],
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
    const other = RingProgramBinary.parse(elf(512, () => 0));
    await expect(verifyRingProgram(client, PROGRAM, other)).rejects.toMatchObject({
      code: "RING_PROGRAM_MISMATCH",
    });
    accounts.set(PROGRAM, ownedAccount(BPF_LOADER_UPGRADEABLE_ID, programAccount(PAYER)));
    await expect(fetchRingProgramData(client, PROGRAM)).rejects.toMatchObject({
      code: "RING_PROGRAM_DATA_INVALID",
    });
    accounts.set(PROGRAM, ownedAccount(SYSTEM_PROGRAM, new Uint8Array()));
    await expect(fetchRingProgramData(client, PROGRAM)).rejects.toMatchObject({
      code: "RING_PROGRAM_ADDRESS_OCCUPIED",
      details: { ringProgramId: PROGRAM, owner: SYSTEM_PROGRAM },
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

  it("accepts the loader write boundary and refuses one byte beyond it", () => {
    const input = { buffer: BUFFER, authority: AUTHORITY, offset: 0 };
    const bytes = new Uint8Array(1_217).fill(7);
    expect(writeBufferInstruction({ ...input, bytes: bytes.subarray(0, 1_216) }).data).toHaveLength(
      1_232,
    );
    expect(() => writeBufferInstruction({ ...input, bytes })).toThrowError(
      expect.objectContaining({
        code: "RING_PROGRAM_WRITE_TOO_LARGE",
        details: { length: 1_217, limit: 1_216 },
      }),
    );
    expect(bytes).toEqual(new Uint8Array(1_217).fill(7));
  });

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
    const close = closeBufferInstruction({
      buffer: BUFFER,
      recipient: PAYER,
      authority: AUTHORITY,
    });
    expect([...(close.data ?? [])]).toEqual([5, 0, 0, 0]);
    expect(roles(close)).toEqual([
      [BUFFER, AccountRole.WRITABLE],
      [PAYER, AccountRole.WRITABLE],
      [AUTHORITY, AccountRole.READONLY_SIGNER],
    ]);
  });

  it("matches the Agave 4.2 loader extension encoding and accounts", async () => {
    const dataAddress = await ringProgramDataAddress(PROGRAM);
    const extend = await extendProgramInstruction({
      ringProgramId: PROGRAM,
      payer: PAYER,
      additionalBytes: 10_240,
    });
    expect([...(extend.data ?? [])]).toEqual([6, 0, 0, 0, 0, 0x28, 0, 0]);
    expect(roles(extend)).toEqual([
      [dataAddress, AccountRole.WRITABLE],
      [PROGRAM, AccountRole.WRITABLE],
      [SYSTEM_PROGRAM, AccountRole.READONLY],
      [PAYER, AccountRole.WRITABLE_SIGNER],
    ]);
  });
});

describe("deployment", () => {
  const binary = RingProgramBinary.parse(elf(3_000));
  const BUFFER_RENT = 7n * (37n + 3_000n);
  /** The deploy drains the buffer into the payer, the program data costs the difference. */
  const DEPLOY_REQUIRED = 20_000_000n + BUFFER_RENT + 7n * 36n + 7n * (45n + 3_000n) - BUFFER_RENT;

  async function signers() {
    const [payer, authority, program, buffer] = await Promise.all([
      generateKeyPairSigner(),
      generateKeyPairSigner(),
      generateKeyPairSigner(),
      generateKeyPairSigner(),
    ]);
    return {
      payer,
      authority,
      program,
      buffer,
      programData: await ringProgramDataAddress(program.address),
      policyConfig: await ringPolicyConfigAddress(program.address),
    };
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
    readonly failFirstStatusLookup?: boolean;
    readonly failFirstSend?: boolean;
    readonly rejectOnChain?: boolean;
    readonly rejectInPreflight?: boolean;
    /** The first attempt lands after its confirmation timed out. */
    readonly landLate?: boolean;
    /** The extend lands, its confirmation fails and the statuses never show it. */
    readonly hideExtendLanding?: boolean;
    /** Sends resolve only through their abort signal. */
    readonly hangSends?: boolean;
    readonly occupiedBy?: Address;
    readonly policyConfig?: Readonly<{ owner?: Address; size: number }>;
  }

  /** The extend and then the program exist once a send follows the buffer content read. */
  function chain(keys: Awaited<ReturnType<typeof signers>>, options: ChainOptions = {}) {
    const sends: number[] = [];
    const writes: { offset: number; bytes: Uint8Array }[] = [];
    const rents: bigint[] = [];
    const capacity = options.deployed?.capacity ?? options.deployed?.bytes.length ?? 0;
    const needsExtend = options.deployed !== undefined && capacity < binary.bytes.length;
    const grown = capacity + Math.max(binary.bytes.length - capacity, 10_240);
    let contentRead = 0;
    let extended = false;
    let hidden = false;
    let finished = false;
    let bufferCreated = options.buffer !== undefined;
    let inFlight = 0;
    let maxInFlight = 0;
    let slot = 10n;
    let confirmations = 0;
    let sendCalls = 0;
    let statusCalls = 0;
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
        send: async () => {
          statusCalls += 1;
          if (options.failFirstStatusLookup && statusCalls === 1) throw new Error("rate limited");
          return {
            value: [
              options.landLate && confirmations === 1
                ? { err: null, confirmationStatus: "confirmed" as const, slot: 3n }
                : null,
            ],
          };
        },
      }),
      sendTransaction: (encoded: string) => ({
        send: async ({ abortSignal }: { abortSignal?: AbortSignal }) => {
          sendCalls += 1;
          if (options.failFirstSend && sendCalls === 1) throw new Error("connection reset");
          if (options.rejectInPreflight) {
            throw getSolanaErrorFromJsonRpcError({
              code: SOLANA_ERROR__JSON_RPC__SERVER_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE,
              message: "Transaction simulation failed",
              data: { accounts: null, err: "AccountInUse", logs: [], unitsConsumed: 0n },
            });
          }
          if (options.hangSends) {
            await new Promise((_, reject) =>
              abortSignal?.addEventListener("abort", () => reject(new Error("aborted"))),
            );
          }
          const transaction = getTransactionDecoder().decode(Buffer.from(encoded, "base64"));
          const compiled = getCompiledTransactionMessageDecoder().decode(transaction.messageBytes);
          if (compiled.version !== 1) throw new Error("expected transaction version 1");
          const message = decompileTransactionMessage(compiled, { lastValidBlockHeight: 1n });
          for (const instruction of message.instructions) {
            if (instruction.programAddress !== BPF_LOADER_UPGRADEABLE_ID) continue;
            const data = new Uint8Array(instruction.data ?? []);
            const view = new DataView(data.buffer);
            if (view.getUint32(0, true) !== 1) continue;
            expect(data.length).toBeLessThanOrEqual(1_232);
            const bytes = data.slice(16);
            expect(view.getBigUint64(8, true)).toBe(BigInt(bytes.length));
            writes.push({ offset: view.getUint32(4, true), bytes });
          }
          inFlight += 1;
          maxInFlight = Math.max(maxInFlight, inFlight);
          await new Promise((resolve) => setTimeout(resolve, 1));
          inFlight -= 1;
          sends.push(Buffer.from(encoded, "base64").length);
          const dropped =
            options.rejectOnChain || (options.failFirstConfirmation && sendCalls === 1);
          if (dropped) return "1".repeat(87);
          bufferCreated = true;
          if (contentRead > 0) {
            if (needsExtend && !extended) extended = true;
            else finished = true;
          }
          return "1".repeat(87);
        },
      }),
    };
    const fake = {
      sends,
      writes,
      rents,
      maxInFlight: () => maxInFlight,
      statusCalls: () => statusCalls,
      getLatestBlockhash: vi.fn(async () => BLOCKHASH),
      getBalance: vi.fn(async () => options.balance ?? 1_000_000_000_000n),
      getAccount: vi.fn(async (account: Address) => {
        if (account === keys.buffer.address) {
          if (!bufferCreated) return undefined;
          contentRead += 1;
          return ownedAccount(options.buffer?.owner ?? BPF_LOADER_UPGRADEABLE_ID, bufferData());
        }
        if (account === keys.program.address && options.occupiedBy !== undefined) {
          return ownedAccount(options.occupiedBy, new Uint8Array());
        }
        if (account === keys.policyConfig) {
          return options.policyConfig === undefined
            ? undefined
            : ownedAccount(
                options.policyConfig.owner ?? keys.program.address,
                new Uint8Array(options.policyConfig.size),
              );
        }
        const deployed = finished
          ? {
              authority: keys.authority.address,
              bytes: binary.bytes,
              capacity: extended ? grown : binary.bytes.length,
            }
          : extended && options.deployed !== undefined
            ? { ...options.deployed, capacity: grown }
            : options.deployed;
        if (deployed === undefined) return undefined;
        if (account === keys.program.address) {
          return ownedAccount(BPF_LOADER_UPGRADEABLE_ID, programAccount(keys.programData));
        }
        return ownedAccount(BPF_LOADER_UPGRADEABLE_ID, programData({ slot: 3n, ...deployed }));
      }),
      confirmTransaction: vi.fn(async () => {
        confirmations += 1;
        if (options.hideExtendLanding && extended && !hidden) {
          hidden = true;
          throw new ClientError("CLIENT_RPC", {
            details: { method: "getSignatureStatuses", reason: "signature not confirmed" },
          });
        }
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

  it("rejects an unchecked binary before paid deployment work", async () => {
    const keys = await signers();
    const client = chain(keys);
    const unchecked = { bytes: new Uint8Array(3_000), byteLength: 3_000, sha256: binary.sha256 };
    await expect(
      deployRingProgram({
        ...params(keys, client),
        // @ts-expect-error Unchecked binary descriptor.
        binary: unchecked,
      }),
    ).rejects.toMatchObject({
      code: "RING_DEPLOY_PROGRAM",
      causeCode: "RING_PROGRAM_BINARY_INVALID",
    });
    expect(client.getAccount).not.toHaveBeenCalled();
    expect(client.getBalance).not.toHaveBeenCalled();
    expect(client.rents).toEqual([]);
    expect(client.sends).toEqual([]);
    expect(client.writes).toEqual([]);
  });

  it("deploys through version 1 packets, one blockhash per transaction, within the concurrency", async () => {
    const keys = await signers();
    const client = chain(keys);
    const outcome = await deployRingProgram({ ...params(keys, client), concurrency: 2 });
    expect(outcome.kind).toBe("deployed");
    expect(outcome.programData.upgradeAuthority).toBe(keys.authority.address);
    for (const size of client.sends) expect(size).toBeLessThanOrEqual(4096);
    // Multiple bounded loader writes share one large transaction.
    expect(client.sends.filter((size) => size > 1232)).toHaveLength(1);
    expect(client.writes.map(({ offset }) => offset)).toEqual([0, 1_216, 2_432]);
    expect(Uint8Array.from(client.writes.flatMap(({ bytes }) => [...bytes]))).toEqual(binary.bytes);
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

  it("keeps retrying when the recovery status lookup is transiently unavailable", async () => {
    const keys = await signers();
    const client = chain(keys, { failFirstConfirmation: true, failFirstStatusLookup: true });
    await expect(deployRingProgram(params(keys, client))).resolves.toMatchObject({
      kind: "deployed",
    });
    expect(client.statusCalls()).toBe(1);
    expect(client.confirmTransaction.mock.calls.length).toBeGreaterThan(1);
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
    expect(resumed.sends.length).toBeGreaterThan(0);
    expect(fresh.sends.length).toBe(resumed.sends.length + 1);
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

  it("stops at a transaction preflight refused without re-signing it", async () => {
    const keys = await signers();
    const refused = chain(keys, { rejectInPreflight: true });
    await expect(deployRingProgram(params(keys, refused))).rejects.toMatchObject({
      code: "RING_DEPLOY_PROGRAM",
      causeCode: "CLIENT_RPC",
    });
    expect(refused.getLatestBlockhash).toHaveBeenCalledTimes(1);
    expect(refused.confirmTransaction).not.toHaveBeenCalled();
  });

  it("reads the chain instead of repeating an extend whose landing stayed hidden", async () => {
    const keys = await signers();
    const deployed = { authority: keys.authority.address, bytes: new Uint8Array(1_000) };
    const hidden = chain(keys, { deployed, hideExtendLanding: true });
    await expect(deployRingProgram(params(keys, hidden))).resolves.toMatchObject({
      kind: "upgraded",
    });
    const plain = chain(keys, { deployed });
    await deployRingProgram(params(keys, plain));
    expect(hidden.sends.length).toBe(plain.sends.length);
    expect(hidden.confirmTransaction).toHaveBeenCalledTimes(plain.sends.length);
  });

  it("refuses an occupied address and bad options before any read or send", async () => {
    const keys = await signers();
    const occupied = chain(keys, { occupiedBy: SYSTEM_PROGRAM });
    await expect(deployRingProgram(params(keys, occupied))).rejects.toMatchObject({
      code: "RING_DEPLOY_PROGRAM",
      causeCode: "RING_PROGRAM_ADDRESS_OCCUPIED",
      details: undefined,
    });
    expect(occupied.sends).toHaveLength(0);
    for (const options of [{ concurrency: 0 }, { attempts: 0 }, { concurrency: 1.5 }]) {
      const client = chain(keys);
      await expect(
        deployRingProgram({ ...params(keys, client), ...options }),
      ).rejects.toMatchObject({
        code: "RING_DEPLOY_PROGRAM",
        causeCode: "RING_DEPLOY_OPTIONS_INVALID",
      });
      expect(client.getAccount).not.toHaveBeenCalled();
    }
  });

  it("gives a stalled send the deadline and names the buffer it leaves behind", async () => {
    const keys = await signers();
    const stalled = chain(keys, { hangSends: true });
    await expect(
      deployRingProgram({ ...params(keys, stalled), attempts: 1 }, { timeoutMs: 20 }),
    ).rejects.toMatchObject({
      code: "RING_DEPLOY_PROGRAM",
      causeCode: "CLIENT_TIMEOUT",
      details: { buffer: keys.buffer.address },
    });
    expect(stalled.sends).toHaveLength(0);
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

  it("refuses an upgrade the on-chain policy config would not survive before any send", async () => {
    const keys = await signers();
    const deployed = { authority: keys.authority.address, bytes: new Uint8Array(1_000) };
    const incompatible = chain(keys, {
      deployed,
      policyConfig: { size: RING_POLICY_CONFIG_SIZE - 1 },
    });
    await expect(deployRingProgram(params(keys, incompatible))).rejects.toMatchObject({
      code: "RING_DEPLOY_PROGRAM",
      causeCode: "RING_POLICY_CONFIG_INCOMPATIBLE",
    });
    expect(incompatible.sends).toHaveLength(0);
    // A foreign-owned account at the PDA is not a policy the upgraded program loads.
    const foreign = chain(keys, { deployed, policyConfig: { owner: SYSTEM_PROGRAM, size: 0 } });
    await expect(deployRingProgram(params(keys, foreign))).resolves.toMatchObject({
      kind: "upgraded",
    });
    const compatible = chain(keys, { deployed, policyConfig: { size: RING_POLICY_CONFIG_SIZE } });
    await expect(deployRingProgram(params(keys, compatible))).resolves.toMatchObject({
      kind: "upgraded",
    });
  });
});
