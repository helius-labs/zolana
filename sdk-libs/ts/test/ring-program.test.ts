import { AccountRole, getAddressDecoder, type Address } from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import { SYSTEM_PROGRAM } from "../src/interface/instructions/index.js";
import { addressBytes, sha256 } from "../src/interface/internal.js";
import { transactionSize } from "../src/interface/transaction-size.js";
import type { Bytes32 } from "../src/interface/types.js";
import { BPF_LOADER_UPGRADEABLE_ID, ringProgramDataAddress } from "../src/ring/config.js";
import {
  CLOCK_SYSVAR as CLOCK,
  RENT_SYSVAR as RENT,
  decodeRingProgramData,
  deployWithMaxDataLenInstruction,
  extendProgramInstruction,
  fetchRingProgramData,
  initializeBufferInstruction,
  planRingProgramDeployment,
  ringProgramBinary,
  setUpgradeAuthorityInstruction,
  upgradeInstruction,
  verifyRingProgram,
  writeBufferInstruction,
} from "../src/ring/program.js";

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
  it("encode the bincode tags and account orders of the upgradeable loader", async () => {
    const dataAddress = await ringProgramDataAddress(PROGRAM);
    const roles = (instruction: {
      accounts?: readonly { address: Address; role: AccountRole }[];
    }) => instruction.accounts?.map((meta) => [meta.address, meta.role]);
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

describe("deployment planning", () => {
  const binary = ringProgramBinary(Uint8Array.from({ length: 3_000 }, (_, index) => index % 251));

  async function client(
    deployed?: Readonly<{ authority?: Address; bytes: Uint8Array; capacity?: number }>,
  ) {
    const accounts = new Map<Address, ReturnType<typeof ownedAccount>>();
    if (deployed !== undefined) {
      accounts.set(PROGRAM, ownedAccount(BPF_LOADER_UPGRADEABLE_ID, new Uint8Array(36)));
      accounts.set(
        await ringProgramDataAddress(PROGRAM),
        ownedAccount(BPF_LOADER_UPGRADEABLE_ID, programData({ slot: 3n, ...deployed })),
      );
    }
    const rents: bigint[] = [];
    return {
      rents,
      getAccount: vi.fn(async (account: Address) => accounts.get(account)),
      getLatestBlockhash: vi.fn(async () => BLOCKHASH),
      solanaRpc: solanaRpcReads({
        getMinimumBalanceForRentExemption: (space: bigint) => ({
          send: async () => {
            rents.push(space);
            return space * 7n;
          },
        }),
      }),
      commitment: "confirmed" as const,
    };
  }

  const params = (fake: Awaited<ReturnType<typeof client>>) => ({
    client: fake,
    ringProgramId: PROGRAM,
    binary,
    authority: AUTHORITY,
    payer: PAYER,
    buffer: BUFFER,
  });

  it("plans a first deploy with full writes and the program keypair on the finish", async () => {
    const fake = await client();
    const plan = await planRingProgramDeployment(params(fake));
    expect(plan.kind).toBe("deploy");
    if (plan.kind !== "deploy") return;
    expect(Object.keys(plan.prepare.signatures).sort()).toEqual([PAYER, BUFFER].sort());
    expect(Object.keys(plan.finish.signatures).sort()).toEqual([PAYER, PROGRAM, AUTHORITY].sort());
    expect(plan.writes.length).toBeGreaterThan(2);
    for (const write of plan.writes.slice(0, -1)) {
      expect(transactionSize(write)).toBe(1232);
      expect(Object.keys(write.signatures).sort()).toEqual([PAYER, AUTHORITY].sort());
    }
    const priced = await planRingProgramDeployment({
      ...params(await client()),
      computeUnitPriceMicroLamports: 1_000n,
    });
    if (priced.kind !== "deploy") throw new Error("expected a deploy");
    expect(priced.writes.length).toBeGreaterThanOrEqual(plan.writes.length);
    for (const write of priced.writes) expect(transactionSize(write)).toBeLessThanOrEqual(1232);
    expect(fake.rents).toEqual([37n + 3_000n, 36n, 45n + 3_000n]);
    expect(plan.requiredLamports).toBe(20_000_000n + 7n * (37n + 3_000n + 36n + 45n + 3_000n));
  });

  it("plans an upgrade with an extension when the binary outgrew the program data", async () => {
    const fake = await client({ authority: AUTHORITY, bytes: new Uint8Array(1_000) });
    const plan = await planRingProgramDeployment(params(fake));
    expect(plan.kind).toBe("upgrade");
    if (plan.kind !== "upgrade") return;
    expect(Object.keys(plan.finish.signatures).sort()).toEqual([PAYER, AUTHORITY].sort());
    expect(fake.rents).toEqual([37n + 3_000n, 45n + 1_000n, 45n + 1_000n + 10_240n]);
    expect(plan.requiredLamports).toBe(20_000_000n + 7n * (37n + 3_000n) + 7n * 10_240n);
    const same = await client({
      authority: AUTHORITY,
      bytes: new Uint8Array(1_000),
      capacity: 4_000,
    });
    const grown = await planRingProgramDeployment(params(same));
    expect(grown.kind).toBe("upgrade");
    expect(same.rents).toEqual([37n + 3_000n]);
  });

  it("reports a present binary and refuses a foreign or renounced authority", async () => {
    const present = await client({ authority: AUTHORITY, bytes: binary.bytes });
    await expect(planRingProgramDeployment(params(present))).resolves.toMatchObject({
      kind: "present",
    });
    expect(present.getLatestBlockhash).not.toHaveBeenCalled();
    const foreign = await client({ authority: PAYER, bytes: binary.bytes });
    await expect(planRingProgramDeployment(params(foreign))).rejects.toMatchObject({
      code: "RING_BUILD_PROGRAM",
      causeCode: "RING_PROGRAM_AUTHORITY_MISMATCH",
    });
    const immutable = await client({ bytes: binary.bytes });
    await expect(planRingProgramDeployment(params(immutable))).rejects.toMatchObject({
      code: "RING_BUILD_PROGRAM",
      causeCode: "RING_PROGRAM_IMMUTABLE",
    });
  });
});
