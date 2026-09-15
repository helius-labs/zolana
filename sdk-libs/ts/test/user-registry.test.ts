import { readFileSync } from "node:fs";

import {
  AccountRole,
  address,
  appendTransactionMessageInstructions,
  assertIsFullySignedTransaction,
  blockhash,
  compileTransaction,
  createKeyPairSignerFromPrivateKeyBytes,
  createTransactionMessage,
  getAddressEncoder,
  getCompiledTransactionMessageDecoder,
  pipe,
  setTransactionMessageFeePayerSigner,
  setTransactionMessageLifetimeUsingBlockhash,
  signTransactionMessageWithSigners,
  type Instruction,
} from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import { getUserRecordAddress } from "../src/addresses.js";
import { compileUnsignedTransaction } from "../src/flows/compile.js";
import {
  getRegisterInstruction,
  getSetMergingEnabledInstruction,
  type RegisterInstructionData,
} from "../src/instructions.js";
import { type Bytes32, type Bytes33, USER_REGISTRY_PROGRAM_ID } from "../src/interface/index.js";
import { userRecordPda } from "../src/interface/pda/index.js";
import { ShieldedKeypair, SigningKey } from "../src/keypair/index.js";
import { checkedBytes } from "../src/keypair/bytes.js";
import { buildRegistrationTransaction, buildSetMergingEnabledTransaction } from "../src/index.js";

const fixtures = readFileSync(new URL("../fixtures/user-registry.txt", import.meta.url), "utf8")
  .trim()
  .split("\n")
  .map((line) => line.split(" "));
const OWNER = address("US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx");
const RECORD = address("AfUWiF4smfE7Uxi1n5QY94eoU4wahDg9nHtzmE31z8Er");
const DATA: RegisterInstructionData = {
  ownerP256: undefined,
  nullifierPublicKey: checkedBytes<Bytes32>(
    Uint8Array.from({ length: 32 }, (_, index) => index),
    32,
    "nullifierPublicKey",
  ),
  viewingPublicKey: checkedBytes<Bytes33>(
    Uint8Array.from({ length: 33 }, (_, index) => index + 32),
    33,
    "viewingPublicKey",
  ),
};
const LIFETIME = {
  blockhash: blockhash("11111111111111111111111111111111"),
  lastValidBlockHeight: 1n,
};

function rustInstruction(name: string): Instruction {
  const [, program, hex, ...accounts] = fixtures.find(([kind]) => kind === name)!;
  return {
    programAddress: address(program!),
    data: new Uint8Array(Buffer.from(hex!, "hex")),
    accounts: accounts.map((entry) => {
      const [key, writable, signer] = entry.split(":");
      return {
        address: address(key!),
        role: [
          AccountRole.READONLY,
          AccountRole.WRITABLE,
          AccountRole.READONLY_SIGNER,
          AccountRole.WRITABLE_SIGNER,
        ][Number(writable) + 2 * Number(signer)]!,
      };
    }),
  };
}

describe("user-registry instructions", () => {
  it.each(fixtures.filter(([kind]) => kind === "pda"))(
    "matches the Rust %s for owner %s",
    async (_kind, owner, record, bump) => {
      expect(await getUserRecordAddress(address(owner!))).toBe(record);
      expect(await userRecordPda(address(owner!))).toEqual([record, Number(bump)]);
    },
  );

  it("matches Rust register bytes, account order, and roles", () => {
    expect(getRegisterInstruction({ userRecord: RECORD, owner: OWNER, data: DATA })).toEqual(
      rustInstruction("register"),
    );
  });

  it.each([true, false])("matches Rust merge opt-in with enabled=%s", (enabled) => {
    expect(getSetMergingEnabledInstruction({ userRecord: RECORD, owner: OWNER, enabled })).toEqual(
      rustInstruction(enabled ? "enableMerging" : "disableMerging"),
    );
  });

  it("rejects P256 owner registration at runtime", () => {
    expect(() =>
      getRegisterInstruction({
        userRecord: RECORD,
        owner: OWNER,
        data: {
          ...DATA,
          // @ts-expect-error -- P256 owners require unsupported proof-of-possession composition.
          ownerP256: new Uint8Array(33),
        },
      }),
    ).toThrow(expect.objectContaining({ code: "INTERFACE_CODEC" }));
  });

  it.each(["nullifierPublicKey", "viewingPublicKey"] as const)("checks %s length", (field) => {
    expect(() =>
      getRegisterInstruction({
        userRecord: RECORD,
        owner: OWNER,
        data: { ...DATA, [field]: new Uint8Array(31) },
      }),
    ).toThrow(expect.objectContaining({ code: "INTERFACE_INVALID_LENGTH" }));
  });

  it("composes registration and merge opt-in into one Kit transaction with the owner signer", async () => {
    const signer = await createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(7));
    const owner = { ...signer, signTransactions: vi.fn(signer.signTransactions) };
    const userRecord = await getUserRecordAddress(owner.address);
    const instructions = [
      getRegisterInstruction({ userRecord, owner, data: DATA }),
      getSetMergingEnabledInstruction({ userRecord, owner, enabled: true }),
    ];
    expect(owner.signTransactions).not.toHaveBeenCalled();
    for (const instruction of instructions) {
      expect(instruction.accounts?.[1]).toHaveProperty("signer", owner);
    }
    const message = pipe(
      createTransactionMessage({ version: 0 }),
      (message) => setTransactionMessageFeePayerSigner(owner, message),
      (message) => setTransactionMessageLifetimeUsingBlockhash(LIFETIME, message),
      (message) => appendTransactionMessageInstructions(instructions, message),
    );
    const unsigned = compileTransaction(message);
    expect(Object.keys(unsigned.signatures)).toEqual([owner.address]);
    const compiled = getCompiledTransactionMessageDecoder().decode(unsigned.messageBytes);
    if (compiled.version !== 0) throw new Error("Expected a v0 transaction");
    expect(compiled.instructions.map((instruction) => instruction.data)).toEqual(
      instructions.map((instruction) => instruction.data),
    );
    expect(compiled.instructions.map((instruction) => instruction.accountIndices)).toEqual([
      [
        compiled.staticAccounts.indexOf(userRecord),
        0,
        compiled.staticAccounts.indexOf(address("11111111111111111111111111111111")),
      ],
      [compiled.staticAccounts.indexOf(userRecord), 0],
    ]);
    const signed = await signTransactionMessageWithSigners(message);
    assertIsFullySignedTransaction(signed);
    expect(owner.signTransactions).toHaveBeenCalledOnce();
  });
});

function registrationFixture() {
  const shieldedAddress = ShieldedKeypair.fromKeypair(
    SigningKey.fromEd25519Bytes(checkedBytes<Bytes32>(new Uint8Array(32).fill(7), 32, "seed")),
  ).shieldedAddress();
  const data = {
    nullifierPublicKey: shieldedAddress.nullifierPublicKey,
    viewingPublicKey: shieldedAddress.viewingPublicKey.toBytes(),
  };
  const recordData = Uint8Array.of(
    1,
    ...getAddressEncoder().encode(OWNER),
    255,
    0,
    ...data.nullifierPublicKey,
    ...data.viewingPublicKey,
    1,
  );
  const record = { owner: USER_REGISTRY_PROGRAM_ID, data: recordData, lamports: 1n };
  return { shieldedAddress, data, recordData, record };
}

describe("registry transaction helper compatibility", () => {
  const context = { timeoutMs: 1_000 };

  it("registers a missing record using the public instruction", async () => {
    const { shieldedAddress, data } = registrationFixture();
    const client = {
      getAccount: vi.fn(async () => undefined),
      getLatestBlockhash: vi.fn(async () => LIFETIME),
    };
    expect(
      await buildRegistrationTransaction(
        { client, owner: OWNER, address: shieldedAddress },
        context,
      ),
    ).toEqual(
      compileUnsignedTransaction({
        feePayer: OWNER,
        lifetime: LIFETIME,
        instructions: [getRegisterInstruction({ userRecord: RECORD, owner: OWNER, data })],
      }),
    );
    expect(client.getAccount).toHaveBeenCalledExactlyOnceWith(RECORD, context);
    expect(client.getLatestBlockhash).toHaveBeenCalledExactlyOnceWith(context);
  });

  it("returns undefined without a blockhash when the published keys already match", async () => {
    const { shieldedAddress, record } = registrationFixture();
    const client = { getAccount: vi.fn(async () => record), getLatestBlockhash: vi.fn() };
    expect(
      await buildRegistrationTransaction({ client, owner: OWNER, address: shieldedAddress }),
    ).toBeUndefined();
    expect(client.getLatestBlockhash).not.toHaveBeenCalled();
  });

  it("updates differing keys with discriminator 2 and no system account", async () => {
    const { shieldedAddress, data, record, recordData } = registrationFixture();
    const client = {
      getAccount: vi.fn(async () => ({
        ...record,
        data: Uint8Array.of(
          ...recordData.slice(0, 35),
          ...DATA.nullifierPublicKey,
          ...DATA.viewingPublicKey,
          1,
        ),
      })),
      getLatestBlockhash: vi.fn(async () => LIFETIME),
    };
    const expected = rustInstruction("updateKeys");
    expect(
      await buildRegistrationTransaction({ client, owner: OWNER, address: shieldedAddress }),
    ).toEqual(
      compileUnsignedTransaction({
        feePayer: OWNER,
        lifetime: LIFETIME,
        instructions: [
          {
            ...expected,
            data: Uint8Array.of(2, 0, ...data.nullifierPublicKey, ...data.viewingPublicKey),
          },
        ],
      }),
    );
  });

  it.each([true, false])(
    "builds merge opt-in using the public instruction (%s)",
    async (enabled) => {
      const client = { getLatestBlockhash: vi.fn(async () => LIFETIME) };
      expect(
        await buildSetMergingEnabledTransaction({ client, owner: OWNER, enabled }, context),
      ).toEqual(
        compileUnsignedTransaction({
          feePayer: OWNER,
          lifetime: LIFETIME,
          instructions: [rustInstruction(enabled ? "enableMerging" : "disableMerging")],
        }),
      );
      expect(client.getLatestBlockhash).toHaveBeenCalledExactlyOnceWith(context);
    },
  );

  it.each([
    ["program", "WALLET_USER_RECORD_PROGRAM_MISMATCH"],
    ["owner", "WALLET_USER_RECORD_OWNER_MISMATCH"],
    ["bump", "WALLET_USER_RECORD_BUMP_MISMATCH"],
  ] as const)("preserves the record %s error before blockhash lookup", async (field, code) => {
    const { shieldedAddress, record, recordData } = registrationFixture();
    if (field === "owner") recordData.fill(0, 1, 33);
    if (field === "bump") recordData[33] = 254;
    const account = { ...record, owner: field === "program" ? OWNER : record.owner };
    const client = { getAccount: vi.fn(async () => account), getLatestBlockhash: vi.fn() };
    await expect(
      buildRegistrationTransaction({ client, owner: OWNER, address: shieldedAddress }),
    ).rejects.toMatchObject({
      code: "WALLET_BUILD_REGISTRATION",
      causeCodes: expect.arrayContaining([code]),
    });
    expect(client.getLatestBlockhash).not.toHaveBeenCalled();
  });

  it("preserves RPC errors as wallet build errors", async () => {
    const { shieldedAddress } = registrationFixture();
    const cause = new Error("RPC unavailable");
    const client = {
      getAccount: vi.fn().mockRejectedValue(cause),
      getLatestBlockhash: vi.fn().mockRejectedValue(cause),
    };
    await expect(
      buildRegistrationTransaction({ client, owner: OWNER, address: shieldedAddress }),
    ).rejects.toMatchObject({ code: "WALLET_BUILD_REGISTRATION", cause });
    expect(client.getLatestBlockhash).not.toHaveBeenCalled();
    await expect(
      buildSetMergingEnabledTransaction({ client, owner: OWNER, enabled: true }),
    ).rejects.toMatchObject({ code: "WALLET_BUILD_SET_MERGING_ENABLED", cause });
  });
});
