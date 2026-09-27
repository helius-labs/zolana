import {
  AccountRole,
  address,
  getAddressEncoder,
  getCompiledTransactionMessageDecoder,
  getInstructionsFromCompiledTransactionMessage,
  type Address,
  type Blockhash,
  type Instruction,
  type Transaction,
  type TransactionSigner,
} from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import {
  ShieldedKeypair,
  SigningKey,
  USER_REGISTRY_PROGRAM_ID,
  buildRegistrationTransaction,
  buildSetMergingEnabledTransaction,
} from "../src/index.js";
import { getUserRecordPda } from "../src/addresses.js";
import {
  getP256KeyBindingMessage,
  getP256VerifyInstruction,
  getRegisterInstruction,
  getSetMergingEnabledInstruction,
  getUpdateKeysInstruction,
} from "../src/instructions.js";
import { SECP256R1_PROGRAM_ID } from "../src/interface/program.js";
import type { Bytes32, Bytes33, Bytes64 } from "../src/interface/index.js";

const OWNER = address("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");
const PAYER = address("trEEbaNobcTESNmtsPBj3FX27q5sDCQePV2kb12FYho");
const SYSTEM_PROGRAM = address("11111111111111111111111111111111");
const INSTRUCTIONS_SYSVAR = address("Sysvar1nstructions1111111111111111111111111");
const BLOCKHASH = "11111111111111111111111111111111" as Blockhash;
const NULLIFIER_KEY = new Uint8Array(32).fill(7) as Bytes32;
const VIEWING_KEY = new Uint8Array(33).fill(8) as Bytes33;
const P256_KEY = new Uint8Array(33).fill(3) as Bytes33;
// Copy of `CANONICAL_HEAD` in programs/user-registry/src/instructions/p256_proof.rs.
const CANONICAL_HEAD = Uint8Array.of(
  1,
  0,
  49,
  0,
  255,
  255,
  16,
  0,
  255,
  255,
  113,
  0,
  161,
  0,
  255,
  255,
);

function roles(instruction: Instruction): readonly AccountRole[] {
  return (instruction.accounts ?? []).map((account) => account.role);
}

function addresses(instruction: Instruction): readonly string[] {
  return (instruction.accounts ?? []).map((account) => account.address);
}

function compiledInstructions(transaction: Transaction): readonly Instruction[] {
  const compiled = getCompiledTransactionMessageDecoder().decode(transaction.messageBytes);
  return getInstructionsFromCompiledTransactionMessage(compiled);
}

/**
 * The compiled message upgrades every slot holding the fee payer to a writable
 * signer, so those slots are only required to be writable signers; every other
 * slot must keep the role the instruction builder assigned.
 */
function expectSameAccounts(compiled: Instruction, expected: Instruction, feePayer: Address): void {
  expect(addresses(compiled)).toEqual(addresses(expected));
  const compiledRoles = roles(compiled);
  const expectedRoles = roles(expected);
  expect(compiledRoles.length).toBe(expectedRoles.length);
  compiledRoles.forEach((role, index) => {
    if (compiled.accounts?.[index]?.address === feePayer) {
      expect(role).toBe(AccountRole.WRITABLE_SIGNER);
      return;
    }
    expect(role).toBe(expectedRoles[index]);
  });
}

const blockhashClient = {
  getLatestBlockhash: vi.fn(async () => ({ blockhash: BLOCKHASH, lastValidBlockHeight: 1n })),
};

describe("user-registry package surface", () => {
  it("exports the record address and the five instruction builders", async () => {
    const [addressesModule, instructionsModule] = await Promise.all([
      import("../src/addresses.js"),
      import("../src/instructions.js"),
    ]);
    expect(addressesModule.getUserRecordPda).toBeTypeOf("function");
    expect(instructionsModule.getRegisterInstruction).toBeTypeOf("function");
    expect(instructionsModule.getSetMergingEnabledInstruction).toBeTypeOf("function");
    expect(instructionsModule.getUpdateKeysInstruction).toBeTypeOf("function");
    expect(instructionsModule.getP256KeyBindingMessage).toBeTypeOf("function");
    expect(instructionsModule.getP256VerifyInstruction).toBeTypeOf("function");
  });

  it("derives the user record from the registry seed and program", async () => {
    const pda = await getUserRecordPda(OWNER);
    expect(pda.address).not.toBe(OWNER);
    expect(pda.bump).toBeGreaterThanOrEqual(0);
    expect(pda.bump).toBeLessThanOrEqual(255);
    await expect(getUserRecordPda(OWNER)).resolves.toEqual(pda);
  });
});

describe("user-registry instruction builders", () => {
  it("builds an ed25519 register: tag 0, option 0, keys, owner paying its own rent", async () => {
    const { address: userRecord } = await getUserRecordPda(OWNER);
    const instruction = getRegisterInstruction({
      userRecord,
      owner: OWNER,
      nullifierPublicKey: NULLIFIER_KEY,
      viewingPublicKey: VIEWING_KEY,
    });

    expect(instruction.programAddress).toBe(USER_REGISTRY_PROGRAM_ID);
    expect(instruction.data).toEqual(Uint8Array.of(0, 0, ...NULLIFIER_KEY, ...VIEWING_KEY));
    expect(addresses(instruction)).toEqual([userRecord, OWNER, OWNER, SYSTEM_PROGRAM]);
    expect(roles(instruction)).toEqual([
      AccountRole.WRITABLE,
      AccountRole.READONLY_SIGNER,
      AccountRole.WRITABLE_SIGNER,
      AccountRole.READONLY,
    ]);
  });

  it("puts a sponsor payer in the writable signer slot", async () => {
    const { address: userRecord } = await getUserRecordPda(OWNER);
    const instruction = getRegisterInstruction({
      userRecord,
      owner: OWNER,
      payer: PAYER,
      nullifierPublicKey: NULLIFIER_KEY,
      viewingPublicKey: VIEWING_KEY,
    });
    expect(addresses(instruction)).toEqual([userRecord, OWNER, PAYER, SYSTEM_PROGRAM]);
    expect(roles(instruction)[2]).toBe(AccountRole.WRITABLE_SIGNER);
  });

  it("attaches the owner and payer signers when they are passed", async () => {
    const { address: userRecord } = await getUserRecordPda(OWNER);
    const owner = { address: OWNER } as TransactionSigner;
    const payer = { address: PAYER } as TransactionSigner;
    const instruction = getRegisterInstruction({
      userRecord,
      owner,
      payer,
      nullifierPublicKey: NULLIFIER_KEY,
      viewingPublicKey: VIEWING_KEY,
    });
    expect(instruction.accounts?.[1]).toMatchObject({ address: OWNER, signer: owner });
    expect(instruction.accounts?.[2]).toMatchObject({ address: PAYER, signer: payer });
    expect(instruction.accounts?.[0]).not.toHaveProperty("signer");
  });

  it("builds the merge opt-in: tag 1 then the flag, record and owner only", async () => {
    const { address: userRecord } = await getUserRecordPda(OWNER);
    const enabled = getSetMergingEnabledInstruction({ userRecord, owner: OWNER, enabled: true });
    const disabled = getSetMergingEnabledInstruction({ userRecord, owner: OWNER, enabled: false });

    expect(enabled.programAddress).toBe(USER_REGISTRY_PROGRAM_ID);
    expect(enabled.data).toEqual(Uint8Array.of(1, 1));
    expect(disabled.data).toEqual(Uint8Array.of(1, 0));
    expect(addresses(enabled)).toEqual([userRecord, OWNER]);
    expect(roles(enabled)).toEqual([AccountRole.WRITABLE, AccountRole.READONLY_SIGNER]);
  });

  it("builds an ed25519 key update: tag 2, record and readonly owner signer", async () => {
    const { address: userRecord } = await getUserRecordPda(OWNER);
    const instruction = getUpdateKeysInstruction({
      userRecord,
      owner: OWNER,
      nullifierPublicKey: NULLIFIER_KEY,
      viewingPublicKey: VIEWING_KEY,
    });

    expect(instruction.data).toEqual(Uint8Array.of(2, 0, ...NULLIFIER_KEY, ...VIEWING_KEY));
    expect(addresses(instruction)).toEqual([userRecord, OWNER]);
    expect(roles(instruction)).toEqual([AccountRole.WRITABLE, AccountRole.READONLY_SIGNER]);
  });

  it("appends the instructions sysvar and the P-256 option for a P-256 owner", async () => {
    const { address: userRecord } = await getUserRecordPda(OWNER);
    const keys = {
      userRecord,
      owner: OWNER,
      ownerP256: P256_KEY,
      nullifierPublicKey: NULLIFIER_KEY,
      viewingPublicKey: VIEWING_KEY,
    };
    const register = getRegisterInstruction(keys);
    const update = getUpdateKeysInstruction(keys);

    expect(register.data).toEqual(
      Uint8Array.of(0, 1, ...P256_KEY, ...NULLIFIER_KEY, ...VIEWING_KEY),
    );
    expect(addresses(register)).toEqual([
      userRecord,
      OWNER,
      OWNER,
      SYSTEM_PROGRAM,
      INSTRUCTIONS_SYSVAR,
    ]);
    expect(roles(register).at(-1)).toBe(AccountRole.READONLY);
    expect(update.data).toEqual(Uint8Array.of(2, 1, ...P256_KEY, ...NULLIFIER_KEY, ...VIEWING_KEY));
    expect(addresses(update)).toEqual([userRecord, OWNER, INSTRUCTIONS_SYSVAR]);
  });

  it("rejects wrong key lengths with the interface codec error", async () => {
    const { address: userRecord } = await getUserRecordPda(OWNER);
    expect(() =>
      getRegisterInstruction({
        userRecord,
        owner: OWNER,
        nullifierPublicKey: new Uint8Array(31) as Bytes32,
        viewingPublicKey: VIEWING_KEY,
      }),
    ).toThrow(expect.objectContaining({ code: "INTERFACE_CODEC" }));
    expect(() =>
      getUpdateKeysInstruction({
        userRecord,
        owner: OWNER,
        ownerP256: new Uint8Array(32) as Bytes33,
        nullifierPublicKey: NULLIFIER_KEY,
        viewingPublicKey: VIEWING_KEY,
      }),
    ).toThrow(expect.objectContaining({ code: "INTERFACE_CODEC" }));
  });

  it("builds the 161-byte P-256 key binding message in the Rust layout", async () => {
    const { address: userRecord } = await getUserRecordPda(OWNER);
    const message = getP256KeyBindingMessage({ userRecord, owner: OWNER, ownerP256: P256_KEY });
    const encoder = getAddressEncoder();

    expect(message).toHaveLength(161);
    expect(message.slice(0, 32)).toEqual(
      Uint8Array.of(...new TextEncoder().encode("zolana:user-registry:p256:v1"), 0, 0, 0, 0),
    );
    expect(message.slice(32, 64)).toEqual(new Uint8Array(encoder.encode(USER_REGISTRY_PROGRAM_ID)));
    expect(message.slice(64, 96)).toEqual(new Uint8Array(encoder.encode(userRecord)));
    expect(message.slice(96, 128)).toEqual(new Uint8Array(encoder.encode(OWNER)));
    expect(message.slice(128)).toEqual(P256_KEY);
  });

  it("builds the self-contained 274-byte secp256r1 verify instruction", () => {
    const message = new Uint8Array(161).fill(9);
    const signature = new Uint8Array(64).fill(5) as Bytes64;
    const instruction = getP256VerifyInstruction({ message, signature, pubkey: P256_KEY });

    expect(instruction.programAddress).toBe(SECP256R1_PROGRAM_ID);
    expect(instruction.accounts).toEqual([]);
    expect(instruction.data).toHaveLength(274);
    expect(instruction.data?.slice(0, 16)).toEqual(CANONICAL_HEAD);
    expect(instruction.data?.slice(16, 49)).toEqual(P256_KEY);
    expect(instruction.data?.slice(49, 113)).toEqual(signature);
    expect(instruction.data?.slice(113)).toEqual(message);
  });

  it("rejects malformed secp256r1 inputs with the interface codec error", () => {
    const message = new Uint8Array(161);
    const signature = new Uint8Array(64) as Bytes64;
    expect(() =>
      getP256VerifyInstruction({ message: new Uint8Array(160), signature, pubkey: P256_KEY }),
    ).toThrow(
      expect.objectContaining({
        code: "INTERFACE_CODEC",
        details: expect.objectContaining({ name: "message", expected: 161, actual: 160 }),
      }),
    );
    expect(() =>
      getP256VerifyInstruction({
        message,
        signature: new Uint8Array(63) as Bytes64,
        pubkey: P256_KEY,
      }),
    ).toThrow(expect.objectContaining({ code: "INTERFACE_CODEC" }));
    expect(() =>
      getP256VerifyInstruction({ message, signature, pubkey: new Uint8Array(32) as Bytes33 }),
    ).toThrow(expect.objectContaining({ code: "INTERFACE_CODEC" }));
  });
});

describe("transaction builders keep their bytes", () => {
  it("buildRegistrationTransaction compiles the same register instruction", async () => {
    const keypair = ShieldedKeypair.fromKeypair(
      SigningKey.fromEd25519Bytes(new Uint8Array(32).fill(4) as Bytes32),
    );
    const owner = keypair.shieldedAddress().solanaAddress();
    const { address: userRecord } = await getUserRecordPda(owner);
    const transaction = await buildRegistrationTransaction({
      client: { getAccount: vi.fn(async () => undefined), ...blockhashClient },
      owner,
      address: keypair.shieldedAddress(),
    });
    const expected = getRegisterInstruction({
      userRecord,
      owner,
      nullifierPublicKey: keypair.nullifierPublicKey(),
      viewingPublicKey: keypair.viewingPublicKey().toBytes(),
    });

    expect(transaction).toBeDefined();
    const [compiled, ...rest] = compiledInstructions(transaction!);
    expect(rest).toHaveLength(0);
    expect(compiled?.programAddress).toBe(USER_REGISTRY_PROGRAM_ID);
    expect(compiled?.data).toEqual(expected.data);
    expect(compiled?.data).toEqual(
      Uint8Array.of(0, 0, ...keypair.nullifierPublicKey(), ...keypair.viewingPublicKey().toBytes()),
    );
    expectSameAccounts(compiled!, expected, owner);
  });

  it("buildRegistrationTransaction with a sponsor compiles the same payer slot", async () => {
    const keypair = ShieldedKeypair.fromKeypair(
      SigningKey.fromEd25519Bytes(new Uint8Array(32).fill(5) as Bytes32),
    );
    const owner = keypair.shieldedAddress().solanaAddress();
    const { address: userRecord } = await getUserRecordPda(owner);
    const transaction = await buildRegistrationTransaction({
      client: { getAccount: vi.fn(async () => undefined), ...blockhashClient },
      owner,
      payer: PAYER,
      address: keypair.shieldedAddress(),
    });
    const expected = getRegisterInstruction({
      userRecord,
      owner,
      payer: PAYER,
      nullifierPublicKey: keypair.nullifierPublicKey(),
      viewingPublicKey: keypair.viewingPublicKey().toBytes(),
    });

    const [compiled] = compiledInstructions(transaction!);
    expect(compiled?.data).toEqual(expected.data);
    expectSameAccounts(compiled!, expected, PAYER);
    expect(roles(compiled!)[1]).toBe(AccountRole.READONLY_SIGNER);
  });

  it("buildRegistrationTransaction compiles the same key update on a key change", async () => {
    const current = ShieldedKeypair.fromKeypair(
      SigningKey.fromEd25519Bytes(new Uint8Array(32).fill(2) as Bytes32),
    ).shieldedAddress();
    const replacement = ShieldedKeypair.fromKeypair(
      SigningKey.fromEd25519Bytes(new Uint8Array(32).fill(1) as Bytes32),
    );
    const owner = replacement.shieldedAddress().solanaAddress();
    const pda = await getUserRecordPda(owner);
    const data = Uint8Array.of(
      1,
      ...getAddressEncoder().encode(owner),
      pda.bump,
      0,
      ...current.nullifierPublicKey,
      ...current.viewingPublicKey.toBytes(),
      0,
    );
    const transaction = await buildRegistrationTransaction({
      client: {
        getAccount: vi.fn(async () => ({ owner: USER_REGISTRY_PROGRAM_ID, data, lamports: 1n })),
        ...blockhashClient,
      },
      owner,
      address: replacement.shieldedAddress(),
    });
    const expected = getUpdateKeysInstruction({
      userRecord: pda.address,
      owner,
      nullifierPublicKey: replacement.nullifierPublicKey(),
      viewingPublicKey: replacement.viewingPublicKey().toBytes(),
    });

    const [compiled] = compiledInstructions(transaction!);
    expect(compiled?.data).toEqual(expected.data);
    expect(compiled?.data?.[0]).toBe(2);
    expectSameAccounts(compiled!, expected, owner);
  });

  it("buildSetMergingEnabledTransaction compiles the same opt-in instruction", async () => {
    const { address: userRecord } = await getUserRecordPda(OWNER);
    const transaction = await buildSetMergingEnabledTransaction({
      client: blockhashClient,
      owner: OWNER,
      enabled: true,
    });
    const expected = getSetMergingEnabledInstruction({ userRecord, owner: OWNER, enabled: true });

    const [compiled, ...rest] = compiledInstructions(transaction);
    expect(rest).toHaveLength(0);
    expect(compiled?.programAddress).toBe(USER_REGISTRY_PROGRAM_ID);
    expect(compiled?.data).toEqual(Uint8Array.of(1, 1));
    expectSameAccounts(compiled!, expected, OWNER);
  });

  it("still rejects P-256 registration through the transaction builder", async () => {
    await expect(
      buildRegistrationTransaction({
        client: { getAccount: vi.fn(async () => undefined), ...blockhashClient },
        owner: OWNER,
        address: ShieldedKeypair.generate("p256").shieldedAddress(),
      }),
    ).rejects.toMatchObject({
      code: "WALLET_BUILD_REGISTRATION",
      causeCode: "WALLET_P256_REGISTRATION_UNSUPPORTED",
    });
  });
});
