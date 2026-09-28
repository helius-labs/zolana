import {
  AccountRole,
  address,
  getAddressEncoder,
  getCompiledTransactionMessageDecoder,
  getInstructionsFromCompiledTransactionMessage,
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
  ViewingKey,
  buildRegistrationTransaction,
  buildSetMergingEnabledTransaction,
} from "../src/index.js";
import { getUserRecordAddress } from "../src/addresses.js";
import {
  getRegisterInstructionAsync,
  getSetMergingEnabledInstructionAsync,
} from "../src/instructions.js";
import type { Bytes32, Bytes33 } from "../src/interface/index.js";
import { internalUserRecordPda } from "../src/wallet/registry.js";

const OWNER = address("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");
const PAYER = address("trEEbaNobcTESNmtsPBj3FX27q5sDCQePV2kb12FYho");
const SYSTEM_PROGRAM = address("11111111111111111111111111111111");
const BLOCKHASH = "11111111111111111111111111111111" as Blockhash;
const NULLIFIER_KEY = new Uint8Array(32).fill(7) as Bytes32;
const VIEWING_KEY = new Uint8Array(33).fill(8) as Bytes33;

const blockhashClient = {
  getLatestBlockhash: vi.fn(async () => ({ blockhash: BLOCKHASH, lastValidBlockHeight: 1n })),
};
const emptyRegistry = { getAccount: vi.fn(async () => undefined), ...blockhashClient };

function signingKey(seed: number): SigningKey {
  return SigningKey.fromEd25519Bytes(new Uint8Array(32).fill(seed) as Bytes32);
}

function accountsOf(instruction: Instruction) {
  return (instruction.accounts ?? []).map(({ address, role }) => ({ address, role }));
}

function onlyInstruction(transaction: Transaction): Instruction {
  const message = getCompiledTransactionMessageDecoder().decode(transaction.messageBytes);
  const [instruction, ...rest] = getInstructionsFromCompiledTransactionMessage(message);
  expect(rest).toEqual([]);
  if (instruction === undefined) throw new Error("transaction carries no instruction");
  return instruction;
}

describe("getRegisterInstructionAsync", () => {
  it("encodes tag 0, no P-256 owner, then the nullifier and viewing keys", async () => {
    const instruction = await getRegisterInstructionAsync({
      owner: OWNER,
      nullifierPublicKey: NULLIFIER_KEY,
      viewingPublicKey: VIEWING_KEY,
    });

    expect(instruction.programAddress).toBe(USER_REGISTRY_PROGRAM_ID);
    expect(instruction.data).toEqual(Uint8Array.of(0, 0, ...NULLIFIER_KEY, ...VIEWING_KEY));
    expect(accountsOf(instruction)).toEqual([
      { address: await getUserRecordAddress(OWNER), role: AccountRole.WRITABLE },
      { address: OWNER, role: AccountRole.READONLY_SIGNER },
      { address: OWNER, role: AccountRole.WRITABLE_SIGNER },
      { address: SYSTEM_PROGRAM, role: AccountRole.READONLY },
    ]);
  });

  it("puts a sponsor in the payer slot", async () => {
    const instruction = await getRegisterInstructionAsync({
      owner: OWNER,
      payer: PAYER,
      nullifierPublicKey: NULLIFIER_KEY,
      viewingPublicKey: VIEWING_KEY,
    });

    expect(accountsOf(instruction)).toEqual([
      { address: await getUserRecordAddress(OWNER), role: AccountRole.WRITABLE },
      { address: OWNER, role: AccountRole.READONLY_SIGNER },
      { address: PAYER, role: AccountRole.WRITABLE_SIGNER },
      { address: SYSTEM_PROGRAM, role: AccountRole.READONLY },
    ]);
  });

  it("attaches transaction signers to the owner and payer accounts", async () => {
    const owner = { address: OWNER } as TransactionSigner;
    const payer = { address: PAYER } as TransactionSigner;
    const instruction = await getRegisterInstructionAsync({
      owner,
      payer,
      nullifierPublicKey: NULLIFIER_KEY,
      viewingPublicKey: VIEWING_KEY,
    });
    const [record, ownerMeta, payerMeta, system] = instruction.accounts ?? [];

    expect(record).toEqual({
      address: await getUserRecordAddress(OWNER),
      role: AccountRole.WRITABLE,
    });
    expect(ownerMeta).toMatchObject({ address: OWNER, signer: owner });
    expect(payerMeta).toMatchObject({ address: PAYER, signer: payer });
    expect(system).not.toHaveProperty("signer");
  });

  it("rejects keys of the wrong length", async () => {
    const invalidLength = { code: "INTERFACE_INVALID_LENGTH" };

    await expect(
      getRegisterInstructionAsync({
        owner: OWNER,
        nullifierPublicKey: new Uint8Array(31) as Bytes32,
        viewingPublicKey: VIEWING_KEY,
      }),
    ).rejects.toMatchObject(invalidLength);
    await expect(
      getRegisterInstructionAsync({
        owner: OWNER,
        nullifierPublicKey: NULLIFIER_KEY,
        viewingPublicKey: new Uint8Array(34) as Bytes33,
      }),
    ).rejects.toMatchObject(invalidLength);
  });
});

describe("getSetMergingEnabledInstructionAsync", () => {
  it("encodes tag 1 and the flag for the owner's record", async () => {
    const enabled = await getSetMergingEnabledInstructionAsync({ owner: OWNER, enabled: true });
    const disabled = await getSetMergingEnabledInstructionAsync({ owner: OWNER, enabled: false });

    expect(enabled.programAddress).toBe(USER_REGISTRY_PROGRAM_ID);
    expect(enabled.data).toEqual(Uint8Array.of(1, 1));
    expect(disabled.data).toEqual(Uint8Array.of(1, 0));
    expect(accountsOf(enabled)).toEqual([
      { address: await getUserRecordAddress(OWNER), role: AccountRole.WRITABLE },
      { address: OWNER, role: AccountRole.READONLY_SIGNER },
    ]);
  });
});

describe("buildRegistrationTransaction", () => {
  it("registers a new owner with the register instruction", async () => {
    const keypair = ShieldedKeypair.fromKeypair(signingKey(4));
    const owner = keypair.shieldedAddress().solanaAddress();

    const transaction = await buildRegistrationTransaction({
      client: emptyRegistry,
      owner,
      address: keypair.shieldedAddress(),
    });
    const instruction = onlyInstruction(transaction!);
    const expected = await getRegisterInstructionAsync({
      owner,
      nullifierPublicKey: keypair.nullifierPublicKey(),
      viewingPublicKey: keypair.viewingPublicKey().toBytes(),
    });

    expect(instruction.programAddress).toBe(USER_REGISTRY_PROGRAM_ID);
    expect(instruction.data).toEqual(expected.data);
    expect(accountsOf(instruction)).toEqual([
      { address: await getUserRecordAddress(owner), role: AccountRole.WRITABLE },
      { address: owner, role: AccountRole.WRITABLE_SIGNER },
      { address: owner, role: AccountRole.WRITABLE_SIGNER },
      { address: SYSTEM_PROGRAM, role: AccountRole.READONLY },
    ]);
  });

  it("lets a sponsor pay the rent and the fee", async () => {
    const keypair = ShieldedKeypair.fromKeypair(signingKey(5));
    const owner = keypair.shieldedAddress().solanaAddress();

    const transaction = await buildRegistrationTransaction({
      client: emptyRegistry,
      owner,
      payer: PAYER,
      address: keypair.shieldedAddress(),
    });

    expect(accountsOf(onlyInstruction(transaction!))).toEqual([
      { address: await getUserRecordAddress(owner), role: AccountRole.WRITABLE },
      { address: owner, role: AccountRole.READONLY_SIGNER },
      { address: PAYER, role: AccountRole.WRITABLE_SIGNER },
      { address: SYSTEM_PROGRAM, role: AccountRole.READONLY },
    ]);
  });

  it("updates the viewing key of an existing record", async () => {
    const published = ShieldedKeypair.fromKeypair(signingKey(1)).shieldedAddress();
    const replacement = ShieldedKeypair.withViewingKey(signingKey(1), ViewingKey.generate());
    const owner = published.solanaAddress();
    const pda = await internalUserRecordPda(owner);
    const recordData = Uint8Array.of(
      1,
      ...getAddressEncoder().encode(owner),
      pda.bump,
      0,
      ...published.nullifierPublicKey,
      ...published.viewingPublicKey.toBytes(),
      0,
    );

    const transaction = await buildRegistrationTransaction({
      client: {
        getAccount: vi.fn(async () => ({
          owner: USER_REGISTRY_PROGRAM_ID,
          data: recordData,
          lamports: 1n,
        })),
        ...blockhashClient,
      },
      owner,
      address: replacement.shieldedAddress(),
    });
    const instruction = onlyInstruction(transaction!);

    expect(instruction.data).toEqual(
      Uint8Array.of(
        2,
        0,
        ...replacement.nullifierPublicKey(),
        ...replacement.viewingPublicKey().toBytes(),
      ),
    );
    expect(accountsOf(instruction)).toEqual([
      { address: pda.address, role: AccountRole.WRITABLE },
      { address: owner, role: AccountRole.WRITABLE_SIGNER },
    ]);
  });
});

describe("buildSetMergingEnabledTransaction", () => {
  it("compiles the set-merging-enabled instruction", async () => {
    const transaction = await buildSetMergingEnabledTransaction({
      client: blockhashClient,
      owner: OWNER,
      enabled: true,
    });
    const instruction = onlyInstruction(transaction);

    expect(instruction.programAddress).toBe(USER_REGISTRY_PROGRAM_ID);
    expect(instruction.data).toEqual(Uint8Array.of(1, 1));
    expect(accountsOf(instruction)).toEqual([
      { address: await getUserRecordAddress(OWNER), role: AccountRole.WRITABLE },
      { address: OWNER, role: AccountRole.WRITABLE_SIGNER },
    ]);
  });
});
