import { AccountRole, address, getAddressDecoder, type TransactionSigner } from "@solana/kit";
import { describe, expect, it } from "vitest";

import {
  createProtocolConfigInstruction,
  createTreeInstructions,
  setTreeFeesInstruction,
  updateProtocolConfigInstruction,
} from "../src/interface/instructions/index.js";
import {
  DEFAULT_APPEND_REIMBURSEMENT_LAMPORTS,
  DEFAULT_CLOSE_REIMBURSEMENT_LAMPORTS,
  InstructionTag,
  PROTOCOL_CONFIG_SIZE,
  SHIELDED_POOL_PROGRAM_ID,
  STATE_ROOT_OFFSET,
  ShieldedPoolError,
  StateDiscriminator,
  TREE_ACCOUNT_SIZE,
  TREE_FEES_OFFSET,
  TREE_FEE_BALANCE_OFFSET,
  decodeProtocolConfig,
  decodeShieldedPoolError,
  decodeTreeFeeSchedule,
  decodeTreeFees,
  defaultTreeFees,
  encodeTreeFeeSchedule,
} from "../src/interface/index.js";
import { protocolConfigAddress } from "../src/interface/pda/index.js";

const SYSTEM = address("11111111111111111111111111111111");
const TREE = address("2RJD1KnDRGEkvuFfAGrJ7PD28LRE9LRDjZznDywagzmr");
const AUTHORITY = address("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");

function filled(byte: number, length = 32): Uint8Array {
  return new Uint8Array(length).fill(byte);
}

function filledAddress(byte: number) {
  return getAddressDecoder().decode(filled(byte));
}

const FEES = Object.freeze({
  feePerNullifier: 0x0102n,
  appendReimbursement: 0x0304_0506n,
  closeReimbursement: 0xffff_ffff_ffff_ffffn,
});
// Three little-endian u64s.
const FEE_BYTES = Uint8Array.of(
  2,
  1,
  0,
  0,
  0,
  0,
  0,
  0,
  6,
  5,
  4,
  3,
  0,
  0,
  0,
  0,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
);

describe("tree fee schedule", () => {
  it("prices the default schedule at exact batch cost, rounded up", () => {
    expect(DEFAULT_APPEND_REIMBURSEMENT_LAMPORTS).toBe(5_000n);
    expect(DEFAULT_CLOSE_REIMBURSEMENT_LAMPORTS).toBe(170n);
    expect(defaultTreeFees(250n)).toEqual({
      feePerNullifier: 190n,
      appendReimbursement: 5_000n,
      closeReimbursement: 170n,
    });
    expect(defaultTreeFees(10n).feePerNullifier).toBe(670n);
    expect(defaultTreeFees(3n).feePerNullifier).toBe(1837n);
    expect(defaultTreeFees(0n)).toEqual({
      feePerNullifier: 0n,
      appendReimbursement: 0n,
      closeReimbursement: 0n,
    });
    expect(() => defaultTreeFees(-1n)).toThrow();
  });

  it("encodes and decodes the borsh schedule as three u64 LE", () => {
    expect(encodeTreeFeeSchedule(FEES)).toEqual(FEE_BYTES);
    expect(decodeTreeFeeSchedule(FEE_BYTES)).toEqual(FEES);
    expect(() => decodeTreeFeeSchedule(FEE_BYTES.subarray(1))).toThrow(
      expect.objectContaining({ code: "INTERFACE_INVALID_LENGTH" }),
    );
    expect(() => encodeTreeFeeSchedule({ ...FEES, feePerNullifier: 1n << 64n })).toThrow();
  });

  it("reads the fee header of a tree account at the Rust offsets", () => {
    expect(TREE_FEES_OFFSET).toBe(8);
    expect(TREE_FEE_BALANCE_OFFSET).toBe(32);
    expect(STATE_ROOT_OFFSET).toBe(80);

    const account = new Uint8Array(TREE_ACCOUNT_SIZE).fill(0xee);
    account[0] = StateDiscriminator.treeAccount;
    account.set(FEE_BYTES, TREE_FEES_OFFSET);
    account.set(Uint8Array.of(0x21, 0x43, 0, 0, 0, 0, 0, 0), TREE_FEE_BALANCE_OFFSET);
    expect(decodeTreeFees(account)).toEqual({ fees: FEES, feeBalance: 0x4321n });

    account[0] = StateDiscriminator.protocolConfig;
    expect(() => decodeTreeFees(account)).toThrow(
      expect.objectContaining({ code: "INTERFACE_INVALID_DISCRIMINATOR" }),
    );
    expect(() => decodeTreeFees(account.subarray(0, 40))).toThrow(
      expect.objectContaining({ code: "INTERFACE_INVALID_ACCOUNT_DATA" }),
    );
  });

  it("builds set_tree_fees with a read-only config and a writable tree", async () => {
    expect(InstructionTag.setTreeFees).toBe(19);
    const authority = { address: AUTHORITY } as TransactionSigner;
    const instruction = await setTreeFeesInstruction({ authority, tree: TREE, fees: FEES });

    expect(instruction.programAddress).toBe(SHIELDED_POOL_PROGRAM_ID);
    expect(instruction.data).toEqual(Uint8Array.of(InstructionTag.setTreeFees, ...FEE_BYTES));
    expect(instruction.accounts?.map((account) => [account.address, account.role])).toEqual([
      [AUTHORITY, AccountRole.READONLY_SIGNER],
      [await protocolConfigAddress(), AccountRole.READONLY],
      [TREE, AccountRole.WRITABLE],
    ]);
    expect(instruction.accounts?.[0]).toMatchObject({ signer: authority });
  });

  it("lets create_tree override the default schedule", async () => {
    const [step] = await createTreeInstructions({
      payer: AUTHORITY,
      authority: AUTHORITY,
      treeId: 0,
      fees: FEES,
    });
    expect(step?.data).toHaveLength(1 + 46);
    expect(step?.data?.subarray(1 + 22)).toEqual(FEE_BYTES);
  });
});

describe("protocol config fee authority", () => {
  it("decodes the 166-byte account with the fee authority after the ring authority", () => {
    expect(PROTOCOL_CONFIG_SIZE).toBe(166);
    const data = Uint8Array.of(
      StateDiscriminator.protocolConfig,
      ...filled(1),
      ...filled(2),
      ...filled(3),
      ...filled(4),
      ...filled(5),
      1,
      0,
      1,
      7,
      1,
    );
    expect(data).toHaveLength(PROTOCOL_CONFIG_SIZE);
    expect(decodeProtocolConfig(data)).toEqual({
      authority: filledAddress(1),
      treeCreationAuthority: filledAddress(2),
      foresterAuthority: filledAddress(3),
      ringCreationAuthority: filledAddress(4),
      feeAuthority: filledAddress(5),
      treeCreationIsPermissionless: true,
      ringActivationIsPermissionless: false,
      splInterfaceCreationIsPermissionless: true,
      nextTreeId: 0x0107,
    });
    expect(() => decodeProtocolConfig(data.subarray(0, 134))).toThrow(
      expect.objectContaining({ code: "INTERFACE_INVALID_ACCOUNT_DATA" }),
    );
  });

  it("appends the fee authority to create_protocol_config data", async () => {
    const authority = { address: AUTHORITY } as TransactionSigner;
    const instruction = await createProtocolConfigInstruction({
      authority,
      protocolAuthority: filledAddress(1),
      treeCreationAuthority: filledAddress(2),
      treeCreationIsPermissionless: true,
      foresterAuthority: filledAddress(3),
      ringCreationAuthority: filledAddress(4),
      ringActivationIsPermissionless: false,
      splInterfaceCreationIsPermissionless: true,
      feeAuthority: filledAddress(5),
    });

    expect(instruction.data).toEqual(
      Uint8Array.of(
        InstructionTag.createProtocolConfig,
        ...filled(1),
        ...filled(2),
        1,
        ...filled(3),
        ...filled(4),
        0,
        1,
        ...filled(5),
      ),
    );
    expect(instruction.accounts?.map((account) => [account.address, account.role])).toEqual([
      [AUTHORITY, AccountRole.WRITABLE_SIGNER],
      [await protocolConfigAddress(), AccountRole.WRITABLE],
      [SYSTEM, AccountRole.READONLY],
    ]);
  });

  it("encodes the fee authority update as variant 7", async () => {
    const instruction = await updateProtocolConfigInstruction({
      authority: AUTHORITY,
      update: { field: "feeAuthority", value: filledAddress(5) },
    });

    expect(instruction.data).toEqual(
      Uint8Array.of(InstructionTag.updateProtocolConfig, 7, ...filled(5)),
    );
    expect(instruction.accounts?.map((account) => [account.address, account.role])).toEqual([
      [AUTHORITY, AccountRole.READONLY_SIGNER],
      [await protocolConfigAddress(), AccountRole.WRITABLE],
    ]);
  });

  it("names the fee error code", () => {
    expect(ShieldedPoolError.InvalidReimbursementRecipient).toBe(7055);
    expect(decodeShieldedPoolError(7055)).toEqual({
      kind: "known",
      code: 7055,
      name: "InvalidReimbursementRecipient",
    });
  });
});
