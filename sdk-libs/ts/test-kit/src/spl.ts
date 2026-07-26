import { SPL_TOKEN_PROGRAM_ID, type Address, type Instruction } from "@zolana/interface";
import { splAssetRegistryAddress, splAssetVaultAddress } from "@zolana/interface/pda";
import {
  createAssetCounterInstruction,
  createSplInterfaceInstruction,
} from "@zolana/interface/instructions";

import { TestKitError } from "./error.js";

const TOKEN_AMOUNT_OFFSET = 64;
const TOKEN_AMOUNT_END = 72;

export function splInterfaceAddresses(mint: Address): Readonly<{
  registry: Address;
  vault: Address;
}> {
  return Object.freeze({
    registry: splAssetRegistryAddress(mint),
    vault: splAssetVaultAddress(mint),
  });
}

export function createSplInterfaceInstructions(
  authority: Address,
  mint: Address,
): readonly Instruction[] {
  return Object.freeze([
    createAssetCounterInstruction({ authority }),
    createSplInterfaceInstruction({ authority, mint }),
  ]);
}

export function mintToInstruction(
  input: Readonly<{
    mint: Address;
    account: Address;
    authority: Address;
    amount: bigint;
  }>,
): Instruction {
  if (input.amount < 0n || input.amount > 0xffff_ffff_ffff_ffffn) {
    throw new TestKitError("TEST_KIT_INVALID_CONFIG", {
      details: { field: "amount" },
    });
  }
  const data = new Uint8Array(9);
  data[0] = 7;
  new DataView(data.buffer).setBigUint64(1, input.amount, true);
  return Object.freeze({
    programAddress: SPL_TOKEN_PROGRAM_ID,
    accounts: Object.freeze([
      Object.freeze({ address: input.mint, isSigner: false, isWritable: true }),
      Object.freeze({ address: input.account, isSigner: false, isWritable: true }),
      Object.freeze({ address: input.authority, isSigner: true, isWritable: false }),
    ]),
    data,
  });
}

export function tokenAmount(accountData: Uint8Array): bigint {
  if (accountData.length < TOKEN_AMOUNT_END) {
    throw new TestKitError("TEST_KIT_FIXTURE", {
      details: {
        reason: "tokenAccountLength",
        expectedAtLeast: TOKEN_AMOUNT_END,
        actual: accountData.length,
      },
    });
  }
  return new DataView(
    accountData.buffer,
    accountData.byteOffset + TOKEN_AMOUNT_OFFSET,
    8,
  ).getBigUint64(0, true);
}
