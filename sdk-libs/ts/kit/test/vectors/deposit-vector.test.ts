import { AccountRole } from "@solana/kit";
import type { Address, Bytes31, Bytes32 } from "@zolana/interface";
import { depositInstruction as zolanaDepositInstruction } from "@zolana/interface/instructions";
import { expect, it } from "vitest";

import { fixtureAccount, hexBytes, readDepositFixture } from "../../../interface/test/fixture.js";
import { fromKitInstruction } from "../../src/index.js";
import { depositInstruction } from "../../src/instructions/index.js";

function toHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/**
 * Kit's documented `AccountRole` mapping, listed explicitly so the vector does
 * not call `toAccountRole` and compare the function to itself.
 */
function expectedRole(signer: boolean, writable: boolean): AccountRole {
  if (signer && writable) return AccountRole.WRITABLE_SIGNER;
  if (signer) return AccountRole.READONLY_SIGNER;
  if (writable) return AccountRole.WRITABLE;
  return AccountRole.READONLY;
}

const fixture = readDepositFixture(
  new URL("../../../fixtures/interface/deposit-instruction-v1.json", import.meta.url),
);

const input = {
  tree: fixtureAccount(fixture, 0).address as Address,
  depositor: fixtureAccount(fixture, 1).address as Address,
  data: {
    amount: BigInt(fixture.inputs.amount),
    blinding: hexBytes(fixture.inputs.blindingBytes) as Bytes31,
    memo: hexBytes(fixture.inputs.memoBytes),
    owner: hexBytes(fixture.inputs.ownerBytes) as Bytes32,
    viewTag: hexBytes(fixture.inputs.viewTagBytes) as Bytes32,
  },
};

it("matches the P00 deposit instruction vector byte for byte", () => {
  const built = depositInstruction(input);
  expect(built.programAddress).toBe(fixture.expected.programId);
  expect(built.data).toBeInstanceOf(Uint8Array);
  expect(toHex(built.data as Uint8Array)).toBe(fixture.expected.dataBytes);
  expect(built.accounts).toEqual(
    fixture.expected.accounts.map((account) => ({
      address: account.address,
      role: expectedRole(account.signer, account.writable),
    })),
  );
});

it("returns the Zolana instruction unchanged when converted back", () => {
  expect(fromKitInstruction(depositInstruction(input))).toEqual(zolanaDepositInstruction(input));
});
