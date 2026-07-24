import { expect, it } from "vitest";

import { type Address, type Bytes31, type Bytes32 } from "../../src/index.js";
import { depositInstruction } from "../../src/instructions/index.js";
import { fixtureAccount, hexBytes, readDepositFixture } from "../fixture.js";

function toHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

it("matches the P00 deposit instruction vector", () => {
  const fixture = readDepositFixture(
    new URL("../../../fixtures/interface/deposit-instruction-v1.json", import.meta.url),
  );
  const built = depositInstruction({
    tree: fixtureAccount(fixture, 0).address as Address,
    depositor: fixtureAccount(fixture, 1).address as Address,
    data: {
      amount: BigInt(fixture.inputs.amount),
      blinding: hexBytes(fixture.inputs.blindingBytes) as Bytes31,
      memo: hexBytes(fixture.inputs.memoBytes),
      owner: hexBytes(fixture.inputs.ownerBytes) as Bytes32,
      viewTag: hexBytes(fixture.inputs.viewTagBytes) as Bytes32,
    },
  });
  expect(built.programAddress).toBe(fixture.expected.programId);
  expect(toHex(built.data)).toBe(fixture.expected.dataBytes);
  expect(built.accounts).toEqual(
    fixture.expected.accounts.map((account) => ({
      address: account.address,
      isSigner: account.signer,
      isWritable: account.writable,
    })),
  );
});
