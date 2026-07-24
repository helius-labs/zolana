import { readFileSync } from "node:fs";

import { expect, it } from "vitest";

import { type Address, type Bytes31, type Bytes32 } from "../../src/index.js";
import { depositInstruction } from "../../src/instructions/index.js";

function bytes(hex: string): Uint8Array {
  const pairs = hex.match(/../g);
  if (pairs === null) throw new Error("fixture contains invalid hex");
  return Uint8Array.from(pairs.map((value) => Number.parseInt(value, 16)));
}

function toHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

it("matches the P00 deposit instruction vector", () => {
  const fixture = JSON.parse(
    readFileSync(
      new URL("../../../fixtures/interface/deposit-instruction-v1.json", import.meta.url),
      "utf8",
    ),
  ) as {
    inputs: {
      amount: string;
      blindingBytes: string;
      memoBytes: string;
      ownerBytes: string;
      viewTagBytes: string;
    };
    expected: {
      accounts: readonly {
        address: string;
        signer: boolean;
        writable: boolean;
      }[];
      dataBytes: string;
      programId: string;
    };
  };
  const built = depositInstruction({
    tree: fixture.expected.accounts[0]!.address as Address,
    depositor: fixture.expected.accounts[1]!.address as Address,
    data: {
      amount: BigInt(fixture.inputs.amount),
      blinding: bytes(fixture.inputs.blindingBytes) as Bytes31,
      memo: bytes(fixture.inputs.memoBytes),
      owner: bytes(fixture.inputs.ownerBytes) as Bytes32,
      viewTag: bytes(fixture.inputs.viewTagBytes) as Bytes32,
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
