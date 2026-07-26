import type { Address, Instruction } from "@zolana/interface";
import { SHIELDED_POOL_PROGRAM_ID } from "@zolana/interface";
import { createTreeInstruction } from "@zolana/interface/instructions";

import { TestKitError } from "./error.js";

export const ZONE_TEST_PROGRAM_ID = "9EwHno8C1T1vVGjasGnDH1GubiEu8qbgLX9qDjBshFhz" as Address;

export function systemCreateAccountInstruction(
  input: Readonly<{
    payer: Address;
    account: Address;
    lamports: bigint;
    space: bigint;
    owner?: Address;
  }>,
): Instruction {
  const data = new Uint8Array(52);
  writeU64(data, 4, input.lamports, "lamports");
  writeU64(data, 12, input.space, "space");
  data.set(decodeBase58(input.owner ?? SHIELDED_POOL_PROGRAM_ID), 20);
  return Object.freeze({
    programAddress: "11111111111111111111111111111111" as Address,
    accounts: Object.freeze([
      Object.freeze({ address: input.payer, isSigner: true, isWritable: true }),
      Object.freeze({ address: input.account, isSigner: true, isWritable: true }),
    ]),
    data,
  });
}

export function createTreeInstructions(
  input: Readonly<{
    payer: Address;
    authority: Address;
    tree: Address;
    lamports: bigint;
    space: bigint;
  }>,
): readonly Instruction[] {
  return Object.freeze([
    systemCreateAccountInstruction({
      payer: input.payer,
      account: input.tree,
      lamports: input.lamports,
      space: input.space,
    }),
    createTreeInstruction({
      authority: input.authority,
      tree: input.tree,
    }),
  ]);
}

function writeU64(bytes: Uint8Array, offset: number, value: bigint, field: string): void {
  if (value < 0n || value > 0xffff_ffff_ffff_ffffn) {
    throw new TestKitError("TEST_KIT_INVALID_CONFIG", { details: { field } });
  }
  new DataView(bytes.buffer).setBigUint64(offset, value, true);
}

function decodeBase58(value: string): Uint8Array {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const bytes = [0];
  for (const character of value) {
    let carry = alphabet.indexOf(character);
    if (carry < 0)
      throw new TestKitError("TEST_KIT_INVALID_CONFIG", { details: { field: "owner" } });
    for (let index = 0; index < bytes.length; index++) {
      const next = (bytes[index] ?? 0) * 58 + carry;
      bytes[index] = next & 0xff;
      carry = next >> 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  for (let index = 0; index < value.length - 1 && value[index] === "1"; index++) bytes.push(0);
  const result = Uint8Array.from(bytes.reverse());
  if (result.length !== 32) {
    throw new TestKitError("TEST_KIT_INVALID_CONFIG", {
      details: { field: "owner", expected: 32, actual: result.length },
    });
  }
  return result;
}
