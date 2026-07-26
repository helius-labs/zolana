import type { Rpc } from "@zolana/client";
import type { Address, Instruction, RequestContext } from "@zolana/interface";
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

/**
 * Reads the rent itself, as `create_tree_instructions` does, rather than taking
 * it: the caller has no other way to learn the exempt balance for `accountSize`,
 * and a guessed one leaves the tree closable.
 *
 * The read is optional on `Rpc` because Rust defaults it to `unsupported`, so an
 * rpc that does not answer it is refused here rather than sent a tree account
 * funded with nothing.
 */
export async function createTreeInstructions(
  rpc: Pick<Rpc, "getMinimumBalanceForRentExemption">,
  input: Readonly<{
    payer: Address;
    authority: Address;
    tree: Address;
    accountSize: number;
  }>,
  context?: RequestContext,
): Promise<readonly Instruction[]> {
  const getRent = rpc.getMinimumBalanceForRentExemption;
  if (getRent === undefined) {
    throw new TestKitError("TEST_KIT_RPC", {
      details: { method: "getMinimumBalanceForRentExemption", reason: "unsupported" },
    });
  }
  const lamports = await getRent.call(rpc, input.accountSize, context);
  return Object.freeze([
    systemCreateAccountInstruction({
      payer: input.payer,
      account: input.tree,
      lamports,
      space: BigInt(input.accountSize),
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
