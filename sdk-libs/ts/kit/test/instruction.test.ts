import { AccountRole, type Instruction as KitInstruction } from "@solana/kit";
import type { Address, Instruction } from "@zolana/interface";
import { describe, expect, it } from "vitest";

import {
  fromAccountRole,
  fromKitInstruction,
  KitError,
  toAccountRole,
  toKitInstruction,
} from "../src/index.js";

const PROGRAM = "sppzgEd25DF4PC1FgNerLWVZndUAV82LV9Dy5yCvRVA" as Address;
const SYSTEM_PROGRAM = "11111111111111111111111111111111" as Address;
const LOOKUP_TABLE = "AddressLookupTab1e1111111111111111111111111" as Address;

const PERMISSIONS = [
  { isSigner: false, isWritable: false, role: AccountRole.READONLY },
  { isSigner: false, isWritable: true, role: AccountRole.WRITABLE },
  { isSigner: true, isWritable: false, role: AccountRole.READONLY_SIGNER },
  { isSigner: true, isWritable: true, role: AccountRole.WRITABLE_SIGNER },
] as const;

describe("account roles", () => {
  it("maps both booleans onto the role Kit documents for them", () => {
    for (const { isSigner, isWritable, role } of PERMISSIONS) {
      expect(toAccountRole({ isSigner, isWritable })).toBe(role);
      expect(fromAccountRole(role)).toEqual({ isSigner, isWritable });
    }
  });

  it("rejects a number that is not one of the four roles", () => {
    expect(() => fromAccountRole(7 as AccountRole)).toThrow(KitError);
  });
});

describe("instruction conversion", () => {
  const instruction: Instruction = {
    programAddress: PROGRAM,
    accounts: [
      { address: SYSTEM_PROGRAM, isSigner: false, isWritable: false },
      { address: PROGRAM, isSigner: true, isWritable: true },
    ],
    data: Uint8Array.of(1, 2, 3),
  };

  it("round-trips an instruction through Kit's shape", () => {
    expect(fromKitInstruction(toKitInstruction(instruction))).toEqual(instruction);
  });

  it("reads Kit's absent accounts and data as empty rather than missing", () => {
    expect(fromKitInstruction({ programAddress: PROGRAM })).toEqual({
      programAddress: PROGRAM,
      accounts: [],
      data: new Uint8Array(0),
    });
  });

  it("refuses an account that must be resolved through a lookup table", () => {
    const withLookup: KitInstruction = {
      programAddress: PROGRAM,
      accounts: [
        {
          address: SYSTEM_PROGRAM,
          addressIndex: 0,
          lookupTableAddress: LOOKUP_TABLE,
          role: AccountRole.READONLY,
        },
      ],
    };
    expect(() => fromKitInstruction(withLookup)).toThrow(KitError);
    expect(() => fromKitInstruction(withLookup)).toThrow(/address lookup table/u);
  });

  it("validates addresses on the way out, where Zolana's cast did not", () => {
    expect(() =>
      toKitInstruction({
        programAddress: "not an address" as Address,
        accounts: [],
        data: new Uint8Array(0),
      }),
    ).toThrow(KitError);
  });
});
