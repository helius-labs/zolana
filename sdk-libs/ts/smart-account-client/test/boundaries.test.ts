import { describe, expect, it } from "vitest";
import type { Address } from "@zolana/interface";

import { encodeAddress } from "../src/base58.js";
import {
  SmartAccountClientError,
  createSmartAccountInstruction,
  executeSyncInstruction,
  settingsAddress,
  smartAccountAddress,
  treasuryAddress,
} from "../src/index.js";

const CREATOR = testAddress(1);
const SETTINGS = settingsAddress(1n)[0];
const PROGRAM = testAddress(2);
const SIGNER = testAddress(3);

describe("integer and signer validation", () => {
  it("accepts the u128, u8, u32, and permission boundaries", () => {
    expect(settingsAddress((1n << 128n) - 1n)[0]).toHaveLength(44);
    expect(smartAccountAddress(SETTINGS, 255)[0]).toBeTypeOf("string");

    const instruction = create({
      settingsSeed: (1n << 128n) - 1n,
      timeLock: 0xffff_ffff,
      permissions: 255,
    });
    expect(instruction.data.length).toBeGreaterThan(0);
  });

  it.each([
    ["settingsSeed", -1n],
    ["settingsSeed", 1n << 128n],
    ["accountIndex", -1],
    ["accountIndex", 256],
    ["timeLock", -1],
    ["timeLock", 0x1_0000_0000],
    ["permissions", -1],
    ["permissions", 256],
    ["threshold", -1],
    ["threshold", 0x1_0000],
  ] as const)("rejects an invalid %s boundary", (field, value) => {
    expectError("SMART_ACCOUNT_INVALID_INTEGER", () => {
      if (field === "settingsSeed") {
        settingsAddress(value);
      } else if (field === "accountIndex") {
        smartAccountAddress(SETTINGS, value);
      } else {
        create({
          ...(field === "timeLock" ? { timeLock: value } : {}),
          ...(field === "permissions" ? { permissions: value } : {}),
          ...(field === "threshold" ? { threshold: value } : {}),
        });
      }
    });
  });

  // Rust's create builder is infallible for these shapes: empty signers, a
  // zero or oversized threshold, and duplicate keys all serialize.
  it("accepts empty, duplicate, and out-of-range threshold signer sets", () => {
    expect(
      createSmartAccountInstruction({
        creator: CREATOR,
        treasury: treasuryAddress(),
        settingsSeed: 1n,
        signers: [],
        threshold: 1,
        timeLock: 0,
      }).data.length,
    ).toBeGreaterThan(0);

    expect(
      createSmartAccountInstruction({
        creator: CREATOR,
        treasury: treasuryAddress(),
        settingsSeed: 1n,
        signers: [
          { key: SIGNER, permissions: { mask: 1 } },
          { key: SIGNER, permissions: { mask: 2 } },
        ],
        threshold: 1,
        timeLock: 0,
      }).data.length,
    ).toBeGreaterThan(0);

    expect(create({ threshold: 0 }).data.length).toBeGreaterThan(0);
    expect(create({ threshold: 2 }).data.length).toBeGreaterThan(0);
  });

  it("accepts duplicate execute signer keys", () => {
    const instruction = executeSyncInstruction({
      settings: SETTINGS,
      accountIndex: 0,
      signerKeys: [SIGNER, SIGNER],
      innerInstructions: [],
    });
    expect(instruction.accounts.filter((account) => account.address === SIGNER)).toHaveLength(2);
  });

  it("rejects malformed addresses before serialization", () => {
    expectError("SMART_ACCOUNT_INVALID_ADDRESS", () =>
      create({ creator: "not-an-address" as Address }),
    );
    expectError("SMART_ACCOUNT_INVALID_ADDRESS", () =>
      executeSyncInstruction({
        settings: "1111" as Address,
        accountIndex: 0,
        signerKeys: [],
        innerInstructions: [],
      }),
    );
  });
});

describe("count and payload boundaries", () => {
  it("accepts 255 signers and rejects 256", () => {
    const signers = Array.from({ length: 255 }, (_, index) => testAddress(index + 10));
    expect(
      executeSyncInstruction({
        settings: SETTINGS,
        accountIndex: 0,
        signerKeys: signers,
        innerInstructions: [],
      }).accounts,
    ).toHaveLength(258);

    expectError("SMART_ACCOUNT_TOO_MANY_SIGNERS", () =>
      executeSyncInstruction({
        settings: SETTINGS,
        accountIndex: 0,
        signerKeys: [...signers, testAddress(300)],
        innerInstructions: [],
      }),
    );
  });

  it("accepts 255 inner instructions and rejects 256", () => {
    const instructions = Array.from({ length: 255 }, () => inner());
    expect(
      executeSyncInstruction({
        settings: SETTINGS,
        accountIndex: 0,
        signerKeys: [],
        innerInstructions: instructions,
      }).data.length,
    ).toBe(1036);

    expectError("SMART_ACCOUNT_TOO_MANY_INSTRUCTIONS", () =>
      executeSyncInstruction({
        settings: SETTINGS,
        accountIndex: 0,
        signerKeys: [],
        innerInstructions: [...instructions, inner()],
      }),
    );
  });

  it("accepts 255 accounts per instruction and rejects 256", () => {
    const accounts = Array.from({ length: 255 }, () => meta(SIGNER, false, false));
    expect(
      executeSyncInstruction({
        settings: SETTINGS,
        accountIndex: 0,
        signerKeys: [],
        innerInstructions: [inner({ accounts })],
      }).data.length,
    ).toBe(275);

    expectError("SMART_ACCOUNT_TOO_MANY_ACCOUNTS", () =>
      executeSyncInstruction({
        settings: SETTINGS,
        accountIndex: 0,
        signerKeys: [],
        innerInstructions: [inner({ accounts: [...accounts, meta(SIGNER, false, false)] })],
      }),
    );
  });

  // The compiled list is addressed by u8 index, so 256 entries fit and the
  // 257th is the first that cannot be named. Rust allocates the same range:
  // `compile_instructions_to_payload` refuses only once the index exceeds u8.
  it("accepts 256 unique compiled accounts, the full u8 index range, and rejects 257", () => {
    // Plus the vault and the inner program id, which the compiler adds first.
    const accounts = Array.from({ length: 254 }, (_, index) =>
      meta(testAddress(index + 1000), false, false),
    );
    const compiled = executeSyncInstruction({
      settings: SETTINGS,
      accountIndex: 0,
      signerKeys: [],
      innerInstructions: [inner({ accounts })],
    });
    // Settings and the program precede the 256 CPI accounts on the outer list.
    expect(compiled.accounts).toHaveLength(258);
    // The payload must name the last account as index 255, not wrap to zero.
    expect(compiled.data).toContain(255);

    expectError("SMART_ACCOUNT_TOO_MANY_ACCOUNTS", () =>
      executeSyncInstruction({
        settings: SETTINGS,
        accountIndex: 0,
        signerKeys: [],
        innerInstructions: [
          inner({ accounts: [...accounts, meta(testAddress(2000), false, false)] }),
        ],
      }),
    );
  });

  // Rust measures transaction size elsewhere and does not refuse here.
  it("accepts instruction and payload sizes past the 1232-byte packet limit", () => {
    expect(
      executeSyncInstruction({
        settings: SETTINGS,
        accountIndex: 0,
        signerKeys: [],
        innerInstructions: [inner({ data: new Uint8Array(1213) })],
      }).data.length,
    ).toBeGreaterThan(1232);

    const signers = Array.from({ length: 37 }, (_, index) => ({
      key: testAddress(index + 500),
      permissions: { mask: 7 },
    }));
    expect(
      createSmartAccountInstruction({
        creator: CREATOR,
        treasury: treasuryAddress(),
        settingsSeed: 1n,
        signers,
        threshold: 1,
        timeLock: 0,
      }).data.length,
    ).toBeGreaterThan(1232);
  });

  // Rust writes `ix.data.len() as u16`, so 0x10000 keeps the bytes and a zero prefix.
  it("truncates an inner data length past u16 the way Rust does", () => {
    const data = new Uint8Array(0x1_0000);
    data[0] = 7;
    data[0xffff] = 9;
    const instruction = executeSyncInstruction({
      settings: SETTINGS,
      accountIndex: 0,
      signerKeys: [],
      innerInstructions: [inner({ data })],
    });
    // Execute header (8+1+1+1+4) then payload: count, program index, account
    // count, u16 length, then the inner bytes.
    const lengthOffset = 8 + 1 + 1 + 1 + 4 + 1 + 1 + 1;
    expect(instruction.data[lengthOffset]).toBe(0);
    expect(instruction.data[lengthOffset + 1]).toBe(0);
    expect(instruction.data[lengthOffset + 2]).toBe(7);
    expect(instruction.data[lengthOffset + 2 + 0xffff]).toBe(9);
    expect(instruction.data.length).toBe(lengthOffset + 2 + 0x1_0000);
  });
});

function create(
  overrides: {
    creator?: Address;
    settingsSeed?: bigint;
    threshold?: number;
    timeLock?: number;
    permissions?: number;
  } = {},
) {
  return createSmartAccountInstruction({
    creator: overrides.creator ?? CREATOR,
    treasury: treasuryAddress(),
    settingsSeed: overrides.settingsSeed ?? 1n,
    signers: [{ key: SIGNER, permissions: { mask: overrides.permissions ?? 7 } }],
    threshold: overrides.threshold ?? 1,
    timeLock: overrides.timeLock ?? 0,
  });
}

function inner(
  overrides: {
    accounts?: readonly ReturnType<typeof meta>[];
    data?: Uint8Array;
  } = {},
) {
  return {
    programAddress: PROGRAM,
    accounts: overrides.accounts ?? [],
    data: overrides.data ?? new Uint8Array(),
  };
}

function meta(address: Address, isSigner: boolean, isWritable: boolean) {
  return { address, isSigner, isWritable };
}

function testAddress(value: number): Address {
  const bytes = new Uint8Array(32);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, value);
  bytes[31] = 1;
  return encodeAddress(bytes);
}

function expectError(code: `SMART_ACCOUNT_${string}`, call: () => unknown): void {
  try {
    call();
    throw new Error(`expected ${code}`);
  } catch (error) {
    expect(error).toBeInstanceOf(SmartAccountClientError);
    expect((error as SmartAccountClientError).code).toBe(code);
  }
}
