import { describe, expect, it } from "vitest";
import type { Address } from "@zolana/interface";

import { encodeAddress } from "../src/base58.js";
import {
  SMART_ACCOUNT_PROGRAM_ID,
  allPermissions,
  createSmartAccountInstruction,
  executeSyncInstruction,
  programConfigAddress,
  settingsAddress,
  smartAccountAddress,
  treasuryAddress,
} from "../src/index.js";

const CREATOR = address("2ktgiq7GNkitdMWCLmUtZm4qM8UEWerKXcL4WtAaRfPP");
const PROGRAM_CONFIG = address("GmY9kVi3FhrCUn2MJkzzpE6C5618YoHuGsgqHU78cKus");
const TREASURY = address("CvxpwskyftbvvXLSwsMoW7QByjo7yBeYY85nRM6WMsqy");
const SYSTEM_PROGRAM = address("11111111111111111111111111111111");
const PROTOCOL_VAULT = address("EdMSvMoHfsemd2s7eHCrRnuM1dzPu2CpUrHJN98XYC9y");

const SETTINGS_VECTORS = [
  [
    "41gqrPgijYycTaCCzKyLfvqikMEH9fzGCwZYAKQHvMbd",
    249,
    "EdMSvMoHfsemd2s7eHCrRnuM1dzPu2CpUrHJN98XYC9y",
    255,
  ],
  [
    "9pits5NtSr7qjgYxf8CAiRbST3CfpsVs58ExNyW9YJnn",
    254,
    "HentFJ9edn8jLudNMN4UWDcE5gQCskFjrBkzGf5fmexW",
    252,
  ],
  [
    "4ozU3bD11Bij9sBWaRctx3eQChbeYaBDA4csb5gENoDY",
    255,
    "EoRGAciEX8g2qZgfqrvwzrM9zV7SYbdjRvw76cvFdSNy",
    254,
  ],
  [
    "DgnxgGSgo81CuGtVHZy8ZWQsKuU6RQwUYiDjgdZdc4Qp",
    252,
    "HeyDRGGvcgSgAKDV92nK9TNN2qbYLrjsVtBj662AnS2x",
    255,
  ],
  [
    "7GfwwYesGFkWvAqh8vebkUFgubtpaCEfh6GvoX5f194s",
    255,
    "43FjdgD5zqL9Yay7sCx2iyzJSJ82oi1dzcGLV6o8eaFB",
    252,
  ],
] as const;

const CREATE_DATA = [
  "c566fde74d543211000100010000001b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b07000000000000",
  "c566fde74d54321101ca77f5636e4c00c96eae141e79ee412bc0ac098d26d010b958fb13800aa4c82c0100010000001c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c07000000000000",
  "c566fde74d54321101ca77f5636e4c00c96eae141e79ee412bc0ac098d26d010b958fb13800aa4c82c0100010000001d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d07000000000000",
  "c566fde74d54321101ca77f5636e4c00c96eae141e79ee412bc0ac098d26d010b958fb13800aa4c82c0100010000001e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e07000000000000",
  "c566fde74d54321101ca77f5636e4c00c96eae141e79ee412bc0ac098d26d010b958fb13800aa4c82c0100010000001f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f07000000000000",
] as const;

describe("frozen Rust vectors", () => {
  it("matches the program ID, PDA addresses, and bumps", () => {
    expect(SMART_ACCOUNT_PROGRAM_ID).toBe("SMRTzfY6DfH5ik3TKiyLFfXexV8uSG3d2UksSCYdunG");
    expect(programConfigAddress()).toEqual([PROGRAM_CONFIG, 253]);
    expect(treasuryAddress()).toBe(TREASURY);

    for (const [index, [settings, settingsBump, vault, vaultBump]] of SETTINGS_VECTORS.entries()) {
      expect(settingsAddress(BigInt(index + 1))).toEqual([settings, settingsBump]);
      expect(smartAccountAddress(address(settings), 0)).toEqual([vault, vaultBump]);
    }
  });

  it("matches all five standard create instructions", () => {
    for (const [index, [settings]] of SETTINGS_VECTORS.entries()) {
      const seed = index + 1;
      const instruction = createSmartAccountInstruction({
        creator: CREATOR,
        treasury: TREASURY,
        settingsSeed: BigInt(seed),
        ...(seed === 1 ? {} : { settingsAuthority: PROTOCOL_VAULT }),
        signers: [
          {
            key: repeatedByteAddress(26 + seed),
            permissions: allPermissions(),
          },
        ],
        threshold: 1,
        timeLock: 0,
      });

      expect(instruction.programAddress).toBe(SMART_ACCOUNT_PROGRAM_ID);
      expect(instruction.accounts).toEqual([
        meta(PROGRAM_CONFIG, false, true),
        meta(TREASURY, false, true),
        meta(CREATOR, true, true),
        meta(SYSTEM_PROGRAM, false, false),
        meta(SMART_ACCOUNT_PROGRAM_ID, false, false),
        meta(address(settings), false, true),
      ]);
      expect(hex(instruction.data)).toBe(CREATE_DATA[index]);
    }
  });

  it("matches the Rust execute payload, indexes, and account flags", () => {
    const settings = address(SETTINGS_VECTORS[0][0]);
    const member = repeatedByteAddress(42);
    const program = repeatedByteAddress(9);
    const duplicate = repeatedByteAddress(8);
    const signer = repeatedByteAddress(7);

    const instruction = executeSyncInstruction({
      settings,
      accountIndex: 0,
      signerKeys: [member],
      innerInstructions: [
        {
          programAddress: program,
          accounts: [meta(PROTOCOL_VAULT, true, false), meta(duplicate, false, false)],
          data: Uint8Array.of(1, 2, 3),
        },
        {
          programAddress: program,
          accounts: [meta(duplicate, false, true), meta(signer, true, false)],
          data: new Uint8Array(),
        },
      ],
    });

    expect(hex(instruction.data)).toBe(
      "5a51bb512746804e0001001000000002010200020300010203010202030000",
    );
    expect(instruction.accounts).toEqual([
      meta(settings, false, true),
      meta(SMART_ACCOUNT_PROGRAM_ID, false, false),
      meta(member, true, false),
      meta(PROTOCOL_VAULT, false, true),
      meta(program, false, false),
      meta(duplicate, false, true),
      meta(signer, true, false),
    ]);
  });
});

function repeatedByteAddress(byte: number): Address {
  return encodeAddress(new Uint8Array(32).fill(byte));
}

function address(value: string): Address {
  return value as Address;
}

function meta(addressValue: Address, isSigner: boolean, isWritable: boolean) {
  return { address: addressValue, isSigner, isWritable };
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
