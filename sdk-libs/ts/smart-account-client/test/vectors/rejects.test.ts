import { describe, expect, it } from "vitest";
import type { Address } from "@zolana/interface";

import fixture from "../../../vectors/smart-account-rejects-v1.json" with { type: "json" };
import { encodeAddress } from "../../src/base58.js";
import {
  SmartAccountClientError,
  createSmartAccountInstruction,
  executeSyncInstruction,
  settingsAddress,
  treasuryAddress,
} from "../../src/index.js";

const CREATOR = encodeAddress(new Uint8Array(32).fill(1));
const PROGRAM = encodeAddress(new Uint8Array(32).fill(9));
const SETTINGS = settingsAddress(1n)[0];
const TREASURY = treasuryAddress();

type RejectCase = Readonly<{
  accepted: boolean;
  id: string;
  kind: string;
  rustPanic: string;
}>;

type AcceptCase = Readonly<{
  accepted: boolean;
  id: string;
}>;

type TamperCase = Readonly<{
  id: string;
  canonicalDataBytes: string;
  tamperedDataBytes: string;
  regeneratedMatchesCanonical: boolean;
  programId: string;
}>;

function uniqueAddress(value: number): Address {
  const bytes = new Uint8Array(32);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, value, true);
  bytes[31] = 1;
  return encodeAddress(bytes);
}

function inner(accounts: readonly Address[]) {
  return {
    programAddress: PROGRAM,
    accounts: accounts.map((address) => ({ address, isSigner: false, isWritable: false })),
    data: new Uint8Array(),
  };
}

/** Rust panic kind → TypeScript `SmartAccountClientError.code` at the builder. */
const REJECT_CODES: Readonly<Record<string, `SMART_ACCOUNT_${string}`>> = {
  "execute-256-signers": "SMART_ACCOUNT_TOO_MANY_SIGNERS",
  "execute-256-inner-instructions": "SMART_ACCOUNT_TOO_MANY_INSTRUCTIONS",
  "execute-256-accounts-per-instruction": "SMART_ACCOUNT_TOO_MANY_ACCOUNTS",
  "execute-257-compiled-accounts": "SMART_ACCOUNT_TOO_MANY_ACCOUNTS",
  "execute-255-distinct-accounts-compiled-overflow": "SMART_ACCOUNT_TOO_MANY_ACCOUNTS",
};

function runCase(id: string): "accepted" | SmartAccountClientError {
  try {
    switch (id) {
      case "create-empty-signers":
        createSmartAccountInstruction({
          creator: CREATOR,
          treasury: TREASURY,
          settingsSeed: 1n,
          signers: [],
          threshold: 1,
          timeLock: 0,
        });
        return "accepted";
      case "create-duplicate-signers": {
        const key = uniqueAddress(7);
        createSmartAccountInstruction({
          creator: CREATOR,
          treasury: TREASURY,
          settingsSeed: 1n,
          signers: [
            { key, permissions: { mask: 1 } },
            { key, permissions: { mask: 2 } },
          ],
          threshold: 1,
          timeLock: 0,
        });
        return "accepted";
      }
      case "create-zero-threshold":
        createSmartAccountInstruction({
          creator: CREATOR,
          treasury: TREASURY,
          settingsSeed: 1n,
          signers: [{ key: uniqueAddress(7), permissions: { mask: 7 } }],
          threshold: 0,
          timeLock: 0,
        });
        return "accepted";
      case "execute-255-signers":
        executeSyncInstruction({
          settings: SETTINGS,
          accountIndex: 0,
          signerKeys: Array.from({ length: 255 }, (_, index) => uniqueAddress(index + 10)),
          innerInstructions: [],
        });
        return "accepted";
      case "execute-255-inner-instructions":
        executeSyncInstruction({
          settings: SETTINGS,
          accountIndex: 0,
          signerKeys: [],
          innerInstructions: Array.from({ length: 255 }, () => inner([])),
        });
        return "accepted";
      case "execute-255-accounts-per-instruction": {
        const repeated = uniqueAddress(300);
        executeSyncInstruction({
          settings: SETTINGS,
          accountIndex: 0,
          signerKeys: [],
          innerInstructions: [inner(Array.from({ length: 255 }, () => repeated))],
        });
        return "accepted";
      }
      case "execute-256-compiled-accounts": {
        const instruction = executeSyncInstruction({
          settings: SETTINGS,
          accountIndex: 0,
          signerKeys: [],
          innerInstructions: [
            inner(Array.from({ length: 254 }, (_, index) => uniqueAddress(index + 1000))),
          ],
        });
        expect(instruction.accounts).toHaveLength(258);
        return "accepted";
      }
      case "execute-duplicate-signer-keys": {
        const member = uniqueAddress(42);
        executeSyncInstruction({
          settings: SETTINGS,
          accountIndex: 0,
          signerKeys: [member, member],
          innerInstructions: [],
        });
        return "accepted";
      }
      case "execute-256-signers":
        executeSyncInstruction({
          settings: SETTINGS,
          accountIndex: 0,
          signerKeys: Array.from({ length: 256 }, (_, index) => uniqueAddress(index + 10)),
          innerInstructions: [],
        });
        return "accepted";
      case "execute-256-inner-instructions":
        executeSyncInstruction({
          settings: SETTINGS,
          accountIndex: 0,
          signerKeys: [],
          innerInstructions: Array.from({ length: 256 }, () => inner([])),
        });
        return "accepted";
      case "execute-256-accounts-per-instruction": {
        const repeated = uniqueAddress(300);
        executeSyncInstruction({
          settings: SETTINGS,
          accountIndex: 0,
          signerKeys: [],
          innerInstructions: [inner(Array.from({ length: 256 }, () => repeated))],
        });
        return "accepted";
      }
      case "execute-257-compiled-accounts":
        executeSyncInstruction({
          settings: SETTINGS,
          accountIndex: 0,
          signerKeys: [],
          innerInstructions: [
            inner(Array.from({ length: 255 }, (_, index) => uniqueAddress(index + 1000))),
          ],
        });
        return "accepted";
      case "execute-255-distinct-accounts-compiled-overflow":
        executeSyncInstruction({
          settings: SETTINGS,
          accountIndex: 0,
          signerKeys: [],
          innerInstructions: [
            inner(Array.from({ length: 255 }, (_, index) => uniqueAddress(index + 2000))),
          ],
        });
        return "accepted";
      default:
        throw new Error(`unhandled case ${id}`);
    }
  } catch (error) {
    if (error instanceof SmartAccountClientError) return error;
    throw error;
  }
}

describe("smart-account rejects (Rust-generated)", () => {
  it("pins the generator identity", () => {
    expect(fixture.id).toBe("smart-account-rejects-v1");
    expect(fixture.rustPath).toBe("sdk-libs/smart-account-client/src/lib.rs");
  });

  for (const testCase of fixture.accepts as AcceptCase[]) {
    it(`accepts ${testCase.id}`, () => {
      expect(testCase.accepted).toBe(true);
      expect(runCase(testCase.id)).toBe("accepted");
    });
  }

  for (const testCase of fixture.rejects as RejectCase[]) {
    const expectedCode = REJECT_CODES[testCase.id];
    if (expectedCode === undefined) {
      throw new Error(`missing REJECT_CODES entry for ${testCase.id}`);
    }
    it(`rejects ${testCase.id} (${testCase.kind}) with ${expectedCode}`, () => {
      expect(testCase.accepted).toBe(false);
      expect(testCase.rustPanic.length).toBeGreaterThan(0);
      const result = runCase(testCase.id);
      expect(result).toBeInstanceOf(SmartAccountClientError);
      expect((result as SmartAccountClientError).code).toBe(expectedCode);
    });
  }

  for (const tamper of fixture.tampers as TamperCase[]) {
    it(`keeps ${tamper.id} from following the flipped bytes`, () => {
      expect(tamper.regeneratedMatchesCanonical).toBe(true);
      expect(tamper.canonicalDataBytes).not.toBe(tamper.tamperedDataBytes);

      const instruction = createSmartAccountInstruction({
        creator: CREATOR,
        treasury: TREASURY,
        settingsSeed: 1n,
        signers: [{ key: encodeAddress(new Uint8Array(32).fill(0x1b)), permissions: { mask: 7 } }],
        threshold: 1,
        timeLock: 0,
      });
      expect(hex(instruction.data)).toBe(tamper.canonicalDataBytes);
      expect(hex(instruction.data)).not.toBe(tamper.tamperedDataBytes);
      expect(instruction.programAddress).toBe(tamper.programId);
    });
  }
});

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
