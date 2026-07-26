import { describe, expect, it } from "vitest";
import type { Address } from "@zolana/interface";

import { encodeAddress } from "../src/base58.js";
import {
  SMART_ACCOUNT_PROGRAM_ID,
  SmartAccountClientError,
  allPermissions,
  createSmartAccountInstruction,
  executeSyncInstruction,
  programConfigAddress,
  settingsAddress,
  smartAccountAddress,
  treasuryAddress,
} from "../src/index.js";
import type { Permissions, SmartAccountSigner } from "../src/index.js";

const SIGNER = testAddress(1);

describe("public declaration ledger", () => {
  it("test-smart-account-client-root-const-smart-account-program-id", () => {
    expect(SMART_ACCOUNT_PROGRAM_ID).toBe("SMRTzfY6DfH5ik3TKiyLFfXexV8uSG3d2UksSCYdunG");
  });

  it("test-smart-account-client-root-interface-permissions", () => {
    const permissions: Permissions = { mask: 7 };
    expect(permissions).toEqual({ mask: 7 });
  });

  it("test-smart-account-client-root-interface-smart-account-signer", () => {
    const signer: SmartAccountSigner = { key: SIGNER, permissions: { mask: 7 } };
    expect(signer.key).toBe(SIGNER);
  });

  it("test-smart-account-client-root-class-smart-account-client-error", () => {
    const error = new SmartAccountClientError("SMART_ACCOUNT_TEST", "test");
    expect(error).toMatchObject({ name: "SmartAccountClientError", code: "SMART_ACCOUNT_TEST" });
  });

  it("test-smart-account-client-root-function-all-permissions", () => {
    expect(allPermissions()).toEqual({ mask: 7 });
  });

  it("test-smart-account-client-root-function-program-config-address", () => {
    expect(programConfigAddress()).toEqual(["GmY9kVi3FhrCUn2MJkzzpE6C5618YoHuGsgqHU78cKus", 253]);
  });

  it("test-smart-account-client-root-function-treasury-address", () => {
    expect(treasuryAddress()).toBe("CvxpwskyftbvvXLSwsMoW7QByjo7yBeYY85nRM6WMsqy");
  });

  it("test-smart-account-client-root-function-settings-address", () => {
    expect(settingsAddress(1n)).toEqual(["41gqrPgijYycTaCCzKyLfvqikMEH9fzGCwZYAKQHvMbd", 249]);
  });

  it("test-smart-account-client-root-function-smart-account-address", () => {
    expect(smartAccountAddress(settingsAddress(1n)[0], 0)).toEqual([
      "EdMSvMoHfsemd2s7eHCrRnuM1dzPu2CpUrHJN98XYC9y",
      255,
    ]);
  });

  it("test-smart-account-client-root-function-create-smart-account-instruction", () => {
    expect(createInstruction().data).toHaveLength(54);
  });

  it("test-smart-account-client-root-function-execute-sync-instruction", () => {
    expect(
      executeSyncInstruction({
        settings: settingsAddress(1n)[0],
        accountIndex: 0,
        signerKeys: [SIGNER],
        innerInstructions: [],
      }).data,
    ).toHaveLength(16);
  });
});

function createInstruction() {
  return createSmartAccountInstruction({
    creator: testAddress(2),
    treasury: treasuryAddress(),
    settingsSeed: 1n,
    signers: [{ key: SIGNER, permissions: allPermissions() }],
    threshold: 1,
    timeLock: 0,
  });
}

function testAddress(value: number): Address {
  const bytes = new Uint8Array(32);
  new DataView(bytes.buffer).setUint32(0, value);
  bytes[31] = 1;
  return encodeAddress(bytes);
}
