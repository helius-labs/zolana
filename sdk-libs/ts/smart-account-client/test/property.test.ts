import { describe, expect, it } from "vitest";
import type { Address } from "@zolana/interface";

import { encodeAddress } from "../src/base58.js";
import { executeSyncInstruction, settingsAddress, smartAccountAddress } from "../src/index.js";

const SETTINGS = settingsAddress(7n)[0];
const PROGRAM = testAddress(1);

describe("payload compilation properties", () => {
  it("unions duplicate privileges without changing their first index", () => {
    for (let seed = 0; seed < 64; seed += 1) {
      const duplicate = testAddress(seed + 10);
      const other = testAddress(seed + 100);
      const firstWritable = (seed & 1) !== 0;
      const secondWritable = (seed & 2) !== 0;
      const firstSigner = (seed & 4) !== 0;
      const secondSigner = (seed & 8) !== 0;

      const instruction = executeSyncInstruction({
        settings: SETTINGS,
        accountIndex: 0,
        signerKeys: [],
        innerInstructions: [
          {
            programAddress: PROGRAM,
            accounts: [meta(duplicate, firstSigner, firstWritable), meta(other, false, false)],
            data: Uint8Array.of(seed),
          },
          {
            programAddress: PROGRAM,
            accounts: [meta(duplicate, secondSigner, secondWritable)],
            data: new Uint8Array(),
          },
        ],
      });

      const duplicateMeta = instruction.accounts.find((account) => account.address === duplicate);
      expect(duplicateMeta).toEqual(
        meta(duplicate, firstSigner || secondSigner, firstWritable || secondWritable),
      );
      expect(payloadIndexes(instruction.data)).toEqual([
        [1, 2, 3],
        [1, 2],
      ]);
    }
  });

  it("always clears the vault outer signer bit", () => {
    for (const accountIndex of [0, 1, 127, 255]) {
      const vault = smartAccountAddress(SETTINGS, accountIndex)[0];
      const instruction = executeSyncInstruction({
        settings: SETTINGS,
        accountIndex,
        signerKeys: [],
        innerInstructions: [
          {
            programAddress: PROGRAM,
            accounts: [meta(vault, true, false), meta(vault, false, true)],
            data: new Uint8Array(),
          },
        ],
      });
      const outerVault = instruction.accounts.find((account) => account.address === vault);
      expect(outerVault).toEqual(meta(vault, false, true));
      expect(payloadIndexes(instruction.data)).toEqual([[1, 0, 0]]);
    }
  });

  it("returns bytes and account objects independent of caller mutation", () => {
    const data = Uint8Array.of(4, 5, 6);
    const accounts = [meta(testAddress(500), false, true)];
    const innerInstructions = [{ programAddress: PROGRAM, accounts, data }];
    const instruction = executeSyncInstruction({
      settings: SETTINGS,
      accountIndex: 0,
      signerKeys: [],
      innerInstructions,
    });
    const originalData = new Uint8Array(instruction.data);
    const originalAccounts = instruction.accounts.map((account) => ({ ...account }));

    data.fill(0);
    accounts[0] = meta(testAddress(501), true, false);

    expect(instruction.data).toEqual(originalData);
    expect(instruction.accounts).toEqual(originalAccounts);
  });
});

function payloadIndexes(data: Uint8Array): number[][] {
  const payload = data.subarray(15);
  const count = payload[0] ?? 0;
  const result: number[][] = [];
  let offset = 1;
  for (let instructionIndex = 0; instructionIndex < count; instructionIndex += 1) {
    const programIndex = payload[offset] ?? 0;
    const accountCount = payload[offset + 1] ?? 0;
    const indexes = [programIndex];
    offset += 2;
    for (let accountIndex = 0; accountIndex < accountCount; accountIndex += 1) {
      indexes.push(payload[offset] ?? 0);
      offset += 1;
    }
    const dataLength = (payload[offset] ?? 0) | ((payload[offset + 1] ?? 0) << 8);
    offset += 2 + dataLength;
    result.push(indexes);
  }
  return result;
}

function meta(address: Address, isSigner: boolean, isWritable: boolean) {
  return { address, isSigner, isWritable };
}

function testAddress(value: number): Address {
  const bytes = new Uint8Array(32);
  new DataView(bytes.buffer).setUint32(0, value);
  bytes[31] = 1;
  return encodeAddress(bytes);
}
