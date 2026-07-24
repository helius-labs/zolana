/// <reference types="node" />

import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

import type { Address, Instruction } from "@zolana/interface";
import {
  SMART_ACCOUNT_PROGRAM_ID,
  allPermissions,
  createSmartAccountInstruction,
  programConfigAddress,
  settingsAddress,
  smartAccountAddress,
  treasuryAddress,
} from "@zolana/smart-account-client";

import { TestKitError } from "./error.js";
import { fixtureJson } from "./fixtures/index.js";

export interface StandardAccounts {
  readonly protocolSettings: Address;
  readonly protocolVault: Address;
  readonly foresterSettings: Address;
  readonly foresterVault: Address;
  readonly mergeSettings: Address;
  readonly mergeVault: Address;
  readonly treeSettings: Address;
  readonly treeVault: Address;
  readonly zoneSettings: Address;
  readonly zoneVault: Address;
}

export function standardAccounts(): StandardAccounts {
  const [protocolSettings] = settingsAddress(1n);
  const [foresterSettings] = settingsAddress(2n);
  const [mergeSettings] = settingsAddress(3n);
  const [treeSettings] = settingsAddress(4n);
  const [zoneSettings] = settingsAddress(5n);
  return Object.freeze({
    protocolSettings,
    protocolVault: smartAccountAddress(protocolSettings, 0)[0],
    foresterSettings,
    foresterVault: smartAccountAddress(foresterSettings, 0)[0],
    mergeSettings,
    mergeVault: smartAccountAddress(mergeSettings, 0)[0],
    treeSettings,
    treeVault: smartAccountAddress(treeSettings, 0)[0],
    zoneSettings,
    zoneVault: smartAccountAddress(zoneSettings, 0)[0],
  });
}

export async function verifyStandardAccountsFixture(): Promise<StandardAccounts> {
  const fixture = await fixtureJson<{
    readonly expected: Readonly<Record<string, Address>>;
  }>("test-kit/standard-accounts-v1");
  const accounts = standardAccounts();
  const expected = fixture.expected;
  for (const name of [
    "protocolVault",
    "foresterVault",
    "mergeVault",
    "treeVault",
    "zoneVault",
  ] as const) {
    if (accounts[name] !== expected[name]) {
      throw new TestKitError("TEST_KIT_FIXTURE", {
        details: {
          reason: "standardAccount",
          name,
          expected: expected[name],
          actual: accounts[name],
        },
      });
    }
  }
  return accounts;
}

export function createStandardAccountInstructions(
  input: Readonly<{
    creator: Address;
    signers: Readonly<{
      protocol: Address;
      forester: Address;
      merge: Address;
      tree: Address;
      zone: Address;
    }>;
  }>,
): readonly Instruction[] {
  const accounts = standardAccounts();
  const values = [
    [1n, undefined, input.signers.protocol],
    [2n, accounts.protocolVault, input.signers.forester],
    [3n, accounts.protocolVault, input.signers.merge],
    [4n, accounts.protocolVault, input.signers.tree],
    [5n, accounts.protocolVault, input.signers.zone],
  ] as const;
  return Object.freeze(
    values.map(([settingsSeed, settingsAuthority, signer]) =>
      createSmartAccountInstruction({
        creator: input.creator,
        treasury: treasuryAddress(),
        settingsSeed,
        ...(settingsAuthority === undefined ? {} : { settingsAuthority }),
        signers: [{ key: signer, permissions: allPermissions() }],
        threshold: 1,
        timeLock: 0,
      }),
    ),
  );
}

export async function writeProgramConfigFixture(accountDirectory: string): Promise<void> {
  const [programConfig] = programConfigAddress();
  const data = new Uint8Array(160);
  data.set([196, 210, 90, 231, 144, 149, 140, 63]);
  data.set(decodeBase58(treasuryAddress()), 64);
  const fixture = {
    pubkey: programConfig,
    account: {
      lamports: 1_000_000,
      data: [Buffer.from(data).toString("base64"), "base64"],
      owner: SMART_ACCOUNT_PROGRAM_ID,
      executable: false,
      rentEpoch: "18446744073709551615",
    },
  };
  await mkdir(accountDirectory, { recursive: true });
  await writeFile(
    path.join(accountDirectory, "squads_program_config.json"),
    JSON.stringify(fixture).replace('"18446744073709551615"', "18446744073709551615"),
  );
}

function decodeBase58(value: string): Uint8Array {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const bytes = [0];
  for (const character of value) {
    let carry = alphabet.indexOf(character);
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
  return Uint8Array.from(bytes.reverse());
}
