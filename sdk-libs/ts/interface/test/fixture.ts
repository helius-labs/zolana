import { readFileSync } from "node:fs";

export interface DepositFixtureAccount {
  readonly address: string;
  readonly signer: boolean;
  readonly writable: boolean;
}

export interface DepositFixture {
  readonly inputs: Readonly<{
    amount: string;
    blindingBytes: string;
    memoBytes: string;
    ownerBytes: string;
    viewTagBytes: string;
  }>;
  readonly expected: Readonly<{
    accounts: readonly DepositFixtureAccount[];
    dataBytes: string;
    programId: string;
  }>;
}

const readTextFile = readFileSync as unknown as (path: URL, encoding: "utf8") => string;

function record(value: unknown, name: string): Readonly<Record<string, unknown>> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${name} must be an object`);
  }
  return value as Readonly<Record<string, unknown>>;
}

function stringField(value: Readonly<Record<string, unknown>>, key: string): string {
  const field = value[key];
  if (typeof field !== "string") throw new Error(`fixture ${key} must be a string`);
  return field;
}

function booleanField(value: Readonly<Record<string, unknown>>, key: string): boolean {
  const field = value[key];
  if (typeof field !== "boolean") throw new Error(`fixture ${key} must be a boolean`);
  return field;
}

export function readDepositFixture(url: URL): DepositFixture {
  const parsed: unknown = JSON.parse(readTextFile(url, "utf8"));
  const root = record(parsed, "fixture");
  const inputs = record(root.inputs, "fixture inputs");
  const expected = record(root.expected, "fixture expected");
  if (!Array.isArray(expected.accounts)) throw new Error("fixture accounts must be an array");
  const accounts = expected.accounts.map((value, index) => {
    const account = record(value, `fixture account ${String(index)}`);
    return {
      address: stringField(account, "address"),
      signer: booleanField(account, "signer"),
      writable: booleanField(account, "writable"),
    };
  });
  return {
    inputs: {
      amount: stringField(inputs, "amount"),
      blindingBytes: stringField(inputs, "blindingBytes"),
      memoBytes: stringField(inputs, "memoBytes"),
      ownerBytes: stringField(inputs, "ownerBytes"),
      viewTagBytes: stringField(inputs, "viewTagBytes"),
    },
    expected: {
      accounts,
      dataBytes: stringField(expected, "dataBytes"),
      programId: stringField(expected, "programId"),
    },
  };
}

export function fixtureAccount(fixture: DepositFixture, index: number): DepositFixtureAccount {
  const account = fixture.expected.accounts[index];
  if (account === undefined) throw new Error(`fixture account ${String(index)} is missing`);
  return account;
}

export function hexBytes(value: string): Uint8Array {
  if (value.length % 2 !== 0 || !/^[\da-f]*$/iu.test(value)) {
    throw new Error("fixture contains invalid hex");
  }
  return Uint8Array.from({ length: value.length / 2 }, (_, index) =>
    Number.parseInt(value.slice(index * 2, index * 2 + 2), 16),
  );
}
