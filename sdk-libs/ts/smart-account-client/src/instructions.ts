import type { Address, Instruction } from "@zolana/interface";

import { decodeAddress } from "./base58.js";
import { SmartAccountClientError } from "./error.js";
import {
  SMART_ACCOUNT_PROGRAM_ID_VALUE,
  assertUnsignedInteger,
  programConfigAddress,
  settingsAddress,
  smartAccountAddress,
  unsignedLittleEndian,
} from "./pda.js";

export interface Permissions {
  readonly mask: number;
}

export interface SmartAccountSigner {
  readonly key: Address;
  readonly permissions: Permissions;
}

type AccountMeta = Instruction["accounts"][number];

const CREATE_DISCRIMINATOR = Uint8Array.of(197, 102, 253, 231, 77, 84, 50, 17);
const EXECUTE_DISCRIMINATOR = Uint8Array.of(90, 81, 187, 81, 39, 70, 128, 78);
const SYSTEM_PROGRAM = "11111111111111111111111111111111" as Address;
const MAX_U8 = 0xff;
const MAX_U16 = 0xffff;
const MAX_U32 = 0xffff_ffff;
const U128_MAX = (1n << 128n) - 1n;

export function allPermissions(): Permissions {
  return { mask: 0b111 };
}

export function createSmartAccountInstruction(
  input: Readonly<{
    creator: Address;
    treasury: Address;
    settingsSeed: bigint;
    settingsAuthority?: Address;
    signers: readonly SmartAccountSigner[];
    threshold: number;
    timeLock: number;
  }>,
): Instruction {
  decodeAddress(input.creator);
  decodeAddress(input.treasury);
  if (
    typeof input.settingsSeed !== "bigint" ||
    input.settingsSeed < 0n ||
    input.settingsSeed > U128_MAX
  ) {
    throw invalidInteger("settingsSeed", input.settingsSeed);
  }
  assertUnsignedInteger("threshold", input.threshold, MAX_U16);
  assertUnsignedInteger("timeLock", input.timeLock, MAX_U32);
  for (const signer of input.signers) {
    decodeAddress(signer.key);
    assertUnsignedInteger("permissions.mask", signer.permissions.mask, MAX_U8);
  }

  const authorityBytes =
    input.settingsAuthority === undefined ? undefined : decodeAddress(input.settingsAuthority);
  const writer = new ByteWriter();
  writer.bytes(CREATE_DISCRIMINATOR);
  writer.optionBytes(authorityBytes);
  writer.u16(input.threshold);
  writer.u32(input.signers.length);
  for (const signer of input.signers) {
    writer.bytes(decodeAddress(signer.key));
    writer.u8(signer.permissions.mask);
  }
  writer.u32(input.timeLock);
  writer.u8(0);
  writer.u8(0);
  const data = writer.finish();

  const [programConfig] = programConfigAddress();
  const [settings] = settingsAddress(input.settingsSeed);
  return instruction(
    [
      account(programConfig, false, true),
      account(input.treasury, false, true),
      account(input.creator, true, true),
      account(SYSTEM_PROGRAM, false, false),
      account(SMART_ACCOUNT_PROGRAM_ID_VALUE, false, false),
      account(settings, false, true),
    ],
    data,
  );
}

export function executeSyncInstruction(
  input: Readonly<{
    settings: Address;
    accountIndex: number;
    signerKeys: readonly Address[];
    innerInstructions: readonly Instruction[];
  }>,
): Instruction {
  decodeAddress(input.settings);
  assertUnsignedInteger("accountIndex", input.accountIndex, MAX_U8);
  assertCount("signerKeys", input.signerKeys.length);
  assertCount("innerInstructions", input.innerInstructions.length);
  for (const key of input.signerKeys) {
    decodeAddress(key);
  }

  const [vault] = smartAccountAddress(input.settings, input.accountIndex);
  const { payload, accounts: compiledAccounts } = compilePayload(input.innerInstructions, vault);

  const writer = new ByteWriter();
  writer.bytes(EXECUTE_DISCRIMINATOR);
  writer.u8(input.accountIndex);
  writer.u8(input.signerKeys.length);
  writer.u8(0);
  writer.u32(payload.length);
  writer.bytes(payload);
  const data = writer.finish();

  const accounts = [
    account(input.settings, false, true),
    account(SMART_ACCOUNT_PROGRAM_ID_VALUE, false, false),
    ...input.signerKeys.map((key) => account(key, true, false)),
    ...compiledAccounts,
  ];
  return instruction(accounts, data);
}

function compilePayload(
  innerInstructions: readonly Instruction[],
  vault: Address,
): Readonly<{ payload: Uint8Array; accounts: readonly AccountMeta[] }> {
  const accounts: MutableAccountMeta[] = [];
  const indexes = new Map<Address, number>();

  function ensureAccount(address: Address, isSigner: boolean, isWritable: boolean): number {
    decodeAddress(address);
    const existingIndex = indexes.get(address);
    if (existingIndex !== undefined) {
      const existing = mutableAccountAt(accounts, existingIndex);
      existing.isSigner ||= isSigner;
      existing.isWritable ||= isWritable;
      return existingIndex;
    }

    // The payload references accounts by u8 index, so the compiled list holds
    // 256 entries rather than 255: the bound is on the index it hands back.
    if (accounts.length > MAX_U8) {
      throw new SmartAccountClientError(
        "SMART_ACCOUNT_TOO_MANY_ACCOUNTS",
        "compiled account count exceeds u8",
        { details: { maximum: MAX_U8 + 1 } },
      );
    }
    const index = accounts.length;
    indexes.set(address, index);
    accounts.push({ address, isSigner, isWritable });
    return index;
  }

  ensureAccount(vault, false, true);
  for (const inner of innerInstructions) {
    ensureAccount(inner.programAddress, false, false);
    assertCount("innerInstruction.accounts", inner.accounts.length);
    for (const meta of inner.accounts) {
      ensureAccount(meta.address, meta.isSigner, meta.isWritable);
    }
  }

  const writer = new ByteWriter();
  writer.u8(innerInstructions.length);
  for (const inner of innerInstructions) {
    writer.u8(ensureAccount(inner.programAddress, false, false));
    writer.u8(inner.accounts.length);
    for (const meta of inner.accounts) {
      writer.u8(ensureAccount(meta.address, meta.isSigner, meta.isWritable));
    }
    // Rust writes `ix.data.len() as u16`: full bytes stay, high length bits drop.
    writer.u16(inner.data.length & MAX_U16);
    writer.bytes(inner.data);
  }
  const payload = writer.finish();

  const vaultIndex = indexes.get(vault);
  if (vaultIndex === undefined) {
    throw new SmartAccountClientError("SMART_ACCOUNT_INVALID_INDEX", "vault index is missing");
  }
  const vaultMeta = mutableAccountAt(accounts, vaultIndex);
  vaultMeta.isSigner = false;
  return {
    payload,
    accounts: accounts.map((meta) => account(meta.address, meta.isSigner, meta.isWritable)),
  };
}

function assertCount(name: string, count: number): void {
  if (count > MAX_U8) {
    throw new SmartAccountClientError(countErrorCode(name), `${name} count exceeds u8`, {
      details: { actual: count, maximum: MAX_U8 },
    });
  }
}

function countErrorCode(name: string): `SMART_ACCOUNT_${string}` {
  if (name === "innerInstructions") return "SMART_ACCOUNT_TOO_MANY_INSTRUCTIONS";
  if (name === "signerKeys") return "SMART_ACCOUNT_TOO_MANY_SIGNERS";
  return "SMART_ACCOUNT_TOO_MANY_ACCOUNTS";
}

function invalidInteger(name: string, value: number | bigint): SmartAccountClientError {
  return new SmartAccountClientError("SMART_ACCOUNT_INVALID_INTEGER", `${name} is out of range`, {
    details: { name, value: value.toString() },
  });
}

function account(
  address: Address,
  isSigner: boolean,
  isWritable: boolean,
): Readonly<{ address: Address; isSigner: boolean; isWritable: boolean }> {
  return { address, isSigner, isWritable };
}

function instruction(accounts: readonly AccountMeta[], data: Uint8Array): Instruction {
  return {
    programAddress: SMART_ACCOUNT_PROGRAM_ID_VALUE,
    accounts: accounts.map((meta) => ({ ...meta })),
    data: new Uint8Array(data),
  };
}

interface MutableAccountMeta {
  address: Address;
  isSigner: boolean;
  isWritable: boolean;
}

function mutableAccountAt(accounts: MutableAccountMeta[], index: number): MutableAccountMeta {
  const value = accounts[index];
  if (value === undefined) {
    throw new SmartAccountClientError("SMART_ACCOUNT_INVALID_INDEX", "account index is missing", {
      details: { index },
    });
  }
  return value;
}

class ByteWriter {
  readonly #bytes: number[] = [];

  u8(value: number): void {
    this.#bytes.push(value);
  }

  u16(value: number): void {
    this.bytes(unsignedLittleEndian(BigInt(value), 2));
  }

  u32(value: number): void {
    this.bytes(unsignedLittleEndian(BigInt(value), 4));
  }

  optionBytes(value: Uint8Array | undefined): void {
    this.u8(value === undefined ? 0 : 1);
    if (value !== undefined) this.bytes(value);
  }

  bytes(value: Uint8Array): void {
    for (const byte of value) this.#bytes.push(byte);
  }

  finish(): Uint8Array {
    return Uint8Array.from(this.#bytes);
  }
}
