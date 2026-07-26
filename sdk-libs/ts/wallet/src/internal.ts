import { checkedTransactionSize } from "@zolana/interface";
import type { Address, Bytes32, Instruction, Signature, Transaction } from "@zolana/interface";

import { WalletError } from "./error.js";

const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function copy32(value: Uint8Array, field: string): Bytes32 {
  if (!(value instanceof Uint8Array) || value.length !== 32) {
    throw new WalletError("WALLET_INVALID_LENGTH", {
      details: {
        field,
        expected: 32,
        actual: value instanceof Uint8Array ? value.length : -1,
      },
    });
  }
  return new Uint8Array(value) as Bytes32;
}

export function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}

export function bytesKey(value: Uint8Array): string {
  return [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function decodeBase58(value: string, length: number, field: string): Uint8Array {
  if (typeof value !== "string" || value.length === 0) {
    throw new WalletError("WALLET_INVALID_ADDRESS", { details: { field } });
  }
  const bytes = [0];
  for (const character of value) {
    const digit = BASE58.indexOf(character);
    if (digit < 0) {
      throw new WalletError("WALLET_INVALID_ADDRESS", { details: { field } });
    }
    let carry = digit;
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
  if (result.length !== length) {
    throw new WalletError("WALLET_INVALID_LENGTH", {
      details: { field, expected: length, actual: result.length },
    });
  }
  return result;
}

export function encodeBase58(value: Uint8Array): string {
  if (value.length === 0) return "";
  const digits = [0];
  for (const byte of value) {
    let carry = byte;
    for (let index = 0; index < digits.length; index++) {
      const next = (digits[index] ?? 0) * 256 + carry;
      digits[index] = next % 58;
      carry = Math.floor(next / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  let prefix = "";
  for (let index = 0; index < value.length - 1 && value[index] === 0; index++) prefix += "1";
  return (
    prefix +
    digits
      .reverse()
      .map((digit) => BASE58[digit])
      .join("")
  );
}

export function checkedAddress(value: Address, field: string): Address {
  decodeBase58(value, 32, field);
  return value;
}

export function concat(...parts: readonly Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function compactU16(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff) {
    throw new WalletError("WALLET_INVALID_INTEGER", { details: { value } });
  }
  const bytes: number[] = [];
  let remaining = value;
  do {
    let byte = remaining & 0x7f;
    remaining >>>= 7;
    if (remaining !== 0) byte |= 0x80;
    bytes.push(byte);
  } while (remaining !== 0);
  return Uint8Array.from(bytes);
}

export function compileTransaction(
  input: Readonly<{
    feePayer: Address;
    recentBlockhash: string;
    instructions: readonly Instruction[];
  }>,
): Transaction {
  checkedAddress(input.feePayer, "feePayer");
  const accounts = new Map<
    Address,
    { address: Address; isSigner: boolean; isWritable: boolean; order: number }
  >();
  let order = 0;
  accounts.set(input.feePayer, {
    address: input.feePayer,
    isSigner: true,
    isWritable: true,
    order: order++,
  });
  for (const instruction of input.instructions) {
    checkedAddress(instruction.programAddress, "programAddress");
    for (const meta of instruction.accounts) {
      checkedAddress(meta.address, "account");
      const existing = accounts.get(meta.address);
      accounts.set(meta.address, {
        address: meta.address,
        isSigner: (existing?.isSigner ?? false) || meta.isSigner,
        isWritable: (existing?.isWritable ?? false) || meta.isWritable,
        order: existing?.order ?? order++,
      });
    }
    if (!accounts.has(instruction.programAddress)) {
      accounts.set(instruction.programAddress, {
        address: instruction.programAddress,
        isSigner: false,
        isWritable: false,
        order: order++,
      });
    }
  }
  const ordered = [...accounts.values()].sort((left, right) => {
    if (left.address === input.feePayer) return -1;
    if (right.address === input.feePayer) return 1;
    if (left.isSigner !== right.isSigner) return left.isSigner ? -1 : 1;
    if (left.isWritable !== right.isWritable) return left.isWritable ? -1 : 1;
    const leftBytes = decodeBase58(left.address, 32, "account");
    const rightBytes = decodeBase58(right.address, 32, "account");
    for (let index = 0; index < leftBytes.length; index++) {
      if (leftBytes[index] !== rightBytes[index]) {
        return (leftBytes[index] ?? 0) - (rightBytes[index] ?? 0);
      }
    }
    return left.order - right.order;
  });
  if (ordered.length > 256) throw new WalletError("WALLET_TOO_MANY_ACCOUNTS");
  const indexes = new Map(ordered.map((account, index) => [account.address, index]));
  const requiredSignatures = ordered.filter((account) => account.isSigner).length;
  const readonlySigners = ordered.filter(
    (account) => account.isSigner && !account.isWritable,
  ).length;
  const readonlyUnsigned = ordered.filter(
    (account) => !account.isSigner && !account.isWritable,
  ).length;
  const parts: Uint8Array[] = [
    Uint8Array.of(requiredSignatures, readonlySigners, readonlyUnsigned),
    compactU16(ordered.length),
    ...ordered.map((account) => decodeBase58(account.address, 32, "account")),
    decodeBase58(input.recentBlockhash, 32, "recentBlockhash"),
    compactU16(input.instructions.length),
  ];
  for (const instruction of input.instructions) {
    const programIndex = indexes.get(instruction.programAddress);
    if (programIndex === undefined) throw new WalletError("WALLET_TRANSACTION_ASSEMBLY");
    const accountIndexes = instruction.accounts.map((account) => indexes.get(account.address));
    if (accountIndexes.some((index) => index === undefined)) {
      throw new WalletError("WALLET_TRANSACTION_ASSEMBLY");
    }
    parts.push(
      Uint8Array.of(programIndex),
      compactU16(accountIndexes.length),
      Uint8Array.from(accountIndexes as number[]),
      compactU16(instruction.data.length),
      new Uint8Array(instruction.data),
    );
  }
  return checkedTransactionSize(
    Object.freeze({
      messageBytes: concat(...parts),
      signatures: Object.freeze(
        Array.from({ length: requiredSignatures }, (): Signature | undefined => undefined),
      ),
    }),
  );
}

export function base64Bytes(value: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const clean = value.endsWith("==")
    ? value.slice(0, -2)
    : value.endsWith("=")
      ? value.slice(0, -1)
      : value;
  if (clean.length % 4 === 1) throw new WalletError("WALLET_INVALID_BASE64");
  let bits = 0;
  let bitCount = 0;
  const output: number[] = [];
  for (const character of clean) {
    const digit = alphabet.indexOf(character);
    if (digit < 0) throw new WalletError("WALLET_INVALID_BASE64");
    bits = bits * 64 + digit;
    bitCount += 6;
    if (bitCount >= 8) {
      bitCount -= 8;
      output.push((bits >> bitCount) & 0xff);
      bits &= (1 << bitCount) - 1;
    }
  }
  return Uint8Array.from(output);
}
