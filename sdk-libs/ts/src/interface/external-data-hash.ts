import type { Address, Bytes32, MessageData, ResolvedOutput } from "./types.js";
import {
  addressBytes,
  copyBytes,
  fail,
  sha256,
  signedBigint,
  unsigned,
  unsignedBigint,
} from "./internal.js";

export interface ExternalDataHashInput {
  readonly instructionDiscriminator: number;
  readonly expiryUnixTs: bigint;
  readonly relayerFee: number;
  readonly publicSolAmount?: bigint;
  readonly publicSplAmount?: bigint;
  readonly userSolAccount: Address;
  readonly userSplTokenAccount: Address;
  readonly splTokenInterface: Address;
  readonly dataHash?: Bytes32;
  readonly zoneDataHash?: Bytes32;
  readonly outputs: readonly ResolvedOutput[];
  readonly messages: readonly MessageData[];
}

export function externalDataHash(input: ExternalDataHashInput): Bytes32 {
  const parts: Uint8Array[] = [
    Uint8Array.of(unsigned(input.instructionDiscriminator, 0xff, "instructionDiscriminator")),
    integer(unsignedBigint(input.expiryUnixTs, (1n << 64n) - 1n, "expiryUnixTs"), 8),
    integer(BigInt(unsigned(input.relayerFee, 0xffff, "relayerFee")), 2),
    integer(signedAmount(input.publicSolAmount, "publicSolAmount"), 8),
    integer(signedAmount(input.publicSplAmount, "publicSplAmount"), 8),
    addressBytes(input.userSolAccount, "userSolAccount"),
    addressBytes(input.userSplTokenAccount, "userSplTokenAccount"),
    addressBytes(input.splTokenInterface, "splTokenInterface"),
    optionalBytes(input.dataHash, "dataHash"),
    optionalBytes(input.zoneDataHash, "zoneDataHash"),
    count(input.outputs.length, "outputs"),
  ];

  input.outputs.forEach((output, index) => {
    const position = String(index);
    parts.push(
      copyBytes(output.utxoHash, 32, `outputs[${position}].utxoHash`),
      copyBytes(output.ownerTag, 32, `outputs[${position}].ownerTag`),
    );
    if (output.data === undefined) {
      parts.push(Uint8Array.of(0));
    } else {
      const data = copyBytes(output.data);
      parts.push(Uint8Array.of(1), count(data.length, `outputs[${position}].data`), data);
    }
  });

  parts.push(count(input.messages.length, "messages"));
  input.messages.forEach((message, index) => {
    const position = String(index);
    const data = copyBytes(message.data);
    parts.push(
      copyBytes(message.viewTag, 32, `messages[${position}].viewTag`),
      count(data.length, `messages[${position}].data`),
      data,
    );
  });

  const digest = sha256(concat(parts));
  digest[0] = 0;
  return digest as Bytes32;
}

function signedAmount(value: bigint | undefined, name: string): bigint {
  const amount = signedBigint(value ?? 0n, -(1n << 63n), (1n << 63n) - 1n, name);
  return BigInt.asUintN(64, amount);
}

function optionalBytes(value: Bytes32 | undefined, name: string): Uint8Array {
  return value === undefined ? new Uint8Array(32) : copyBytes(value, 32, name);
}

function count(value: number, name: string): Uint8Array {
  return integer(BigInt(unsigned(value, 0xffff, name)), 2);
}

function integer(value: bigint, length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  let remaining = value;
  for (let index = length - 1; index >= 0; index -= 1) {
    bytes[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  if (remaining !== 0n) fail("INTERFACE_INVALID_INTEGER", { value: value.toString(), length });
  return bytes;
}

function concat(parts: readonly Uint8Array[]): Uint8Array {
  const bytes = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    bytes.set(part, offset);
    offset += part.length;
  }
  return bytes;
}
