import type {
  Bytes16,
  Bytes32,
  Bytes33,
  MessageData,
  ResolvedInterfaceTransfer,
  ResolvedOutput,
} from "./types.js";
import { addressBytes, copyBytes, fail, sha256, unsigned, unsignedBigint } from "./internal.js";

export interface ExternalDataHashInput {
  readonly instructionDiscriminator: number;
  readonly expiryUnixTs: bigint;
  readonly interfaceTransfers: readonly ResolvedInterfaceTransfer[];
  readonly dataHash?: Bytes32;
  readonly ringDataHash?: Bytes32;
  readonly txViewingPk: Bytes33;
  readonly salt: Bytes16;
  readonly outputs: readonly ResolvedOutput[];
  readonly messages: readonly MessageData[];
}

export function externalDataHash(input: ExternalDataHashInput): Bytes32 {
  const parts: Uint8Array[] = [
    Uint8Array.of(unsigned(input.instructionDiscriminator, 0xff, "instructionDiscriminator")),
    integer(unsignedBigint(input.expiryUnixTs, (1n << 64n) - 1n, "expiryUnixTs"), 8),
    Uint8Array.of(unsigned(input.interfaceTransfers.length, 0xff, "interfaceTransfers")),
  ];
  input.interfaceTransfers.forEach((transfer, index) => {
    const position = `interfaceTransfers[${String(index)}]`;
    const amount = integer(
      unsignedBigint(transfer.amount, (1n << 64n) - 1n, `${position}.amount`),
      8,
    );
    if (transfer.kind === "solDeposit" || transfer.kind === "solWithdrawal") {
      parts.push(
        Uint8Array.of(0, transfer.kind === "solDeposit" ? 1 : 0),
        amount,
        addressBytes(transfer.recipient, `${position}.recipient`),
      );
    } else {
      parts.push(
        Uint8Array.of(1, transfer.kind === "splDeposit" ? 1 : 0),
        amount,
        addressBytes(transfer.tokenAccount, `${position}.tokenAccount`),
        addressBytes(transfer.splInterfacePda, `${position}.splInterfacePda`),
      );
    }
  });
  parts.push(
    optionalBytes(input.dataHash, "dataHash"),
    optionalBytes(input.ringDataHash, "ringDataHash"),
    copyBytes(input.txViewingPk, 33, "txViewingPk"),
    copyBytes(input.salt, 16, "salt"),
    count(input.outputs.length, "outputs"),
  );

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

function optionalBytes(value: Bytes32 | undefined, name: string): Uint8Array {
  return value === undefined
    ? new Uint8Array(33)
    : concat([Uint8Array.of(1), copyBytes(value, 32, name)]);
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
