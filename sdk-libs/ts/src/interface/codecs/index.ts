import type {
  Address,
  Bytes32,
  DepositInstructionData,
  InputUtxo,
  MergeTransactInstructionData,
  OwnerTag,
  ProtocolConfigAccount,
  SplAssetCounterAccount,
  SplAssetRegistryAccount,
  TransactInstructionData,
  TransactOutput,
  TransactProof,
  ZoneConfigAccount,
} from "../types.js";
import { MERGE_INPUT_COUNT } from "../constants.js";
import type { AddressTreeParams } from "../program.js";
import { StateDiscriminator } from "../state.js";
import {
  Reader,
  Writer,
  copyBytes,
  encodeBase58,
  fail,
  sha256,
  unsignedBigint,
} from "../internal.js";

function encoded<T>(
  value: T,
  write: (writer: Writer, input: T) => void,
  size?: number,
): Uint8Array {
  const writer = new Writer();
  write(writer, value);
  const bytes = writer.finish();
  if (size !== undefined && bytes.length !== size) {
    fail("INTERFACE_INVALID_LENGTH", { expected: size, actual: bytes.length });
  }
  return bytes;
}

function byteVector(writer: Writer, value: Uint8Array, name: string): void {
  writer.u16(value.length, `${name}.length`).bytes(value);
}

function writeDepositData(writer: Writer, value: DepositInstructionData): void {
  writer.u8(value.assets.length, "assets.length");
  for (const asset of value.assets) {
    if (asset.kind === "sol") {
      writer.u8(0, "asset.kind");
    } else {
      writer.u8(1, "asset.kind").u8(asset.splInterfaceBump, "asset.splInterfaceBump");
    }
  }
  writer.u8(value.deposits.length, "deposits.length");
  for (const deposit of value.deposits) {
    writer
      .u8(deposit.assetIndex, "deposit.assetIndex")
      .bytes(deposit.viewTag, 32, "deposit.viewTag")
      .bytes(deposit.recipientOwnerHash, 32, "deposit.owner")
      .bytes(deposit.blinding, 32, "deposit.blinding")
      .u64(deposit.amount, "deposit.amount")
      .option(deposit.utxoData, (output, data) => {
        output.bytes(data.dataHash, 32, "deposit.utxoData.dataHash");
        byteVector(output, data.data, "deposit.utxoData.data");
      })
      .option(deposit.memo, (output, memo) => {
        byteVector(output, memo, "deposit.memo");
      });
  }
}

export function encodeDepositInstructionData(value: DepositInstructionData): Uint8Array {
  return encoded(value, writeDepositData);
}

export function encodeAddressTreeParams(value: AddressTreeParams): Uint8Array {
  return encoded(
    value,
    (writer, input) => {
      writer
        .u64(input.inputQueueBatchSize, "inputQueueBatchSize")
        .u64(input.inputQueueZkpBatchSize, "inputQueueZkpBatchSize")
        .u32(input.rootHistoryCapacity, "rootHistoryCapacity")
        .u32(input.height, "height");
    },
    24,
  );
}

function writeProof(writer: Writer, proof: TransactProof): void {
  writer.bytes(proof.a, 32, "proof.a").bytes(proof.b, 64, "proof.b").bytes(proof.c, 32, "proof.c");
}

function writeInput(writer: Writer, value: InputUtxo): void {
  writer
    .bytes(value.nullifierHash, 32, "input.nullifierHash")
    .u16(value.nullifierTreeRootIndex, "input.nullifierTreeRootIndex")
    .u16(value.utxoTreeRootIndex, "input.utxoTreeRootIndex");
}

function writeOwnerTag(writer: Writer, value: OwnerTag): void {
  switch (value.kind) {
    case "inline":
      writer.u8(0, "ownerTag.kind").bytes(value.value, 32, "ownerTag.value");
      return;
    case "account":
      writer.u8(1, "ownerTag.kind").u8(value.index, "ownerTag.index");
      return;
    default:
      fail("INTERFACE_CODEC", { name: "ownerTag.kind" });
  }
}

function writeCircuit(writer: Writer, value: TransactInstructionData["circuit"]): void {
  const tag = value.kind === "confidentialEddsa" ? 0 : value.kind === "zoneEddsa" ? 1 : 2;
  writer
    .u16(tag, "circuit.kind")
    .u8(value.inputs, "circuit.inputs")
    .u8(value.outputs, "circuit.outputs")
    .u8(value.publicAssetSlots, "circuit.publicAssetSlots");
}

function writeInterfaceTransfer(
  writer: Writer,
  value: TransactInstructionData["interfaceTransfers"][number],
): void {
  const tag =
    value.kind === "solDeposit"
      ? 0
      : value.kind === "solWithdrawal"
        ? 1
        : value.kind === "splDeposit"
          ? 2
          : 3;
  writer.u8(tag, "interfaceTransfer.kind").u64(value.amount, "interfaceTransfer.amount");
  if (value.kind === "splDeposit" || value.kind === "splWithdrawal") {
    writer.u8(value.splInterfaceBump, "interfaceTransfer.splInterfaceBump");
  }
}

function writeOutput(writer: Writer, value: TransactOutput): void {
  writer.bytes(value.utxoHash, 32, "output.utxoHash");
  writeOwnerTag(writer, value.ownerTag);
  writer.option(value.data, (output, data) => {
    byteVector(output, data, "output.data");
  });
}

function writeTransactData(writer: Writer, value: TransactInstructionData): void {
  writer.u64(value.expiryUnixTs, "expiryUnixTs").bytes(value.privateTxHash, 32, "privateTxHash");
  writeCircuit(writer, value.circuit);
  writer.bytes(value.txViewingPk, 33, "txViewingPk").bytes(value.salt, 16, "salt");
  writeProof(writer, value.proof);
  writer.u8(value.inputs.length, "inputs.length");
  for (const input of value.inputs) writeInput(writer, input);
  writer.u8(value.interfaceTransfers.length, "interfaceTransfers.length");
  for (const transfer of value.interfaceTransfers) writeInterfaceTransfer(writer, transfer);
  writer
    .option(value.dataHash, (output, hash) => output.bytes(hash, 32, "dataHash"))
    .option(value.zoneDataHash, (output, hash) => output.bytes(hash, 32, "zoneDataHash"))
    .u8(value.outputs.length, "outputs.length");
  for (const output of value.outputs) writeOutput(writer, output);
  writer.u8(value.messages.length, "messages.length");
  for (const message of value.messages) {
    writer.bytes(message.viewTag, 32, "message.viewTag");
    byteVector(writer, message.data, "message.data");
  }
}

export function encodeTransactInstructionData(value: TransactInstructionData): Uint8Array {
  return encoded(value, writeTransactData);
}

function writeMergeData(writer: Writer, value: MergeTransactInstructionData): void {
  if (
    value.nullifiers.length !== MERGE_INPUT_COUNT ||
    value.utxoTreeRootIndexes.length !== MERGE_INPUT_COUNT ||
    value.nullifierTreeRootIndexes.length !== MERGE_INPUT_COUNT
  ) {
    fail("INTERFACE_INVALID_LENGTH", {
      nullifiers: value.nullifiers.length,
      utxoTreeRootIndexes: value.utxoTreeRootIndexes.length,
      nullifierTreeRootIndexes: value.nullifierTreeRootIndexes.length,
    });
  }
  writer
    .u64(value.expiryUnixTs, "expiryUnixTs")
    .bytes(value.proof.a, 32, "proof.a")
    .bytes(value.proof.b, 64, "proof.b")
    .bytes(value.proof.c, 32, "proof.c")
    .bytes(value.outputUtxoHash, 32, "outputUtxoHash")
    .bool(value.eddsaOwner, "eddsaOwner")
    .bytes(value.privateTxHash, 32, "privateTxHash")
    .u8(value.nullifiers.length, "nullifiers.length");
  for (const nullifier of value.nullifiers) writer.bytes(nullifier, 32, "nullifier");
  writer.u8(value.utxoTreeRootIndexes.length, "utxoTreeRootIndexes.length");
  for (const index of value.utxoTreeRootIndexes) writer.u16(index, "utxoTreeRootIndex");
  writer.u8(value.nullifierTreeRootIndexes.length, "nullifierTreeRootIndexes.length");
  for (const index of value.nullifierTreeRootIndexes) {
    writer.u16(index, "nullifierTreeRootIndex");
  }
}

export function encodeMergeTransactInstructionData(
  value: MergeTransactInstructionData,
): Uint8Array {
  return encoded(value, writeMergeData, 492);
}

export function mergeExternalDataHash(
  input: Readonly<{
    instructionTag: number;
    expiryUnixTs: bigint;
    outputUtxoHash: Bytes32;
  }>,
): Bytes32 {
  const expiry = unsignedBigint(input.expiryUnixTs, (1n << 64n) - 1n, "expiryUnixTs");
  const writer = new Writer()
    .u8(input.instructionTag, "instructionTag")
    .bytes(
      Uint8Array.from({ length: 8 }, (_, index) =>
        Number((expiry >> BigInt((7 - index) * 8)) & 255n),
      ),
    )
    .bytes(input.outputUtxoHash, 32, "outputUtxoHash");
  const digest = sha256(writer.finish());
  digest[0] = 0;
  return digest as Bytes32;
}

function decodeAccount<T>(
  bytes: Uint8Array,
  size: number,
  discriminator: number,
  decode: (reader: Reader) => T,
): T {
  if (bytes.length !== size) {
    fail("INTERFACE_INVALID_ACCOUNT_DATA", { expected: size, actual: bytes.length });
  }
  const reader = new Reader(copyBytes(bytes));
  const actual = reader.u8("discriminator");
  if (actual !== discriminator) {
    fail("INTERFACE_INVALID_DISCRIMINATOR", { expected: discriminator, actual });
  }
  const value = decode(reader);
  reader.done();
  return value;
}

function readAddress(reader: Reader, name: string): Address {
  return encodeBase58(reader.bytes(32, name));
}

export function decodeProtocolConfigAccount(bytes: Uint8Array): ProtocolConfigAccount {
  return decodeAccount(bytes, 132, StateDiscriminator.protocolConfig, (reader) => ({
    authority: readAddress(reader, "authority"),
    treeCreationAuthority: readAddress(reader, "treeCreationAuthority"),
    foresterAuthority: readAddress(reader, "foresterAuthority"),
    zoneCreationAuthority: readAddress(reader, "zoneCreationAuthority"),
    treeCreationIsPermissionless: reader.nonzeroBool("treeCreationIsPermissionless"),
    zoneCreationIsPermissionless: reader.nonzeroBool("zoneCreationIsPermissionless"),
    splInterfaceCreationIsPermissionless: reader.nonzeroBool(
      "splInterfaceCreationIsPermissionless",
    ),
  }));
}

export function decodeSplAssetCounterAccount(bytes: Uint8Array): SplAssetCounterAccount {
  return decodeAccount(bytes, 16, StateDiscriminator.splAssetCounter, (reader) => {
    reader.bytes(7, "reserved");
    return { nextId: reader.u64("nextId") };
  });
}

export function decodeSplAssetRegistryAccount(bytes: Uint8Array): SplAssetRegistryAccount {
  return decodeAccount(bytes, 48, StateDiscriminator.splAssetRegistry, (reader) => {
    reader.bytes(7, "reserved");
    return { mint: readAddress(reader, "mint"), assetId: reader.u64("assetId") };
  });
}

export function decodeZoneConfigAccount(bytes: Uint8Array): ZoneConfigAccount {
  return decodeAccount(bytes, 67, StateDiscriminator.zoneConfig, (reader) => ({
    authority: readAddress(reader, "authority"),
    programId: readAddress(reader, "programId"),
    zoneAuthorityTransactIsEnabled: reader.nonzeroBool("zoneAuthorityTransactIsEnabled"),
    bump: reader.u8("bump"),
  }));
}
