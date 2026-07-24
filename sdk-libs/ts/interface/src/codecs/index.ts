import {
  type Address,
  type Bytes16,
  type Bytes31,
  type Bytes32,
  type Bytes33,
  type Bytes64,
  type DepositInstructionData,
  type InputUtxo,
  type OwnerTag,
  type ProtocolConfigAccount,
  type SplAssetCounterAccount,
  type SplAssetRegistryAccount,
  type TransactInstructionData,
  type TransactOutput,
  type TransactProof,
  type ZoneConfigAccount,
} from "../index.js";
import { Reader, Writer, addressBytes, copyBytes, encodeBase58, fail } from "../internal.js";

export interface Codec<T> {
  encode(value: T): Uint8Array;
  decode(bytes: Uint8Array): T;
}

function byteVector(writer: Writer, value: Uint8Array, name: string): void {
  writer.u16(value.length, `${name}.length`).bytes(value);
}

function readByteVector(reader: Reader, name: string): Uint8Array {
  return reader.bytes(reader.u16(`${name}.length`), name);
}

function writeDepositData(writer: Writer, value: DepositInstructionData): void {
  writer
    .bytes(value.viewTag, 32, "viewTag")
    .bytes(value.owner, 32, "owner")
    .bytes(value.blinding, 31, "blinding")
    .u64(value.amount, "amount")
    .option(value.utxoData, (output, data) => {
      output.bytes(data.dataHash, 32, "utxoData.dataHash");
      byteVector(output, data.data, "utxoData.data");
    })
    .option(value.memo, (output, memo) => {
      byteVector(output, memo, "memo");
    });
}

function readDepositData(reader: Reader): DepositInstructionData {
  const value: DepositInstructionData = {
    viewTag: reader.bytes(32, "viewTag") as Bytes32,
    owner: reader.bytes(32, "owner") as Bytes32,
    blinding: reader.bytes(31, "blinding") as Bytes31,
    amount: reader.u64("amount"),
  };
  const utxoData = reader.option("utxoData", (input) => ({
    dataHash: input.bytes(32, "utxoData.dataHash") as Bytes32,
    data: readByteVector(input, "utxoData.data"),
  }));
  const memo = reader.option("memo", (input) => readByteVector(input, "memo"));
  return {
    ...value,
    ...(utxoData === undefined ? {} : { utxoData }),
    ...(memo === undefined ? {} : { memo }),
  };
}

export const depositInstructionDataCodec: Codec<DepositInstructionData> = {
  encode(value) {
    const writer = new Writer();
    writeDepositData(writer, value);
    return writer.finish();
  },
  decode(bytes) {
    const reader = new Reader(copyBytes(bytes));
    const value = readDepositData(reader);
    reader.done();
    return value;
  },
};

function writeProof(writer: Writer, proof: TransactProof): void {
  if (proof.rail === "eddsa") {
    writer
      .u8(0, "proof.rail")
      .bytes(proof.a, 32, "proof.a")
      .bytes(proof.b, 64, "proof.b")
      .bytes(proof.c, 32, "proof.c");
    return;
  }
  writer
    .u8(1, "proof.rail")
    .bytes(proof.a, 32, "proof.a")
    .bytes(proof.b, 64, "proof.b")
    .bytes(proof.c, 32, "proof.c")
    .bytes(proof.commitment, 32, "proof.commitment")
    .bytes(proof.commitmentPok, 32, "proof.commitmentPok");
}

function readProof(reader: Reader): TransactProof {
  const rail = reader.u8("proof.rail");
  const a = reader.bytes(32, "proof.a") as Bytes32;
  const b = reader.bytes(64, "proof.b") as Bytes64;
  const c = reader.bytes(32, "proof.c") as Bytes32;
  if (rail === 0) return { rail: "eddsa", a, b, c };
  if (rail === 1) {
    return {
      rail: "p256",
      a,
      b,
      c,
      commitment: reader.bytes(32, "proof.commitment") as Bytes32,
      commitmentPok: reader.bytes(32, "proof.commitmentPok") as Bytes32,
    };
  }
  fail("INTERFACE_CODEC", { name: "proof.rail", actual: rail });
}

function writeInput(writer: Writer, value: InputUtxo): void {
  writer
    .bytes(value.nullifierHash, 32, "input.nullifierHash")
    .u16(value.nullifierTreeRootIndex, "input.nullifierTreeRootIndex")
    .u16(value.utxoTreeRootIndex, "input.utxoTreeRootIndex")
    .u8(value.treeIndex, "input.treeIndex")
    .u8(value.eddsaSignerIndex, "input.eddsaSignerIndex");
}

function readInput(reader: Reader): InputUtxo {
  return {
    nullifierHash: reader.bytes(32, "input.nullifierHash") as Bytes32,
    nullifierTreeRootIndex: reader.u16("input.nullifierTreeRootIndex"),
    utxoTreeRootIndex: reader.u16("input.utxoTreeRootIndex"),
    treeIndex: reader.u8("input.treeIndex"),
    eddsaSignerIndex: reader.u8("input.eddsaSignerIndex"),
  };
}

function writeOwnerTag(writer: Writer, value: OwnerTag): void {
  switch (value.kind) {
    case "inline":
      writer.u8(0, "ownerTag.kind").bytes(value.value, 32, "ownerTag.value");
      return;
    case "account":
      writer.u8(1, "ownerTag.kind").u8(value.index, "ownerTag.index");
      return;
    case "p256SigningKey":
      writer.u8(2, "ownerTag.kind");
      return;
    default:
      fail("INTERFACE_CODEC", { name: "ownerTag.kind" });
  }
}

function readOwnerTag(reader: Reader): OwnerTag {
  const kind = reader.u8("ownerTag.kind");
  if (kind === 0) {
    return { kind: "inline", value: reader.bytes(32, "ownerTag.value") as Bytes32 };
  }
  if (kind === 1) return { kind: "account", index: reader.u8("ownerTag.index") };
  if (kind === 2) return { kind: "p256SigningKey" };
  fail("INTERFACE_CODEC", { name: "ownerTag.kind", actual: kind });
}

function writeOutput(writer: Writer, value: TransactOutput): void {
  writer.bytes(value.utxoHash, 32, "output.utxoHash");
  writeOwnerTag(writer, value.ownerTag);
  writer.option(value.data, (output, data) => {
    byteVector(output, data, "output.data");
  });
}

function readOutput(reader: Reader): TransactOutput {
  const utxoHash = reader.bytes(32, "output.utxoHash") as Bytes32;
  const ownerTag = readOwnerTag(reader);
  const data = reader.option("output.data", (input) => readByteVector(input, "output.data"));
  return {
    utxoHash,
    ownerTag,
    ...(data === undefined ? {} : { data }),
  };
}

function writeTransactData(writer: Writer, value: TransactInstructionData): void {
  writer
    .u64(value.expiryUnixTs, "expiryUnixTs")
    .u16(value.relayerFee, "relayerFee")
    .bytes(value.privateTxHash, 32, "privateTxHash")
    .option(value.p256SigningPkX, (output, key) => output.bytes(key, 32, "p256SigningPkX"))
    .bytes(value.txViewingPk, 33, "txViewingPk")
    .bytes(value.salt, 16, "salt");
  writeProof(writer, value.proof);
  writer.u8(value.inputs.length, "inputs.length");
  for (const input of value.inputs) writeInput(writer, input);
  writer
    .option(value.publicSolAmount, (output, amount) => output.i64(amount, "publicSolAmount"))
    .option(value.publicSplAmount, (output, amount) => output.i64(amount, "publicSplAmount"))
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

function readTransactData(reader: Reader): TransactInstructionData {
  const expiryUnixTs = reader.u64("expiryUnixTs");
  const relayerFee = reader.u16("relayerFee");
  const privateTxHash = reader.bytes(32, "privateTxHash") as Bytes32;
  const p256SigningPkX = reader.option(
    "p256SigningPkX",
    (input) => input.bytes(32, "p256SigningPkX") as Bytes32,
  );
  const txViewingPk = reader.bytes(33, "txViewingPk") as Bytes33;
  const salt = reader.bytes(16, "salt") as Bytes16;
  const proof = readProof(reader);
  const inputs = Array.from({ length: reader.u8("inputs.length") }, () => readInput(reader));
  const publicSolAmount = reader.option("publicSolAmount", (input) => input.i64("publicSolAmount"));
  const publicSplAmount = reader.option("publicSplAmount", (input) => input.i64("publicSplAmount"));
  const dataHash = reader.option("dataHash", (input) => input.bytes(32, "dataHash") as Bytes32);
  const zoneDataHash = reader.option(
    "zoneDataHash",
    (input) => input.bytes(32, "zoneDataHash") as Bytes32,
  );
  const outputs = Array.from({ length: reader.u8("outputs.length") }, () => readOutput(reader));
  const messages = Array.from({ length: reader.u8("messages.length") }, () => ({
    viewTag: reader.bytes(32, "message.viewTag") as Bytes32,
    data: readByteVector(reader, "message.data"),
  }));
  return {
    proof,
    expiryUnixTs,
    relayerFee,
    privateTxHash,
    txViewingPk,
    salt,
    inputs,
    outputs,
    messages,
    ...(p256SigningPkX === undefined ? {} : { p256SigningPkX }),
    ...(publicSolAmount === undefined ? {} : { publicSolAmount }),
    ...(publicSplAmount === undefined ? {} : { publicSplAmount }),
    ...(dataHash === undefined ? {} : { dataHash }),
    ...(zoneDataHash === undefined ? {} : { zoneDataHash }),
  };
}

export const transactInstructionDataCodec: Codec<TransactInstructionData> = {
  encode(value) {
    const writer = new Writer();
    writeTransactData(writer, value);
    return writer.finish();
  },
  decode(bytes) {
    const reader = new Reader(copyBytes(bytes));
    const value = readTransactData(reader);
    reader.done();
    return value;
  },
};

function accountCodec<T>(
  size: number,
  discriminator: number,
  encode: (writer: Writer, value: T) => void,
  decode: (reader: Reader) => T,
): Codec<T> {
  return {
    encode(value) {
      const writer = new Writer().u8(discriminator, "discriminator");
      encode(writer, value);
      const bytes = writer.finish();
      if (bytes.length !== size) {
        fail("INTERFACE_INVALID_ACCOUNT_DATA", { expected: size, actual: bytes.length });
      }
      return bytes;
    },
    decode(bytes) {
      if (bytes.length !== size) {
        fail("INTERFACE_INVALID_ACCOUNT_DATA", { expected: size, actual: bytes.length });
      }
      const reader = new Reader(copyBytes(bytes));
      const actual = reader.u8("discriminator");
      if (actual !== discriminator) {
        fail("INTERFACE_INVALID_DISCRIMINATOR", {
          expected: discriminator,
          actual,
        });
      }
      const value = decode(reader);
      reader.done();
      return value;
    },
  };
}

function writeAddress(writer: Writer, value: Address, name: string): void {
  writer.bytes(addressBytes(value, name), 32, name);
}

function readAddress(reader: Reader, name: string): Address {
  return encodeBase58(reader.bytes(32, name));
}

export const protocolConfigAccountCodec: Codec<ProtocolConfigAccount> = accountCodec(
  132,
  3,
  (writer, value) => {
    writeAddress(writer, value.authority, "authority");
    writeAddress(writer, value.treeCreationAuthority, "treeCreationAuthority");
    writeAddress(writer, value.foresterAuthority, "foresterAuthority");
    writeAddress(writer, value.zoneCreationAuthority, "zoneCreationAuthority");
    writer
      .bool(value.treeCreationIsPermissionless, "treeCreationIsPermissionless")
      .bool(value.zoneCreationIsPermissionless, "zoneCreationIsPermissionless")
      .bool(value.splInterfaceCreationIsPermissionless, "splInterfaceCreationIsPermissionless");
  },
  (reader) => ({
    authority: readAddress(reader, "authority"),
    treeCreationAuthority: readAddress(reader, "treeCreationAuthority"),
    foresterAuthority: readAddress(reader, "foresterAuthority"),
    zoneCreationAuthority: readAddress(reader, "zoneCreationAuthority"),
    treeCreationIsPermissionless: reader.bool("treeCreationIsPermissionless"),
    zoneCreationIsPermissionless: reader.bool("zoneCreationIsPermissionless"),
    splInterfaceCreationIsPermissionless: reader.bool("splInterfaceCreationIsPermissionless"),
  }),
);

export const splAssetCounterAccountCodec: Codec<SplAssetCounterAccount> = accountCodec(
  16,
  6,
  (writer, value) => writer.bytes(new Uint8Array(7)).u64(value.nextId, "nextId"),
  (reader) => {
    reader.bytes(7, "reserved");
    return { nextId: reader.u64("nextId") };
  },
);

export const splAssetRegistryAccountCodec: Codec<SplAssetRegistryAccount> = accountCodec(
  48,
  5,
  (writer, value) => {
    writer.bytes(new Uint8Array(7));
    writeAddress(writer, value.mint, "mint");
    writer.u64(value.assetId, "assetId");
  },
  (reader) => {
    reader.bytes(7, "reserved");
    return { mint: readAddress(reader, "mint"), assetId: reader.u64("assetId") };
  },
);

export const zoneConfigAccountCodec: Codec<ZoneConfigAccount> = accountCodec(
  67,
  4,
  (writer, value) => {
    writeAddress(writer, value.authority, "authority");
    writeAddress(writer, value.programId, "programId");
    writer
      .bool(value.zoneAuthorityTransactIsEnabled, "zoneAuthorityTransactIsEnabled")
      .u8(value.bump, "bump");
  },
  (reader) => ({
    authority: readAddress(reader, "authority"),
    programId: readAddress(reader, "programId"),
    zoneAuthorityTransactIsEnabled: reader.bool("zoneAuthorityTransactIsEnabled"),
    bump: reader.u8("bump"),
  }),
);
