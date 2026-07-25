import {
  type Address,
  type AddressTreeParams,
  type BatchUpdateNullifierTreeData,
  type Bytes16,
  type Bytes31,
  type Bytes32,
  type Bytes33,
  type Bytes64,
  type CreateTreeData,
  type CreateZoneConfigData,
  type DepositInstructionData,
  type MergeTransactInstructionData,
  type MergeZoneInstructionData,
  type UpdateZoneConfigData,
  type UpdateZoneConfigOwnerData,
  type ZoneDepositInstructionData,
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
import {
  MERGE_ENCRYPTED_UTXO_LENGTH,
  MERGE_ENCRYPTED_UTXO_TYPE_PREFIX,
  MERGE_INPUT_COUNT,
} from "../constants.js";
import { StateDiscriminator } from "../state.js";
import {
  Reader,
  Writer,
  addressBytes,
  copyBytes,
  encodeBase58,
  fail,
  sha256,
  unsignedBigint,
} from "../internal.js";

export interface Codec<T> {
  encode(value: T): Uint8Array;
  decode(bytes: Uint8Array): T;
}

function strictCodec<T>(
  write: (writer: Writer, value: T) => void,
  read: (reader: Reader) => T,
  size?: number,
): Codec<T> {
  return {
    encode(value) {
      const writer = new Writer();
      write(writer, value);
      const bytes = writer.finish();
      if (size !== undefined && bytes.length !== size) {
        fail("INTERFACE_INVALID_LENGTH", { expected: size, actual: bytes.length });
      }
      return bytes;
    },
    decode(bytes) {
      if (size !== undefined && bytes.length !== size) {
        fail("INTERFACE_INVALID_LENGTH", { expected: size, actual: bytes.length });
      }
      const reader = new Reader(copyBytes(bytes));
      const value = read(reader);
      reader.done();
      return value;
    },
  };
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

function writeZoneDepositData(writer: Writer, value: ZoneDepositInstructionData): void {
  writer
    .bytes(value.viewTag, 32, "viewTag")
    .bytes(value.owner, 32, "owner")
    .bytes(value.blinding, 31, "blinding")
    .u64(value.amount, "amount")
    .bytes(value.zoneDataHash, 32, "zoneDataHash");
  byteVector(writer, value.zoneData, "zoneData");
  writer
    .option(value.utxoData, (output, data) => {
      output.bytes(data.dataHash, 32, "utxoData.dataHash");
      byteVector(output, data.data, "utxoData.data");
    })
    .option(value.memo, (output, memo) => {
      byteVector(output, memo, "memo");
    });
}

function readZoneDepositData(reader: Reader): ZoneDepositInstructionData {
  const viewTag = reader.bytes(32, "viewTag") as Bytes32;
  const owner = reader.bytes(32, "owner") as Bytes32;
  const blinding = reader.bytes(31, "blinding") as Bytes31;
  const amount = reader.u64("amount");
  const zoneDataHash = reader.bytes(32, "zoneDataHash") as Bytes32;
  const zoneData = readByteVector(reader, "zoneData");
  const utxoData = reader.option("utxoData", (input) => ({
    dataHash: input.bytes(32, "utxoData.dataHash") as Bytes32,
    data: readByteVector(input, "utxoData.data"),
  }));
  const memo = reader.option("memo", (input) => readByteVector(input, "memo"));
  return {
    viewTag,
    owner,
    blinding,
    amount,
    zoneDataHash,
    zoneData,
    ...(utxoData === undefined ? {} : { utxoData }),
    ...(memo === undefined ? {} : { memo }),
  };
}

export const zoneDepositInstructionDataCodec = strictCodec(
  writeZoneDepositData,
  readZoneDepositData,
);

export const batchUpdateNullifierTreeDataCodec = strictCodec<BatchUpdateNullifierTreeData>(
  (writer, value) => {
    writer
      .bytes(value.newRoot, 32, "newRoot")
      .bytes(value.oldRoot, 32, "oldRoot")
      .u16(value.zkpBatchIndex, "zkpBatchIndex")
      .bytes(value.compressedProof.a, 32, "compressedProof.a")
      .bytes(value.compressedProof.b, 64, "compressedProof.b")
      .bytes(value.compressedProof.c, 32, "compressedProof.c");
  },
  (reader) => ({
    newRoot: reader.bytes(32, "newRoot") as Bytes32,
    oldRoot: reader.bytes(32, "oldRoot") as Bytes32,
    zkpBatchIndex: reader.u16("zkpBatchIndex"),
    compressedProof: {
      a: reader.bytes(32, "compressedProof.a") as Bytes32,
      b: reader.bytes(64, "compressedProof.b") as Bytes64,
      c: reader.bytes(32, "compressedProof.c") as Bytes32,
    },
  }),
  194,
);

export const createTreeDataCodec = strictCodec<CreateTreeData>(
  (writer, value) => writer.bytes(addressBytes(value.owner, "owner")),
  (reader) => ({ owner: encodeBase58(reader.bytes(32, "owner")) }),
  32,
);

function writeOptionalAddress(writer: Writer, value: Address | undefined, name: string): void {
  writer.option(value, (output, address) => output.bytes(addressBytes(address, name)));
}

function readOptionalAddress(reader: Reader, name: string): Address | undefined {
  return reader.option(name, (input) => encodeBase58(input.bytes(32, name)));
}

export const addressTreeParamsCodec = strictCodec<AddressTreeParams>(
  (writer, value) => {
    writer.u64(value.index, "index");
    writeOptionalAddress(writer, value.programOwner, "programOwner");
    writeOptionalAddress(writer, value.forester, "forester");
    writer
      .u64(value.inputQueueBatchSize, "inputQueueBatchSize")
      .u64(value.inputQueueZkpBatchSize, "inputQueueZkpBatchSize")
      .u32(value.rootHistoryCapacity, "rootHistoryCapacity")
      .option(value.networkFee, (output, fee) => output.u64(fee, "networkFee"))
      .option(value.rolloverThreshold, (output, threshold) =>
        output.u64(threshold, "rolloverThreshold"),
      )
      .option(value.closeThreshold, (output, threshold) =>
        output.u64(threshold, "closeThreshold"),
      )
      .u32(value.height, "height");
  },
  (reader) => {
    const index = reader.u64("index");
    const programOwner = readOptionalAddress(reader, "programOwner");
    const forester = readOptionalAddress(reader, "forester");
    const inputQueueBatchSize = reader.u64("inputQueueBatchSize");
    const inputQueueZkpBatchSize = reader.u64("inputQueueZkpBatchSize");
    const rootHistoryCapacity = reader.u32("rootHistoryCapacity");
    const networkFee = reader.option("networkFee", (input) => input.u64("networkFee"));
    const rolloverThreshold = reader.option("rolloverThreshold", (input) =>
      input.u64("rolloverThreshold"),
    );
    const closeThreshold = reader.option("closeThreshold", (input) =>
      input.u64("closeThreshold"),
    );
    const height = reader.u32("height");
    return {
      index,
      inputQueueBatchSize,
      inputQueueZkpBatchSize,
      rootHistoryCapacity,
      height,
      ...(programOwner === undefined ? {} : { programOwner }),
      ...(forester === undefined ? {} : { forester }),
      ...(networkFee === undefined ? {} : { networkFee }),
      ...(rolloverThreshold === undefined ? {} : { rolloverThreshold }),
      ...(closeThreshold === undefined ? {} : { closeThreshold }),
    };
  },
);

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

/**
 * Recorded divergence from `program-libs/interface`, pinned by
 * `interface/test/vectors/rust-oracle.test.ts`. `MergeTransactIxData` carries no
 * prefix rule, so Rust reads and writes any first byte and the shielded-pool
 * program is what refuses a non-canonical one with `InvalidMergeOutputScheme`.
 * Both merge codecs route through here so the pending ruling on whether the SDK
 * should refuse this early is a change in one place.
 */
function checkMergeOutputScheme(encryptedUtxo: Uint8Array): void {
  if (encryptedUtxo[0] !== MERGE_ENCRYPTED_UTXO_TYPE_PREFIX) {
    fail("INTERFACE_CODEC", {
      name: "encryptedUtxo.typePrefix",
      expected: MERGE_ENCRYPTED_UTXO_TYPE_PREFIX,
      actual: encryptedUtxo[0],
    });
  }
}

function writeMergeData(writer: Writer, value: MergeTransactInstructionData): void {
  if (
    value.nullifiers.length !== MERGE_INPUT_COUNT ||
    value.utxoTreeRootIndexes.length !== MERGE_INPUT_COUNT ||
    value.nullifierTreeRootIndexes.length !== MERGE_INPUT_COUNT ||
    value.encryptedUtxo.length !== MERGE_ENCRYPTED_UTXO_LENGTH
  ) {
    fail("INTERFACE_INVALID_LENGTH", {
      nullifiers: value.nullifiers.length,
      utxoTreeRootIndexes: value.utxoTreeRootIndexes.length,
      nullifierTreeRootIndexes: value.nullifierTreeRootIndexes.length,
      encryptedUtxo: value.encryptedUtxo.length,
    });
  }
  checkMergeOutputScheme(value.encryptedUtxo);
  writer
    .u64(value.expiryUnixTs, "expiryUnixTs")
    .bytes(value.proof.a, 32, "proof.a")
    .bytes(value.proof.b, 64, "proof.b")
    .bytes(value.proof.c, 32, "proof.c")
    .bytes(value.proof.commitment, 32, "proof.commitment")
    .bytes(value.proof.commitmentPok, 32, "proof.commitmentPok")
    .bytes(value.outputUtxoHash, 32, "outputUtxoHash")
    .u8(value.nullifiers.length, "nullifiers.length");
  for (const nullifier of value.nullifiers) writer.bytes(nullifier, 32, "nullifier");
  writer.u8(value.utxoTreeRootIndexes.length, "utxoTreeRootIndexes.length");
  for (const index of value.utxoTreeRootIndexes) writer.u16(index, "utxoTreeRootIndex");
  writer.u8(value.nullifierTreeRootIndexes.length, "nullifierTreeRootIndexes.length");
  for (const index of value.nullifierTreeRootIndexes) {
    writer.u16(index, "nullifierTreeRootIndex");
  }
  writer
    .bytes(value.privateTxHash, 32, "privateTxHash")
    .u16(value.encryptedUtxo.length, "encryptedUtxo.length")
    .bytes(value.encryptedUtxo)
    .bool(value.eddsaOwner, "eddsaOwner");
}

function readFixedList<T>(
  reader: Reader,
  name: string,
  read: (input: Reader) => T,
): readonly T[] {
  const length = reader.u8(`${name}.length`);
  if (length !== MERGE_INPUT_COUNT) {
    fail("INTERFACE_INVALID_LENGTH", { name, expected: MERGE_INPUT_COUNT, actual: length });
  }
  return Array.from({ length }, () => read(reader));
}

function readMergeData(reader: Reader): MergeTransactInstructionData {
  const expiryUnixTs = reader.u64("expiryUnixTs");
  const proof = {
    a: reader.bytes(32, "proof.a") as Bytes32,
    b: reader.bytes(64, "proof.b") as Bytes64,
    c: reader.bytes(32, "proof.c") as Bytes32,
    commitment: reader.bytes(32, "proof.commitment") as Bytes32,
    commitmentPok: reader.bytes(32, "proof.commitmentPok") as Bytes32,
  };
  const outputUtxoHash = reader.bytes(32, "outputUtxoHash") as Bytes32;
  const nullifiers = readFixedList(reader, "nullifiers", (input) =>
    input.bytes(32, "nullifier"),
  ) as readonly Bytes32[];
  const utxoTreeRootIndexes = readFixedList(reader, "utxoTreeRootIndexes", (input) =>
    input.u16("utxoTreeRootIndex"),
  );
  const nullifierTreeRootIndexes = readFixedList(
    reader,
    "nullifierTreeRootIndexes",
    (input) => input.u16("nullifierTreeRootIndex"),
  );
  const privateTxHash = reader.bytes(32, "privateTxHash") as Bytes32;
  const encryptedLength = reader.u16("encryptedUtxo.length");
  if (encryptedLength !== MERGE_ENCRYPTED_UTXO_LENGTH) {
    fail("INTERFACE_INVALID_LENGTH", {
      name: "encryptedUtxo",
      expected: MERGE_ENCRYPTED_UTXO_LENGTH,
      actual: encryptedLength,
    });
  }
  const encryptedUtxo = reader.bytes(encryptedLength, "encryptedUtxo");
  checkMergeOutputScheme(encryptedUtxo);
  return {
    expiryUnixTs,
    proof,
    outputUtxoHash,
    nullifiers,
    utxoTreeRootIndexes,
    nullifierTreeRootIndexes,
    privateTxHash,
    encryptedUtxo,
    eddsaOwner: reader.bool("eddsaOwner"),
  };
}

export const mergeTransactInstructionDataCodec = strictCodec(
  writeMergeData,
  readMergeData,
  668,
);

export const mergeZoneInstructionDataCodec = strictCodec<MergeZoneInstructionData>(
  (writer, value) => {
    writer.bytes(value.mergeViewTag, 32, "mergeViewTag");
    writeMergeData(writer, value.merge);
  },
  (reader) => ({
    mergeViewTag: reader.bytes(32, "mergeViewTag") as Bytes32,
    merge: readMergeData(reader),
  }),
  700,
);

export function mergeExternalDataHash(input: Readonly<{
  instructionTag: number;
  expiryUnixTs: bigint;
  outputUtxoHash: Bytes32;
  encryptedUtxo: Uint8Array;
}>): Bytes32 {
  const expiry = unsignedBigint(input.expiryUnixTs, (1n << 64n) - 1n, "expiryUnixTs");
  const writer = new Writer()
    .u8(input.instructionTag, "instructionTag")
    .bytes(
      Uint8Array.from({ length: 8 }, (_, index) =>
        Number((expiry >> BigInt((7 - index) * 8)) & 255n),
      ),
    )
    .bytes(input.outputUtxoHash, 32, "outputUtxoHash");
  const length = input.encryptedUtxo.length;
  if (length > 0xffff) {
    fail("INTERFACE_INVALID_LENGTH", { name: "encryptedUtxo", maximum: 0xffff, actual: length });
  }
  writer
    .bytes(Uint8Array.of(length >>> 8, length & 255))
    .bytes(copyBytes(input.encryptedUtxo));
  const digest = sha256(writer.finish());
  digest[0] = 0;
  return digest as Bytes32;
}

export const createZoneConfigDataCodec = strictCodec<CreateZoneConfigData>(
  (writer, value) =>
    writer
      .bytes(addressBytes(value.programId, "programId"))
      .bytes(addressBytes(value.authority, "authority"))
      .bool(value.zoneAuthorityTransactIsEnabled, "zoneAuthorityTransactIsEnabled"),
  (reader) => ({
    programId: encodeBase58(reader.bytes(32, "programId")),
    authority: encodeBase58(reader.bytes(32, "authority")),
    zoneAuthorityTransactIsEnabled: reader.bool("zoneAuthorityTransactIsEnabled"),
  }),
  65,
);

export const updateZoneConfigOwnerDataCodec = strictCodec<UpdateZoneConfigOwnerData>(
  (writer, value) => writer.bytes(addressBytes(value.newAuthority, "newAuthority")),
  (reader) => ({ newAuthority: encodeBase58(reader.bytes(32, "newAuthority")) }),
  32,
);

export const updateZoneConfigDataCodec = strictCodec<UpdateZoneConfigData>(
  (writer, value) =>
    writer.bool(value.zoneAuthorityTransactIsEnabled, "zoneAuthorityTransactIsEnabled"),
  (reader) => ({
    zoneAuthorityTransactIsEnabled: reader.bool("zoneAuthorityTransactIsEnabled"),
  }),
  1,
);

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
  StateDiscriminator.protocolConfig,
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
    treeCreationIsPermissionless: reader.nonzeroBool("treeCreationIsPermissionless"),
    zoneCreationIsPermissionless: reader.nonzeroBool("zoneCreationIsPermissionless"),
    splInterfaceCreationIsPermissionless: reader.nonzeroBool(
      "splInterfaceCreationIsPermissionless",
    ),
  }),
);

export const splAssetCounterAccountCodec: Codec<SplAssetCounterAccount> = accountCodec(
  16,
  StateDiscriminator.splAssetCounter,
  (writer, value) => writer.bytes(new Uint8Array(7)).u64(value.nextId, "nextId"),
  (reader) => {
    reader.bytes(7, "reserved");
    return { nextId: reader.u64("nextId") };
  },
);

export const splAssetRegistryAccountCodec: Codec<SplAssetRegistryAccount> = accountCodec(
  48,
  StateDiscriminator.splAssetRegistry,
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
  StateDiscriminator.zoneConfig,
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
    zoneAuthorityTransactIsEnabled: reader.nonzeroBool("zoneAuthorityTransactIsEnabled"),
    bump: reader.u8("bump"),
  }),
);
