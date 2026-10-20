import type {
  Address,
  Bytes32,
  Bytes16,
  Bytes33,
  Bytes128,
  DepositAssetKind,
  CacheAccount,
  CircuitId,
  CreateCacheData,
  DepositInstructionData,
  InputUtxo,
  MergeOutputEncryption,
  MergeTransactInstructionData,
  OwnerTag,
  ProtocolConfigAccount,
  RingDepositInstructionData,
  SplAssetCounterAccount,
  SplAssetRegistryAccount,
  TransactExternalData,
  TransactInstructionData,
  TransactOutput,
  TransactProof,
  TreeContext,
  RingConfigAccount,
  TreeFeeSchedule,
  TreeFees,
  TreeHeadRoots,
} from "../types.js";
import { validCacheAccess } from "../cache.js";
import { mergePaddedInputCount } from "../constants.js";
import type { CreateTreeData, NullifierTreeParams } from "../program.js";
import {
  CACHE_ACCOUNT_SIZE,
  CACHE_CAPACITY,
  MergeEncryptionScheme,
  NULLIFIER_ROOT_HISTORY_CURSOR_OFFSET,
  NULLIFIER_ROOT_HISTORY_OFFSET,
  NULLIFIER_TREE_ROOT_HISTORY_CAPACITY,
  PROTOCOL_CONFIG_SIZE,
  STATE_HEIGHT,
  StateDiscriminator,
  TREE_ACCOUNT_SIZE,
  TREE_FEES_OFFSET,
  TREE_FEE_BALANCE_OFFSET,
  UTXO_ROOT_HISTORY_CAPACITY,
  UTXO_ROOT_HISTORY_CURSOR_OFFSET,
  UTXO_ROOT_HISTORY_OFFSET,
  UTXO_SUBTREES_LEN_OFFSET,
} from "../state.js";
import {
  Reader,
  Writer,
  addressBytes,
  copyBytes,
  encodeBase58,
  fail,
  sha256,
  unsigned,
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
      .bytes(deposit.recipientOwnerHash, 32, "deposit.recipientOwnerHash")
      .u64(deposit.amount, "deposit.amount")
      .option(deposit.memo, (output, memo) => {
        byteVector(output, memo, "deposit.memo");
      });
  }
}

export function encodeDepositInstructionData(value: DepositInstructionData): Uint8Array {
  return encoded(value, writeDepositData);
}

function writeRingDepositData(writer: Writer, value: RingDepositInstructionData): void {
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
      .bytes(deposit.ownerUtxoHash, 32, "deposit.ownerUtxoHash")
      .u64(deposit.amount, "deposit.amount")
      .bytes(deposit.ringDataHash, 32, "deposit.ringDataHash")
      .bytes(deposit.encrypted.txViewingPublicKey, 33, "deposit.encrypted.txViewingPublicKey")
      .bytes(deposit.encrypted.salt, 16, "deposit.encrypted.salt");
    byteVector(writer, deposit.encrypted.ciphertext, "deposit.encrypted.ciphertext");
  }
}

export function encodeRingDepositInstructionData(value: RingDepositInstructionData): Uint8Array {
  return encoded(value, writeRingDepositData);
}

/** Decodes the unchanged SPP deposit wire, including its u16 ciphertext lengths. */
export function decodeRingDepositInstructionData(bytes: Uint8Array): RingDepositInstructionData {
  const reader = new Reader(bytes);
  const assets = Array.from({ length: reader.u8("assets.length") }, (): DepositAssetKind => {
    const kind = reader.u8("asset.kind");
    if (kind === 0) return { kind: "sol" };
    if (kind === 1) return { kind: "spl", splInterfaceBump: reader.u8("splInterfaceBump") };
    return fail("INTERFACE_CODEC", { field: "asset.kind" });
  });
  const deposits = Array.from({ length: reader.u8("deposits.length") }, () => {
    const assetIndex = reader.u8("assetIndex");
    if (assetIndex >= assets.length) fail("INTERFACE_CODEC", { field: "assetIndex" });
    return {
      assetIndex,
      viewTag: reader.bytes(32, "viewTag") as Bytes32,
      ownerUtxoHash: reader.bytes(32, "ownerUtxoHash") as Bytes32,
      amount: reader.u64("amount"),
      ringDataHash: reader.bytes(32, "ringDataHash") as Bytes32,
      encrypted: {
        txViewingPublicKey: reader.bytes(33, "txViewingPublicKey") as Bytes33,
        salt: reader.bytes(16, "salt") as Bytes16,
        ciphertext: reader.bytes(reader.u16("ciphertext.length"), "ciphertext"),
      },
    };
  });
  reader.done();
  return { assets, deposits };
}

function writeNullifierTreeParams(writer: Writer, value: NullifierTreeParams): void {
  writer
    .u64(value.inputQueueBatchSize, "inputQueueBatchSize")
    .u64(value.inputQueueZkpBatchSize, "inputQueueZkpBatchSize")
    .u32(value.height, "height");
}

function writeTreeFeeSchedule(writer: Writer, value: TreeFeeSchedule): void {
  writer
    .u64(value.feePerNullifier, "feePerNullifier")
    .u64(value.appendReimbursement, "appendReimbursement")
    .u64(value.closeReimbursement, "closeReimbursement");
}

function readTreeFeeSchedule(reader: Reader): TreeFeeSchedule {
  return {
    feePerNullifier: reader.u64("feePerNullifier"),
    appendReimbursement: reader.u64("appendReimbursement"),
    closeReimbursement: reader.u64("closeReimbursement"),
  };
}

/** Borsh `TreeFeeSchedule`: three u64 LE. */
export function encodeTreeFeeSchedule(value: TreeFeeSchedule): Uint8Array {
  return encoded(value, writeTreeFeeSchedule, 24);
}

export function decodeTreeFeeSchedule(bytes: Uint8Array): TreeFeeSchedule {
  if (bytes.length !== 24) {
    fail("INTERFACE_INVALID_LENGTH", { expected: 24, actual: bytes.length });
  }
  const reader = new Reader(copyBytes(bytes));
  const value = readTreeFeeSchedule(reader);
  reader.done();
  return value;
}

/** Borsh `CreateTreeData { tree_id: u16, nullifier_params, fees }`. */
export function encodeCreateTreeData(value: CreateTreeData): Uint8Array {
  return encoded(
    value,
    (writer, input) => {
      writer.u16(input.treeId, "treeId");
      writeNullifierTreeParams(writer, input.nullifierParams);
      writeTreeFeeSchedule(writer, input.fees);
    },
    46,
  );
}

function writeProof(writer: Writer, proof: TransactProof): void {
  writer.bytes(proof.a, 32, "proof.a").bytes(proof.b, 128, "proof.b").bytes(proof.c, 32, "proof.c");
}

function writeInput(writer: Writer, value: InputUtxo): void {
  writer
    .bytes(value.nullifierHash, 32, "input.nullifierHash")
    .u8(value.treeIndex, "input.treeIndex");
}

/** Mirrors Rust `TreeContext`, the root history positions of one input tree. */
export function writeTreeContext(writer: Writer, value: TreeContext): void {
  writer
    .u16(value.utxoTreeRootIndex, "treeContext.utxoTreeRootIndex")
    .u16(value.nullifierTreeRootIndex, "treeContext.nullifierTreeRootIndex");
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

function circuitTag(value: CircuitId): number {
  switch (value.kind) {
    case "confidentialEddsa":
      return 0;
    case "confidentialRingEddsa":
      return 1;
    case "ringAuthority":
      return 2;
    case "anonymousRingEddsa":
      return 3;
    case "confidentialEddsaCached":
      return 4;
    case "confidentialRingEddsaCached":
      return 5;
    default:
      return fail("INTERFACE_CODEC", { name: "circuit.kind" });
  }
}

function writeCircuit(writer: Writer, value: CircuitId): void {
  writer
    .u16(circuitTag(value), "circuit.kind")
    .u8(value.inputs, "circuit.inputs")
    .u8(value.outputs, "circuit.outputs")
    .u8(value.publicAssetSlots, "circuit.publicAssetSlots");
  if (value.kind === "anonymousRingEddsa") {
    const { bsb22Commitment, defaultOwnerTag } = value.proofData;
    // Rust `FixedOptionOwnerTag`, an absent tag still writes its 32 zero bytes.
    writer
      .bytes(bsb22Commitment.commitment, 32, "circuit.bsb22Commitment.commitment")
      .bytes(bsb22Commitment.commitmentPok, 32, "circuit.bsb22Commitment.commitmentPok")
      .u8(defaultOwnerTag === undefined ? 0 : 1, "circuit.defaultOwnerTag.present")
      .bytes(defaultOwnerTag ?? new Uint8Array(32), 32, "circuit.defaultOwnerTag");
    return;
  }
  if (value.kind !== "confidentialEddsaCached" && value.kind !== "confidentialRingEddsaCached")
    return;
  if (!validCacheAccess(value.cacheAccess, value.inputs, value.outputs)) {
    fail("INTERFACE_INVALID_SHAPE", {
      name: "circuit.cacheAccess",
      inputs: value.inputs,
      outputs: value.outputs,
    });
  }
  writer.u64(value.cacheAccess.readBitmap, "circuit.cacheAccess.readBitmap");
  value.cacheAccess.writeSlots.forEach((entry, index) => {
    writer
      .u8(entry.output, `circuit.cacheAccess.writeSlots[${String(index)}].output`)
      .u8(entry.slot, `circuit.cacheAccess.writeSlots[${String(index)}].slot`);
  });
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

function writeTransactExternalData(writer: Writer, value: TransactExternalData): void {
  writer
    .u64(value.expiryUnixTs, "expiryUnixTs")
    .bytes(value.txViewingPk, 33, "txViewingPk")
    .bytes(value.salt, 16, "salt")
    .u8(value.interfaceTransfers.length, "interfaceTransfers.length");
  for (const transfer of value.interfaceTransfers) writeInterfaceTransfer(writer, transfer);
  writer
    .option(value.dataHash, (output, hash) => output.bytes(hash, 32, "dataHash"))
    .option(value.ringDataHash, (output, hash) => output.bytes(hash, 32, "ringDataHash"))
    .u8(value.outputs.length, "outputs.length");
  for (const output of value.outputs) writeOutput(writer, output);
  writer.u8(value.messages.length, "messages.length");
  for (const message of value.messages) {
    writer.bytes(message.viewTag, 32, "message.viewTag");
    byteVector(writer, message.data, "message.data");
  }
}

function writeTransactData(writer: Writer, value: TransactInstructionData): void {
  writeTransactExternalData(writer, value);
  writer.bytes(value.privateTxHash, 32, "privateTxHash");
  writeCircuit(writer, value.circuit);
  writeProof(writer, value.proof);
  writer.u8(value.inputs.length, "inputs.length");
  for (const input of value.inputs) writeInput(writer, input);
  writer.u8(value.treeContexts.length, "treeContexts.length");
  for (const context of value.treeContexts) writeTreeContext(writer, context);
}

export function encodeTransactExternalData(value: TransactExternalData): Uint8Array {
  return encoded(value, writeTransactExternalData);
}

/**
 * The `transact` instruction data without the leading `InstructionTag.transact`
 * byte. A program forwarding it to the shielded pool through a CPI prepends
 * that tag, as Rust `SppTransactAccounts::invoke` does.
 */
export function encodeTransactInstructionData(value: TransactInstructionData): Uint8Array {
  return encoded(value, writeTransactData);
}

/** Wincode `MergeOutputEncryption`: the u8 scheme tag, then that scheme's body. */
function writeMergeOutputEncryption(writer: Writer, value: MergeOutputEncryption): void {
  if (value.scheme !== MergeEncryptionScheme.PoseidonCtrV1) {
    fail("INTERFACE_INVALID_DISCRIMINATOR", { outputEncryption: value.scheme });
  }
  writer.u8(value.scheme, "outputEncryption.scheme").bytes(value.salt, 16, "outputEncryption.salt");
  if (value.ciphertext.length !== 3) {
    fail("INTERFACE_INVALID_LENGTH", { outputEncryption: value.ciphertext.length });
  }
  for (const element of value.ciphertext) writer.bytes(element, 32, "outputEncryption.ciphertext");
}

function writeMergeData(writer: Writer, value: MergeTransactInstructionData): void {
  // The instruction carries the sent nullifiers; compact padding fills the
  // narrowest merge circuit that holds them.
  if (
    value.nullifiers.length === 0 ||
    mergePaddedInputCount(value.nullifiers.length) === undefined
  ) {
    fail("INTERFACE_INVALID_LENGTH", { nullifiers: value.nullifiers.length });
  }
  writer
    .u64(value.expiryUnixTs, "expiryUnixTs")
    .bytes(value.proof.a, 32, "proof.a")
    .bytes(value.proof.b, 128, "proof.b")
    .bytes(value.proof.c, 32, "proof.c")
    .bytes(value.outputUtxoHash, 32, "outputUtxoHash");
  writeMergeOutputEncryption(writer, value.outputEncryption);
  writer
    .bytes(value.privateTxHash, 32, "privateTxHash")
    .u8(value.nullifiers.length, "nullifiers.length");
  for (const nullifier of value.nullifiers) writer.bytes(nullifier, 32, "nullifier");
  writer
    .u16(value.utxoTreeRootIndex, "utxoTreeRootIndex")
    .u16(value.nullifierTreeRootIndex, "nullifierTreeRootIndex")
    .option(value.cacheSlot, (output, slot) => {
      output.u8(unsigned(slot, CACHE_CAPACITY - 1, "cacheSlot"), "cacheSlot");
    });
}

function readMergeOutputEncryption(reader: Reader): MergeOutputEncryption {
  const scheme = reader.u8("outputEncryption.scheme");
  if (scheme !== MergeEncryptionScheme.PoseidonCtrV1) {
    fail("INTERFACE_CODEC", { name: "outputEncryption.scheme", actual: scheme });
  }
  return {
    scheme,
    salt: reader.bytes(16, "outputEncryption.salt") as Bytes16,
    ciphertext: [
      reader.bytes(32, "outputEncryption.ciphertext") as Bytes32,
      reader.bytes(32, "outputEncryption.ciphertext") as Bytes32,
      reader.bytes(32, "outputEncryption.ciphertext") as Bytes32,
    ],
  };
}

/** Reads one `MergeTransactIxData` body, the caller owns the surrounding frame. */
export function readMergeData(reader: Reader): MergeTransactInstructionData {
  const expiryUnixTs = reader.u64("expiryUnixTs");
  const proof = {
    a: reader.bytes(32, "proof.a") as Bytes32,
    b: reader.bytes(128, "proof.b") as Bytes128,
    c: reader.bytes(32, "proof.c") as Bytes32,
  };
  const outputUtxoHash = reader.bytes(32, "outputUtxoHash") as Bytes32;
  const outputEncryption = readMergeOutputEncryption(reader);
  const privateTxHash = reader.bytes(32, "privateTxHash") as Bytes32;
  const count = reader.u8("nullifiers.length");
  if (count === 0 || mergePaddedInputCount(count) === undefined) {
    fail("INTERFACE_CODEC", { name: "nullifiers.length", actual: count });
  }
  const nullifiers = Array.from({ length: count }, () => reader.bytes(32, "nullifier") as Bytes32);
  const utxoTreeRootIndex = reader.u16("utxoTreeRootIndex");
  const nullifierTreeRootIndex = reader.u16("nullifierTreeRootIndex");
  const cacheSlot = reader.option("cacheSlot", (input) =>
    unsigned(input.u8("cacheSlot"), CACHE_CAPACITY - 1, "cacheSlot"),
  );
  return {
    expiryUnixTs,
    proof,
    outputUtxoHash,
    outputEncryption,
    privateTxHash,
    nullifiers,
    utxoTreeRootIndex,
    nullifierTreeRootIndex,
    ...(cacheSlot === undefined ? {} : { cacheSlot }),
  };
}

export function decodeMergeTransactInstructionData(
  bytes: Uint8Array,
): MergeTransactInstructionData {
  const reader = new Reader(bytes);
  const value = readMergeData(reader);
  reader.done();
  return value;
}

const MERGE_FIXED_DATA_LENGTH = 383;

export function encodeMergeTransactInstructionData(
  value: MergeTransactInstructionData,
): Uint8Array {
  return encoded(
    value,
    writeMergeData,
    MERGE_FIXED_DATA_LENGTH +
      32 * value.nullifiers.length +
      (value.cacheSlot === undefined ? 0 : 1),
  );
}

export function mergeExternalDataHash(
  input: Readonly<{
    instructionTag: number;
    expiryUnixTs: bigint;
    outputUtxoHash: Bytes32;
    cache?: Readonly<{ address: Address; slot: number }>;
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
    .bytes(input.outputUtxoHash, 32, "outputUtxoHash")
    .option(input.cache, (output, cache) => {
      output
        .bytes(addressBytes(cache.address, "cache.address"), 32, "cache.address")
        .u8(cache.slot, "cache.slot");
    });
  const digest = sha256(writer.finish());
  digest[0] = 0;
  return digest as Bytes32;
}

export function encodeCreateCacheData(value: CreateCacheData): Uint8Array {
  return encoded(
    value,
    (writer, input) => {
      writer
        .bytes(addressBytes(input.writeAuthority, "writeAuthority"), 32, "writeAuthority")
        .u64(input.nonce, "nonce")
        .u16(input.treeId, "treeId")
        .i64(input.expiresAt, "expiresAt");
    },
    50,
  );
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
  return decodeAccount(
    bytes,
    PROTOCOL_CONFIG_SIZE,
    StateDiscriminator.protocolConfig,
    (reader) => ({
      authority: readAddress(reader, "authority"),
      treeCreationAuthority: readAddress(reader, "treeCreationAuthority"),
      foresterAuthority: readAddress(reader, "foresterAuthority"),
      ringCreationAuthority: readAddress(reader, "ringCreationAuthority"),
      feeAuthority: readAddress(reader, "feeAuthority"),
      treeCreationIsPermissionless: reader.nonzeroBool("treeCreationIsPermissionless"),
      ringActivationIsPermissionless: reader.nonzeroBool("ringActivationIsPermissionless"),
      splInterfaceCreationIsPermissionless: reader.nonzeroBool(
        "splInterfaceCreationIsPermissionless",
      ),
      nextTreeId: reader.u16("nextTreeId"),
    }),
  );
}

export function decodeTreeId(bytes: Uint8Array): number {
  return treeAccountReader(bytes, 2, 4).u16("treeId");
}

/**
 * Reads the fee schedule and accrued fee balance from a full tree account.
 * The tree header is `discriminator, state, tree_id, padding[4], fees, fee_balance`.
 */
export function decodeTreeFees(bytes: Uint8Array): TreeFees {
  const reader = treeAccountReader(bytes, TREE_FEES_OFFSET, TREE_FEE_BALANCE_OFFSET + 8);
  const fees = readTreeFeeSchedule(reader);
  const feeBalance = reader.u64("feeBalance");
  reader.done();
  return { fees, feeBalance };
}

/** Mirrors Rust `current_roots`, the nullifier index is the slot before the write cursor. */
export function decodeTreeHeadRoots(bytes: Uint8Array): TreeHeadRoots {
  const utxo = treeAccountReader(
    bytes,
    UTXO_ROOT_HISTORY_CURSOR_OFFSET,
    UTXO_SUBTREES_LEN_OFFSET + 1,
  );
  const stateRootIndex = utxo.u16("rootHistoryCursor");
  const written = utxo.u16("rootHistoryLen");
  const stateCapacity = utxo.u16("rootHistoryCapacity");
  const subtreesLen = utxo.u8("subtreesLen");
  utxo.done();
  if (stateCapacity !== UTXO_ROOT_HISTORY_CAPACITY || subtreesLen !== STATE_HEIGHT) {
    fail("INTERFACE_INVALID_ACCOUNT_DATA");
  }
  if (
    written === 0 ||
    written > stateCapacity ||
    stateRootIndex >= stateCapacity ||
    (written < stateCapacity && stateRootIndex + 1 !== written)
  ) {
    fail("INTERFACE_INVALID_ACCOUNT_DATA", { field: "stateRootIndex", actual: stateRootIndex });
  }
  const stateRoot = historyRoot(bytes, UTXO_ROOT_HISTORY_OFFSET, stateRootIndex, "stateRoot");
  const cursor = new Reader(
    copyBytes(
      bytes.subarray(
        NULLIFIER_ROOT_HISTORY_CURSOR_OFFSET,
        NULLIFIER_ROOT_HISTORY_CURSOR_OFFSET + 8,
      ),
    ),
  ).u64("rootHistoryCursor");
  const capacity = BigInt(NULLIFIER_TREE_ROOT_HISTORY_CAPACITY);
  if (cursor >= capacity) {
    fail("INTERFACE_INVALID_ACCOUNT_DATA", { field: "nullifierRootIndex", actual: cursor });
  }
  const nullifierRootIndex = Number((cursor + capacity - 1n) % capacity);
  const nullifierRoot = historyRoot(
    bytes,
    NULLIFIER_ROOT_HISTORY_OFFSET,
    nullifierRootIndex,
    "nullifierRoot",
  );
  return Object.freeze({ stateRoot, stateRootIndex, nullifierRoot, nullifierRootIndex });
}

function treeAccountReader(bytes: Uint8Array, start: number, end: number): Reader {
  if (bytes.length !== TREE_ACCOUNT_SIZE) {
    fail("INTERFACE_INVALID_ACCOUNT_DATA", { expected: TREE_ACCOUNT_SIZE, actual: bytes.length });
  }
  const discriminator = bytes[0];
  if (discriminator !== StateDiscriminator.treeAccount) {
    fail("INTERFACE_INVALID_DISCRIMINATOR", {
      expected: StateDiscriminator.treeAccount,
      actual: discriminator,
    });
  }
  return new Reader(copyBytes(bytes.subarray(start, end)));
}

function historyRoot(bytes: Uint8Array, offset: number, index: number, field: string): Bytes32 {
  const start = offset + index * 32;
  const root = copyBytes(bytes.subarray(start, start + 32), 32, field) as Bytes32;
  if (root.every((byte) => byte === 0)) {
    fail("INTERFACE_INVALID_ACCOUNT_DATA", { field, index });
  }
  return root;
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

export function decodeCacheAccount(bytes: Uint8Array): CacheAccount {
  return decodeAccount(bytes, CACHE_ACCOUNT_SIZE, StateDiscriminator.cache, (reader) =>
    Object.freeze({
      bump: reader.u8("bump"),
      treeId: reader.u16("treeId"),
      expiresAt: reader.i64("expiresAt"),
      rentSponsor: readAddress(reader, "rentSponsor"),
      writeAuthority: readAddress(reader, "writeAuthority"),
      utxoHashes: Object.freeze(
        Array.from(
          { length: CACHE_CAPACITY },
          (_, slot) => reader.bytes(32, `utxoHashes[${String(slot)}]`) as Bytes32,
        ),
      ),
    }),
  );
}

export function decodeRingConfigAccount(bytes: Uint8Array): RingConfigAccount {
  // 1 + 32 + 32 + 1 + 1 + 1 + 1. The program asserts the same size; the three
  // flags run enabled, paused, activated, and the bump is last.
  return decodeAccount(bytes, 69, StateDiscriminator.ringConfig, (reader) => ({
    authority: readAddress(reader, "authority"),
    programId: readAddress(reader, "programId"),
    ringAuthorityTransactIsEnabled: reader.nonzeroBool("ringAuthorityTransactIsEnabled"),
    paused: reader.nonzeroBool("paused"),
    activated: reader.nonzeroBool("activated"),
    bump: reader.u8("bump"),
  }));
}
