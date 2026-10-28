import { bytesToBigInt, equalBytes } from "../../interface/bytes.js";
import { wireDecoder } from "../../interface/decode.js";
import { BN254_SCALAR_ORDER } from "../../hasher/index.js";
import { splInterfaceWithBump, treeAddress } from "../../interface/pda/index.js";
import type { Address, Bytes32, OwnerTag } from "../../interface/types.js";
import { randomBytes, type Bytes34 } from "../../keypair/bytes.js";
import { SHIELDED_PUBLIC_KEY_LENGTH } from "../../keypair/constants.js";
import { ShieldedPublicKey } from "../../keypair/public-key.js";
import {
  SHIELDED_ADDRESS_LENGTH,
  ShieldedAddress,
  type ViewingKeyLike,
} from "../../keypair/shielded.js";
import type { ViewingKey } from "../../keypair/viewing-key.js";

import { AssetRegistry, Mint } from "../asset.js";
import { Data, type DataRecord } from "../data.js";
import { TransactionError } from "../error.js";
import {
  SppProofInputs,
  createExternalData,
  dummyCiphertextLength,
  type ExternalData,
  type SettlementTransfer,
} from "../instructions/transact.js";
import { U64_MAX, checked, copy, decodeAddress } from "../internal.js";
import {
  ProofInputUtxo,
  Utxo,
  checkedTreeId,
  createProofOutput,
  type ProofOutputUtxo,
  type TreeId,
} from "../utxo.js";
import { encryptConfidentialTransfer } from "./encrypt-rails.js";
import type { WalletUtxo } from "./state.js";

export interface ProgramMint {
  readonly asset: string;
  readonly assetId: bigint;
}

export type ProgramDataRecord =
  | Readonly<{ kind: "ringData"; bytes: Uint8Array }>
  | Readonly<{ kind: "utxoData"; bytes: Uint8Array }>
  | Readonly<{ kind: "memo"; bytes: Uint8Array }>;

export interface ProgramData {
  readonly records: ProgramDataRecord[];
}

export interface ProgramUtxo {
  readonly owner: Uint8Array;
  readonly asset: ProgramMint;
  readonly amount: bigint;
  readonly blinding: Uint8Array;
  readonly ringProgramId?: string;
  readonly data?: ProgramData;
}

export interface ProgramProofInputUtxo {
  readonly utxo: ProgramUtxo;
  readonly nullifierPubkey: Uint8Array;
  readonly utxoHash: Uint8Array;
  readonly nullifier: Uint8Array;
  readonly dataHash?: Uint8Array;
  readonly ringDataHash?: Uint8Array;
  readonly treeId: number;
  readonly leafIndex: bigint;
  readonly cacheSlot?: number;
  readonly address?: boolean;
  readonly compact?: boolean;
}

export interface ProgramProofOutputUtxo {
  readonly asset: ProgramMint;
  readonly amount: bigint;
  readonly blinding: Uint8Array;
  readonly ringProgramId?: string;
  readonly ringDataHash?: Uint8Array;
  readonly dataHash?: Uint8Array;
  readonly ownerAddress?: Uint8Array;
  readonly ownerTag?: Uint8Array;
  readonly data?: ProgramData;
  readonly cacheSlot?: number;
  readonly compact?: boolean;
}

export type ProgramOwnerTag =
  | Readonly<{ kind: "inline"; value: Uint8Array }>
  | Readonly<{ kind: "account"; index: number }>;

export interface ProgramResolvedOwnerTag {
  readonly tag: ProgramOwnerTag;
  readonly resolved: Uint8Array;
}

export type ProgramSettlementTransfer =
  | Readonly<{ kind: "sol"; isDeposit: boolean; amount: bigint; userSolAccount: string }>
  | Readonly<{
      kind: "spl";
      mint: string;
      isDeposit: boolean;
      amount: bigint;
      userSplToken: string;
    }>;

export interface ProgramFinalizedTransaction {
  readonly inputUtxos: ProgramProofInputUtxo[];
  readonly outputUtxos: ProgramProofOutputUtxo[];
  readonly outputHashes: Uint8Array[];
  readonly ownerTags: ProgramResolvedOwnerTag[];
  readonly interfaceTransfers: ProgramSettlementTransfer[];
  readonly firstNullifier: Uint8Array;
  readonly blindingSeed: Uint8Array;
  readonly privateTxBlinding: Uint8Array;
  readonly paddingIndependentPrivateTxHash: Uint8Array;
  readonly outputTreeId: number;
  readonly payer: string;
  readonly sender: Uint8Array;
}

export interface ProgramWalletUtxo {
  readonly utxo: ProgramUtxo;
  readonly nullifierPubkey: Uint8Array;
  readonly utxoHash: Uint8Array;
  readonly nullifier: Uint8Array;
  readonly dataHash?: Uint8Array;
  readonly ringDataHash?: Uint8Array;
  readonly treeId: number;
  readonly leafIndex: bigint;
  readonly latestTreeId?: number;
  readonly slot?: bigint;
  readonly txSignature?: Uint8Array;
  readonly slotIndex?: number;
}

export interface DecodedProgramTransaction {
  readonly sender: ShieldedAddress;
  readonly payer: Address;
  readonly inputs: readonly ProofInputUtxo[];
  readonly outputs: readonly ProofOutputUtxo[];
  readonly outputHashes: readonly Bytes32[];
  readonly ownerTags: readonly OwnerTag[];
  readonly resolvedOwnerTags: readonly Bytes32[];
  readonly interfaceTransfers: readonly SettlementTransfer[];
  readonly firstNullifier: Bytes32;
  readonly outputTreeId: TreeId;
  readonly blindingSeed: Bytes32;
  readonly privateTxBlinding: Bytes32;
  readonly paddingIndependentPrivateTxHash: Bytes32;
  encrypt(tx: ViewingKey, options?: ProgramEncryptOptions): ExternalData;
  /** Derives the transaction viewing key, encrypts outputs, and returns SPP proof inputs. */
  encryptWithKeys(keys: ProgramTransactionKeys, options?: ProgramEncryptOptions): SppProofInputs;
}

export type ProgramEncryptOptions = Readonly<{ expiryUnixTs?: bigint }>;

/** Validated prover inputs and their typed SPP transaction. */
export type ProgramProofInputs = Readonly<Record<string, string>>;

export interface ProgramTransaction {
  readonly proofInputs: ProgramProofInputs;
  readonly publicHash: Bytes32;
  readonly transaction: DecodedProgramTransaction;
}

export type ProgramTransactionKeys = Pick<ViewingKeyLike, "publicKey" | "transactionViewingKey">;

interface ResolvedTag {
  readonly tag: OwnerTag;
  readonly resolved: Bytes32;
}

const FINALIZED_KEYS = [
  "inputUtxos",
  "outputUtxos",
  "outputHashes",
  "ownerTags",
  "interfaceTransfers",
  "firstNullifier",
  "blindingSeed",
  "privateTxBlinding",
  "paddingIndependentPrivateTxHash",
  "outputTreeId",
  "payer",
  "sender",
] as const;
const INPUT_KEYS = [
  "utxo",
  "nullifierPubkey",
  "utxoHash",
  "nullifier",
  "dataHash",
  "ringDataHash",
  "treeId",
  "leafIndex",
  "cacheSlot",
  "address",
  "compact",
] as const;
const UTXO_KEYS = ["owner", "asset", "amount", "blinding", "ringProgramId", "data"] as const;
const OUTPUT_KEYS = [
  "asset",
  "amount",
  "blinding",
  "ringProgramId",
  "ringDataHash",
  "dataHash",
  "ownerAddress",
  "ownerTag",
  "data",
  "cacheSlot",
  "compact",
] as const;

const invalid = (field: string): TransactionError =>
  new TransactionError("TRANSACTION_DESERIALIZE", { field });
const decoder = wireDecoder(invalid);

/**
 * Binds a generated `<name>Transaction` function to a snapshot of the trusted
 * registry. Input types are inferred from the generated function; each call
 * validates its wasm result and returns an SDK transaction ready for encryption.
 * Bind again after registering additional assets.
 */
export function bindProgramTransaction<Input>(
  build: (inputs: Input, sender: Uint8Array, payer: string) => unknown,
  config: Readonly<{ assets: AssetRegistry }>,
): (inputs: Input, sender: Uint8Array, payer: string) => Promise<ProgramTransaction> {
  if (typeof build !== "function") throw invalid("build");
  if (typeof config !== "object" || config === null || !(config.assets instanceof AssetRegistry))
    throw invalid("assets");
  const assets = config.assets.clone();
  return async (inputs, sender, payer) => {
    const expectedSender = shieldedAddress(sender, "sender").toBytes();
    const expectedPayer = decoder.address(payer, "payer");
    let raw: unknown;
    try {
      raw = await build(inputs, copy(expectedSender), expectedPayer);
    } catch (cause) {
      throw new TransactionError("TRANSACTION_PROGRAM_BUILD", undefined, cause);
    }
    const result = exactRecord(raw, "programTransaction", [
      "finalizedTx",
      "proofInputs",
      "publicHash",
    ]);
    const publicHash = fixedBytes<Bytes32>(result["publicHash"], 32, "publicHash");
    if (bytesToBigInt(publicHash) >= BN254_SCALAR_ORDER) throw invalid("publicHash");
    const fields = decoder.record(result["proofInputs"], "proofInputs");
    if (Object.keys(fields).length === 0) throw invalid("proofInputs");
    const proofInputs = Object.freeze(
      Object.fromEntries(
        Object.entries(fields).map(([name, value]) => {
          const scalar = decoder.string(value, `proofInputs.${name}`);
          if (!/^(0|[1-9][0-9]*)$/u.test(scalar) || BigInt(scalar) >= BN254_SCALAR_ORDER)
            throw invalid(`proofInputs.${name}`);
          return [name, scalar];
        }),
      ),
    );
    if (proofInputs["public_hash"] !== bytesToBigInt(publicHash).toString())
      throw new TransactionError("TRANSACTION_PROGRAM_PUBLIC_HASH_MISMATCH");
    const transaction = await decodeProgramTransaction(result["finalizedTx"], assets);
    if (transaction.payer !== expectedPayer)
      throw new TransactionError("TRANSACTION_PROGRAM_PAYER_MISMATCH");
    if (!equalBytes(transaction.sender.toBytes(), expectedSender))
      throw new TransactionError("TRANSACTION_PROGRAM_SENDER_MISMATCH");
    return Object.freeze({ proofInputs, publicHash, transaction });
  };
}

export async function decodeProgramTransaction(
  value: unknown,
  assets: AssetRegistry,
): Promise<DecodedProgramTransaction> {
  const entry = exactRecord(value, "finalizedTx", FINALIZED_KEYS);
  const payer = decoder.address(entry["payer"], "payer");
  const sender = shieldedAddress(entry["sender"], "sender");
  const inputs = list(entry["inputUtxos"], "inputUtxos", (item, path) =>
    proofInput(item, path, assets),
  );
  const outputs = list(entry["outputUtxos"], "outputUtxos", (item, path) =>
    proofOutput(item, path, assets),
  );
  const outputHashes = list(entry["outputHashes"], "outputHashes", (item, path) =>
    fixedBytes<Bytes32>(item, 32, path),
  );
  const tags = list(entry["ownerTags"], "ownerTags", resolvedOwnerTag);
  const interfaceTransfers = await Promise.all(
    list(entry["interfaceTransfers"], "interfaceTransfers", settlementTransfer),
  );
  const firstNullifier = fixedBytes<Bytes32>(entry["firstNullifier"], 32, "firstNullifier");
  const blindingSeed = fixedBytes<Bytes32>(entry["blindingSeed"], 32, "blindingSeed");
  const privateTxBlinding = fixedBytes<Bytes32>(
    entry["privateTxBlinding"],
    32,
    "privateTxBlinding",
  );
  const paddingIndependentPrivateTxHash = fixedBytes<Bytes32>(
    entry["paddingIndependentPrivateTxHash"],
    32,
    "paddingIndependentPrivateTxHash",
  );
  const outputTreeId = treeId(entry["outputTreeId"], "outputTreeId");

  const first = inputs[0];
  if (first === undefined) throw new TransactionError("TRANSACTION_NO_INPUTS");
  if (!equalBytes(first.nullifier(), firstNullifier)) {
    throw new TransactionError("TRANSACTION_FIRST_NULLIFIER_MISMATCH");
  }
  if (outputHashes.length !== outputs.length) {
    throw new TransactionError("TRANSACTION_OUTPUT_HASH_COUNT_MISMATCH", {
      got: outputHashes.length,
      expected: outputs.length,
    });
  }
  outputs.forEach((output, slotIndex) => {
    const utxoHash = outputHashes[slotIndex];
    if (utxoHash === undefined || !equalBytes(output.hash(outputTreeId), utxoHash)) {
      throw new TransactionError("TRANSACTION_OUTPUT_HASH_MISMATCH", { slotIndex });
    }
  });
  checkOwnerTags(outputs, tags, payer);

  const ownerTags = Object.freeze(tags.map((entry) => entry.tag));
  const resolvedOwnerTags = Object.freeze(tags.map((entry) => entry.resolved));
  const frozenInputs = Object.freeze(inputs);
  const frozenOutputs = Object.freeze(outputs);
  const frozenHashes = Object.freeze(outputHashes);
  const frozenTransfers = Object.freeze(interfaceTransfers);
  const encrypt = (tx: ViewingKey, options?: ProgramEncryptOptions): ExternalData => {
    const encrypted = encryptConfidentialTransfer(tx, { outputs: frozenOutputs });
    // A dummy is never encrypted: it carries a length-matched random ciphertext
    // under the participant tag it was padded with, like Rust `encrypt_with_viewing_key`.
    const dummyLength = frozenOutputs.some((output) => output.isDummy())
      ? dummyCiphertextLength(encrypted.salt)
      : 0;
    return createExternalData({
      ...(options?.expiryUnixTs === undefined ? {} : { expiryUnixTs: options.expiryUnixTs }),
      txViewingPublicKey: encrypted.txViewingPublicKey,
      salt: encrypted.salt,
      interfaceTransfers: frozenTransfers,
      outputs: tags.flatMap((entry, slotIndex) => {
        if (frozenOutputs[slotIndex]?.isCompact()) return [];
        const output = frozenOutputs[slotIndex];
        const slot = encrypted.payload[slotIndex];
        const data = output?.isDummy() ? randomBytes(dummyLength) : slot?.data;
        if (
          data === undefined ||
          (slot !== undefined && !equalBytes(slot.viewTag, entry.resolved))
        ) {
          throw new TransactionError("TRANSACTION_OWNER_TAG_MISMATCH", { slotIndex });
        }
        const utxoHash = frozenHashes[slotIndex];
        if (utxoHash === undefined) {
          throw new TransactionError("TRANSACTION_OUTPUT_HASH_COUNT_MISMATCH", { slotIndex });
        }
        return [{ utxoHash, ownerTag: entry.tag, data }];
      }),
      resolvedOwnerTags: resolvedOwnerTags.filter(
        (_, slotIndex) => !frozenOutputs[slotIndex]?.isCompact(),
      ),
      messages: [],
    });
  };
  return Object.freeze({
    sender,
    payer,
    inputs: frozenInputs,
    outputs: frozenOutputs,
    outputHashes: frozenHashes,
    ownerTags,
    resolvedOwnerTags,
    interfaceTransfers: frozenTransfers,
    firstNullifier,
    outputTreeId,
    blindingSeed,
    privateTxBlinding,
    paddingIndependentPrivateTxHash,
    encrypt,
    encryptWithKeys(keys: ProgramTransactionKeys, options?: ProgramEncryptOptions): SppProofInputs {
      if (!keys.publicKey().equals(sender.viewingPublicKey)) {
        throw new TransactionError("TRANSACTION_KEYS_IDENTITY_MISMATCH");
      }
      const tx = keys.transactionViewingKey(firstNullifier);
      try {
        return new SppProofInputs({
          payer,
          inputUtxos: frozenInputs,
          outputs: frozenOutputs,
          externalData: encrypt(tx, options),
          blindingSeed,
          outputTreeId,
        });
      } finally {
        tx.destroy();
      }
    },
  });
}

export function toProgramWalletUtxo(
  utxo: WalletUtxo,
  input: Readonly<{ nullifierPublicKey: Bytes32; treeId: TreeId; assets: AssetRegistry }>,
): ProgramWalletUtxo {
  if (!(utxo.utxo instanceof Utxo)) {
    throw new TransactionError("TRANSACTION_DESERIALIZE", { field: "utxo" });
  }
  const treeId = checkedTreeId(input.treeId);
  if (treeAddress(treeId) !== utxo.outputContext.tree) {
    throw new TransactionError("TRANSACTION_INPUT_TREE_MISMATCH", { treeId });
  }
  const nullifierPublicKey = checked<Bytes32>(input.nullifierPublicKey, 32, "nullifier public key");
  const utxoHash = checked<Bytes32>(utxo.outputContext.hash, 32, "UTXO hash");
  if (
    !equalBytes(
      utxo.utxo.hash(nullifierPublicKey, treeId, utxo.dataHash, utxo.ringDataHash),
      utxoHash,
    )
  ) {
    throw new TransactionError("TRANSACTION_INPUT_OWNER_MISMATCH", { reason: "utxoHash" });
  }
  const leafIndex = utxo.outputContext.leafIndex;
  if (typeof leafIndex !== "bigint" || leafIndex < 0n || leafIndex > U64_MAX) {
    throw new TransactionError("TRANSACTION_INVALID_POSITION", { position: String(leafIndex) });
  }
  return Object.freeze({
    utxo: Object.freeze({
      owner: utxo.utxo.owner.toBytes(),
      asset: Object.freeze({
        asset: utxo.utxo.asset,
        assetId: input.assets.assetId(utxo.utxo.asset),
      }),
      amount: utxo.utxo.amount,
      blinding: copy(utxo.utxo.blinding),
      ...(utxo.utxo.ringProgramId === undefined ? {} : { ringProgramId: utxo.utxo.ringProgramId }),
      data: Object.freeze({ records: [...utxo.utxo.data.records()] }),
    }),
    nullifierPubkey: nullifierPublicKey,
    utxoHash,
    nullifier: checked<Bytes32>(utxo.nullifier, 32, "nullifier"),
    ...(utxo.dataHash === undefined
      ? {}
      : { dataHash: checked<Bytes32>(utxo.dataHash, 32, "data hash") }),
    ...(utxo.ringDataHash === undefined
      ? {}
      : { ringDataHash: checked<Bytes32>(utxo.ringDataHash, 32, "ring data hash") }),
    treeId,
    leafIndex,
  });
}

function checkOwnerTags(
  outputs: readonly ProofOutputUtxo[],
  tags: readonly ResolvedTag[],
  payer: Address,
): void {
  if (tags.length !== outputs.length) {
    throw new TransactionError("TRANSACTION_OWNER_TAG_COUNT_MISMATCH", {
      got: tags.length,
      expected: outputs.length,
    });
  }
  const payerBytes = decodeAddress(payer);
  outputs.forEach((output, slotIndex) => {
    const entry = tags[slotIndex];
    if (entry === undefined) {
      throw new TransactionError("TRANSACTION_OWNER_TAG_COUNT_MISMATCH", { slotIndex });
    }
    // A dummy publishes the participant tag it was padded with.
    const viewTag = output.isCompact()
      ? new Uint8Array(32)
      : (output.ownerAddress?.confidentialViewTag() ?? output.ownerTag);
    if (viewTag === undefined || !equalBytes(entry.resolved, viewTag)) {
      throw new TransactionError("TRANSACTION_OWNER_TAG_MISMATCH", {
        slotIndex,
        reason: "viewTag",
      });
    }
    if (entry.tag.kind === "inline" && !equalBytes(entry.tag.value, entry.resolved)) {
      throw new TransactionError("TRANSACTION_OWNER_TAG_MISMATCH", {
        slotIndex,
        reason: "inline",
      });
    }
    if (
      entry.tag.kind === "account" &&
      (entry.tag.index !== 0 || !equalBytes(entry.resolved, payerBytes))
    ) {
      throw new TransactionError("TRANSACTION_OWNER_TAG_MISMATCH", {
        slotIndex,
        reason: "account",
      });
    }
  });
}

function proofInput(value: unknown, path: string, assets: AssetRegistry): ProofInputUtxo {
  const entry = exactRecord(value, path, INPUT_KEYS);
  const utxoHash = fixedBytes<Bytes32>(entry["utxoHash"], 32, `${path}.utxoHash`);
  const leafIndex = u64(entry["leafIndex"], `${path}.leafIndex`);
  const address =
    entry["address"] === undefined ? false : decoder.boolean(entry["address"], `${path}.address`);
  if (address && leafIndex !== 0n) {
    throw new TransactionError("TRANSACTION_ADDRESS_INPUT_NONEMPTY_FIELD", { field: "leaf_index" });
  }
  const input = new ProofInputUtxo({
    utxo: utxoValue(entry["utxo"], `${path}.utxo`, assets),
    address,
    ...optional(entry, "compact", path, (item, field) => ({
      compact: decoder.boolean(item, field),
    })),
    nullifierPublicKey: fixedBytes<Bytes32>(
      entry["nullifierPubkey"],
      32,
      `${path}.nullifierPubkey`,
    ),
    nullifier: fixedBytes<Bytes32>(entry["nullifier"], 32, `${path}.nullifier`),
    treeId: treeId(entry["treeId"], `${path}.treeId`),
    ...optional(entry, "dataHash", path, (item, field) => ({
      dataHash: fixedBytes<Bytes32>(item, 32, field),
    })),
    ...optional(entry, "ringDataHash", path, (item, field) => ({
      ringDataHash: fixedBytes<Bytes32>(item, 32, field),
    })),
    ...optional(entry, "cacheSlot", path, (item, field) => ({ cacheSlot: u8(item, field) })),
  });
  if (!equalBytes(input.hash(), utxoHash)) {
    throw new TransactionError("TRANSACTION_INPUT_HASH_MISMATCH", { field: path });
  }
  return input;
}

function utxoValue(value: unknown, path: string, assets: AssetRegistry): Utxo {
  const entry = exactRecord(value, path, UTXO_KEYS);
  const asset = mint(entry["asset"], `${path}.asset`, assets);
  return new Utxo({
    owner: publicKey(entry["owner"], `${path}.owner`),
    asset: asset.asset,
    mint: asset,
    amount: u64(entry["amount"], `${path}.amount`),
    blinding: fixedBytes<Bytes32>(entry["blinding"], 32, `${path}.blinding`),
    data: data(entry["data"], `${path}.data`),
    ...optional(entry, "ringProgramId", path, (item, field) => ({
      ringProgramId: decoder.address(item, field),
    })),
  });
}

function proofOutput(value: unknown, path: string, assets: AssetRegistry): ProofOutputUtxo {
  const entry = exactRecord(value, path, OUTPUT_KEYS);
  if (entry["compact"] === true && entry["ownerAddress"] !== undefined)
    throw invalid(`${path}.compact`);
  const asset = mint(entry["asset"], `${path}.asset`, assets);
  return createProofOutput({
    asset: asset.asset,
    mint: asset,
    amount: u64(entry["amount"], `${path}.amount`),
    blinding: fixedBytes<Bytes32>(entry["blinding"], 32, `${path}.blinding`),
    data: data(entry["data"], `${path}.data`),
    ...optional(entry, "ringProgramId", path, (item, field) => ({
      ringProgramId: decoder.address(item, field),
    })),
    ...optional(entry, "ringDataHash", path, (item, field) => ({
      ringDataHash: fixedBytes<Bytes32>(item, 32, field),
    })),
    ...optional(entry, "dataHash", path, (item, field) => ({
      dataHash: fixedBytes<Bytes32>(item, 32, field),
    })),
    ...optional(entry, "compact", path, (item, field) => ({
      compact: decoder.boolean(item, field),
    })),
    ...optional(entry, "ownerAddress", path, (item, field) => ({
      ownerAddress: shieldedAddress(item, field),
    })),
    ...optional(entry, "ownerTag", path, (item, field) => ({
      ownerTag: fixedBytes<Bytes32>(item, 32, field),
    })),
    ...optional(entry, "cacheSlot", path, (item, field) => ({ cacheSlot: u8(item, field) })),
  });
}

function resolvedOwnerTag(value: unknown, path: string): ResolvedTag {
  const entry = exactRecord(value, path, ["tag", "resolved"]);
  return Object.freeze({
    tag: ownerTag(entry["tag"], `${path}.tag`),
    resolved: fixedBytes<Bytes32>(entry["resolved"], 32, `${path}.resolved`),
  });
}

function ownerTag(value: unknown, path: string): OwnerTag {
  const entry = decoder.record(value, path);
  const kind = entry["kind"];
  if (kind === "inline") {
    exactKeys(entry, path, ["kind", "value"]);
    return Object.freeze({
      kind,
      value: fixedBytes<Bytes32>(entry["value"], 32, `${path}.value`),
    });
  }
  if (kind === "account") {
    exactKeys(entry, path, ["kind", "index"]);
    return Object.freeze({ kind, index: u8(entry["index"], `${path}.index`) });
  }
  throw new TransactionError("TRANSACTION_BAD_DISCRIMINATOR", { field: `${path}.kind` });
}

async function settlementTransfer(value: unknown, path: string): Promise<SettlementTransfer> {
  const entry = decoder.record(value, path);
  const kind = entry["kind"];
  if (kind === "sol") {
    exactKeys(entry, path, ["kind", "isDeposit", "amount", "userSolAccount"]);
    return Object.freeze({
      kind,
      isDeposit: decoder.boolean(entry["isDeposit"], `${path}.isDeposit`),
      amount: u64(entry["amount"], `${path}.amount`),
      userSolAccount: decoder.address(entry["userSolAccount"], `${path}.userSolAccount`),
    });
  }
  if (kind === "spl") {
    exactKeys(entry, path, ["kind", "mint", "isDeposit", "amount", "userSplToken"]);
    const mintAddress = decoder.address(entry["mint"], `${path}.mint`);
    const isDeposit = decoder.boolean(entry["isDeposit"], `${path}.isDeposit`);
    const amount = u64(entry["amount"], `${path}.amount`);
    const tokenAccount = decoder.address(entry["userSplToken"], `${path}.userSplToken`);
    const [, splInterfaceBump] = await splInterfaceWithBump(mintAddress);
    return Object.freeze({
      kind,
      mint: mintAddress,
      isDeposit,
      amount,
      tokenAccount,
      splInterfaceBump,
    });
  }
  throw new TransactionError("TRANSACTION_BAD_DISCRIMINATOR", { field: `${path}.kind` });
}

function mint(value: unknown, path: string, assets: AssetRegistry): Mint {
  const entry = exactRecord(value, path, ["asset", "assetId"]);
  const asset = decoder.address(entry["asset"], `${path}.asset`);
  const assetId = u64(entry["assetId"], `${path}.assetId`);
  if (assets.resolve(assetId) !== asset) {
    throw new TransactionError("TRANSACTION_MINT_MISMATCH", {
      field: path,
      assetId: String(assetId),
      mint: asset,
    });
  }
  return Mint.fromRegistry(assets, asset);
}

function data(value: unknown, path: string): Data {
  if (value === undefined) return new Data();
  const entry = exactRecord(value, path, ["records"]);
  return new Data(list(entry["records"], `${path}.records`, dataRecord));
}

function dataRecord(value: unknown, path: string): DataRecord {
  const entry = exactRecord(value, path, ["kind", "bytes"]);
  const kind = entry["kind"];
  if (kind !== "ringData" && kind !== "utxoData" && kind !== "memo") {
    throw new TransactionError("TRANSACTION_BAD_DISCRIMINATOR", { field: `${path}.kind` });
  }
  const bytes = entry["bytes"];
  if (!(bytes instanceof Uint8Array)) throw invalid(`${path}.bytes`);
  return Object.freeze({ kind, bytes: new Uint8Array(bytes) });
}

function shieldedAddress(value: unknown, path: string): ShieldedAddress {
  const bytes = fixedBytes<Uint8Array>(value, SHIELDED_ADDRESS_LENGTH, path);
  return inKeypairCategory(path, () => ShieldedAddress.fromBytes(bytes));
}

function publicKey(value: unknown, path: string): ShieldedPublicKey {
  const bytes = fixedBytes<Bytes34>(value, SHIELDED_PUBLIC_KEY_LENGTH, path);
  if (bytes.every((byte) => byte === 0)) return ShieldedPublicKey.zeroed();
  return inKeypairCategory(path, () => ShieldedPublicKey.fromBytes(bytes));
}

function inKeypairCategory<T>(path: string, run: () => T): T {
  try {
    return run();
  } catch (cause) {
    if (cause instanceof TransactionError) throw cause;
    throw new TransactionError("TRANSACTION_KEYPAIR", { field: path }, cause);
  }
}

function list<T>(value: unknown, path: string, decode: (item: unknown, path: string) => T): T[] {
  const items = decoder.list(value, path);
  return Array.from(items, (item, index) => decode(item, `${path}[${String(index)}]`));
}

function optional<K extends string, T>(
  entry: Readonly<Record<string, unknown>>,
  key: K,
  path: string,
  decode: (item: unknown, path: string) => T,
): T | Record<never, never> {
  const item = entry[key];
  return item === undefined ? {} : decode(item, `${path}.${key}`);
}

function exactRecord(
  value: unknown,
  path: string,
  keys: readonly string[],
): Record<string, unknown> {
  const entry = decoder.record(value, path);
  exactKeys(entry, path, keys);
  return entry;
}

function exactKeys(
  entry: Readonly<Record<string, unknown>>,
  path: string,
  keys: readonly string[],
): void {
  for (const key of Object.keys(entry)) {
    if (!keys.includes(key)) throw invalid(`${path}.${key}`);
  }
}

function fixedBytes<T extends Uint8Array>(value: unknown, length: number, path: string): T {
  if (!(value instanceof Uint8Array)) throw invalid(path);
  return checked<T>(value, length, path);
}

function u64(value: unknown, path: string): bigint {
  if (typeof value !== "bigint") throw invalid(path);
  if (value < 0n || value > U64_MAX) {
    throw new TransactionError("TRANSACTION_INVALID_INTEGER", { field: path, bits: 64 });
  }
  return value;
}

function u8(value: unknown, path: string): number {
  if (typeof value !== "number") throw invalid(path);
  if (!Number.isInteger(value) || value < 0 || value > 0xff) {
    throw new TransactionError("TRANSACTION_INVALID_INTEGER", { field: path, bits: 8 });
  }
  return value;
}

function treeId(value: unknown, path: string): TreeId {
  if (typeof value !== "number") throw invalid(path);
  return checkedTreeId(value);
}
