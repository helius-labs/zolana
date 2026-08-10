import {
  address as kitAddress,
  assertIsSignature,
  getBase64Decoder,
  getBase64Encoder,
} from "@solana/kit";

import type { Address, Bytes32, Bytes33, Signature } from "../../interface/types.js";
import type { Bytes34 } from "../../keypair/bytes.js";
import { P256PublicKey, ShieldedPublicKey } from "../../keypair/public-key.js";
import { ShieldedAddress } from "../../keypair/shielded.js";

import { Data, type DataRecord } from "../data.js";
import { TransactionError } from "../error.js";
import { Utxo } from "../utxo.js";
import { AssetRegistry, SOL_ASSET_ID } from "./asset.js";
import {
  Wallet,
  hex,
  type PrivateTransaction,
  type PrivateTransactionDirection,
  type PrivateTransactionKind,
  type ViewingKeyEntry,
  type WalletUtxo,
} from "./state.js";

const decodeBase64 = getBase64Encoder();
const encodeBase64 = getBase64Decoder();
const U64_MAX = 0xffff_ffff_ffff_ffffn;
const I64_MIN = -(1n << 63n);
const I64_MAX = (1n << 63n) - 1n;

interface SerializedViewingKeyEntry {
  readonly viewingPublicKey: string;
  readonly createdAt: string;
}

interface SerializedDataRecord {
  readonly kind: DataRecord["kind"];
  readonly bytes: string;
}

interface SerializedWalletUtxo {
  readonly owner: string;
  readonly asset: Address;
  readonly amount: string;
  readonly blinding: string;
  readonly data: readonly SerializedDataRecord[];
  readonly ringProgramId?: Address;
  readonly outputContext: Readonly<{
    hash: string;
    tree: Address;
    leafIndex: string;
  }>;
  readonly nullifier: string;
  readonly dataHash?: string;
  readonly ringDataHash?: string;
  readonly spent: boolean;
}

interface SerializedPrivateTransaction {
  readonly id: Readonly<{
    signature: Signature;
    slot: string;
    index: string;
  }>;
  readonly kind: PrivateTransactionKind;
  readonly direction: PrivateTransactionDirection;
  readonly status: "confirmed";
  readonly asset: Address;
  readonly amount: string;
  readonly counterpartyViewingPublicKey?: string;
}

/**
 * Versioned, JSON-safe wallet state. It contains private note plaintext and
 * blindings, but never signing, nullifier, or viewing secrets. Applications
 * must still encrypt it at rest.
 */
export interface SerializedWalletState {
  readonly version: 1;
  readonly identity: Readonly<{
    signingPublicKey: string;
    nullifierPublicKey: string;
    viewingPublicKey: string;
  }>;
  readonly assets: readonly Readonly<{ assetId: string; mint: Address }>[];
  readonly viewingKeyHistory: readonly SerializedViewingKeyEntry[];
  readonly utxos: readonly SerializedWalletUtxo[];
  readonly transactions: readonly SerializedPrivateTransaction[];
  readonly nullifiers: readonly string[];
  readonly lastSynced: string;
}

export function serializeWallet(wallet: Wallet): string {
  if (!(wallet instanceof Wallet)) fail("wallet");
  const state = wallet._state();
  const snapshot: SerializedWalletState = {
    version: 1,
    identity: {
      signingPublicKey: encode(wallet.identity.signingPublicKey.toBytes()),
      nullifierPublicKey: encode(wallet.identity.nullifierPublicKey),
      viewingPublicKey: encode(wallet.identity.viewingPublicKey.toBytes()),
    },
    assets: wallet.registry
      .entries()
      .filter(([assetId]) => assetId !== SOL_ASSET_ID)
      .map(([assetId, mint]) => Object.freeze({ assetId: assetId.toString(), mint })),
    viewingKeyHistory: state.viewingKeyHistory.map(serializeViewingKeyEntry),
    utxos: state.utxos.map(serializeUtxo),
    transactions: state.transactions.map(serializeTransaction),
    nullifiers: [...state.nullifiers].sort().map((value) => encode(unhex(value))),
    lastSynced: wallet.lastSynced.toString(),
  };
  return JSON.stringify(snapshot);
}

export function deserializeWallet(serialized: string): Wallet {
  try {
    if (typeof serialized !== "string") fail("serialized");
    return hydrate(JSON.parse(serialized) as unknown);
  } catch (cause) {
    if (cause instanceof TransactionError) throw cause;
    throw new TransactionError("TRANSACTION_DESERIALIZE", { field: "wallet" }, cause);
  }
}

function hydrate(value: unknown): Wallet {
  const snapshot = record(value, "wallet");
  if (snapshot["version"] !== 1) fail("version");
  const identityValue = record(snapshot["identity"], "identity");
  const identity = ShieldedAddress.fromPublicKeys(
    ShieldedPublicKey.fromBytes(
      bytes(identityValue["signingPublicKey"], 34, "identity.signingPublicKey") as Bytes34,
    ),
    bytes(identityValue["nullifierPublicKey"], 32, "identity.nullifierPublicKey") as Bytes32,
    P256PublicKey.fromBytes(
      bytes(identityValue["viewingPublicKey"], 33, "identity.viewingPublicKey") as Bytes33,
    ),
  );
  const registry = new AssetRegistry(
    array(snapshot["assets"], "assets").map((entry, index) => {
      const item = record(entry, `assets[${String(index)}]`);
      return [
        unsigned(item["assetId"], `assets[${String(index)}].assetId`),
        address(item["mint"], `assets[${String(index)}].mint`),
      ] as const;
    }),
  );
  const viewingKeyHistory = array(snapshot["viewingKeyHistory"], "viewingKeyHistory").map(
    deserializeViewingKeyEntry,
  );
  if (
    !viewingKeyHistory.some(
      (entry) =>
        encode(entry.viewingPublicKey.toBytes()) === encode(identity.viewingPublicKey.toBytes()),
    )
  ) {
    fail("viewingKeyHistory");
  }
  const decodedUtxos = array(snapshot["utxos"], "utxos").map(deserializeUtxo);
  const expectedOwner = encode(identity.signingPublicKey.toBytes());
  if (decodedUtxos.some((entry) => encode(entry.utxo.owner.toBytes()) !== expectedOwner)) {
    fail("utxos.owner");
  }
  const transactions = array(snapshot["transactions"], "transactions").map(deserializeTransaction);
  const nullifiers = new Set(
    array(snapshot["nullifiers"], "nullifiers").map((value, index) =>
      hex(bytes(value, 32, `nullifiers[${String(index)}]`)),
    ),
  );
  const utxos = decodedUtxos.map((entry) =>
    entry.spent || !nullifiers.has(hex(entry.nullifier))
      ? entry
      : Object.freeze({ ...entry, spent: true }),
  );
  const wallet = new Wallet({ identity, registry });
  wallet._replace({
    utxos,
    transactions,
    nullifiers,
    viewingKeyHistory,
    lastSynced: signed(snapshot["lastSynced"], "lastSynced"),
  });
  return wallet;
}

function serializeViewingKeyEntry(value: ViewingKeyEntry): SerializedViewingKeyEntry {
  return {
    viewingPublicKey: encode(value.viewingPublicKey.toBytes()),
    createdAt: value.createdAt.toString(),
  };
}

function deserializeViewingKeyEntry(value: unknown, index: number): ViewingKeyEntry {
  const path = `viewingKeyHistory[${String(index)}]`;
  const entry = record(value, path);
  if (Object.keys(entry).some((key) => key !== "viewingPublicKey" && key !== "createdAt")) {
    fail(path);
  }
  return {
    viewingPublicKey: P256PublicKey.fromBytes(
      bytes(entry["viewingPublicKey"], 33, `${path}.viewingPublicKey`) as Bytes33,
    ),
    createdAt: signed(entry["createdAt"], `${path}.createdAt`),
  };
}

function serializeUtxo(value: WalletUtxo): SerializedWalletUtxo {
  return {
    owner: encode(value.utxo.owner.toBytes()),
    asset: value.utxo.asset,
    amount: value.utxo.amount.toString(),
    blinding: encode(value.utxo.blinding),
    data: value.utxo.data.records().map((record) => ({
      kind: record.kind,
      bytes: encode(record.bytes),
    })),
    ...(value.utxo.ringProgramId === undefined ? {} : { ringProgramId: value.utxo.ringProgramId }),
    outputContext: {
      hash: encode(value.outputContext.hash),
      tree: value.outputContext.tree,
      leafIndex: value.outputContext.leafIndex.toString(),
    },
    nullifier: encode(value.nullifier),
    ...(value.dataHash === undefined ? {} : { dataHash: encode(value.dataHash) }),
    ...(value.ringDataHash === undefined ? {} : { ringDataHash: encode(value.ringDataHash) }),
    spent: value.spent,
  };
}

function deserializeUtxo(value: unknown, index: number): WalletUtxo {
  const path = `utxos[${String(index)}]`;
  const entry = record(value, path);
  const context = record(entry["outputContext"], `${path}.outputContext`);
  const records = array(entry["data"], `${path}.data`).map((value, recordIndex) => {
    const recordPath = `${path}.data[${String(recordIndex)}]`;
    const item = record(value, recordPath);
    const kind = item["kind"];
    if (kind !== "ringData" && kind !== "utxoData" && kind !== "memo") {
      fail(`${recordPath}.kind`);
    }
    return {
      kind,
      bytes: bytes(item["bytes"], undefined, `${recordPath}.bytes`),
    } satisfies DataRecord;
  });
  return {
    utxo: new Utxo({
      owner: ShieldedPublicKey.fromBytes(bytes(entry["owner"], 34, `${path}.owner`) as Bytes34),
      asset: address(entry["asset"], `${path}.asset`),
      amount: unsigned(entry["amount"], `${path}.amount`),
      blinding: bytes(entry["blinding"], 32, `${path}.blinding`) as Bytes32,
      data: new Data(records),
      ...(entry["ringProgramId"] === undefined
        ? {}
        : { ringProgramId: address(entry["ringProgramId"], `${path}.ringProgramId`) }),
    }),
    outputContext: {
      hash: bytes(context["hash"], 32, `${path}.outputContext.hash`) as Bytes32,
      tree: address(context["tree"], `${path}.outputContext.tree`),
      leafIndex: unsigned(context["leafIndex"], `${path}.outputContext.leafIndex`),
    },
    nullifier: bytes(entry["nullifier"], 32, `${path}.nullifier`) as Bytes32,
    ...(entry["dataHash"] === undefined
      ? {}
      : { dataHash: bytes(entry["dataHash"], 32, `${path}.dataHash`) as Bytes32 }),
    ...(entry["ringDataHash"] === undefined
      ? {}
      : { ringDataHash: bytes(entry["ringDataHash"], 32, `${path}.ringDataHash`) as Bytes32 }),
    spent: boolean(entry["spent"], `${path}.spent`),
  };
}

function serializeTransaction(value: PrivateTransaction): SerializedPrivateTransaction {
  return {
    id: {
      signature: value.id.signature,
      slot: value.id.slot.toString(),
      index: value.id.index.toString(),
    },
    kind: value.kind,
    direction: value.direction,
    status: value.status,
    asset: value.asset,
    amount: value.amount.toString(),
    ...(value.counterpartyViewingPublicKey === undefined
      ? {}
      : { counterpartyViewingPublicKey: encode(value.counterpartyViewingPublicKey.toBytes()) }),
  };
}

function deserializeTransaction(value: unknown, index: number): PrivateTransaction {
  const path = `transactions[${String(index)}]`;
  const item = record(value, path);
  const id = record(item["id"], `${path}.id`);
  const kind = item["kind"];
  if (
    kind !== "deposit" &&
    kind !== "privateTransfer" &&
    kind !== "publicWithdrawal" &&
    kind !== "split" &&
    kind !== "merge"
  ) {
    fail(`${path}.kind`);
  }
  const direction = item["direction"];
  if (direction !== "inbound" && direction !== "outbound" && direction !== "selfTransfer") {
    fail(`${path}.direction`);
  }
  if (item["status"] !== "confirmed") fail(`${path}.status`);
  return {
    id: {
      signature: signature(id["signature"], `${path}.id.signature`),
      slot: unsigned(id["slot"], `${path}.id.slot`),
      index: unsigned(id["index"], `${path}.id.index`),
    },
    kind,
    direction,
    status: "confirmed",
    asset: address(item["asset"], `${path}.asset`),
    amount: unsigned(item["amount"], `${path}.amount`),
    ...(item["counterpartyViewingPublicKey"] === undefined
      ? {}
      : {
          counterpartyViewingPublicKey: P256PublicKey.fromBytes(
            bytes(
              item["counterpartyViewingPublicKey"],
              33,
              `${path}.counterpartyViewingPublicKey`,
            ) as Bytes33,
          ),
        }),
  };
}

function encode(value: Uint8Array): string {
  return encodeBase64.decode(value);
}

function unhex(value: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/.test(value)) fail("nullifiers");
  return Uint8Array.from({ length: 32 }, (_, index) =>
    Number.parseInt(value.slice(index * 2, index * 2 + 2), 16),
  );
}

function bytes(value: unknown, length: number | undefined, field: string): Uint8Array {
  if (typeof value !== "string") fail(field);
  try {
    const decoded = new Uint8Array(decodeBase64.encode(value));
    if (encode(decoded) !== value || (length !== undefined && decoded.length !== length)) {
      fail(field);
    }
    return decoded;
  } catch (cause) {
    if (cause instanceof TransactionError) throw cause;
    fail(field);
  }
}

function unsigned(value: unknown, field: string): bigint {
  const parsed = decimal(value, field);
  if (parsed < 0n || parsed > U64_MAX) fail(field);
  return parsed;
}

function signed(value: unknown, field: string): bigint {
  const parsed = decimal(value, field);
  if (parsed < I64_MIN || parsed > I64_MAX) fail(field);
  return parsed;
}

function decimal(value: unknown, field: string): bigint {
  if (typeof value !== "string" || !/^(?:0|-?[1-9][0-9]*)$/.test(value)) fail(field);
  try {
    return BigInt(value);
  } catch {
    fail(field);
  }
}

function address(value: unknown, field: string): Address {
  if (typeof value !== "string") fail(field);
  try {
    return kitAddress(value);
  } catch {
    fail(field);
  }
}

function signature(value: unknown, field: string): Signature {
  if (typeof value !== "string") fail(field);
  try {
    assertIsSignature(value);
    return value;
  } catch {
    fail(field);
  }
}

function boolean(value: unknown, field: string): boolean {
  if (typeof value !== "boolean") fail(field);
  return value;
}

function array(value: unknown, field: string): readonly unknown[] {
  if (!Array.isArray(value)) fail(field);
  return value;
}

function record(value: unknown, field: string): Readonly<Record<string, unknown>> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) fail(field);
  return value as Readonly<Record<string, unknown>>;
}

function fail(field: string): never {
  throw new TransactionError("TRANSACTION_DESERIALIZE", { field });
}
