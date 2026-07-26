import { address, type Address } from "@solana/kit";

export { initializePoseidon, isPoseidonInitialized } from "../hasher/index.js";
import { encodeBase58 } from "./internal.js";
import { InterfaceError } from "./errors.js";
import {
  ADDRESS_TREE_HEIGHT,
  ADDRESS_TREE_INPUT_QUEUE_BATCH_SIZE,
  ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE,
  ADDRESS_TREE_ROOT_HISTORY_CAPACITY,
} from "./state.js";
import {
  protocolConfigAccountCodec,
  splAssetCounterAccountCodec,
  splAssetRegistryAccountCodec,
  zoneConfigAccountCodec,
} from "./codecs/index.js";

export { InterfaceError, ShieldedPoolError, decodeShieldedPoolError } from "./errors.js";
export type {
  DecodedShieldedPoolError,
  InterfaceErrorCode,
  ShieldedPoolErrorCode,
  ShieldedPoolErrorName,
} from "./errors.js";
export { externalDataHash } from "./external-data-hash.js";
export type { ExternalDataHashInput } from "./external-data-hash.js";
export {
  ciphertextHash,
  ownerPkFieldCompressed,
  pack33,
  pkFieldCompressed,
} from "./merge-utils.js";
export { SPP_SUPPORTED_SHAPES, selectSppShape, validateSppShape } from "./shape.js";
export type { Shape } from "./shape.js";
export {
  TRANSACTION_SIZE_LIMIT,
  checkedTransactionSize,
  transactionSize,
} from "./transaction-size.js";

type FixedBytes<Length extends number> = Uint8Array & {
  readonly __fixedBytesLength: Length;
};

export type { Address, Instruction, Signature, Transaction } from "@solana/kit";
export type Bytes16 = FixedBytes<16>;
export type Bytes31 = FixedBytes<31>;
export type Bytes32 = FixedBytes<32>;
export type Bytes33 = FixedBytes<33>;
export type Bytes64 = FixedBytes<64>;
export type Bytes128 = FixedBytes<128>;

export const P256_PROOF_LENGTH = 192;
export {
  MERGE_ENCRYPTED_UTXO_LENGTH,
  MERGE_ENCRYPTED_UTXO_TYPE_PREFIX,
  MERGE_INPUT_COUNT,
} from "./constants.js";
export {
  ADDRESS_TREE_HEIGHT,
  ADDRESS_TREE_INPUT_QUEUE_BATCH_SIZE,
  ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE,
  ADDRESS_TREE_ROOT_HISTORY_CAPACITY,
  FIRST_ASSET_ID,
  FORESTER_REIMBURSEMENT_LAMPORTS,
  foresterFeePerQueueElement,
  STATE_HEIGHT,
  STATE_ROOT_OFFSET,
  StateDiscriminator,
  TREE_ACCOUNT_SIZE,
} from "./state.js";

export interface RequestContext {
  readonly signal?: AbortSignal;
  readonly timeoutMs?: number;
}

export const SHIELDED_POOL_PROGRAM_ID = address("sppzgEd25DF4PC1FgNerLWVZndUAV82LV9Dy5yCvRVA");
export const USER_REGISTRY_PROGRAM_ID = address("EXM6UUA56UJySzRDCx4dKwN6Xdcrkq3kmizqgZwgwNEc");
export const DEFAULT_TREE_ADDRESS = address("treeYbr45LjxovKvtD46uEphM64kwoFFPYhVNw1A8x8");
export const SOL_INTERFACE = encodeBase58(
  Uint8Array.from([
    153, 202, 212, 28, 214, 25, 170, 103, 127, 203, 31, 129, 56, 221, 77, 131, 217, 62, 194, 23,
    222, 98, 111, 179, 160, 182, 255, 213, 208, 236, 115, 61,
  ]),
);
export const SHIELDED_POOL_CPI_AUTHORITY = encodeBase58(
  Uint8Array.from([
    88, 254, 248, 74, 86, 156, 76, 98, 4, 160, 29, 78, 152, 238, 8, 247, 252, 20, 54, 18, 242, 184,
    160, 99, 112, 248, 135, 246, 47, 245, 181, 43,
  ]),
);
export const SPL_TOKEN_PROGRAM_ID = address("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
export const ASSOCIATED_TOKEN_PROGRAM_ID = address("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
export const UTXO_DOMAIN = 1 as const;

export const InstructionTag = Object.freeze({
  transact: 0,
  deposit: 1,
  zoneTransact: 2,
  zoneAuthorityTransact: 3,
  createSplInterface: 4,
  createTree: 5,
  createProtocolConfig: 6,
  updateProtocolConfig: 7,
  pauseTree: 8,
  createZoneConfig: 9,
  updateZoneConfigOwner: 10,
  updateZoneConfig: 11,
  mergeTransact: 12,
  zoneMergeTransact: 13,
  emitEvent: 14,
  zoneDeposit: 15,
  createAssetCounter: 16,
  batchUpdateNullifierTree: 51,
} as const);
export type InstructionTag = (typeof InstructionTag)[keyof typeof InstructionTag];

export interface DepositInstructionData {
  readonly viewTag: Bytes32;
  readonly owner: Bytes32;
  readonly blinding: Bytes31;
  readonly amount: bigint;
  readonly utxoData?: UtxoData;
  readonly memo?: Uint8Array;
}

export interface UtxoData {
  readonly dataHash: Bytes32;
  readonly data: Uint8Array;
}

export interface ZoneDepositInstructionData extends DepositInstructionData {
  readonly zoneDataHash: Bytes32;
  readonly zoneData: Uint8Array;
}

export interface CompressedProof {
  readonly a: Bytes32;
  readonly b: Bytes64;
  readonly c: Bytes32;
}

export interface BatchUpdateNullifierTreeData {
  readonly newRoot: Bytes32;
  readonly oldRoot: Bytes32;
  readonly zkpBatchIndex: number;
  readonly compressedProof: CompressedProof;
}

export interface AddressTreeParams {
  readonly inputQueueBatchSize: bigint;
  readonly inputQueueZkpBatchSize: bigint;
  readonly rootHistoryCapacity: number;
  readonly height: number;
}

export function addressTreeParams(): AddressTreeParams {
  return Object.freeze({
    inputQueueBatchSize: ADDRESS_TREE_INPUT_QUEUE_BATCH_SIZE,
    inputQueueZkpBatchSize: ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE,
    rootHistoryCapacity: ADDRESS_TREE_ROOT_HISTORY_CAPACITY,
    height: ADDRESS_TREE_HEIGHT,
  });
}

export interface DepositSplAccounts {
  readonly userToken: Address;
  readonly splTokenInterface: Address;
  readonly registry: Address;
  readonly tokenProgram: Address;
}

export interface InputUtxo {
  readonly nullifierHash: Bytes32;
  readonly nullifierTreeRootIndex: number;
  readonly utxoTreeRootIndex: number;
  readonly treeIndex: number;
  readonly eddsaSignerIndex: number;
}

export type OwnerTag =
  | Readonly<{ kind: "inline"; value: Bytes32 }>
  | Readonly<{ kind: "account"; index: number }>
  | Readonly<{ kind: "p256SigningKey" }>;

export interface TransactOutput {
  readonly utxoHash: Bytes32;
  readonly ownerTag: OwnerTag;
  readonly data?: Uint8Array;
}

export interface MessageData {
  readonly viewTag: Bytes32;
  readonly data: Uint8Array;
}

export interface OutputUtxo {
  readonly viewTag: Bytes32;
  readonly utxoHash: Bytes32;
  readonly data: Uint8Array;
}

export interface ResolvedOutput {
  readonly utxoHash: Bytes32;
  readonly ownerTag: Bytes32;
  readonly data?: Uint8Array;
}

export type TransactProof =
  | Readonly<{ rail: "eddsa"; a: Bytes32; b: Bytes64; c: Bytes32 }>
  | Readonly<{
      rail: "p256";
      a: Bytes32;
      b: Bytes64;
      c: Bytes32;
      commitment: Bytes32;
      commitmentPok: Bytes32;
    }>;

export interface TransactInstructionData {
  readonly proof: TransactProof;
  readonly expiryUnixTs: bigint;
  readonly relayerFee: number;
  readonly privateTxHash: Bytes32;
  readonly p256SigningPkX?: Bytes32;
  readonly txViewingPk: Bytes33;
  readonly salt: Bytes16;
  readonly inputs: readonly InputUtxo[];
  readonly publicSolAmount?: bigint;
  readonly publicSplAmount?: bigint;
  readonly dataHash?: Bytes32;
  readonly zoneDataHash?: Bytes32;
  readonly outputs: readonly TransactOutput[];
  readonly messages: readonly MessageData[];
}

export type TransactWithdrawal =
  | Readonly<{ kind: "sol"; recipient: Address }>
  | Readonly<{
      kind: "spl";
      cpiAuthority?: Address;
      splTokenInterface: Address;
      recipient: Address;
      userTokenAccount: Address;
      tokenProgram: Address;
    }>;

export interface ProtocolConfigAccount {
  readonly authority: Address;
  readonly treeCreationAuthority: Address;
  readonly treeCreationIsPermissionless: boolean;
  readonly foresterAuthority: Address;
  readonly zoneCreationAuthority: Address;
  readonly zoneCreationIsPermissionless: boolean;
  readonly splInterfaceCreationIsPermissionless: boolean;
}

export interface SplAssetCounterAccount {
  readonly nextId: bigint;
}

export interface SplAssetRegistryAccount {
  readonly mint: Address;
  readonly assetId: bigint;
}

export interface ZoneConfigAccount {
  readonly authority: Address;
  readonly programId: Address;
  readonly zoneAuthorityTransactIsEnabled: boolean;
  readonly bump: number;
}

export interface MergeTransactInstructionData {
  readonly expiryUnixTs: bigint;
  readonly proof: Readonly<{
    a: Bytes32;
    b: Bytes64;
    c: Bytes32;
    commitment: Bytes32;
    commitmentPok: Bytes32;
  }>;
  readonly outputUtxoHash: Bytes32;
  readonly nullifiers: readonly Bytes32[];
  readonly utxoTreeRootIndexes: readonly number[];
  readonly nullifierTreeRootIndexes: readonly number[];
  readonly privateTxHash: Bytes32;
  readonly encryptedUtxo: Uint8Array;
  readonly eddsaOwner: boolean;
}

export interface MergeZoneInstructionData {
  readonly mergeViewTag: Bytes32;
  readonly merge: MergeTransactInstructionData;
}

export interface CreateZoneConfigData {
  readonly programId: Address;
  readonly authority: Address;
  readonly zoneAuthorityTransactIsEnabled: boolean;
}

export interface UpdateZoneConfigOwnerData {
  readonly newAuthority: Address;
}

export interface UpdateZoneConfigData {
  readonly zoneAuthorityTransactIsEnabled: boolean;
}

export function fetchTag(
  tag: OwnerTag,
  p256SigningPkX: Bytes32 | undefined,
  accountAddress: (index: number) => Bytes32 | undefined,
): Bytes32 {
  if (tag.kind === "inline") return tag.value.slice() as Bytes32;
  const value = tag.kind === "account" ? accountAddress(tag.index) : p256SigningPkX;
  if (value === undefined) {
    throw new InterfaceError("INTERFACE_CODEC", {
      reason: tag.kind === "account" ? "owner tag account missing" : "missing P256 signing key",
    });
  }
  return value.slice() as Bytes32;
}

export function decodeProtocolConfig(data: Uint8Array): ProtocolConfigAccount {
  return protocolConfigAccountCodec.decode(data);
}

export function decodeSplAssetCounter(data: Uint8Array): SplAssetCounterAccount {
  return splAssetCounterAccountCodec.decode(data);
}

export function decodeSplAssetRegistry(data: Uint8Array): SplAssetRegistryAccount {
  return splAssetRegistryAccountCodec.decode(data);
}

export function decodeZoneConfig(data: Uint8Array): ZoneConfigAccount {
  return zoneConfigAccountCodec.decode(data);
}
