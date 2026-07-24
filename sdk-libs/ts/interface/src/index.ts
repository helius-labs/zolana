import { encodeBase58 } from "./internal.js";
import {
  protocolConfigAccountCodec,
  splAssetCounterAccountCodec,
  splAssetRegistryAccountCodec,
  zoneConfigAccountCodec,
} from "./codecs/index.js";

export { InterfaceError } from "./errors.js";
export type { InterfaceErrorCode } from "./errors.js";

type FixedBytes<Length extends number> = Uint8Array & {
  readonly __fixedBytesLength: Length;
};

export type Address = string & { readonly __address: unique symbol };
export type Signature = string & { readonly __signature: unique symbol };
export type Bytes16 = FixedBytes<16>;
export type Bytes31 = FixedBytes<31>;
export type Bytes32 = FixedBytes<32>;
export type Bytes33 = FixedBytes<33>;
export type Bytes64 = FixedBytes<64>;
export type Bytes128 = FixedBytes<128>;

export type Transaction = Readonly<{
  messageBytes: Uint8Array;
  signatures: readonly (Signature | undefined)[];
}>;

export type Instruction = Readonly<{
  programAddress: Address;
  accounts: readonly Readonly<{
    address: Address;
    isSigner: boolean;
    isWritable: boolean;
  }>[];
  data: Uint8Array;
}>;

export interface RequestContext {
  readonly signal?: AbortSignal;
  readonly timeoutMs?: number;
}

export const SHIELDED_POOL_PROGRAM_ID = "sppzgEd25DF4PC1FgNerLWVZndUAV82LV9Dy5yCvRVA" as Address;
export const DEFAULT_TREE_ADDRESS = "treeYbr45LjxovKvtD46uEphM64kwoFFPYhVNw1A8x8" as Address;
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
export const SPL_TOKEN_PROGRAM_ID = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" as Address;
export const ASSOCIATED_TOKEN_PROGRAM_ID =
  "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL" as Address;
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
  readonly utxoData?: Readonly<{ dataHash: Bytes32; data: Uint8Array }>;
  readonly memo?: Uint8Array;
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
  readonly messages: readonly Readonly<{ viewTag: Bytes32; data: Uint8Array }>[];
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

export type ShieldedPoolErrorCode =
  | 7000
  | 7001
  | 7002
  | 7003
  | 7004
  | 7005
  | 7006
  | 7007
  | 7008
  | 7009
  | 7010
  | 7011
  | 7012
  | 7013
  | 7014
  | 7015
  | 7016
  | 7017
  | 7018
  | 7019
  | 7020
  | 7021
  | 7022
  | 7023
  | 7024
  | 7025;

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
