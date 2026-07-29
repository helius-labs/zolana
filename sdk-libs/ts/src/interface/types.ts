import type { Address } from "@solana/kit";

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

export interface RequestContext {
  readonly signal?: AbortSignal;
  readonly timeoutMs?: number;
}

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
