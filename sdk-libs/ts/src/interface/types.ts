import type { Address, TransactionSigner } from "@solana/kit";

type FixedBytes<Length extends number> = Uint8Array & {
  readonly __fixedBytesLength: Length;
};

export type { Address, Instruction, Signature, Transaction } from "@solana/kit";
export type SignerAccount = Address | TransactionSigner;
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
  readonly assets: readonly DepositAssetKind[];
  readonly deposits: readonly DepositEntry[];
}

export interface UtxoData {
  readonly dataHash: Bytes32;
  readonly data: Uint8Array;
}

export type DepositAssetKind =
  | Readonly<{ kind: "sol" }>
  | Readonly<{ kind: "spl"; splInterfaceBump: number }>;

export interface DepositEntry {
  readonly assetIndex: number;
  readonly viewTag: Bytes32;
  readonly recipientOwnerHash: Bytes32;
  readonly blinding: Bytes32;
  readonly amount: bigint;
  readonly utxoData?: UtxoData;
  readonly memo?: Uint8Array;
}

export interface DepositSplAccounts {
  readonly mint: Address;
  readonly sourceTokenAccount: Address;
  readonly tokenProgram: Address;
}

export type DepositAsset =
  | Readonly<{ kind: "sol" }>
  | Readonly<{ kind: "spl"; accounts: DepositSplAccounts }>;

export const DepositAsset = Object.freeze({
  sol(): Extract<DepositAsset, { kind: "sol" }> {
    return Object.freeze({ kind: "sol" });
  },
  spl(accounts: DepositSplAccounts): Extract<DepositAsset, { kind: "spl" }> {
    return Object.freeze({
      kind: "spl",
      accounts: Object.freeze({ ...accounts }),
    });
  },
});

export interface AssetDeposit extends Omit<DepositEntry, "assetIndex"> {
  readonly asset: DepositAsset;
}

export interface ZoneAssetDeposit {
  readonly deposit: AssetDeposit;
  readonly zoneDataHash: Bytes32;
  readonly zoneData: Uint8Array;
}

export interface ZoneDepositInstructionData {
  readonly assets: readonly DepositAssetKind[];
  readonly deposits: readonly Readonly<{
    readonly deposit: DepositEntry;
    readonly zoneDataHash: Bytes32;
    readonly zoneData: Uint8Array;
  }>[];
}

export interface InputUtxo {
  readonly nullifierHash: Bytes32;
  readonly nullifierTreeRootIndex: number;
  readonly utxoTreeRootIndex: number;
}

export type OwnerTag =
  | Readonly<{ kind: "inline"; value: Bytes32 }>
  | Readonly<{ kind: "account"; index: number }>;

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

export interface TransactProof {
  readonly a: Bytes32;
  readonly b: Bytes64;
  readonly c: Bytes32;
}

export type CircuitId =
  | Readonly<{
      kind: "confidentialEddsa";
      inputs: number;
      outputs: number;
      publicAssetSlots: number;
    }>
  | Readonly<{
      kind: "zoneEddsa";
      inputs: number;
      outputs: number;
      publicAssetSlots: number;
    }>
  | Readonly<{
      kind: "zoneAuthority";
      inputs: number;
      outputs: number;
      publicAssetSlots: number;
    }>;

export type InterfaceTransfer =
  | Readonly<{ kind: "solDeposit"; amount: bigint }>
  | Readonly<{ kind: "solWithdrawal"; amount: bigint }>
  | Readonly<{ kind: "splDeposit"; amount: bigint; splInterfaceBump: number }>
  | Readonly<{ kind: "splWithdrawal"; amount: bigint; splInterfaceBump: number }>;

export type ResolvedInterfaceTransfer =
  | Readonly<{ kind: "solDeposit"; amount: bigint; recipient: Address }>
  | Readonly<{ kind: "solWithdrawal"; amount: bigint; recipient: Address }>
  | Readonly<{
      kind: "splDeposit";
      amount: bigint;
      sourceTokenAccount: Address;
      splInterfacePda: Address;
    }>
  | Readonly<{
      kind: "splWithdrawal";
      amount: bigint;
      recipientTokenAccount: Address;
      splInterfacePda: Address;
    }>;

export interface TransactInstructionData {
  readonly expiryUnixTs: bigint;
  readonly privateTxHash: Bytes32;
  readonly circuit: CircuitId;
  readonly txViewingPk: Bytes33;
  readonly salt: Bytes16;
  readonly proof: TransactProof;
  readonly inputs: readonly InputUtxo[];
  readonly interfaceTransfers: readonly InterfaceTransfer[];
  readonly dataHash?: Bytes32;
  readonly zoneDataHash?: Bytes32;
  readonly outputs: readonly TransactOutput[];
  readonly messages: readonly MessageData[];
}

export type TransactWithdrawal =
  | Readonly<{ kind: "sol"; recipient: Address }>
  | Readonly<{
      kind: "spl";
      mint: Address;
      splTokenInterface: Address;
      recipientTokenAccount: Address;
      tokenProgram: Address;
    }>;

/// Typed constructors for the settlement accounts a withdrawal needs. The
/// variants are reached through these rather than a `kind` literal so a caller
/// cannot pair a SOL recipient with SPL token accounts.
export const TransactWithdrawal = Object.freeze({
  sol(input: Readonly<{ recipient: Address }>): Extract<TransactWithdrawal, { kind: "sol" }> {
    return Object.freeze({ ...input, kind: "sol" });
  },
  spl(
    input: Readonly<{
      mint: Address;
      splTokenInterface: Address;
      recipientTokenAccount: Address;
      tokenProgram: Address;
    }>,
  ): Extract<TransactWithdrawal, { kind: "spl" }> {
    return Object.freeze({ ...input, kind: "spl" });
  },
});

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
  }>;
  readonly outputUtxoHash: Bytes32;
  readonly eddsaOwner: boolean;
  readonly privateTxHash: Bytes32;
  readonly nullifiers: readonly Bytes32[];
  readonly utxoTreeRootIndexes: readonly number[];
  readonly nullifierTreeRootIndexes: readonly number[];
}

export interface MergeZoneInstructionData {
  readonly outputZoneDataHash: Bytes32;
  readonly merge: MergeTransactInstructionData;
}

export interface BatchUpdateNullifierTreeInstructionData {
  readonly newRoot: Bytes32;
  readonly oldRoot: Bytes32;
  readonly zkpBatchIndex: number;
  readonly compressedProof: Readonly<{
    readonly a: Bytes32;
    readonly b: Bytes64;
    readonly c: Bytes32;
  }>;
}
