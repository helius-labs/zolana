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
    readonly assets: readonly DepositAssetKind[];
    readonly deposits: readonly DepositEntry[];
}
export interface UtxoData {
    readonly dataHash: Bytes32;
    readonly data: Uint8Array;
}
export type DepositAssetKind = Readonly<{
    kind: "sol";
}> | Readonly<{
    kind: "spl";
    vaultBump: number;
}>;
export interface DepositEntry {
    readonly assetIndex: number;
    readonly viewTag: Bytes32;
    readonly owner: Bytes32;
    readonly blinding: Bytes32;
    readonly amount: bigint;
    readonly utxoData?: UtxoData;
    readonly memo?: Uint8Array;
}
export interface DepositSplAccounts {
    readonly mint: Address;
    readonly userToken: Address;
    readonly tokenProgram: Address;
}
export type DepositAsset = Readonly<{
    kind: "sol";
}> | Readonly<{
    kind: "spl";
    accounts: DepositSplAccounts;
}>;
export interface AssetDeposit extends Omit<DepositEntry, "assetIndex"> {
    readonly asset: DepositAsset;
}
export interface InputUtxo {
    readonly nullifierHash: Bytes32;
    readonly nullifierTreeRootIndex: number;
    readonly utxoTreeRootIndex: number;
}
export type OwnerTag = Readonly<{
    kind: "inline";
    value: Bytes32;
}> | Readonly<{
    kind: "account";
    index: number;
}>;
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
export type CircuitId = Readonly<{
    kind: "confidentialEddsa";
    inputs: number;
    outputs: number;
    publicAssetSlots: number;
}> | Readonly<{
    kind: "zoneEddsa";
    inputs: number;
    outputs: number;
    publicAssetSlots: number;
}> | Readonly<{
    kind: "zoneAuthority";
    inputs: number;
    outputs: number;
    publicAssetSlots: number;
}>;
export type InterfaceTransfer = Readonly<{
    kind: "solDeposit";
    amount: bigint;
}> | Readonly<{
    kind: "solWithdrawal";
    amount: bigint;
}> | Readonly<{
    kind: "splDeposit";
    amount: bigint;
    vaultBump: number;
}> | Readonly<{
    kind: "splWithdrawal";
    amount: bigint;
    vaultBump: number;
}>;
export type ResolvedInterfaceTransfer = Readonly<{
    kind: "solDeposit";
    amount: bigint;
    recipient: Address;
}> | Readonly<{
    kind: "solWithdrawal";
    amount: bigint;
    recipient: Address;
}> | Readonly<{
    kind: "splDeposit";
    amount: bigint;
    userTokenAccount: Address;
    vault: Address;
}> | Readonly<{
    kind: "splWithdrawal";
    amount: bigint;
    userTokenAccount: Address;
    vault: Address;
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
export type TransactWithdrawal = Readonly<{
    kind: "sol";
    recipient: Address;
}> | Readonly<{
    kind: "spl";
    mint: Address;
    splTokenInterface: Address;
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
    }>;
    readonly outputUtxoHash: Bytes32;
    readonly eddsaOwner: boolean;
    readonly privateTxHash: Bytes32;
    readonly nullifiers: readonly Bytes32[];
    readonly utxoTreeRootIndexes: readonly number[];
    readonly nullifierTreeRootIndexes: readonly number[];
}
