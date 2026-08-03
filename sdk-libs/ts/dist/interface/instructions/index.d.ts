import { type Instruction, type TransactionSigner } from "@solana/kit";
import type { AddressTreeParams } from "../program.js";
import { type Address, type AssetDeposit, type MergeTransactInstructionData, type TransactInstructionData, type TransactWithdrawal } from "../types.js";
export type { MergeTransactInstructionData } from "../types.js";
export type SignerAccount = Address | TransactionSigner;
export declare function createAssetCounterInstruction(input: Readonly<{
    authority: SignerAccount;
}>): Promise<Instruction>;
export declare function createAssociatedTokenAccountInstruction(input: Readonly<{
    payer: SignerAccount;
    owner: Address;
    mint: Address;
    tokenProgram?: Address | null;
}>): Promise<Instruction>;
export declare function createSplInterfaceInstruction(input: Readonly<{
    authority: SignerAccount;
    mint: Address;
    tokenProgram?: Address | null;
}>): Promise<Instruction>;
export declare function createTreeInstruction(input: Readonly<{
    authority: SignerAccount;
    tree: Address;
    nullifierTreeParams?: AddressTreeParams;
}>): Promise<Instruction>;
export declare function depositInstruction(input: Readonly<{
    tree: Address;
    depositor: SignerAccount;
    deposits: readonly AssetDeposit[];
}>): Promise<Instruction>;
export declare function transactInstruction(input: Readonly<{
    payer: SignerAccount;
    inputTree: Address;
    outputTree: Address;
    withdrawal?: TransactWithdrawal;
    data: TransactInstructionData;
}>): Instruction;
export declare function createProtocolConfigInstruction(input: Readonly<{
    authority: SignerAccount;
    protocolAuthority: Address;
    treeCreationAuthority: Address;
    treeCreationIsPermissionless: boolean;
    foresterAuthority: Address;
    zoneCreationAuthority: Address;
    zoneCreationIsPermissionless: boolean;
    splInterfaceCreationIsPermissionless: boolean;
}>): Promise<Instruction>;
export type ProtocolConfigUpdate = Readonly<{
    field: "protocolAuthority";
    value: SignerAccount;
}> | Readonly<{
    field: "treeCreationAuthority";
    value: Address;
}> | Readonly<{
    field: "foresterAuthority";
    value: Address;
}> | Readonly<{
    field: "zoneCreationAuthority";
    value: Address;
}> | Readonly<{
    field: "treeCreationPermissionless";
    value: boolean;
}> | Readonly<{
    field: "zoneCreationPermissionless";
    value: boolean;
}> | Readonly<{
    field: "splInterfaceCreationPermissionless";
    value: boolean;
}>;
export declare function updateProtocolConfigInstruction(input: Readonly<{
    authority: SignerAccount;
    update: ProtocolConfigUpdate;
}>): Promise<Instruction>;
export declare function pauseTreeInstruction(input: Readonly<{
    authority: SignerAccount;
    tree: Address;
    paused: boolean;
}>): Promise<Instruction>;
export declare function mergeTransactInstruction(input: Readonly<{
    inputTree: Address;
    outputTree: Address;
    payer: SignerAccount;
    userRecord: Address;
    data: MergeTransactInstructionData;
}>): Instruction;
