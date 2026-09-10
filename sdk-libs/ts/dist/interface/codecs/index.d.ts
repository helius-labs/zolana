import type { Bytes32, DepositInstructionData, MergeTransactInstructionData, ProtocolConfigAccount, SplAssetCounterAccount, SplAssetRegistryAccount, TransactInstructionData, ZoneConfigAccount } from "../types.js";
import type { AddressTreeParams } from "../program.js";
export declare function encodeDepositInstructionData(value: DepositInstructionData): Uint8Array;
export declare function encodeAddressTreeParams(value: AddressTreeParams): Uint8Array;
export declare function encodeTransactInstructionData(value: TransactInstructionData): Uint8Array;
export declare function encodeMergeTransactInstructionData(value: MergeTransactInstructionData): Uint8Array;
export declare function mergeExternalDataHash(input: Readonly<{
    instructionTag: number;
    expiryUnixTs: bigint;
    outputUtxoHash: Bytes32;
}>): Bytes32;
export declare function decodeProtocolConfigAccount(bytes: Uint8Array): ProtocolConfigAccount;
export declare function decodeSplAssetCounterAccount(bytes: Uint8Array): SplAssetCounterAccount;
export declare function decodeSplAssetRegistryAccount(bytes: Uint8Array): SplAssetRegistryAccount;
export declare function decodeZoneConfigAccount(bytes: Uint8Array): ZoneConfigAccount;
