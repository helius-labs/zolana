import type { Bytes16, Bytes32, Bytes33, MessageData, ResolvedInterfaceTransfer, ResolvedOutput } from "./types.js";
export interface ExternalDataHashInput {
    readonly instructionDiscriminator: number;
    readonly expiryUnixTs: bigint;
    readonly interfaceTransfers: readonly ResolvedInterfaceTransfer[];
    readonly dataHash?: Bytes32;
    readonly zoneDataHash?: Bytes32;
    readonly txViewingPk: Bytes33;
    readonly salt: Bytes16;
    readonly outputs: readonly ResolvedOutput[];
    readonly messages: readonly MessageData[];
}
export declare function externalDataHash(input: ExternalDataHashInput): Bytes32;
