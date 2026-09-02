import type { ProtocolConfigAccount, SplAssetCounterAccount, SplAssetRegistryAccount, ZoneConfigAccount } from "./types.js";
export declare function decodeProtocolConfig(data: Uint8Array): ProtocolConfigAccount;
export declare function decodeSplAssetCounter(data: Uint8Array): SplAssetCounterAccount;
export declare function decodeSplAssetRegistry(data: Uint8Array): SplAssetRegistryAccount;
export declare function decodeZoneConfig(data: Uint8Array): ZoneConfigAccount;
