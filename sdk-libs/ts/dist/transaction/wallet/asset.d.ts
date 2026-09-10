import type { Address, Bytes32 } from "../../interface/types.js";
export declare const SOL_ASSET_ID = 1n;
export declare const SOL_MINT: Address<"11111111111111111111111111111111">;
export declare class AssetRegistry {
    #private;
    constructor(entries?: readonly (readonly [bigint, Address])[]);
    insert(assetId: bigint, mint: Address): void;
    resolve(assetId: bigint): Address;
    assetId(mint: Address): bigint;
    addressForField(field: Bytes32): Address | undefined;
    entries(): readonly (readonly [bigint, Address])[];
    clone(): AssetRegistry;
}
export declare function addressForAssetField(registry: AssetRegistry, field: Bytes32): Address | undefined;
