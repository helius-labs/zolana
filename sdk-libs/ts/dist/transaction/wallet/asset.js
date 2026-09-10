import { address } from "@solana/kit";
import { TransactionError } from "../error.js";
import { checked, decodeAddress, equal, hashField } from "../internal.js";
export const SOL_ASSET_ID = 1n;
export const SOL_MINT = address("11111111111111111111111111111111");
export class AssetRegistry {
    #byId = new Map([[SOL_ASSET_ID, SOL_MINT]]);
    #byMint = new Map([[SOL_MINT, SOL_ASSET_ID]]);
    constructor(entries = []) {
        for (const [assetId, mint] of entries)
            this.insert(assetId, mint);
    }
    insert(assetId, mint) {
        if (typeof assetId !== "bigint" || assetId < 0n || assetId > 0xffffffffffffffffn) {
            throw new TransactionError("TRANSACTION_INVALID_ASSET_ID", {
                assetId: String(assetId),
            });
        }
        decodeAddress(mint);
        if (assetId <= SOL_ASSET_ID) {
            throw new TransactionError("TRANSACTION_RESERVED_ASSET_ID", {
                assetId: assetId.toString(),
            });
        }
        if (this.#byId.has(assetId)) {
            throw new TransactionError("TRANSACTION_DUPLICATE_ASSET_ID", {
                assetId: assetId.toString(),
            });
        }
        if (this.#byMint.has(mint)) {
            throw new TransactionError("TRANSACTION_DUPLICATE_MINT", { mint });
        }
        this.#byId.set(assetId, mint);
        this.#byMint.set(mint, assetId);
    }
    resolve(assetId) {
        if (typeof assetId !== "bigint") {
            throw new TransactionError("TRANSACTION_INVALID_ASSET_ID", { assetId: String(assetId) });
        }
        const mint = this.#byId.get(assetId);
        if (!mint) {
            throw new TransactionError("TRANSACTION_UNKNOWN_ASSET", {
                assetId: assetId.toString(),
            });
        }
        return mint;
    }
    assetId(mint) {
        decodeAddress(mint);
        const assetId = this.#byMint.get(mint);
        if (assetId === undefined)
            throw new TransactionError("TRANSACTION_UNKNOWN_MINT", { mint });
        return assetId;
    }
    addressForField(field) {
        return addressForAssetField(this, field);
    }
    entries() {
        return [...this.#byId.entries()].map(([id, mint]) => Object.freeze([id, mint]));
    }
    clone() {
        return new AssetRegistry(this.entries().filter(([assetId]) => assetId !== SOL_ASSET_ID));
    }
}
export function addressForAssetField(registry, field) {
    const expected = checked(field, 32, "asset field");
    for (const [, mint] of registry.entries()) {
        if (equal(hashField(decodeAddress(mint)), expected))
            return mint;
    }
    return undefined;
}
