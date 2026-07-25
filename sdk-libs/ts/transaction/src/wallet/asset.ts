import type { Address, Bytes32 } from "@zolana/interface";

import { TransactionError } from "../error.js";
import { checked, decodeAddress, equal, hashField } from "../internal.js";

export const SOL_ASSET_ID = 1n;
export const SOL_MINT = "11111111111111111111111111111111" as Address;

export class AssetRegistry {
  readonly #byId = new Map<bigint, Address>([[SOL_ASSET_ID, SOL_MINT]]);
  readonly #byMint = new Map<Address, bigint>([[SOL_MINT, SOL_ASSET_ID]]);

  constructor(entries: readonly (readonly [bigint, Address])[] = []) {
    for (const [assetId, mint] of entries) this.insert(assetId, mint);
  }

  insert(assetId: bigint, mint: Address): void {
    if (typeof assetId !== "bigint" || assetId < 0n || assetId > 0xffff_ffff_ffff_ffffn) {
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

  resolve(assetId: bigint): Address {
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

  assetId(mint: Address): bigint {
    decodeAddress(mint);
    const assetId = this.#byMint.get(mint);
    if (assetId === undefined) throw new TransactionError("TRANSACTION_UNKNOWN_MINT", { mint });
    return assetId;
  }

  addressForField(field: Bytes32): Address | undefined {
    return addressForAssetField(this, field);
  }

  entries(): readonly (readonly [bigint, Address])[] {
    return [...this.#byId.entries()].map(([id, mint]) => Object.freeze([id, mint] as const));
  }

  clone(): AssetRegistry {
    return new AssetRegistry(this.entries().filter(([assetId]) => assetId !== SOL_ASSET_ID));
  }
}

export function addressForAssetField(registry: AssetRegistry, field: Bytes32): Address | undefined {
  const expected = checked<Bytes32>(field, 32, "asset field");
  for (const [, mint] of registry.entries()) {
    if (equal(hashField(decodeAddress(mint)), expected)) return mint;
  }
  return undefined;
}
