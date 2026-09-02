import { address, type Address } from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import { SPL_TOKEN_2022_PROGRAM_ID, SPL_TOKEN_PROGRAM_ID } from "../src/interface/program.js";
import { SOL_MINT } from "../src/transaction/asset.js";
import { AssetMetadataCache, fetchAssetMetadata } from "../src/wallet/asset-metadata.js";

const MINT = address("So11111111111111111111111111111111111111112");

function mintAccount(decimals: number, owner: Address = SPL_TOKEN_PROGRAM_ID, extensionBytes = 0) {
  const data = new Uint8Array(82 + extensionBytes);
  data[44] = decimals;
  data[45] = 1;
  return { owner, data, lamports: 1n };
}

describe("asset metadata", () => {
  it("returns fixed SOL metadata without an RPC read", async () => {
    const getAccount = vi.fn();
    await expect(fetchAssetMetadata({ getAccount }, SOL_MINT)).resolves.toEqual({
      mint: SOL_MINT,
      decimals: 9,
    });
    expect(getAccount).not.toHaveBeenCalled();
  });

  it("decodes classic and Token-2022 mint decimals", async () => {
    await expect(
      fetchAssetMetadata({ getAccount: async () => mintAccount(6) }, MINT),
    ).resolves.toEqual({ mint: MINT, decimals: 6 });
    await expect(
      fetchAssetMetadata(
        { getAccount: async () => mintAccount(8, SPL_TOKEN_2022_PROGRAM_ID, 32) },
        MINT,
      ),
    ).resolves.toEqual({ mint: MINT, decimals: 8 });
  });

  it("rejects missing, foreign, and malformed mint accounts", async () => {
    await expect(
      fetchAssetMetadata({ getAccount: async () => undefined }, MINT),
    ).rejects.toMatchObject({ code: "WALLET_ASSET_METADATA", details: { reason: "missing" } });
    await expect(
      fetchAssetMetadata(
        { getAccount: async () => mintAccount(6, address("11111111111111111111111111111111")) },
        MINT,
      ),
    ).rejects.toMatchObject({ code: "WALLET_ASSET_METADATA", details: { reason: "owner" } });
    await expect(
      fetchAssetMetadata(
        {
          getAccount: async () => ({
            owner: SPL_TOKEN_PROGRAM_ID,
            data: new Uint8Array(81),
            lamports: 1n,
          }),
        },
        MINT,
      ),
    ).rejects.toMatchObject({ code: "WALLET_ASSET_METADATA", details: { reason: "data" } });
  });

  it("caches successful reads and retries failures", async () => {
    const getAccount = vi
      .fn()
      .mockRejectedValueOnce(new Error("offline"))
      .mockResolvedValue(mintAccount(6));
    const cache = new AssetMetadataCache({ getAccount });

    await expect(cache.get(MINT)).rejects.toMatchObject({
      code: "WALLET_ASSET_METADATA",
      details: { reason: "fetch" },
    });
    await expect(cache.get(MINT)).resolves.toEqual({ mint: MINT, decimals: 6 });
    await expect(cache.get(MINT)).resolves.toEqual({ mint: MINT, decimals: 6 });
    expect(getAccount).toHaveBeenCalledTimes(2);
  });
});
