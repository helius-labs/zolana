import { PublicKey as SolanaPublicKey } from "@solana/web3.js";
import { describe, expect, it } from "vitest";
import {
  AssetRegistry,
  Data,
  NullifierKey,
  PublicKey,
  SOL_ASSET_ID,
  SOL_MINT,
  Utxo,
  deriveBlinding,
  ownerUtxoHash,
  utxoHash,
} from "../src/index.js";

describe("transaction data and utxos", () => {
  it("serializes data records with wincode-compatible tags and lengths", () => {
    const data = new Data([
      { kind: "zoneData", data: new Uint8Array([9, 9]) },
      { kind: "utxoData", data: new Uint8Array([1]) },
      { kind: "memo", data: new TextEncoder().encode("gm") },
    ]);

    expect([...data.serialize()]).toEqual([
      3,
      1, 2, 0, 9, 9,
      2, 1, 0, 1,
      3, 2, 0, 103, 109,
    ]);
    expect(data.memo()).toEqual(new TextEncoder().encode("gm"));
  });

  it("rejects duplicate or non-canonical records", () => {
    expect(() => new Data([
      { kind: "memo", data: new Uint8Array([1]) },
      { kind: "zoneData", data: new Uint8Array([2]) },
    ])).toThrow(/non-canonical/);
    expect(() => new Data([
      { kind: "memo", data: new Uint8Array([1]) },
      { kind: "memo", data: new Uint8Array([2]) },
    ])).toThrow(/duplicate/);
  });

  it("derives blindings and utxo hashes deterministically", () => {
    const seed = new Uint8Array(31).fill(1);
    expect(deriveBlinding(seed, 0)).toHaveLength(31);
    expect(deriveBlinding(seed, 0)).toEqual(deriveBlinding(seed, 0));
    expect(deriveBlinding(seed, 0)).not.toEqual(deriveBlinding(seed, 1));

    const owner = new Uint8Array(32).fill(2);
    const blinding = new Uint8Array(31).fill(3);
    const ownerHash = ownerUtxoHash(owner, blinding);
    const hash = utxoHash({
      asset: SOL_MINT,
      amount: 5n,
      dataHash: new Uint8Array(32),
      zoneDataHash: new Uint8Array(32),
      ownerUtxoHash: ownerHash,
    });
    expect(hash).toHaveLength(32);
    expect(hash).toEqual(utxoHash({
      asset: SOL_MINT,
      amount: 5n,
      dataHash: new Uint8Array(32),
      zoneDataHash: new Uint8Array(32),
      ownerUtxoHash: ownerHash,
    }));
  });

  it("builds wallet utxos and asset registries", () => {
    const owner = PublicKey.fromEd25519(new Uint8Array(32).fill(4));
    const nullifier = new NullifierKey(new Uint8Array(31).fill(5));
    const utxo = new Utxo({
      owner,
      asset: SOL_MINT,
      amount: 10n,
      blinding: new Uint8Array(31).fill(6),
    });
    const hash = utxo.hash(nullifier.pubkey());

    expect(hash).toHaveLength(32);
    expect(utxo.nullifier(hash, nullifier)).toHaveLength(32);
    expect(new AssetRegistry().assetId(SOL_MINT)).toBe(SOL_ASSET_ID);

    const mint = SolanaPublicKey.unique();
    const registry = new AssetRegistry([[2, mint]]);
    expect(registry.assetId(mint)).toBe(2);
  });
});
