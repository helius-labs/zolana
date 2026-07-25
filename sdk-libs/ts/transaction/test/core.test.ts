import type { Address, Bytes31, Bytes32 } from "@zolana/interface";
import {
  NullifierKey,
  ShieldedKeypair,
  ShieldedPublicKey,
  SigningKey,
  ViewingKey,
} from "@zolana/keypair";
import { describe, expect, it } from "vitest";

import {
  AssetRegistry,
  Data,
  ProofInputUtxo,
  SOL_MINT,
  TRANSACTION_ERROR_CODES,
  TransactionError,
  Utxo,
  Wallet,
  canonicalShape,
  deriveBlinding,
  ownerUtxoHash,
  resolveShape,
  unknownTransactionError,
} from "../src/index.js";
import { encodeData } from "../src/serialization/index.js";

function scalar(value: number): Bytes32 {
  const bytes = new Uint8Array(32);
  bytes[31] = value;
  return bytes as Bytes32;
}

function keyMaterial(): Readonly<{
  keypair: ShieldedKeypair;
  nullifier: NullifierKey;
}> {
  const signing = SigningKey.fromBytes(scalar(1));
  const nullifier = NullifierKey.fromSecret(new Uint8Array(31).fill(7) as Bytes31);
  const viewing = ViewingKey.fromBytes(scalar(2));
  return {
    keypair: ShieldedKeypair.fromKeys(signing, nullifier, viewing),
    nullifier,
  };
}

describe("transaction core", () => {
  it("copies and validates canonical data records", () => {
    const memo = Uint8Array.of(4);
    const data = new Data([{ kind: "memo", bytes: memo }]);
    memo[0] = 9;
    expect(data.memo()).toEqual(Uint8Array.of(4));

    expect(
      () =>
        new Data([
          { kind: "memo", bytes: Uint8Array.of(1) },
          { kind: "memo", bytes: Uint8Array.of(2) },
        ]),
    ).toThrow(expect.objectContaining({ code: "TRANSACTION_DUPLICATE_DATA_RECORD" }));
    expect(
      () =>
        new Data([
          { kind: "memo", bytes: Uint8Array.of(1) },
          { kind: "zoneData", bytes: Uint8Array.of(2) },
        ]),
    ).toThrow(expect.objectContaining({ code: "TRANSACTION_NON_CANONICAL_DATA_ORDER" }));

    expect(() => new Data([{ kind: "invalid", bytes: Uint8Array.of(1) }] as never)).toThrow(
      expect.objectContaining({ code: "TRANSACTION_BAD_DISCRIMINATOR" }),
    );
    const oversized = new Data([{ kind: "memo", bytes: new Uint8Array(0x1_0000) }]);
    expect(() => encodeData(oversized)).toThrow(
      expect.objectContaining({ code: "TRANSACTION_SERIALIZE" }),
    );
  });

  it("matches the P00 canonical shape and rejects unsupported declarations", () => {
    expect(canonicalShape(2, 3)).toEqual({ inputs: 2, outputs: 3 });
    expect(resolveShape(1, 1, { inputs: 2, outputs: 2 })).toEqual({
      inputs: 2,
      outputs: 2,
    });
    expect(() => resolveShape(3, 1, { inputs: 2, outputs: 2 })).toThrow(
      expect.objectContaining({ code: "TRANSACTION_TOO_MANY_INPUTS" }),
    );
    expect(() => resolveShape(1, 3, { inputs: 2, outputs: 2 })).toThrow(
      expect.objectContaining({ code: "TRANSACTION_TOO_MANY_OUTPUTS_FOR_SHAPE" }),
    );
    expect(() => resolveShape(1, 1, null as never)).toThrow(
      expect.objectContaining({ code: "TRANSACTION_UNSUPPORTED_SHAPE" }),
    );
    expect(() => canonicalShape(99, 99)).toThrow(
      expect.objectContaining({ code: "TRANSACTION_UNSUPPORTED_SHAPE" }),
    );
  });

  it("binds UTXO hashes and nullifiers to every committed input", () => {
    const { keypair, nullifier } = keyMaterial();
    const base = new Utxo({
      owner: keypair.signingPublicKey(),
      asset: SOL_MINT,
      amount: 42n,
      blinding: new Uint8Array(31).fill(3) as Bytes31,
      zoneProgramId: "SysvarRent111111111111111111111111111111111" as Address,
    });
    const dataHash = scalar(4);
    const zoneHash = scalar(5);
    const hash = base.hash(scalar(6), dataHash, zoneHash);
    expect(base.hash(scalar(6), dataHash, zoneHash)).toEqual(hash);
    expect(base.hash(scalar(6), scalar(7), zoneHash)).not.toEqual(hash);
    expect(base.hash(scalar(8), dataHash, zoneHash)).not.toEqual(hash);
    expect(base.nullifier(hash, nullifier)).not.toEqual(base.nullifier(scalar(9), nullifier));

    const proof = new ProofInputUtxo({
      utxo: base,
      nullifierKey: nullifier,
      dataHash,
      zoneDataHash: zoneHash,
    });
    expect(proof.hash()).toEqual(base.hash(nullifier.publicKey(), dataHash, zoneHash));
    expect(ProofInputUtxo.dummy().isDummy()).toBe(true);
    expect(
      () =>
        new ProofInputUtxo({
          utxo: new Utxo({
            owner: ShieldedPublicKey.zeroed(),
            asset: "SysvarRent111111111111111111111111111111111" as Address,
            amount: 0n,
            blinding: new Uint8Array(31) as Bytes31,
          }),
          nullifierKey: NullifierKey.fromSecret(new Uint8Array(31) as Bytes31),
        }),
    ).toThrow(expect.objectContaining({ code: "TRANSACTION_DUMMY_INPUT_NOT_ALLOWED" }));
  });

  it("derives position-specific blindings and validates their range", () => {
    const seed = new Uint8Array(31).fill(9) as Bytes31;
    expect(deriveBlinding(seed, 0)).not.toEqual(deriveBlinding(seed, 1));
    expect(deriveBlinding(seed, 0)).toEqual(deriveBlinding(seed, 0));
    expect(() => deriveBlinding(seed, 256)).toThrow(
      expect.objectContaining({ code: "TRANSACTION_INVALID_POSITION" }),
    );
    expect(ownerUtxoHash(scalar(1), seed)).toHaveLength(32);
  });

  it("enforces asset uniqueness and computes wallet balance snapshots", () => {
    const mint = "SysvarRent111111111111111111111111111111111" as Address;
    const registry = new AssetRegistry([[2n, mint]]);
    expect(registry.resolve(2n)).toBe(mint);
    expect(registry.assetId(mint)).toBe(2n);
    expect(() => {
      registry.insert(0n, mint);
    }).toThrow(expect.objectContaining({ code: "TRANSACTION_RESERVED_ASSET_ID" }));
    expect(() => {
      registry.insert(2n, "Vote111111111111111111111111111111111111111" as Address);
    }).toThrow(expect.objectContaining({ code: "TRANSACTION_DUPLICATE_ASSET_ID" }));

    const { keypair } = keyMaterial();
    const wallet = new Wallet({ identity: keypair.shieldedAddress(), registry });
    const laterMint = "Vote111111111111111111111111111111111111111" as Address;
    registry.insert(3n, laterMint);
    expect(() => wallet.registry.resolve(3n)).toThrow(
      expect.objectContaining({ code: "TRANSACTION_UNKNOWN_ASSET" }),
    );
    const registrySnapshot = wallet.registry;
    registrySnapshot.insert(4n, laterMint);
    expect(() => wallet.registry.resolve(4n)).toThrow(
      expect.objectContaining({ code: "TRANSACTION_UNKNOWN_ASSET" }),
    );
    expect(wallet.balances()).toEqual([]);
    expect(wallet.balance(SOL_MINT)).toBeUndefined();
    expect(
      () =>
        new Utxo({
          owner: keypair.signingPublicKey(),
          asset: SOL_MINT,
          amount: -1n,
          blinding: new Uint8Array(31) as Bytes31,
        }),
    ).toThrow(TransactionError);
  });

  it("keeps transaction diagnostics closed and redacted", () => {
    expect(TRANSACTION_ERROR_CODES).toContain("TRANSACTION_UNKNOWN_VARIANT");
    const error = unknownTransactionError("FutureVariant", {
      index: 2,
      secretKey: "hidden",
      payload: { value: 7, nonce: "hidden" },
    });
    expect(error.details).toEqual({
      variant: "FutureVariant",
      payload: { index: 2, payload: { value: 7 } },
    });
    expect(JSON.stringify(error)).not.toContain("hidden");
  });
});
