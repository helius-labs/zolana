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

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

// Pinned from `SppProofInputUtxo::new_dummy` with a `[7u8; 31]` blinding; the
// same two digests are asserted in `sdk-libs/transaction/src/instructions/types.rs`.
const DUMMY_ORACLE_HASH = "0497a9bf5848d01c8b5fc1f75603964e63c0e268a206f182e204152de2b7403c";
const DUMMY_ORACLE_NULLIFIER = "1afecf4cfcfd1c73219605b615e66d7236c98ec083f9e555ce904900204d0f29";

const DUMMY_BLINDING = new Uint8Array(31).fill(7) as Bytes31;
const ZERO_NULLIFIER_KEY = (): NullifierKey =>
  NullifierKey.fromSecret(new Uint8Array(31) as Bytes31);

function zeroOwnerUtxo(overrides: Partial<ConstructorParameters<typeof Utxo>[0]> = {}): Utxo {
  return new Utxo({
    owner: ShieldedPublicKey.zeroed(),
    asset: SOL_MINT,
    amount: 0n,
    blinding: DUMMY_BLINDING,
    ...overrides,
  });
}

// The same seven cases the Rust `check_canonical_dummy` table rejects.
function noncanonicalDummies(): readonly (readonly [
  string,
  ConstructorParameters<typeof ProofInputUtxo>[0],
])[] {
  return [
    [
      "asset",
      {
        utxo: zeroOwnerUtxo({ asset: "SysvarRent111111111111111111111111111111111" as Address }),
        nullifierKey: ZERO_NULLIFIER_KEY(),
      },
    ],
    ["amount", { utxo: zeroOwnerUtxo({ amount: 1n }), nullifierKey: ZERO_NULLIFIER_KEY() }],
    [
      "data",
      {
        utxo: zeroOwnerUtxo({ data: new Data([{ kind: "utxoData", bytes: Uint8Array.of(1) }]) }),
        nullifierKey: ZERO_NULLIFIER_KEY(),
      },
    ],
    [
      "zone_program_id",
      {
        utxo: zeroOwnerUtxo({
          zoneProgramId: "SysvarRent111111111111111111111111111111111" as Address,
        }),
        nullifierKey: ZERO_NULLIFIER_KEY(),
      },
    ],
    [
      "data_hash",
      { utxo: zeroOwnerUtxo(), nullifierKey: ZERO_NULLIFIER_KEY(), dataHash: scalar(9) },
    ],
    [
      "zone_data_hash",
      { utxo: zeroOwnerUtxo(), nullifierKey: ZERO_NULLIFIER_KEY(), zoneDataHash: scalar(10) },
    ],
    [
      "nullifier_key",
      {
        utxo: zeroOwnerUtxo(),
        nullifierKey: NullifierKey.fromSecret(new Uint8Array(31).fill(11) as Bytes31),
      },
    ],
  ];
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
    ).toThrow(
      expect.objectContaining({
        code: "TRANSACTION_NONCANONICAL_DUMMY_INPUT",
        details: { field: "asset" },
      }),
    );
  });

  it("accepts and hashes a canonical dummy exactly as Rust does", () => {
    const dummy = ProofInputUtxo.dummy(new Uint8Array(31).fill(7) as Bytes31);

    expect(dummy.isDummy()).toBe(true);
    expect(hex(dummy.hash())).toBe(DUMMY_ORACLE_HASH);
    expect(hex(dummy.nullifier())).toBe(DUMMY_ORACLE_NULLIFIER);
  });

  it("rejects every field a zero-owner input must leave zero", () => {
    for (const [field, input] of noncanonicalDummies()) {
      expect(() => new ProofInputUtxo(input)).toThrow(
        expect.objectContaining({
          code: "TRANSACTION_NONCANONICAL_DUMMY_INPUT",
          details: { field },
        }),
      );
    }
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
