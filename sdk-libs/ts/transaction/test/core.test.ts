import type { Address, Bytes31, Bytes32 } from "../../src/interface/index.js";
import {
  NullifierKey,
  ShieldedKeypair,
  ShieldedPublicKey,
  SigningKey,
  ViewingKey,
} from "../../src/keypair/index.js";
import { describe, expect, it } from "vitest";

import {
  AssetRegistry,
  Data,
  ProofInputUtxo,
  SOL_MINT,
  TransactionError,
  Utxo,
  Wallet,
  canonicalShape,
  createProofOutput,
  deriveBlinding,
  ownerUtxoHash,
  resolveShape,
} from "../../src/transaction/index.js";
import { encodeData } from "../../src/transaction/serialization/index.js";

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
const DUMMY_ORACLE_HASH = "21bad49e7dfee8758b2bd68372ce628c95826624661c03cd7657cee52738d930";
const DUMMY_ORACLE_NULLIFIER = "14b3997656396c9e75335686e9a673fcc06da33bd7e3b4191ed8d1372719a976";

const DUMMY_BLINDING = new Uint8Array(32).fill(7) as Bytes32;
const ZERO_NULLIFIER_KEY = (): NullifierKey =>
  NullifierKey.fromSecret(new Uint8Array(31) as Bytes31);

const ZERO_ADDRESS = "11111111111111111111111111111111" as Address;
const ZONE = "SysvarRent111111111111111111111111111111111" as Address;
const ZERO_HASH = (): Bytes32 => new Uint8Array(32) as Bytes32;

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
      blinding: new Uint8Array(32).fill(3) as Bytes32,
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
            blinding: new Uint8Array(32) as Bytes32,
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
    const dummy = ProofInputUtxo.dummy(new Uint8Array(32).fill(7) as Bytes32);

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

  // The commitment folds an explicit zero hash and an absent one into the same
  // field, so the dummy rule has to agree with it. `dataHash` reaches the
  // constructor unnormalized, which is how the two spellings stay reachable.
  it("accepts a dummy carrying an explicit zero hash, as Rust does", () => {
    const canonical = ProofInputUtxo.dummy(DUMMY_BLINDING);
    const explicit = new ProofInputUtxo({
      utxo: zeroOwnerUtxo(),
      nullifierKey: ZERO_NULLIFIER_KEY(),
      dataHash: ZERO_HASH(),
      zoneDataHash: ZERO_HASH(),
    });

    expect(hex(explicit.hash())).toBe(DUMMY_ORACLE_HASH);
    expect(explicit.hash()).toEqual(canonical.hash());
    expect(explicit.nullifier()).toEqual(canonical.nullifier());
  });

  // The other half of the T28 split, at the dummy rule rather than at the
  // builders: a zero zone address is carried, not absent, so a dummy holding
  // one stays noncanonical however the two hashes are read.
  it("rejects a dummy bound to the zero zone address", () => {
    expect(
      () =>
        new ProofInputUtxo({
          utxo: zeroOwnerUtxo({ zoneProgramId: ZERO_ADDRESS }),
          nullifierKey: ZERO_NULLIFIER_KEY(),
        }),
    ).toThrow(
      expect.objectContaining({
        code: "TRANSACTION_NONCANONICAL_DUMMY_INPUT",
        details: { field: "zone_program_id" },
      }),
    );
  });

  // T28 covers two zone bindings that cost differently, and the suite holds
  // them apart. Normalizing the zone data hash moves no commitment, because the
  // zero was already the committed field. Normalizing the zone address would
  // move one: the zero address commits to `pk_field(0)`, a non-zero field the
  // circuit reads as zone-bound. The two `not.toEqual` assertions fail if
  // anyone extends normalization to the address.
  it("normalizes an explicit zero at the zone data hash and not at the zone address", () => {
    const { keypair, nullifier } = keyMaterial();
    const blinding = new Uint8Array(32).fill(3) as Bytes32;
    const utxo = new Utxo({
      owner: keypair.signingPublicKey(),
      asset: SOL_MINT,
      amount: 42n,
      blinding,
    });
    const unboundInput = new ProofInputUtxo({ utxo, nullifierKey: nullifier });

    const normalizedInput = new ProofInputUtxo({
      utxo,
      nullifierKey: nullifier,
      zoneDataHash: ZERO_HASH(),
    });
    expect(normalizedInput.zoneDataHash).toBeUndefined();
    expect(normalizedInput.hash()).toEqual(unboundInput.hash());

    const zeroZoneInput = new ProofInputUtxo({
      utxo: new Utxo({
        owner: keypair.signingPublicKey(),
        asset: SOL_MINT,
        amount: 42n,
        blinding,
        zoneProgramId: ZERO_ADDRESS,
      }),
      nullifierKey: nullifier,
    });
    expect(zeroZoneInput.hash()).not.toEqual(unboundInput.hash());

    const output = createProofOutput({
      ownerAddress: keypair.shieldedAddress(),
      asset: SOL_MINT,
      amount: 42n,
      blinding,
    });
    expect(
      createProofOutput({ ...output, zoneProgramId: ZONE, zoneDataHash: ZERO_HASH() }).zoneDataHash,
    ).toBeUndefined();
    expect(
      createProofOutput({
        ...output,
        zoneProgramId: ZONE,
        zoneDataHash: ZERO_HASH(),
        data: new Data([{ kind: "zoneData", bytes: Uint8Array.of(1, 2) }]),
      }).zoneDataHash,
    ).toBeUndefined();
    expect(createProofOutput({ ...output, zoneProgramId: ZERO_ADDRESS }).hash()).not.toEqual(
      output.hash(),
    );
  });

  // The commitment is the one hashing path Rust drives through `light_poseidon`
  // directly (`sdk-libs/transaction/src/utxo.rs:12-18`), so an out-of-field
  // input reports `Poseidon` there and `Keypair` everywhere else. Both refuse at
  // hash time, not at construction: nothing has been hashed until then.
  it("refuses commitment inputs at or above the BN254 modulus as poseidon failures", () => {
    const { keypair, nullifier } = keyMaterial();
    const aboveModulus = new Uint8Array(32).fill(0xff) as Bytes32;
    const utxo = new Utxo({
      owner: keypair.signingPublicKey(),
      asset: SOL_MINT,
      amount: 42n,
      blinding: new Uint8Array(32).fill(3) as Bytes32,
      zoneProgramId: ZONE,
    });

    const zoneBound = new ProofInputUtxo({
      utxo,
      nullifierKey: nullifier,
      zoneDataHash: aboveModulus,
    });
    expect(zoneBound.zoneDataHash).toEqual(aboveModulus);
    expect(() => zoneBound.hash()).toThrow(
      expect.objectContaining({ code: "TRANSACTION_POSEIDON" }),
    );

    expect(() =>
      new ProofInputUtxo({
        utxo,
        nullifierKey: nullifier,
        dataHash: aboveModulus,
      }).hash(),
    ).toThrow(expect.objectContaining({ code: "TRANSACTION_POSEIDON" }));

    expect(() => ownerUtxoHash(aboveModulus, new Uint8Array(32).fill(3) as Bytes32)).toThrow(
      expect.objectContaining({ code: "TRANSACTION_POSEIDON" }),
    );
  });

  it("derives position-specific blindings and validates their range", () => {
    const seed = new Uint8Array(32).fill(9) as Bytes32;
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
    // Constructor clones the input registry, so later inserts on the caller's
    // copy do not reach the wallet.
    registry.insert(3n, laterMint);
    expect(() => wallet.registry.resolve(3n)).toThrow(
      expect.objectContaining({ code: "TRANSACTION_UNKNOWN_ASSET" }),
    );
    // Mutations are explicit; the registry getter is a defensive snapshot.
    wallet.registerAsset(4n, laterMint);
    expect(wallet.registry.resolve(4n)).toBe(laterMint);
    expect(wallet.balances()).toEqual([]);
    // A registered mint the wallet holds no note of has a zero balance rather
    // than none; only an unregistered mint is a rejection.
    expect(wallet.balance(SOL_MINT)).toEqual({
      assetId: 1n,
      mint: SOL_MINT,
      amount: 0n,
      utxos: [],
    });
    expect(wallet.balance(laterMint)).toEqual({
      assetId: 4n,
      mint: laterMint,
      amount: 0n,
      utxos: [],
    });
    const unknownMint = "Stake11111111111111111111111111111111111111" as Address;
    expect(() => wallet.balance(unknownMint)).toThrow(
      expect.objectContaining({ code: "TRANSACTION_UNKNOWN_MINT" }),
    );
    expect(
      () =>
        new Utxo({
          owner: keypair.signingPublicKey(),
          asset: SOL_MINT,
          amount: -1n,
          blinding: new Uint8Array(32) as Bytes32,
        }),
    ).toThrow(TransactionError);
  });

  it("keeps transaction diagnostics closed and redacted", () => {
    const error = new TransactionError("TRANSACTION_DESERIALIZE", {
      variant: "FutureVariant",
      index: 2,
      secretKey: "hidden",
      payload: { value: 7, nonce: "hidden" },
    });
    expect(error.details).toEqual({
      variant: "FutureVariant",
      index: 2,
      payload: { value: 7 },
    });
    expect(JSON.stringify(error)).not.toContain("hidden");
  });
});
