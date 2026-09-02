import { getAddressDecoder } from "@solana/kit";
import { describe, expect, it } from "vitest";

import type { Bytes32, Bytes64 } from "../src/interface/index.js";
import { KeypairError, ShieldedKeypair, SigningKey } from "../src/keypair/index.js";
import { LocalShieldedKeys, Utxo, SOL_MINT } from "../src/transaction/index.js";

function hex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function fixture() {
  const signing = SigningKey.fromEd25519Bytes(new Uint8Array(32).fill(42) as Bytes32);
  const publicKey = signing.publicKey().ed25519();
  const solanaPublicKey = getAddressDecoder().decode(publicKey);
  const seed = signing.derivationSeed() as Bytes64;
  const expected = ShieldedKeypair.fromKeypair(
    SigningKey.fromEd25519Bytes(new Uint8Array(32).fill(42) as Bytes32),
  );
  return { solanaPublicKey, seed, expected };
}

describe("LocalShieldedKeys", () => {
  it("reproduces the software identity from a derivation seed without exposing a signer", async () => {
    const { solanaPublicKey, seed, expected } = fixture();
    const keys = LocalShieldedKeys.fromDerivationSeed({ solanaPublicKey, derivationSeed: seed });
    const identity = keys.address();

    expect(hex(identity.signingPublicKey.toBytes())).toBe(
      hex(expected.signingPublicKey().toBytes()),
    );
    expect(hex(identity.nullifierPublicKey)).toBe(hex(expected.nullifierPublicKey()));
    expect(hex(identity.viewingPublicKey.toBytes())).toBe(
      hex(expected.viewingPublicKey().toBytes()),
    );
    // The same derivations the keypair makes, without the key leaving.
    const utxo = new Utxo({
      owner: expected.signingPublicKey(),
      asset: SOL_MINT,
      amount: 5n,
      blinding: new Uint8Array(32).fill(9) as Bytes32,
    });
    const hash = utxo.hash(expected.nullifierPublicKey());
    const [nullifier] = await keys.derive([
      { kind: "nullifier", utxoHash: hash, blinding: utxo.blinding },
    ]);
    expect(hex(nullifier!)).toBe(hex(expected.nullifier(hash, utxo.blinding)));
    expect(
      Object.getOwnPropertyNames(Object.getPrototypeOf(keys)).filter(
        (name) => name.startsWith("sign") || name === "secretBytes" || name === "nullifierKey",
      ),
    ).toEqual([]);
  });

  it("refuses a merge slot outside the protocol's range instead of failing inside the hash", async () => {
    const { solanaPublicKey, seed } = fixture();
    const keys = LocalShieldedKeys.fromDerivationSeed({ solanaPublicKey, derivationSeed: seed });
    const firstNullifier = new Uint8Array(32).fill(3) as Bytes32;
    await expect(
      keys.derive([{ kind: "mergeDummyNullifier", firstNullifier, slotIndex: 256 }]),
    ).rejects.toMatchObject({ code: "TRANSACTION_INVALID_POSITION" });
    await expect(
      keys.derive([{ kind: "mergeDummyNullifier", firstNullifier, slotIndex: 1.5 }]),
    ).rejects.toMatchObject({ code: "TRANSACTION_INVALID_POSITION" });
    await expect(
      keys.derive([{ kind: "mergeDummyNullifier", firstNullifier, slotIndex: 255 }]),
    ).resolves.toHaveLength(1);
  });

  it("lends the nullifier key to one callback and wipes the copy after it", () => {
    const { solanaPublicKey, seed } = fixture();
    const keys = LocalShieldedKeys.fromDerivationSeed({ solanaPublicKey, derivationSeed: seed });
    const lent = keys.withNullifierKey((key) => key);
    expect(() => lent.publicKey()).toThrow("KEYPAIR_INVALID_SECRET_KEY");
    // The keys themselves keep working.
    expect(keys.withNullifierKey((key) => hex(key.publicKey()))).toBe(
      hex(keys.address().nullifierPublicKey),
    );
  });

  it("rejects a seed that is not bound to the Solana public key", () => {
    const { solanaPublicKey, seed } = fixture();
    const mutated = seed.slice() as Bytes64;
    mutated[0] = (mutated[0] ?? 0) ^ 1;

    expect(() =>
      LocalShieldedKeys.fromDerivationSeed({ solanaPublicKey, derivationSeed: mutated }),
    ).toThrowError(
      expect.objectContaining({
        name: "TransactionError",
        code: "TRANSACTION_INVALID_DERIVATION_SEED",
      }),
    );
  });

  it("rejects a seed whose width is not the ed25519 rail's", () => {
    const { solanaPublicKey, seed } = fixture();

    for (const width of [seed.length - 1, seed.length + 1, 0]) {
      const wrong = new Uint8Array(width) as Bytes64;
      wrong.set(seed.subarray(0, Math.min(width, seed.length)));
      let thrown: unknown;
      try {
        LocalShieldedKeys.fromDerivationSeed({ solanaPublicKey, derivationSeed: wrong });
      } catch (error) {
        thrown = error;
      }
      expect(thrown).toBeInstanceOf(KeypairError);
      const error = thrown as KeypairError;
      // Mirrors Rust `KeypairError::InvalidDerivationSeed`, not a generic
      // length error: HKDF-Extract would accept any width and expand a
      // truncated seed into a well-formed but different identity.
      expect(error.code).toBe("KEYPAIR_INVALID_DERIVATION_SEED");
      expect(error.rustVariant).toBe("InvalidDerivationSeed");
      expect(error.details).toMatchObject({ expected: 64, actual: width });
    }
  });

  it("refuses keys that do not describe the address they are built for", () => {
    const keypair = ShieldedKeypair.generate();
    const other = ShieldedKeypair.generate();
    expect(() =>
      LocalShieldedKeys.fromKeys({
        address: keypair.shieldedAddress(),
        viewingKeys: [other.viewingKey()],
        nullifierKey: keypair.nullifierKey(),
      }),
    ).toThrowError(expect.objectContaining({ code: "TRANSACTION_WALLET_AUTHORITY_MISMATCH" }));
    expect(() =>
      LocalShieldedKeys.fromKeys({
        address: keypair.shieldedAddress(),
        viewingKeys: [keypair.viewingKey()],
        nullifierKey: other.nullifierKey(),
      }),
    ).toThrowError(expect.objectContaining({ code: "TRANSACTION_WALLET_AUTHORITY_MISMATCH" }));
  });

  it("opens under a retired viewing key and refuses one it does not hold", async () => {
    const signing = SigningKey.fromEd25519Bytes(new Uint8Array(32).fill(11) as Bytes32);
    const retired = ShieldedKeypair.generate();
    const current = ShieldedKeypair.fromKeypair(signing);
    const keys = LocalShieldedKeys.fromKeys({
      address: current.shieldedAddress(),
      viewingKeys: [current.viewingKey(), retired.viewingKey()],
      nullifierKey: current.nullifierKey(),
    });
    expect(keys.viewingPublicKeys().map((key) => hex(key.toBytes()))).toEqual([
      hex(current.viewingPublicKey().toBytes()),
      hex(retired.viewingPublicKey().toBytes()),
    ]);
    const [txKey] = await keys.transactionKeys([
      {
        viewingPublicKey: retired.viewingPublicKey(),
        firstNullifier: new Uint8Array(32).fill(3) as Bytes32,
      },
    ]);
    expect(txKey).toBeDefined();
    txKey!.destroy();
    await expect(
      keys.transactionKeys([
        {
          viewingPublicKey: ShieldedKeypair.generate().viewingPublicKey(),
          firstNullifier: new Uint8Array(32).fill(3) as Bytes32,
        },
      ]),
    ).rejects.toMatchObject({ code: "TRANSACTION_MISSING_CURRENT_VIEWING_KEY" });
  });
});
