import { getAddressDecoder } from "@solana/kit";
import { describe, expect, it } from "vitest";

import type { Bytes32, Bytes64 } from "../src/interface/index.js";
import { KeypairError, ShieldedKeypair, SigningKey } from "../src/keypair/index.js";
import { ClientEd25519WalletAuthority } from "../src/transaction/index.js";

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

describe("ClientEd25519WalletAuthority", () => {
  it("reproduces the software identity without exposing a signer", async () => {
    const { solanaPublicKey, seed, expected } = fixture();
    const authority = ClientEd25519WalletAuthority.fromDerivationSeed({
      solanaPublicKey,
      derivationSeed: seed,
    });
    // The session wipes the lent keys when the callback settles, capture inside.
    const material = await authority.withSyncSession(async (keys) => {
      const lent = await keys.syncMaterial();
      return {
        identity: lent.identity,
        nullifierSecret: hex(lent.nullifierKey.secretBytes()),
      };
    });

    expect(hex(material.identity.signingPublicKey.toBytes())).toBe(
      hex(expected.signingPublicKey().toBytes()),
    );
    expect(hex(material.identity.nullifierPublicKey)).toBe(hex(expected.nullifierPublicKey()));
    expect(hex(material.identity.viewingPublicKey.toBytes())).toBe(
      hex(expected.viewingPublicKey().toBytes()),
    );
    expect(material.nullifierSecret).toBe(hex(expected.nullifierKey().secretBytes()));
    // The authority exposes scan and encryption material and nothing that can
    // authorize a Solana transaction; that stays with the remote signer.
    expect(
      Object.getOwnPropertyNames(Object.getPrototypeOf(authority)).filter((name) =>
        name.startsWith("sign"),
      ),
    ).toEqual([]);
  });

  it("rejects a seed that is not bound to the Solana public key", () => {
    const { solanaPublicKey, seed } = fixture();
    const mutated = seed.slice() as Bytes64;
    mutated[0] = (mutated[0] ?? 0) ^ 1;

    expect(() =>
      ClientEd25519WalletAuthority.fromDerivationSeed({
        solanaPublicKey,
        derivationSeed: mutated,
      }),
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
        ClientEd25519WalletAuthority.fromDerivationSeed({
          solanaPublicKey,
          derivationSeed: wrong,
        });
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
});
