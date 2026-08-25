import { getAddressDecoder } from "@solana/kit";
import { describe, expect, it } from "vitest";

import type { Bytes32, Bytes64 } from "../src/interface/index.js";
import { ShieldedKeypair, SigningKey } from "../src/keypair/index.js";
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
    const material = await authority.syncMaterial();

    expect(hex(material.identity.signingPublicKey.toBytes())).toBe(
      hex(expected.signingPublicKey().toBytes()),
    );
    expect(hex(material.identity.nullifierPublicKey)).toBe(hex(expected.nullifierPublicKey()));
    expect(hex(material.identity.viewingPublicKey.toBytes())).toBe(
      hex(expected.viewingPublicKey().toBytes()),
    );
    expect(hex(material.nullifierKey.secretBytes())).toBe(
      hex(expected.nullifierKey().secretBytes()),
    );
    expect("sign" in authority).toBe(false);
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
    ).toThrow("KEYPAIR_INVALID_SECRET_KEY");
  });
});
