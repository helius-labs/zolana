import { getAddressDecoder } from "@solana/kit";
import { describe, expect, it } from "vitest";

import type { Bytes32 } from "../src/interface/types.js";
import { ShieldedKeypair } from "../src/keypair/shielded.js";
import { SigningKey } from "../src/keypair/signing-key.js";
import { ViewingKey } from "../src/keypair/viewing-key.js";
import { ed25519DerivationPayload, isDerivationInput } from "../src/keypair/derivation.js";
import { LocalWalletAuthority } from "../src/transaction/wallet/authority.js";
import { createProofOutput } from "../src/transaction/utxo.js";
import { AssetRegistry, SOL_MINT } from "../src/transaction/wallet/asset.js";
import { decryptTransactionViewingSecret, parseAuditorMessage } from "../src/keypair/audit.js";

function seed(byte: number): Bytes32 {
  return new Uint8Array(32).fill(byte) as Bytes32;
}

describe("LocalWalletAuthority", () => {
  it("derives the same keys from a wallet's derivation signature as from the secret", async () => {
    const signing = SigningKey.fromEd25519Bytes(seed(7));
    const keypair = ShieldedKeypair.fromKeypair(signing);
    const solanaPublicKey = getAddressDecoder().decode(signing.publicKey().toBytes().subarray(1));
    const local = new LocalWalletAuthority({ solanaPublicKey, keypair });
    // The browser wallet output of signMessage(ed25519DerivationMessage(pk)).
    const derived = LocalWalletAuthority.fromDerivationSeed({
      solanaPublicKey,
      derivationSeed: signing.derivationSeed(),
    });
    const [localAddress, derivedAddress] = await Promise.all([
      local.shieldedAddress(),
      derived.shieldedAddress(),
    ]);
    expect(derivedAddress.ownerHash()).toEqual(localAddress.ownerHash());
    expect(derivedAddress.viewingPublicKey.toBytes()).toEqual(
      localAddress.viewingPublicKey.toBytes(),
    );
    const [[localViewing], [derivedViewing]] = await Promise.all([
      local.viewingKeys(),
      derived.viewingKeys(),
    ]);
    expect(derivedViewing?.publicKey().toBytes()).toEqual(localViewing?.publicKey().toBytes());
    // The bare payload is a derivation input too, what browser wallets sign.
    expect(isDerivationInput(ed25519DerivationPayload())).toBe(true);
    // The hash-free path a page without Poseidon takes.
    expect(ViewingKey.fromDerivationSeed(signing.derivationSeed()).publicKey().toBytes()).toEqual(
      localViewing?.publicKey().toBytes(),
    );
    const [localNullifier, derivedNullifier] = await Promise.all([
      local.spendNullifierKey(),
      derived.spendNullifierKey(),
    ]);
    expect(derivedNullifier.publicKey()).toEqual(localNullifier.publicKey());
  });

  it("seals the transaction viewing secret to the auditor in an audited transfer", async () => {
    const keypair = ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(seed(8)));
    const solanaPublicKey = getAddressDecoder().decode(
      keypair.signingPublicKey().toBytes().subarray(1),
    );
    const authority = new LocalWalletAuthority({ solanaPublicKey, keypair });
    const auditor = ViewingKey.generate();
    const firstNullifier = seed(9);
    const encrypted = await authority.encryptAuditedTransfer({
      firstNullifier,
      outputs: [
        createProofOutput({
          ownerAddress: keypair.shieldedAddress(),
          asset: SOL_MINT,
          amount: 5n,
          blinding: seed(10),
        }),
      ],
      assets: new AssetRegistry(),
      auditorPublicKey: auditor.publicKey(),
    });
    const plain = await authority.encryptConfidentialTransfer({
      firstNullifier,
      outputs: [],
      assets: new AssetRegistry(),
    });
    // Same transaction viewing key as an unaudited transfer of the same inputs.
    expect(encrypted.txViewingPublicKey.toBytes()).toEqual(plain.txViewingPublicKey.toBytes());
    expect(encrypted.auditorMessage.viewTag).toEqual(auditor.publicKey().x());
    const message = parseAuditorMessage(encrypted.auditorMessage.data);
    const recovered = decryptTransactionViewingSecret(auditor, message);
    expect(recovered).toEqual(encrypted.audit.txViewingSecret);
    expect(ViewingKey.fromBytes(recovered).publicKey().toBytes()).toEqual(
      encrypted.txViewingPublicKey.toBytes(),
    );
    expect(encrypted.payload).toHaveLength(1);
  });
});
