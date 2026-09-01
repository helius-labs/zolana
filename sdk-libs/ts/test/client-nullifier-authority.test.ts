import { address, getAddressDecoder } from "@solana/kit";
import { describe, expect, it } from "vitest";

import type { Bytes32, Bytes64 } from "../src/interface/index.js";
import { ShieldedKeypair, SigningKey } from "../src/keypair/index.js";
import {
  AssetRegistry,
  ClientEd25519WalletAuthority,
  ClientNullifierWalletAuthority,
  Data,
  SOL_MINT,
  Utxo,
  Wallet,
} from "../src/transaction/index.js";

function fixture() {
  const signing = SigningKey.fromEd25519Bytes(new Uint8Array(32).fill(42) as Bytes32);
  const solanaPublicKey = getAddressDecoder().decode(signing.publicKey().ed25519());
  const derivationSeed = signing.derivationSeed() as Bytes64;
  const keypair = ShieldedKeypair.fromKeypair(
    SigningKey.fromEd25519Bytes(new Uint8Array(32).fill(42) as Bytes32),
  );
  return { solanaPublicKey, derivationSeed, keypair };
}

describe("ClientNullifierWalletAuthority", () => {
  it("constructs transactions with a local nullifier role and remote transaction viewing keys", async () => {
    const { solanaPublicKey, derivationSeed } = fixture();
    const full = ClientEd25519WalletAuthority.fromDerivationSeed({
      solanaPublicKey,
      derivationSeed,
    });
    const material = await full.syncMaterial();
    const nullifierSecret = material.nullifierKey.secretBytes();
    const firstNullifier = new Uint8Array(32).fill(0x71) as Bytes32;
    const expected = material.viewingKeys[0]!.transactionViewingKey(firstNullifier);
    const requested: Bytes32[] = [];
    const authority = new ClientNullifierWalletAuthority({
      solanaPublicKey,
      shieldedAddress: material.identity,
      nullifierSecret,
      transactionViewingSecret: async (nullifier) => {
        requested.push(nullifier.slice() as Bytes32);
        return material.viewingKeys[0]!.transactionViewingKey(nullifier).secretBytes();
      },
    });

    const envelope = await authority.encryptConfidentialTransfer({
      firstNullifier,
      outputs: [],
      assets: new AssetRegistry(),
    });
    expect(requested).toEqual([firstNullifier]);
    expect(envelope.txViewingPublicKey.toBytes()).toEqual(expected.publicKey().toBytes());
    expect((authority as unknown as { syncMaterial?: unknown }).syncMaterial).toBeUndefined();

    nullifierSecret.fill(0);
    material.nullifierKey.destroy();
    for (const viewingKey of material.viewingKeys) viewingKey.destroy();
  });

  it("rejects a nullifier secret that does not belong to the public identity", async () => {
    const { solanaPublicKey, derivationSeed, keypair } = fixture();
    const full = ClientEd25519WalletAuthority.fromDerivationSeed({
      solanaPublicKey,
      derivationSeed,
    });
    const secret = (await full.spendNullifierKey()).secretBytes();
    secret[0] = (secret[0] ?? 0) ^ 1;

    expect(
      () =>
        new ClientNullifierWalletAuthority({
          solanaPublicKey,
          shieldedAddress: keypair.shieldedAddress(),
          nullifierSecret: secret,
          transactionViewingSecret: async () => new Uint8Array(32).fill(1) as Bytes32,
        }),
    ).toThrowError(
      expect.objectContaining({
        name: "TransactionError",
        code: "TRANSACTION_WALLET_AUTHORITY_MISMATCH",
      }),
    );
    secret.fill(0);
  });

  it("hydrates a spendable wallet from commitment-checked remote openings", async () => {
    const { solanaPublicKey, derivationSeed } = fixture();
    const authority = ClientEd25519WalletAuthority.fromDerivationSeed({
      solanaPublicKey,
      derivationSeed,
    });
    const material = await authority.syncMaterial();
    const wallet = new Wallet({ identity: material.identity });
    const utxo = new Utxo({
      owner: material.identity.signingPublicKey,
      asset: SOL_MINT,
      amount: 7n,
      blinding: new Uint8Array(32).fill(3) as Bytes32,
      data: new Data(),
    });
    const hash = utxo.hash(material.identity.nullifierPublicKey);
    const opening = {
      utxo,
      outputContext: {
        hash,
        tree: address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3"),
        leafIndex: 4n,
      },
    };

    wallet.replaceSpendableUtxos([opening], material.nullifierKey);
    expect(wallet.utxos()).toHaveLength(1);
    expect(wallet.utxos()[0]?.nullifier).toEqual(
      material.nullifierKey.nullifier(hash, utxo.blinding),
    );
    expect(() =>
      wallet.replaceSpendableUtxos(
        [
          {
            ...opening,
            outputContext: { ...opening.outputContext, hash: new Uint8Array(32) as Bytes32 },
          },
        ],
        material.nullifierKey,
      ),
    ).toThrowError(expect.objectContaining({ code: "TRANSACTION_OUTPUT_COMMITMENT_MISMATCH" }));
  });
});
