import { initWasm } from "@trustwallet/wallet-core";
import { describe, expect, it } from "vitest";

import { ED25519_DERIVATION_MSG, ed25519DerivationMessage } from "../src/keypair/derivation.js";
import {
  CompressedShieldedAddress,
  NullifierKey,
  ShieldedAddress,
  ShieldedKeypair,
  SigningKey,
  ViewingKey,
  ownerHash,
  type Bytes31,
  type Bytes32,
  type Bytes64,
  type ShieldedKeypairLike,
  type SignatureType,
} from "../src/keypair/index.js";

const TEST_MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

const TSPP_COIN_TYPE = 1392955331;

const walletCore = await initWasm();

const GOLDEN = [
  {
    account: 0,
    signingSecret: "37df573b3ac4ad5b522e064e25b63ea16bcbe79d449e81a0268d1047948bb445",
    signingPubkey: "f036276246a75b9de3349ed42b15e232f6518fc20f5fcd4f1d64e81f9bd258f7",
    nullifierSecret: "85e3a0d6bf9d62582e6500ea3245ddddbf65e517dbc985c85982e383e4751e",
    nullifierPubkey: "070a4386ec323b299c7d7b9faf744e001b545974ac02fd148b537a4528ab8474",
    viewingSecret: "1694bc1c8a456511d0364e26c71409b4912c5b2ff56bed3fc9c706e066496a54",
    viewingPubkey: "03170ee9cf7a6f1ad811bd2019d386f67ce337458e0bf585c3cad7ddac85373e32",
    ownerHash: "203c8faa665e74ed4f6e46a11242f040373a20099f8d84fbd4318b11569b6282",
    compressedAddressHash: "0e10fc15c05a214c7534f47aee3f7dd933bde474a44a8f21110f1034a459ca8f",
  },
  {
    account: 1,
    signingSecret: "ba5e7b6e3680b4eb81db8e54c8e466b2e9a899355888403355d858ab985d2fc4",
    signingPubkey: "f8029acf5cbcbdd5ac46ec147f3b78a3df6e5022ef0411db2bab650d329a4cd4",
    nullifierSecret: "62351d526f51996740cc2e88978b084117fdee00af7c04df999a22321c9001",
    nullifierPubkey: "1053061c5b9c4fc75b26b72d83d88d62f80e397cea6f36c07e25c9d8645106fc",
    viewingSecret: "60a8c80b23007c79c1dcf1821446dc77e6fcd2bb3e747ddca629784adaf8fa18",
    viewingPubkey: "03bb3b5ea4e0a873297d1f80e2ee1ebfabf472129debca75fced4753a95769fe27",
    ownerHash: "1576686c1b4584c1e97410005cb3fa8b63a96be36e82199f8f8df2d925e17349",
    compressedAddressHash: "23d94f383599e298bf78215f3bf976e2629b3f180816bcc956fcf9ea15fa6e2f",
  },
] as const;

function bytes(value: string): Uint8Array {
  return Uint8Array.from(value.match(/../g)?.map((pair) => Number.parseInt(pair, 16)) ?? []);
}

function hex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

class SeedBasedShieldedKeypair implements ShieldedKeypairLike {
  readonly signingKey: SigningKey;
  readonly #nullifierKey: NullifierKey;
  readonly #viewingKey: ViewingKey;

  constructor(mnemonic: string, account: number) {
    const wallet = walletCore.HDWallet.createWithMnemonic(mnemonic, "");
    try {
      const deriveKey = (curve: typeof walletCore.Curve.ed25519, path: string): Bytes32 => {
        const key = wallet.getKeyByCurve(curve, path);
        try {
          return key.data().slice() as Bytes32;
        } finally {
          key.delete();
        }
      };
      this.signingKey = SigningKey.fromEd25519Bytes(
        deriveKey(walletCore.Curve.ed25519, `m/44'/501'/${account}'/0'`),
      );
      this.#nullifierKey = NullifierKey.fromSecret(
        deriveKey(walletCore.Curve.ed25519, `m/44'/${TSPP_COIN_TYPE}'/${account}'/1'/0'`).slice(
          1,
        ) as Bytes31,
      );
      this.#viewingKey = ViewingKey.fromBytes(
        deriveKey(walletCore.Curve.nist256p1, `m/44'/${TSPP_COIN_TYPE}'/${account}'/2'/0'`),
      );
    } finally {
      wallet.delete();
    }
  }

  signingPublicKey() {
    return this.signingKey.publicKey();
  }

  viewingPublicKey() {
    return this.#viewingKey.publicKey();
  }

  curve(): SignatureType {
    return this.signingKey.signatureType();
  }

  shieldedAddress(): ShieldedAddress {
    return ShieldedAddress.fromPublicKeys(
      this.signingPublicKey(),
      this.#nullifierKey.publicKey(),
      this.viewingPublicKey(),
    );
  }

  ownerHash(): Bytes32 {
    return ownerHash(
      this.signingPublicKey().ownerProofInputHash(),
      this.#nullifierKey.publicKey(),
    ) as Bytes32;
  }

  compressedAddress(): CompressedShieldedAddress {
    return CompressedShieldedAddress.fromParts(this.ownerHash(), this.viewingPublicKey());
  }

  sign(message: Uint8Array): Bytes64 {
    return this.signingKey.sign(message);
  }

  signHash(messageHash: Bytes32): Bytes64 {
    this.signingPublicKey().p256();
    return this.signingKey.sign(messageHash);
  }

  nullifier(utxoHash: Bytes32, blinding: Bytes32): Bytes32 {
    return this.#nullifierKey.nullifier(utxoHash, blinding);
  }

  nullifierPublicKey(): Bytes32 {
    return this.#nullifierKey.publicKey();
  }

  nullifierKey(): NullifierKey {
    return NullifierKey.fromSecret(this.#nullifierKey.secretBytes());
  }

  viewingKey(): ViewingKey {
    return ViewingKey.fromBytes(this.#viewingKey.secretBytes());
  }
}

describe("seed-based shielded keypair (docs/spec.md Seed phrase)", () => {
  it("matches Solana's BIP44 signing-key derivation", () => {
    const keypair = new SeedBasedShieldedKeypair(TEST_MNEMONIC, 0);
    expect(hex(keypair.signingPublicKey().ed25519())).toBe(GOLDEN[0].signingPubkey);
  });

  it("matches reference parts and the Rust-generated golden values", () => {
    for (const golden of GOLDEN) {
      const keypair = new SeedBasedShieldedKeypair(TEST_MNEMONIC, golden.account);
      const signingReference = SigningKey.fromEd25519Bytes(bytes(golden.signingSecret) as Bytes32);
      const nullifierReference = NullifierKey.fromSecret(bytes(golden.nullifierSecret) as Bytes31);
      const viewingReference = ViewingKey.fromBytes(bytes(golden.viewingSecret) as Bytes32);

      expect(hex(keypair.signingKey.secretBytes())).toBe(golden.signingSecret);
      expect(hex(keypair.nullifierKey().secretBytes())).toBe(golden.nullifierSecret);
      expect(hex(keypair.viewingKey().secretBytes())).toBe(golden.viewingSecret);

      expect(hex(keypair.signingPublicKey().ed25519())).toBe(golden.signingPubkey);
      expect(hex(keypair.nullifierPublicKey())).toBe(golden.nullifierPubkey);
      expect(hex(keypair.viewingPublicKey().toBytes())).toBe(golden.viewingPubkey);
      expect(hex(keypair.ownerHash())).toBe(golden.ownerHash);
      expect(hex(keypair.compressedAddress().hash())).toBe(golden.compressedAddressHash);
      expect(keypair.curve()).toBe("ed25519");

      expect(hex(signingReference.publicKey().toBytes())).toBe(
        hex(keypair.signingPublicKey().toBytes()),
      );
      expect(hex(nullifierReference.publicKey())).toBe(golden.nullifierPubkey);
      expect(hex(viewingReference.publicKey().toBytes())).toBe(golden.viewingPubkey);
      expect(
        hex(
          ownerHash(
            signingReference.publicKey().ownerProofInputHash(),
            nullifierReference.publicKey(),
          ),
        ),
      ).toBe(golden.ownerHash);

      const address = keypair.shieldedAddress();
      expect(hex(address.signingPublicKey.toBytes())).toBe(
        hex(keypair.signingPublicKey().toBytes()),
      );
      expect(hex(address.nullifierPublicKey)).toBe(golden.nullifierPubkey);
      expect(hex(address.viewingPublicKey.toBytes())).toBe(golden.viewingPubkey);
      expect(hex(address.ownerHash())).toBe(golden.ownerHash);

      const compressed = keypair.compressedAddress();
      expect(hex(compressed.ownerHash)).toBe(golden.ownerHash);
      expect(hex(compressed.viewingPublicKey.toBytes())).toBe(golden.viewingPubkey);

      const utxoHash = new Uint8Array(32).fill(1) as Bytes32;
      const blinding = new Uint8Array(32).fill(2) as Bytes32;
      expect(hex(keypair.nullifier(utxoHash, blinding))).toBe(
        hex(nullifierReference.nullifier(utxoHash, blinding)),
      );
    }
  });

  it("is deterministic and separates accounts and rails", () => {
    const first = new SeedBasedShieldedKeypair(TEST_MNEMONIC, 0);
    const second = new SeedBasedShieldedKeypair(TEST_MNEMONIC, 0);
    const firstAddress = first.shieldedAddress();
    const secondAddress = second.shieldedAddress();
    expect(hex(firstAddress.signingPublicKey.toBytes())).toBe(
      hex(secondAddress.signingPublicKey.toBytes()),
    );
    expect(hex(firstAddress.nullifierPublicKey)).toBe(hex(secondAddress.nullifierPublicKey));
    expect(hex(firstAddress.viewingPublicKey.toBytes())).toBe(
      hex(secondAddress.viewingPublicKey.toBytes()),
    );

    const otherAccount = new SeedBasedShieldedKeypair(TEST_MNEMONIC, 1);
    expect(hex(otherAccount.signingPublicKey().toBytes())).not.toBe(
      hex(first.signingPublicKey().toBytes()),
    );
    expect(hex(otherAccount.nullifierPublicKey())).not.toBe(hex(first.nullifierPublicKey()));
    expect(hex(otherAccount.viewingPublicKey().toBytes())).not.toBe(
      hex(first.viewingPublicKey().toBytes()),
    );

    const signatureRail = ShieldedKeypair.fromKeypair(
      SigningKey.fromEd25519Bytes(first.signingKey.secretBytes()),
    );
    expect(hex(signatureRail.signingPublicKey().toBytes())).toBe(
      hex(first.signingPublicKey().toBytes()),
    );
    expect(hex(signatureRail.nullifierPublicKey())).not.toBe(hex(first.nullifierPublicKey()));
    expect(hex(signatureRail.viewingPublicKey().toBytes())).not.toBe(
      hex(first.viewingPublicKey().toBytes()),
    );
  });

  it("signs messages and refuses derivation inputs and P256 prehash signing", () => {
    const keypair = new SeedBasedShieldedKeypair(TEST_MNEMONIC, 0);
    const message = new TextEncoder().encode("private tx hash binding");
    const signature = keypair.sign(message);
    expect(keypair.signingKey.verify(message, signature)).toBe(true);

    const signerPubkey = keypair.signingPublicKey().ed25519();
    expect(() => keypair.sign(new TextEncoder().encode(ED25519_DERIVATION_MSG))).toThrow(
      "KEYPAIR_DERIVATION_INPUT",
    );
    expect(() => keypair.sign(ed25519DerivationMessage(signerPubkey))).toThrow(
      "KEYPAIR_DERIVATION_INPUT",
    );
    expect(() => keypair.signHash(new Uint8Array(32).fill(7) as Bytes32)).toThrow(
      "KEYPAIR_INVALID_SIGNATURE_TYPE",
    );
  });
});
