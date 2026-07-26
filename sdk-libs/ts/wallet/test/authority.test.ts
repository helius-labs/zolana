import type { Address, Bytes32 } from "@zolana/interface";
import { NullifierKey, ShieldedKeypair, SigningKey, ViewingKey } from "@zolana/keypair";
import { AssetRegistry, OutputData, SOL_MINT } from "@zolana/transaction";
import {
  EncryptedScheme,
  decodeOutputData,
  decodeSplitBundle,
  decryptConfidential,
  decryptSplit,
} from "@zolana/transaction/serialization";
import { describe, expect, it } from "vitest";

import { LocalWalletAuthority } from "../src/index.js";
import { hex, hexBytes, walletFixture } from "./helpers/fixtures.js";

interface AuthorityFixture {
  readonly inputs: Readonly<{
    messageHashBytes: string;
    signingSecretBytes: string;
    viewingSeedBytes: string;
  }>;
  readonly expected: Readonly<{
    p256Signature: Readonly<{
      pubkeyBytes: string;
      rBytes: string;
      sBytes: string;
    }>;
    syncMaterial: Readonly<{
      identitySigningPubkeyBytes: string;
      nullifierPubkeyBytes: string;
      viewingKeyCount: string;
    }>;
  }>;
}

function keypair(fixture: AuthorityFixture): ShieldedKeypair {
  const signing = SigningKey.fromBytes(hexBytes(fixture.inputs.signingSecretBytes) as Bytes32);
  return ShieldedKeypair.fromKeys(
    signing,
    NullifierKey.fromSigningKey(signing),
    ViewingKey.fromSeed(hexBytes(fixture.inputs.viewingSeedBytes) as Bytes32, 0),
  );
}

describe("local wallet authority", () => {
  it("matches frozen sync material and P256 signatures", async () => {
    const fixture = await walletFixture<AuthorityFixture>("wallet_authority");
    const authority = new LocalWalletAuthority({
      solanaPublicKey: "11111111111111111111111111111111" as Address,
      keypair: keypair(fixture),
    });
    const material = await authority.syncMaterial();
    expect(hex(material.identity.signingPublicKey.toBytes())).toBe(
      fixture.expected.syncMaterial.identitySigningPubkeyBytes,
    );
    expect(hex(material.nullifierKey.publicKey())).toBe(
      fixture.expected.syncMaterial.nullifierPubkeyBytes,
    );
    expect(material.viewingKeys).toHaveLength(
      Number(fixture.expected.syncMaterial.viewingKeyCount),
    );
    const signature = await authority.signP256(
      hexBytes(fixture.inputs.messageHashBytes) as Bytes32,
    );
    expect(hex(signature.publicKey.toBytes())).toBe(fixture.expected.p256Signature.pubkeyBytes);
    expect(hex(signature.r)).toBe(fixture.expected.p256Signature.rBytes);
    expect(hex(signature.s)).toBe(fixture.expected.p256Signature.sBytes);
  });

  it("encrypts transfer and split payloads that the owner decrypts", async () => {
    const fixture = await walletFixture<AuthorityFixture>("wallet_authority");
    const localKeypair = keypair(fixture);
    const authority = new LocalWalletAuthority({
      solanaPublicKey: "11111111111111111111111111111111" as Address,
      keypair: localKeypair,
    });
    const output = {
      ownerAddress: localKeypair.shieldedAddress(),
      asset: SOL_MINT,
      amount: 9n,
      blinding: new Uint8Array(31).fill(4) as import("@zolana/interface").Bytes31,
      data: new OutputData(),
      ownerHash: () => localKeypair.shieldedAddress().ownerHash(),
      hash: () => new Uint8Array(32) as Bytes32,
      isDummy: () => false,
    };
    const encrypted = await authority.encryptConfidentialTransfer({
      firstNullifier: new Uint8Array(32).fill(7) as Bytes32,
      outputs: [output],
      assets: new AssetRegistry(),
    });
    const slot = encrypted.payload[0];
    if (slot === undefined) throw new Error("missing encrypted slot");
    expect(slot.viewTag).toEqual(localKeypair.signingPublicKey().confidentialViewTag());
    expect(slot.viewTag).not.toEqual(localKeypair.viewingPublicKey().x());
    const decoded = decodeOutputData(slot.data);
    expect(decoded.scheme).toBe(EncryptedScheme.confidential);
    const plaintext = decryptConfidential(
      localKeypair.viewingKey(),
      encrypted.txViewingPublicKey,
      decoded.body,
      encrypted.salt,
      0,
    );
    expect(plaintext.amount).toBe(9n);

    const bundle = {
      ownerPublicKey: localKeypair.signingPublicKey(),
      numOutputs: 2,
      assetId: 0n,
      assetAmount: 4n,
      blindingSeed: new Uint8Array(31).fill(8) as import("@zolana/interface").Bytes31,
      data: new OutputData(),
    };
    const split = await authority.encryptSplit({
      firstNullifier: new Uint8Array(32).fill(9) as Bytes32,
      viewTag: localKeypair.shieldedAddress().confidentialViewTag(),
      bundle,
    });
    const splitData = decodeOutputData(split.payload.data);
    expect(
      decodeSplitBundle(
        decryptSplit(
          localKeypair.viewingKey(),
          split.txViewingPublicKey,
          splitData.body,
          split.salt,
          0,
        ),
      ),
    ).toMatchObject({ numOutputs: 2, assetAmount: 4n });
  });

  it("publishes the Ed25519 signing key as the confidential view tag", async () => {
    const localKeypair = ShieldedKeypair.fromEd25519(new Uint8Array(32).fill(7) as Bytes32, 0);
    const authority = new LocalWalletAuthority({
      solanaPublicKey: "11111111111111111111111111111111" as Address,
      keypair: localKeypair,
    });
    const output = {
      ownerAddress: localKeypair.shieldedAddress(),
      asset: SOL_MINT,
      amount: 9n,
      blinding: new Uint8Array(31).fill(4) as import("@zolana/interface").Bytes31,
      data: new OutputData(),
      ownerHash: () => localKeypair.shieldedAddress().ownerHash(),
      hash: () => new Uint8Array(32) as Bytes32,
      isDummy: () => false,
    };

    const encrypted = await authority.encryptConfidentialTransfer({
      firstNullifier: new Uint8Array(32).fill(7) as Bytes32,
      outputs: [output],
      assets: new AssetRegistry(),
    });
    const slot = encrypted.payload[0];
    if (slot === undefined) throw new Error("missing encrypted slot");

    expect(slot.viewTag).toEqual(localKeypair.signingPublicKey().ed25519());
    expect(slot.viewTag).toEqual(localKeypair.signingPublicKey().confidentialViewTag());
    expect(slot.viewTag).not.toEqual(localKeypair.viewingPublicKey().x());
  });
});
