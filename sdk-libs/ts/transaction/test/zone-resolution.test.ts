import type { Address, Bytes31, Bytes32 } from "@zolana/interface";
import { NullifierKey, ShieldedKeypair, SigningKey, ViewingKey } from "@zolana/keypair";
import { describe, expect, it } from "vitest";

import {
  AssetRegistry,
  Data,
  SOL_ASSET_ID,
  SOL_MINT,
  Utxo,
  Wallet,
  syncWalletWithAuthority,
  deriveBlinding,
} from "../src/index.js";
import {
  EncryptedScheme,
  TRANSFER_PLAINTEXT,
  anonymousRecipientUtxo,
  anonymousSenderUtxos,
  encodeOutputData,
  encodePlaintextTransfer,
  plaintextTransferUtxos,
  prooflessUtxo,
  splitBundleUtxos,
} from "../src/serialization/codecs.js";
import type { WalletAuthority, WalletSyncMaterial } from "../src/wallet/authority.js";
import type { IndexedShieldedTransaction } from "../src/instructions/transact.js";

const SEED = new Uint8Array(32).fill(7) as Bytes32;
const BLINDING_SEED = new Uint8Array(31).fill(5) as Bytes31;
const ZONE = "So11111111111111111111111111111111111111112" as Address;

function zoneData(): Data {
  return new Data([{ kind: "zoneData", bytes: Uint8Array.of(1, 2, 3) }]);
}

function wallet(): Readonly<{
  authority: WalletAuthority;
  material: WalletSyncMaterial;
  keypair: ShieldedKeypair;
}> {
  const signing = SigningKey.fromBytes(SEED);
  const nullifierKey = NullifierKey.fromSigningKey(signing);
  const viewing = ViewingKey.fromSeed(SEED, 0);
  const keypair = ShieldedKeypair.fromKeys(signing, nullifierKey, viewing);
  const material: WalletSyncMaterial = {
    identity: keypair.shieldedAddress(),
    viewingKeys: [viewing],
    nullifierKey,
  };
  const unsupported = (): Promise<never> => Promise.reject(new Error("not used by sync"));
  const authority: WalletAuthority = {
    solanaPublicKey: () => SOL_MINT,
    shieldedAddress: () => Promise.resolve(material.identity),
    viewingKeys: () => Promise.resolve([viewing]),
    spendNullifierKey: () => Promise.resolve(nullifierKey),
    syncMaterial: () => Promise.resolve(material),
    encryptConfidentialTransfer: unsupported,
    encryptAnonymousTransfer: unsupported,
    encryptSplit: unsupported,
    requestUserApproval: () => Promise.resolve(),
    signP256: unsupported,
  };
  return { authority, material, keypair };
}

/**
 * A plaintext-transfer slot whose sender change carries `data`, published
 * against `hash`. Neither the data records nor the zone id reach the
 * commitment on this rail, so a payload that adds zone data to an honest
 * output still matches the leaf the chain holds: the crafted note is
 * indistinguishable from the honest one by hash alone.
 */
function slot(data: Data, owner: ShieldedKeypair, hash: Bytes32): IndexedShieldedTransaction {
  const payload = encodeOutputData(
    EncryptedScheme.plaintextTransfer,
    encodePlaintextTransfer({
      typePrefix: TRANSFER_PLAINTEXT,
      blindingSeed: BLINDING_SEED,
      sender: {
        ownerPublicKey: owner.signingPublicKey(),
        spl: { amount: 1_000n, assetId: SOL_ASSET_ID },
        splData: data,
        solData: new Data(),
      },
      recipientSlots: [],
    }),
    "plaintext",
  );
  return {
    slot: 1n,
    txSignature: "zone-resolution",
    outputSlots: [
      {
        // Plaintext transfer slots are indexed under the owner tag, so a slot
        // tagged anything else is one the sync never opens.
        viewTag: owner.signingPublicKey().confidentialViewTag(),
        outputContext: { hash, tree: SOL_MINT, leafIndex: 0n },
        payload,
      },
    ],
    messages: [],
    nullifiers: [],
    proofless: false,
  };
}

describe("zone resolution on the read path", () => {
  it("refuses a crafted zone-data payload that an honest one would have been stored for", async () => {
    const { authority, material, keypair } = wallet();
    const honest = new Utxo({
      owner: keypair.signingPublicKey(),
      asset: SOL_MINT,
      amount: 1_000n,
      blinding: deriveBlinding(BLINDING_SEED, 0),
    });
    const hash = honest.hash(material.nullifierKey.publicKey());

    const sync = async (data: Data): Promise<number> => {
      const state = new Wallet({ identity: material.identity, registry: new AssetRegistry() });
      const report = await syncWalletWithAuthority({
        wallet: state,
        authority,
        transactions: [slot(data, keypair, hash)],
      });
      return report.storedUtxos;
    };

    expect(await sync(new Data())).toBe(1);
    expect(await sync(zoneData())).toBe(0);
  });

  it("refuses zone data no zone program can enforce, per scheme", () => {
    const assets = new AssetRegistry();
    const owner = ShieldedKeypair.fromKeys(
      SigningKey.fromBytes(SEED),
      NullifierKey.fromSigningKey(SigningKey.fromBytes(SEED)),
      ViewingKey.fromSeed(SEED, 0),
    ).signingPublicKey();

    expect(() =>
      plaintextTransferUtxos(
        {
          typePrefix: TRANSFER_PLAINTEXT,
          blindingSeed: BLINDING_SEED,
          recipientSlots: [
            { ownerPublicKey: owner, assetId: SOL_ASSET_ID, amount: 1_000n, data: zoneData() },
          ],
        },
        assets,
        SOL_MINT,
      ),
    ).toThrow("TRANSACTION_MISSING_ZONE_PROGRAM_ID");

    expect(() =>
      splitBundleUtxos(
        {
          ownerPublicKey: owner,
          numOutputs: 1,
          assetId: SOL_ASSET_ID,
          assetAmount: 7n,
          blindingSeed: BLINDING_SEED,
          data: zoneData(),
        },
        assets,
      ),
    ).toThrow("TRANSACTION_MISSING_ZONE_PROGRAM_ID");
  });

  /**
   * Rust `resolve_zone_program_id` returns `None` when the plaintext carries no
   * zone data, discarding the id its caller supplied. Keeping it instead would
   * move the commitment, since the zone program id is hashed into every leaf.
   */
  it("drops a supplied zone program id when the plaintext carries no zone data", () => {
    const assets = new AssetRegistry();
    const owner = ShieldedKeypair.fromKeys(
      SigningKey.fromBytes(SEED),
      NullifierKey.fromSigningKey(SigningKey.fromBytes(SEED)),
      ViewingKey.fromSeed(SEED, 0),
    ).signingPublicKey();

    const [bundled] = splitBundleUtxos(
      {
        ownerPublicKey: owner,
        numOutputs: 1,
        assetId: SOL_ASSET_ID,
        assetAmount: 7n,
        blindingSeed: BLINDING_SEED,
        data: new Data(),
      },
      assets,
      ZONE,
    );
    expect(bundled?.zoneProgramId).toBeUndefined();

    const recipient = anonymousRecipientUtxo(
      {
        ownerPublicKey: owner,
        senderPublicKey: ViewingKey.fromSeed(SEED, 1).publicKey(),
        assetId: SOL_ASSET_ID,
        amount: 7n,
        blinding: deriveBlinding(BLINDING_SEED, 0),
        data: zoneData(),
      },
      assets,
      ZONE,
    );
    expect(recipient.zoneProgramId).toBe(ZONE);
  });

  /**
   * A payload can fail the asset lookup and the zone resolution at once, and
   * the two rails disagree on which refusal wins unless the order is pinned.
   * Rust's `AnonymousTransferRecipientPlaintext::into_utxo` and
   * `AnonymousTransferSenderPlaintext::into_utxos` build a struct literal whose
   * fields evaluate in written order, `asset` before `zone_program_id`
   * (`sdk-libs/transaction/src/serialization/anonymous.rs:47,50` and
   * `:99,102`), so both report `UnknownAsset`. Rust's `Split::into_utxos`
   * resolves the zone first (`split.rs:61-62`) and reports the zone refusal,
   * which is why the split case below expects the other code.
   */
  it("reports the asset refusal before the zone refusal on the anonymous rails", () => {
    const assets = new AssetRegistry();
    const owner = ShieldedKeypair.fromKeys(
      SigningKey.fromBytes(SEED),
      NullifierKey.fromSigningKey(SigningKey.fromBytes(SEED)),
      ViewingKey.fromSeed(SEED, 0),
    ).signingPublicKey();
    const unregistered = 4242n;

    expect(() =>
      anonymousRecipientUtxo(
        {
          ownerPublicKey: owner,
          senderPublicKey: ViewingKey.fromSeed(SEED, 1).publicKey(),
          assetId: unregistered,
          amount: 7n,
          blinding: deriveBlinding(BLINDING_SEED, 0),
          data: zoneData(),
        },
        assets,
      ),
    ).toThrow(expect.objectContaining({ code: "TRANSACTION_UNKNOWN_ASSET" }));

    expect(() =>
      anonymousSenderUtxos(
        {
          ownerPublicKey: owner,
          splAssetId: unregistered,
          splAmount: 5n,
          solAmount: 0n,
          blindingSeed: BLINDING_SEED,
          recipientViewingPublicKeys: [],
          splData: zoneData(),
          solData: new Data(),
        },
        assets,
        SOL_MINT,
      ),
    ).toThrow(expect.objectContaining({ code: "TRANSACTION_UNKNOWN_ASSET" }));

    expect(() =>
      splitBundleUtxos(
        {
          ownerPublicKey: owner,
          numOutputs: 1,
          assetId: unregistered,
          assetAmount: 7n,
          blindingSeed: BLINDING_SEED,
          data: zoneData(),
        },
        assets,
      ),
    ).toThrow(expect.objectContaining({ code: "TRANSACTION_MISSING_ZONE_PROGRAM_ID" }));
  });

  /**
   * The deposit rail publishes its zone binding in the payload rather than
   * taking one from the reader, so Rust's `Proofless::into_utxos` resolves
   * nothing and keeps whatever the payload said, zone data included.
   */
  it("keeps a proofless payload's own zone binding without resolving it", () => {
    const owner = ShieldedKeypair.fromKeys(
      SigningKey.fromBytes(SEED),
      NullifierKey.fromSigningKey(SigningKey.fromBytes(SEED)),
      ViewingKey.fromSeed(SEED, 0),
    ).signingPublicKey();
    const utxo = prooflessUtxo(
      {
        owner: new Uint8Array(32) as Bytes32,
        blinding: deriveBlinding(BLINDING_SEED, 0),
        asset: SOL_MINT,
        amount: 1_000n,
        zoneData: Uint8Array.of(1, 2, 3),
      },
      owner,
    );
    expect(utxo.zoneProgramId).toBeUndefined();
    expect(utxo.data.zoneData()).toEqual(Uint8Array.of(1, 2, 3));
  });
});
