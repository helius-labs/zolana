import type { Address, Bytes32 } from "@zolana/interface";
import {
  randomSalt,
  type NullifierKey,
  type P256PublicKey,
  type ShieldedAddress,
  type ShieldedKeypair,
  type ViewingKey,
} from "@zolana/keypair";
import type {
  AnonymousRecipientSlot,
  AssetRegistry,
  EncryptedSplit,
  EncryptedTransfer,
  P256Signature,
  ProofOutputUtxo,
  SplitBundlePlaintext,
  WalletAuthority,
  WalletSyncMaterial,
} from "@zolana/transaction";
import {
  EncryptedScheme,
  encodeAnonymousRecipient,
  encodeAnonymousSender,
  encodeOutputData,
  encodeSplitBundle,
  encryptAnonymous,
  encryptConfidential,
  encryptSplit,
  type AnonymousSenderPlaintext,
} from "@zolana/transaction/serialization";

import { WalletError } from "./error.js";

/**
 * Authority material owned by `@zolana/transaction`; re-exported here so the
 * wallet package surface matches the Rust module, which is re-exports only.
 */
export type {
  AnonymousRecipientSlot,
  EncryptedSplit,
  EncryptedTransfer,
  P256Signature,
  SyncWalletAuthority,
  WalletAuthority,
  WalletSyncMaterial,
} from "@zolana/transaction";

export interface ApprovalRequest {
  readonly solanaPublicKey: Address;
  readonly summary: string;
}

export class LocalWalletAuthority implements WalletAuthority {
  readonly #solanaPublicKey: Address;
  readonly #keypair: ShieldedKeypair;

  constructor(input: Readonly<{ solanaPublicKey: Address; keypair: ShieldedKeypair }>) {
    this.#solanaPublicKey = input.solanaPublicKey;
    this.#keypair = input.keypair;
  }

  solanaPublicKey(): Address {
    return this.#solanaPublicKey;
  }

  shieldedAddress(): Promise<ShieldedAddress> {
    return Promise.resolve(this.#keypair.shieldedAddress());
  }

  viewingKeys(): Promise<readonly ViewingKey[]> {
    return Promise.resolve([this.#keypair.viewingKey()]);
  }

  spendNullifierKey(): Promise<NullifierKey> {
    return Promise.resolve(this.#keypair.nullifierKey());
  }

  syncMaterial(): Promise<WalletSyncMaterial> {
    return Promise.resolve({
      identity: this.#keypair.shieldedAddress(),
      viewingKeys: [this.#keypair.viewingKey()],
      nullifierKey: this.#keypair.nullifierKey(),
    });
  }

  encryptConfidentialTransfer(
    input: Readonly<{
      firstNullifier: Bytes32;
      outputs: readonly ProofOutputUtxo[];
      assets: AssetRegistry;
    }>,
  ): Promise<EncryptedTransfer> {
    const tx = this.#keypair.viewingKey().transactionViewingKey(input.firstNullifier);
    const salt = randomSalt();
    const payload = input.outputs.map((output, slotIndex) => {
      if (output.isDummy() || output.ownerAddress === undefined) return undefined;
      const body = encryptConfidential(
        tx,
        output.ownerAddress.viewingPublicKey,
        {
          assetId: input.assets.assetId(output.asset),
          amount: output.amount,
          blinding: output.blinding,
          ...(output.zoneProgramId === undefined ? {} : { zoneProgramId: output.zoneProgramId }),
          data: output.data,
        },
        salt,
        slotIndex,
      );
      return {
        viewTag: output.ownerAddress.signingPublicKey.confidentialViewTag(),
        data: encodeOutputData(EncryptedScheme.confidential, body, "encrypted"),
      };
    });
    return Promise.resolve({ txViewingPublicKey: tx.publicKey(), salt, payload });
  }

  /**
   * Slot 0 carries the sender bundle encrypted to this wallet's own viewing
   * key; recipient `i` occupies slot `i + 1`. Both the order and the slot
   * indices are bound into each ciphertext, so they must match the layout the
   * transfer instruction publishes.
   */
  encryptAnonymousTransfer(
    input: Readonly<{
      firstNullifier: Bytes32;
      senderViewTag: Bytes32;
      sender: AnonymousSenderPlaintext;
      recipients: readonly AnonymousRecipientSlot[];
    }>,
  ): Promise<EncryptedTransfer> {
    const viewingKey = this.#keypair.viewingKey();
    const tx = viewingKey.transactionViewingKey(input.firstNullifier);
    const salt = randomSalt();
    const slot = (
      scheme: EncryptedScheme,
      recipient: P256PublicKey,
      plaintext: Uint8Array,
      slotIndex: number,
      viewTag: Bytes32,
    ): Readonly<{ viewTag: Bytes32; data: Uint8Array }> => ({
      viewTag,
      data: encodeOutputData(
        scheme,
        encryptAnonymous(tx, recipient, plaintext, salt, slotIndex),
        "encrypted",
      ),
    });
    return Promise.resolve({
      txViewingPublicKey: tx.publicKey(),
      salt,
      payload: [
        slot(
          EncryptedScheme.anonymousSender,
          viewingKey.publicKey(),
          encodeAnonymousSender(input.sender),
          0,
          input.senderViewTag,
        ),
        ...input.recipients.map((recipient, index) =>
          slot(
            EncryptedScheme.anonymousRecipient,
            recipient.recipientPublicKey,
            encodeAnonymousRecipient(recipient.plaintext),
            index + 1,
            recipient.viewTag,
          ),
        ),
      ],
    });
  }

  encryptSplit(
    input: Readonly<{
      firstNullifier: Bytes32;
      viewTag: Bytes32;
      bundle: SplitBundlePlaintext;
    }>,
  ): Promise<EncryptedSplit> {
    const viewingKey = this.#keypair.viewingKey();
    const tx = viewingKey.transactionViewingKey(input.firstNullifier);
    const salt = randomSalt();
    const body = encryptSplit(tx, viewingKey.publicKey(), encodeSplitBundle(input.bundle), salt, 0);
    return Promise.resolve({
      txViewingPublicKey: tx.publicKey(),
      salt,
      payload: {
        viewTag: input.viewTag,
        data: encodeOutputData(EncryptedScheme.split, body, "encrypted"),
      },
    });
  }

  requestUserApproval(request: ApprovalRequest): Promise<void> {
    if (request.solanaPublicKey !== this.#solanaPublicKey) {
      return Promise.reject(new WalletError("WALLET_APPROVAL_IDENTITY_MISMATCH"));
    }
    return Promise.resolve();
  }

  signP256(messageHash: Bytes32): Promise<P256Signature> {
    return Promise.resolve(this.#keypair.signP256(messageHash));
  }
}
