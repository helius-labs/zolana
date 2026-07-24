import type { Address, Bytes32 } from "@zolana/interface";
import {
  randomSalt,
  type NullifierKey,
  type ShieldedAddress,
  type ShieldedKeypair,
  type ViewingKey,
} from "@zolana/keypair";
import type {
  AssetRegistry,
  EncryptedSplit,
  EncryptedTransfer,
  P256Signature,
  ProofOutputUtxo,
  SplitBundlePlaintext,
  WalletSyncMaterial,
} from "@zolana/transaction";
import {
  EncryptedScheme,
  encodeOutputData,
  encodeSplitBundle,
  encryptConfidential,
  encryptSplit,
} from "@zolana/transaction/serialization";

import { WalletError } from "./error.js";

export interface ApprovalRequest {
  readonly solanaPublicKey: Address;
  readonly summary: string;
}

export interface WalletAuthority {
  solanaPublicKey(): Address;
  shieldedAddress(): Promise<ShieldedAddress>;
  viewingKeys(): Promise<readonly ViewingKey[]>;
  spendNullifierKey(): Promise<NullifierKey>;
  syncMaterial(): Promise<WalletSyncMaterial>;
  encryptConfidentialTransfer(
    input: Readonly<{
      firstNullifier: Bytes32;
      outputs: readonly ProofOutputUtxo[];
      assets: AssetRegistry;
    }>,
  ): Promise<EncryptedTransfer>;
  encryptSplit(
    input: Readonly<{
      firstNullifier: Bytes32;
      viewTag: Bytes32;
      bundle: SplitBundlePlaintext;
    }>,
  ): Promise<EncryptedSplit>;
  requestUserApproval(request: ApprovalRequest): Promise<void>;
  signP256(messageHash: Bytes32): Promise<P256Signature>;
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
