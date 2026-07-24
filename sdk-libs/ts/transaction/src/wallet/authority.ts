import type { Address, Bytes16, Bytes32 } from "@zolana/interface";
import type { NullifierKey, P256PublicKey, ShieldedAddress, ViewingKey } from "@zolana/keypair";

import type { ProofOutputUtxo } from "../utxo.js";
import type { AssetRegistry } from "./asset.js";

export interface P256Signature {
  readonly publicKey: P256PublicKey;
  readonly r: Bytes32;
  readonly s: Bytes32;
}

export interface EncryptedTransfer {
  readonly txViewingPublicKey: P256PublicKey;
  readonly salt: Bytes16;
  readonly payload: readonly (
    | Readonly<{
        viewTag: Bytes32;
        data: Uint8Array;
      }>
    | undefined
  )[];
}

export interface SplitBundlePlaintext {
  readonly ownerPublicKey: import("@zolana/keypair").ShieldedPublicKey;
  readonly numOutputs: number;
  readonly assetId: bigint;
  readonly assetAmount: bigint;
  readonly blindingSeed: import("@zolana/interface").Bytes31;
  readonly data: import("../data.js").Data;
}

export interface EncryptedSplit {
  readonly txViewingPublicKey: P256PublicKey;
  readonly salt: Bytes16;
  readonly payload: Readonly<{ viewTag: Bytes32; data: Uint8Array }>;
}

export interface WalletSyncMaterial {
  readonly identity: ShieldedAddress;
  readonly viewingKeys: readonly ViewingKey[];
  readonly nullifierKey: NullifierKey;
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
  requestUserApproval(
    request: Readonly<{
      solanaPublicKey: Address;
      summary: string;
    }>,
  ): Promise<void>;
  signP256(messageHash: Bytes32): Promise<P256Signature>;
}
