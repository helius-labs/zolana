import { PublicKey as SolanaPublicKey } from "@solana/web3.js";
import { NullifierKey, P256Pubkey, ShieldedAddress, ShieldedKeypair } from "./keypair.js";

export interface P256Signature {
  sigR: Uint8Array;
  sigS: Uint8Array;
}

export interface ApprovalRequest {
  ownerPubkey: SolanaPublicKey;
  summary: string;
}

export interface ConfidentialRecipientSlot {
  viewTag: Uint8Array;
  recipientPubkey: P256Pubkey;
  plaintext: Uint8Array;
}

export interface AnonymousRecipientSlot {
  viewTag: Uint8Array;
  plaintext: Uint8Array;
}

export interface EncryptedSlot {
  viewTag: Uint8Array;
  data: Uint8Array;
}

export interface EncryptedTransfer {
  txViewingPk: P256Pubkey;
  salt: Uint8Array;
  slots: EncryptedSlot[];
}

export interface WalletAuthority {
  shieldedAddress(ownerPubkey: SolanaPublicKey): Promise<ShieldedAddress>;
  requestUserApproval(request: ApprovalRequest): Promise<void>;
  signP256(ownerPubkey: SolanaPublicKey, messageHash: Uint8Array): Promise<P256Signature>;
  spendNullifierKey(ownerPubkey: SolanaPublicKey): Promise<NullifierKey>;
}

export class LocalWalletAuthority implements WalletAuthority {
  constructor(readonly keypair: ShieldedKeypair) {}

  async shieldedAddress(_ownerPubkey: SolanaPublicKey): Promise<ShieldedAddress> {
    return this.keypair.shieldedAddress();
  }

  async requestUserApproval(_request: ApprovalRequest): Promise<void> {
    return;
  }

  async signP256(_ownerPubkey: SolanaPublicKey, messageHash: Uint8Array): Promise<P256Signature> {
    const sig = this.keypair.sign(messageHash);
    return { sigR: sig.slice(0, 32), sigS: sig.slice(32) };
  }

  async spendNullifierKey(_ownerPubkey: SolanaPublicKey): Promise<NullifierKey> {
    return this.keypair.nullifierKey;
  }
}
