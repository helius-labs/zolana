import type { Address, Bytes16, Bytes32, MessageData } from "../../interface/types.js";
import type { NullifierKey } from "../../keypair/nullifier-key.js";
import type { P256PublicKey } from "../../keypair/public-key.js";
import type { ShieldedAddress, ShieldedKeypair } from "../../keypair/shielded.js";
import type { ViewingKey } from "../../keypair/viewing-key.js";
import { type AnonymousRecipientPlaintext, type AnonymousSenderPlaintext, type SplitBundlePlaintext } from "../serialization/codecs.js";
import type { ProofOutputUtxo } from "../utxo.js";
import type { AssetRegistry } from "./asset.js";
export type { SplitBundlePlaintext };
export interface ApprovalRequest {
    readonly solanaPublicKey: Address;
    readonly summary: string;
}
/**
 * Per-transaction encryption envelope an authority returns: the ephemeral
 * transaction viewing key and salt every ciphertext in the transaction shares
 * (published in the clear), plus the sealed payload the operation produced.
 */
export interface EncryptedEnvelope<P> {
    readonly txViewingPublicKey: P256PublicKey;
    readonly salt: Bytes16;
    readonly payload: P;
}
/**
 * Transfer payload: one ciphertext per output slot, keyed to that output's
 * owner. `undefined` marks a dummy slot the transfer builder pads with a
 * length-matched random ciphertext.
 */
export type EncryptedTransfer = EncryptedEnvelope<readonly (MessageData | undefined)[]>;
/**
 * Split payload: the single sealed slot-0 bundle covering every real output.
 * Unlike a transfer there is exactly one ciphertext; all other slots stay empty
 * on the wire.
 */
export type EncryptedSplit = EncryptedEnvelope<MessageData>;
export interface AnonymousRecipientSlot {
    readonly viewTag: Bytes32;
    readonly recipientPublicKey: P256PublicKey;
    readonly plaintext: AnonymousRecipientPlaintext;
}
export interface WalletSyncMaterial {
    readonly identity: ShieldedAddress;
    readonly viewingKeys: readonly ViewingKey[];
    readonly nullifierKey: NullifierKey;
}
export interface SyncWalletAuthority {
    syncMaterial(): Promise<WalletSyncMaterial>;
}
export interface WalletAuthority {
    solanaPublicKey(): Address;
    shieldedAddress(): Promise<ShieldedAddress>;
    viewingKeys(): Promise<readonly ViewingKey[]>;
    spendNullifierKey(): Promise<NullifierKey>;
    syncMaterial(): Promise<WalletSyncMaterial>;
    encryptConfidentialTransfer(input: Readonly<{
        firstNullifier: Bytes32;
        outputs: readonly ProofOutputUtxo[];
        assets: AssetRegistry;
    }>): Promise<EncryptedTransfer>;
    encryptAnonymousTransfer(input: Readonly<{
        firstNullifier: Bytes32;
        senderViewTag: Bytes32;
        sender: AnonymousSenderPlaintext;
        recipients: readonly AnonymousRecipientSlot[];
    }>): Promise<EncryptedTransfer>;
    encryptSplit(input: Readonly<{
        firstNullifier: Bytes32;
        viewTag: Bytes32;
        bundle: SplitBundlePlaintext;
    }>): Promise<EncryptedSplit>;
    requestUserApproval(request: ApprovalRequest): Promise<void>;
}
/** Binds local shielded keys to the Solana address that publishes them. */
export declare class LocalWalletAuthority implements WalletAuthority {
    #private;
    constructor(input: Readonly<{
        solanaPublicKey: Address;
        keypair: ShieldedKeypair;
    }>);
    solanaPublicKey(): Address;
    shieldedAddress(): Promise<ShieldedAddress>;
    viewingKeys(): Promise<readonly ViewingKey[]>;
    spendNullifierKey(): Promise<NullifierKey>;
    syncMaterial(): Promise<WalletSyncMaterial>;
    encryptConfidentialTransfer(input: Readonly<{
        firstNullifier: Bytes32;
        outputs: readonly ProofOutputUtxo[];
        assets: AssetRegistry;
    }>): Promise<EncryptedTransfer>;
    /**
     * Slot 0 carries the sender bundle encrypted to this wallet's own viewing
     * key; recipient `i` occupies slot `i + 1`. Both the order and the slot
     * indices are bound into each ciphertext, so they must match the layout the
     * transfer instruction publishes.
     */
    encryptAnonymousTransfer(input: Readonly<{
        firstNullifier: Bytes32;
        senderViewTag: Bytes32;
        sender: AnonymousSenderPlaintext;
        recipients: readonly AnonymousRecipientSlot[];
    }>): Promise<EncryptedTransfer>;
    encryptSplit(input: Readonly<{
        firstNullifier: Bytes32;
        viewTag: Bytes32;
        bundle: SplitBundlePlaintext;
    }>): Promise<EncryptedSplit>;
    /** Local keys approve unattended; Rust takes the trait default here. */
    requestUserApproval(request: ApprovalRequest): Promise<void>;
}
