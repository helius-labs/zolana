import { type Bytes16, type Bytes32 } from "./bytes.js";
import { P256PublicKey, type ViewTag } from "./public-key.js";
import type { ViewingKeyLike } from "./shielded.js";
export type Salt = Bytes16;
export declare class ViewingKey implements ViewingKeyLike {
    #private;
    private constructor();
    static generate(): ViewingKey;
    static fromBytes(bytes: Bytes32): ViewingKey;
    static fromSeed(walletSeed: Bytes32, account: number): ViewingKey;
    publicKey(): P256PublicKey;
    secretBytes(): Bytes32;
    ecdh(counterparty: P256PublicKey): Bytes32;
    mergeViewTag(mergeCount: bigint): ViewTag;
    recipientBootstrapViewTag(): ViewTag;
    transactionViewingKey(firstNullifier: Bytes32): ViewingKey;
    encryptSlot(recipientPublicKey: P256PublicKey, plaintext: Uint8Array, salt: Salt, slotIndex: number): Uint8Array;
    decryptUtxo(ciphertext: Uint8Array, txViewingPublicKey: P256PublicKey, salt: Salt, slotIndex: number): Uint8Array;
    decryptSlotEphemeral(recipientPublicKey: P256PublicKey, ciphertext: Uint8Array, salt: Salt, slotIndex: number): Uint8Array;
    encryptVerifiable(userViewingPublicKey: P256PublicKey, plaintext: Uint8Array): Readonly<{
        ciphertext: Uint8Array;
        txViewingPublicKey: P256PublicKey;
    }>;
    decryptVerifiable(txViewingPublicKey: P256PublicKey, ciphertext: Uint8Array): Uint8Array;
    destroy(): void;
}
