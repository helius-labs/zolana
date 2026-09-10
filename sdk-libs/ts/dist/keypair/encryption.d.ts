import { P256PublicKey } from "./public-key.js";
export declare function ecdhX(secret: Uint8Array, counterparty: P256PublicKey): Uint8Array;
export declare function applyTransferCipher(secret: Uint8Array, counterparty: P256PublicKey, ephemeralPublicKey: P256PublicKey, recipientPublicKey: P256PublicKey, input: Uint8Array, salt: Uint8Array, slotIndex: number): Uint8Array;
