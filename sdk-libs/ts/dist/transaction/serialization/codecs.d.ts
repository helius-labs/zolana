import type { Address, Bytes16, Bytes32 } from "../../interface/types.js";
import { P256PublicKey, ShieldedPublicKey } from "../../keypair/public-key.js";
import type { ViewingKeyLike } from "../../keypair/shielded.js";
import type { ViewingKey } from "../../keypair/viewing-key.js";
import { Data } from "../data.js";
import { type AssetRegistry } from "../wallet/asset.js";
import { Utxo } from "../utxo.js";
/**
 * The type prefix each encrypted family writes into its plaintext body. These
 * live beside the reader and the writer that enforce them so a wire-format
 * change has one place to happen; the package root re-exports them, as the Rust
 * crate root does.
 */
export declare const TRANSFER = 1;
export declare const SPLIT = 2;
export declare const MERGE = 3;
export declare const TRANSFER_PLAINTEXT = 4;
export declare const EncryptedScheme: Readonly<{
    readonly proofless: 0;
    readonly anonymousRecipient: 1;
    readonly anonymousSender: 2;
    readonly confidential: 3;
    readonly split: 5;
    readonly merge: 6;
    readonly plaintextTransfer: 7;
}>;
export type EncryptedScheme = (typeof EncryptedScheme)[keyof typeof EncryptedScheme];
export type OutputDataEncoding = "plaintext" | "encrypted" | "verifiable";
export declare function encryptedSchemeFromByte(byte: number): EncryptedScheme;
/** The wire byte for a scheme, the counterpart of Rust `EncryptedScheme::as_byte`. */
export declare function encryptedSchemeToByte(scheme: EncryptedScheme): number;
export declare function outputDataEncoding(scheme: EncryptedScheme): OutputDataEncoding;
export interface ConfidentialOutputPlaintext {
    readonly assetId: bigint;
    readonly amount: bigint;
    readonly blinding: Bytes32;
    readonly zoneProgramId?: Address;
    readonly data: Data;
}
export interface AnonymousRecipientPlaintext {
    readonly ownerPublicKey: ShieldedPublicKey;
    readonly senderPublicKey: P256PublicKey;
    readonly assetId: bigint;
    readonly amount: bigint;
    readonly blinding: Bytes32;
    readonly data: Data;
}
export interface AnonymousSenderPlaintext {
    readonly ownerPublicKey: ShieldedPublicKey;
    readonly splAssetId: bigint;
    readonly splAmount: bigint;
    readonly solAmount: bigint;
    readonly blindingSeed: Bytes32;
    readonly recipientViewingPublicKeys: readonly P256PublicKey[];
    readonly splData: Data;
    readonly solData: Data;
}
export interface SplitBundlePlaintext {
    readonly ownerPublicKey: ShieldedPublicKey;
    readonly numOutputs: number;
    readonly assetId: bigint;
    readonly assetAmount: bigint;
    readonly blindingSeed: Bytes32;
    readonly data: Data;
}
export interface SplitEncryptedUtxos {
    readonly typePrefix: number;
    readonly txViewingPublicKey: P256PublicKey;
    readonly salt: Bytes16;
    readonly ciphertext: Uint8Array;
}
export interface TransferPlaintextSplChange {
    readonly amount: bigint;
    readonly assetId: bigint;
}
export interface TransferPlaintextSender {
    readonly ownerPublicKey: ShieldedPublicKey;
    readonly spl?: TransferPlaintextSplChange;
    readonly solAmount?: bigint;
    readonly splData: Data;
    readonly solData: Data;
}
export interface TransferPlaintextRecipient {
    readonly ownerPublicKey: ShieldedPublicKey;
    readonly assetId: bigint;
    readonly amount: bigint;
    readonly data: Data;
}
export interface TransferPlaintextUtxos {
    readonly typePrefix: number;
    readonly blindingSeed: Bytes32;
    readonly sender?: TransferPlaintextSender;
    readonly recipientSlots: readonly TransferPlaintextRecipient[];
}
export interface ProoflessOutput {
    readonly owner: Bytes32;
    readonly blinding: Bytes32;
    readonly asset: Address;
    readonly amount: bigint;
    readonly dataHash?: Bytes32;
    readonly utxoData?: Uint8Array;
    readonly zoneProgramId?: Address;
    readonly zoneDataHash?: Bytes32;
    readonly zoneData?: Uint8Array;
    readonly memo?: Uint8Array;
}
export declare function encodeData(data: Data): Uint8Array;
export declare function decodeData(bytes: Uint8Array): Data;
export declare function encodeConfidential(value: ConfidentialOutputPlaintext): Uint8Array;
export declare function decodeConfidential(bytes: Uint8Array): ConfidentialOutputPlaintext;
export declare function confidentialUtxo(value: ConfidentialOutputPlaintext, owner: ShieldedPublicKey, assets: AssetRegistry): Utxo;
export declare function confidentialPlaintextFromUtxo(utxo: Utxo, owner: ShieldedPublicKey, assets: AssetRegistry): ConfidentialOutputPlaintext;
export declare function encodeAnonymousRecipient(value: AnonymousRecipientPlaintext): Uint8Array;
export declare function decodeAnonymousRecipient(bytes: Uint8Array): AnonymousRecipientPlaintext;
export declare function anonymousRecipientUtxo(value: AnonymousRecipientPlaintext, assets: AssetRegistry, zoneProgramId?: Address): Utxo;
export declare function encodeAnonymousSender(value: AnonymousSenderPlaintext): Uint8Array;
export declare function decodeAnonymousSender(bytes: Uint8Array): AnonymousSenderPlaintext;
export declare function anonymousSenderUtxos(value: AnonymousSenderPlaintext, assets: AssetRegistry, solMint: Address, zoneProgramId?: Address): readonly Utxo[];
export declare function encodePlaintextTransfer(value: TransferPlaintextUtxos): Uint8Array;
export declare function decodePlaintextTransfer(bytes: Uint8Array, expectedTypePrefix?: number): TransferPlaintextUtxos;
/**
 * Rust `TransferPlaintextUtxos::into_utxos`. Slot 0 is the sender's SPL
 * change, slot 1 its SOL change, and recipients follow from slot 2; the
 * position is what derives each blinding, so it is also the position the
 * published output slot must sit at.
 */
export declare function plaintextTransferUtxos(value: TransferPlaintextUtxos, assets: AssetRegistry, solMint: Address, zoneProgramId?: Address): readonly Utxo[];
export declare function encodeSplitBundle(value: SplitBundlePlaintext): Uint8Array;
export declare function decodeSplitBundle(bytes: Uint8Array): SplitBundlePlaintext;
export declare function encodeSplitEncrypted(value: SplitEncryptedUtxos): Uint8Array;
export declare function decodeSplitEncrypted(bytes: Uint8Array): SplitEncryptedUtxos;
export declare function splitBundleUtxos(value: SplitBundlePlaintext, assets: AssetRegistry, zoneProgramId?: Address): readonly Utxo[];
export declare function encodeOutputData(scheme: EncryptedScheme, body: Uint8Array, encoding?: OutputDataEncoding): Uint8Array;
/**
 * The encoding tag, scheme byte, and remaining body of a slot payload, without
 * requiring the pair to agree. Rust's `OutputDataEncoding::try_from_slice`
 * reads the two independently and every reader dispatches on the pair, so a
 * mismatched payload has to survive parsing in order to be refused where the
 * dispatch happens. Prefer [`decodeOutputData`] unless you are that dispatch.
 */
export declare function readOutputData(bytes: Uint8Array): Readonly<{
    encoding: OutputDataEncoding;
    scheme: EncryptedScheme;
    body: Uint8Array;
}>;
export declare function decodeOutputData(bytes: Uint8Array): Readonly<{
    encoding: OutputDataEncoding;
    scheme: EncryptedScheme;
    body: Uint8Array;
}>;
export declare function encodeProofless(value: ProoflessOutput): Uint8Array;
export declare function decodeProofless(bytes: Uint8Array): ProoflessOutput;
/**
 * Rust `Proofless::into_utxos`. The deposit rail publishes its zone binding in
 * the payload beside the zone data, so unlike the reader-supplied rails there
 * is nothing to resolve; a zone data hash that contradicts the binding is
 * caught when the commitment is computed.
 */
export declare function prooflessUtxo(value: ProoflessOutput, owner: ShieldedPublicKey): Utxo;
export declare function encryptConfidential(tx: ViewingKeyLike, recipient: P256PublicKey, value: ConfidentialOutputPlaintext, salt: Bytes16, slotIndex: number): Uint8Array;
export declare function encryptAnonymous(tx: ViewingKeyLike, recipient: P256PublicKey, plaintext: Uint8Array, salt: Bytes16, slotIndex: number): Uint8Array;
export declare function decryptAnonymous(key: ViewingKeyLike, txViewingPublicKey: P256PublicKey, ciphertext: Uint8Array, salt: Bytes16, slotIndex: number): Uint8Array;
export declare const encryptSplit: typeof encryptAnonymous;
export declare const decryptSplit: typeof decryptAnonymous;
export declare function decryptConfidential(key: ViewingKeyLike, txViewingPublicKey: P256PublicKey, body: Uint8Array, salt: Bytes16, slotIndex: number): ConfidentialOutputPlaintext;
export declare function decryptConfidentialAsSender(tx: ViewingKeyLike, body: Uint8Array, salt: Bytes16, slotIndex: number): ConfidentialOutputPlaintext;
/**
 * Everything a wallet needs to open one output slot, the counterpart of Rust
 * `DecodeCx`. Each field is per-transaction except `slotIndex`, and the
 * encryption schemes bind the slot index, so a context built for one slot must
 * not be reused to open another.
 */
export interface DecodeContext {
    readonly viewingKey: ViewingKey;
    readonly txViewingPublicKey?: P256PublicKey;
    readonly salt?: Bytes16;
    readonly slotIndex: number;
    readonly firstNullifier?: Bytes32;
}
/**
 * Structural view of an indexed transaction, kept local so the codecs stay
 * independent of the instruction types that own the full shape.
 */
type DecodeSource = Readonly<{
    txViewingPublicKey?: P256PublicKey;
    salt?: Bytes16;
    nullifiers: readonly Bytes32[];
}>;
export declare function decodeContextForSlot(viewingKey: ViewingKey, transaction: DecodeSource, slotIndex: number): DecodeContext;
/**
 * The owner, registry, and zone a set of output UTXOs is converted under, the
 * counterpart of Rust `OwnerCx`. The conversions below are the counterparts of
 * the `UtxoSerialization::from_utxos` implementations, which is where a builder
 * turns the UTXOs it just derived back into the plaintext it will encrypt.
 */
export interface OwnerContext {
    readonly owner: ShieldedPublicKey;
    readonly assets: AssetRegistry;
    readonly zoneProgramId?: Address;
}
export declare function plaintextTransferFromUtxos(utxos: readonly Utxo[], owner: OwnerContext, cx: Readonly<{
    blindingSeed: Bytes32;
}>): TransferPlaintextUtxos;
export declare function anonymousRecipientFromUtxos(utxos: readonly Utxo[], owner: OwnerContext, cx: Readonly<{
    senderPublicKey: P256PublicKey;
}>): AnonymousRecipientPlaintext;
export declare function anonymousSenderFromUtxos(utxos: readonly Utxo[], owner: OwnerContext, cx: Readonly<{
    blindingSeed: Bytes32;
    recipientViewingPublicKeys: readonly P256PublicKey[];
}>): AnonymousSenderPlaintext;
export declare function splitBundleFromUtxos(utxos: readonly Utxo[], owner: OwnerContext, cx: Readonly<{
    blindingSeed: Bytes32;
}>): SplitBundlePlaintext;
export declare function prooflessFromUtxos(utxos: readonly Utxo[], owner: OwnerContext, cx: Readonly<{
    ownerHash: Bytes32;
    dataHash?: Bytes32;
    zoneDataHash?: Bytes32;
}>): ProoflessOutput;
export {};
