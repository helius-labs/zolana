import { type Shape } from "../../interface/shape.js";
import { type Address, type Bytes16, type Bytes32, type Signature, type TransactOutput } from "../../interface/types.js";
import { P256PublicKey } from "../../keypair/public-key.js";
import { ShieldedKeypair, type ShieldedAddress } from "../../keypair/shielded.js";
import { ViewingKey } from "../../keypair/viewing-key.js";
import { ProofInputUtxo, Utxo, type ProofOutputUtxo } from "../utxo.js";
import { type AssetRegistry } from "../wallet/asset.js";
export type { Shape };
export declare const SPP_SUPPORTED_SHAPES: readonly Readonly<{
    inputs: number;
    outputs: number;
}>[];
/**
 * Fixed number of leading sender-owned output slots in a transfer: SPL change at
 * slot 0, SOL change at slot 1. Recipients always start at slot 2.
 */
export declare const SENDER_SLOT_COUNT = 2;
/** The BN254 scalar modulus, as the decimal literal Rust pins. */
export declare const BN254_MODULUS_DEC = "21888242871839275222246405745257275088548364400416034343698204186575808495617";
/**
 * A signed public amount as the field element a proof's public inputs carry: a
 * negative amount wraps around the BN254 modulus. Rust takes an `i64`, so the
 * range check here stands in for the type.
 */
export declare function signedToField(value: bigint): Bytes32;
/** The field element an asset mint contributes to a proof's public inputs. */
export declare function assetField(asset: Address): Bytes32;
export declare function canonicalShape(inputs: number, outputs: number): Shape;
/**
 * The proving system whose slot counts the padded transaction already matches.
 * Unlike `canonicalShape` this rounds nothing up: the counts are final by the
 * time a proof is assembled.
 */
export declare function exactShape(inputs: number, outputs: number): Shape;
export declare function resolveShape(inputs: number, outputs: number, declared?: Shape): Shape;
/**
 * The ciphertext ordinal that keys AES-CTR for the slot at `position`, the
 * counterpart of Rust `slot_ordinal`. Every published output of a confidential
 * transfer carries a ciphertext, so the ordinal is the output position. It is a
 * `u32` in the HKDF `info` string, and a wrapped value would reuse a
 * `(key, nonce)` pair across two slots.
 */
export declare function slotOrdinal(position: number): number;
export interface PublicAmounts {
    readonly sol?: bigint;
    readonly spl?: bigint;
}
export type SettlementTransfer = Readonly<{
    kind: "sol";
    isDeposit: boolean;
    amount: bigint;
    userSolAccount: Address;
}> | Readonly<{
    kind: "spl";
    mint: Address;
    isDeposit: boolean;
    amount: bigint;
    userSplToken: Address;
    splTokenInterface: Address;
    vaultBump: number;
}>;
export interface InputUtxoContext {
    readonly index: number;
    readonly utxoHash: Bytes32;
    readonly nullifier: Bytes32;
}
export interface ExternalData {
    readonly instructionDiscriminator: number;
    readonly expiryUnixTs: bigint;
    readonly interfaceTransfers: readonly SettlementTransfer[];
    readonly dataHash?: Bytes32;
    readonly zoneDataHash?: Bytes32;
    readonly txViewingPublicKey: P256PublicKey;
    readonly salt: Bytes16;
    readonly outputs: readonly TransactOutput[];
    readonly resolvedOwnerTags: readonly Bytes32[];
    readonly messages: readonly Readonly<{
        viewTag: Bytes32;
        data: Uint8Array;
    }>[];
    hash(): Bytes32;
    withInterfaceTransfer(transfer: SettlementTransfer): ExternalData;
    withInterfaceTransfers(transfers: readonly SettlementTransfer[]): ExternalData;
}
/**
 * What a caller must supply, the counterpart of Rust `ExternalData::new`. The
 * interface transfers, optional hashes, and expiry carry Rust's defaults, so a
 * confidential transfer names only the fields it actually has.
 */
export interface ExternalDataInit {
    readonly instructionDiscriminator?: number;
    readonly expiryUnixTs?: bigint;
    readonly interfaceTransfers?: readonly SettlementTransfer[];
    readonly dataHash?: Bytes32;
    readonly zoneDataHash?: Bytes32;
    readonly txViewingPublicKey: P256PublicKey;
    readonly salt: Bytes16;
    readonly outputs: readonly TransactOutput[];
    readonly resolvedOwnerTags: readonly Bytes32[];
    readonly messages: readonly Readonly<{
        viewTag: Bytes32;
        data: Uint8Array;
    }>[];
}
export declare function createExternalData(input: ExternalDataInit): ExternalData;
/**
 * A spent UTXO carrying the nullifier public key rather than the secret, for
 * callers that hash a transaction they cannot sign.
 */
export interface InputUtxo {
    readonly utxo: Utxo;
    readonly nullifierPublicKey: Bytes32;
    readonly zoneDataHash?: Bytes32;
    readonly dataHash?: Bytes32;
    hash(): Bytes32;
    isDummy(): boolean;
}
export declare function createInputUtxo(input: Readonly<{
    utxo: Utxo;
    nullifierPublicKey: Bytes32;
    zoneDataHash?: Bytes32;
    dataHash?: Bytes32;
}>): InputUtxo;
export interface PrivateTxHashInput {
    readonly inputHashes: readonly Bytes32[];
    readonly outputHashes: readonly Bytes32[];
    /** One per input slot; omitted means a chain of zeros of the same length. */
    readonly addressHashes?: readonly Bytes32[];
    readonly externalDataHash: Bytes32;
}
/**
 * The circuit reads one address hash per input slot, so a set of a different
 * length would silently shift the address chain rather than fail.
 */
export declare function privateTxHash(input: PrivateTxHashInput): Bytes32;
export interface EncryptedTransaction {
    readonly inputs: readonly InputUtxo[];
    readonly outputs: readonly ProofOutputUtxo[];
    readonly externalData: ExternalData;
    hash(): Bytes32;
}
export declare function createEncryptedTransaction(input: Readonly<{
    inputs: readonly InputUtxo[];
    outputs: readonly ProofOutputUtxo[];
    externalData: ExternalData;
}>): EncryptedTransaction;
export declare class SppProofInputs {
    readonly payerPublicKeyHash: Bytes32;
    readonly inputUtxos: readonly ProofInputUtxo[];
    readonly outputs: readonly ProofOutputUtxo[];
    readonly externalData: ExternalData;
    constructor(input: Readonly<{
        payerPublicKeyHash: Bytes32;
        inputUtxos: readonly ProofInputUtxo[];
        outputs: readonly ProofOutputUtxo[];
        externalData: ExternalData;
    }>);
    checkShape(): Shape;
    inputUtxoHashes(): readonly Bytes32[];
    inputContexts(): readonly InputUtxoContext[];
    dummyNullifiers(): readonly Bytes32[];
    messageHash(): Bytes32;
}
export type WithdrawalTarget = Readonly<{
    kind: "sol";
    recipient: Address;
}> | Readonly<{
    kind: "spl";
    userTokenAccount: Address;
    splTokenInterface: Address;
    vaultBump: number;
}>;
export interface PreparedTransfer {
    readonly owner: ShieldedAddress;
    readonly inputs: readonly ProofInputUtxo[];
    readonly outputs: readonly ProofOutputUtxo[];
    readonly firstNullifier: Bytes32;
    readonly shape: Shape;
    readonly payerPublicKeyHash: Bytes32;
    readonly interfaceTransfers: readonly SettlementTransfer[];
    finalize(input: Readonly<{
        txViewingPublicKey: P256PublicKey;
        salt: Bytes16;
        payload: readonly (Readonly<{
            viewTag: Bytes32;
            data: Uint8Array;
        }> | undefined)[];
    }>): SppProofInputs;
}
export declare class ConfidentialTransfer {
    #private;
    constructor(owner: ShieldedAddress, inputs: readonly ProofInputUtxo[], payer: Address);
    withShape(shape: Shape): this;
    requiresP256Owner(): boolean;
    send(recipient: ShieldedAddress, asset: Address, amount: bigint): void;
    withdraw(asset: Address, amount: bigint, target: WithdrawalTarget): void;
    prepare(): PreparedTransfer;
    /**
     * Keypair rail: encrypt every real slot with the owner's own viewing key and
     * sign in place. The authority rail is `prepare` plus `PreparedTransfer.finalize`,
     * with encryption and signing delegated to a `WalletAuthority`.
     */
    sign(keypair: ShieldedKeypair, assets: AssetRegistry): SppProofInputs;
}
/**
 * Encode each real output as its own confidential ciphertext, keyed to that
 * output's owner viewing key, at `slotIndex == output position`. Dummy outputs
 * yield `undefined`; the transfer builder fills those positions with a
 * length-matched random ciphertext under the sender's tag.
 */
export declare function encodeConfidentialSlots(outputs: readonly ProofOutputUtxo[], assets: AssetRegistry, tx: ViewingKey, salt: Bytes16): readonly (Readonly<{
    viewTag: Bytes32;
    data: Uint8Array;
}> | undefined)[];
export interface OutputContext {
    readonly hash: Bytes32;
    readonly tree: Address;
    readonly leafIndex: bigint;
}
export interface OutputSlot {
    readonly viewTag: Bytes32;
    readonly outputContext: OutputContext;
    readonly payload: Uint8Array;
}
export interface IndexedShieldedTransaction {
    readonly slot: bigint;
    readonly txSignature: Signature;
    readonly txViewingPublicKey?: P256PublicKey;
    readonly salt?: Bytes16;
    readonly outputSlots: readonly OutputSlot[];
    readonly messages: readonly Readonly<{
        viewTag: Bytes32;
        data: Uint8Array;
    }>[];
    readonly nullifiers: readonly Bytes32[];
    readonly proofless: boolean;
}
