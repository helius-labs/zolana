import type { Address, Bytes16, Bytes32 } from "../../interface/types.js";
import type { NullifierKey } from "../../keypair/nullifier-key.js";
import type { P256PublicKey, ShieldedPublicKey } from "../../keypair/public-key.js";
import { ShieldedKeypair, type ShieldedAddress } from "../../keypair/shielded.js";
import { ProofInputUtxo, type ProofOutputUtxo } from "../utxo.js";
import { type AssetRegistry } from "../wallet/asset.js";
import { SppProofInputs, type InputUtxoContext } from "./transact.js";
/** Padded input count of the merge circuit, the counterpart of Rust `MERGE_INPUTS`. */
export declare const MERGE_INPUTS = 8;
export declare class PreparedMerge {
    readonly inputs: readonly ProofInputUtxo[];
    readonly output: ProofOutputUtxo;
    readonly expiryUnixTs: bigint;
    readonly signingPublicKey: ShieldedPublicKey;
    constructor(input: Readonly<{
        inputs: readonly ProofInputUtxo[];
        output: ProofOutputUtxo;
        expiryUnixTs: bigint;
        signingPublicKey: ShieldedPublicKey;
    }>);
    inputUtxoHashes(): readonly InputUtxoContext[];
    dummyNullifiers(nullifierKey: NullifierKey): readonly Bytes32[];
}
export declare class Merge {
    #private;
    constructor(identity: ShieldedKeypair | Readonly<{
        address: ShieldedAddress;
        nullifierKey: NullifierKey;
    }>, inputs: readonly ProofInputUtxo[]);
    prepare(): PreparedMerge;
    withExpiry(expiryUnixTs: bigint): this;
}
export declare class ConfidentialSplit {
    #private;
    constructor(input: Readonly<{
        owner: ShieldedAddress;
        input: ProofInputUtxo;
        asset: Address;
        numOutputs: number;
        perOutputAmount: bigint;
        payer: Address;
    }>);
    prepare(): PreparedSplit;
    /**
     * Keypair rail: assemble with the owner's own viewing key, seal the bundle at
     * slot 0, and sign in place. The authority rail is `prepare` plus
     * `PreparedSplit.finalize`, with encryption and signing delegated to a
     * `WalletAuthority`.
     */
    sign(keypair: ShieldedKeypair, assets: AssetRegistry): SppProofInputs;
}
export declare class PreparedSplit {
    readonly owner: ShieldedAddress;
    readonly input: ProofInputUtxo;
    readonly asset: Address;
    readonly outputs: readonly ProofOutputUtxo[];
    readonly firstNullifier: Bytes32;
    readonly numOutputs: number;
    readonly perOutputAmount: bigint;
    readonly blindingSeed: Bytes32;
    readonly payerPublicKeyHash: Bytes32;
    constructor(input: Readonly<{
        owner: ShieldedAddress;
        input: ProofInputUtxo;
        outputs: readonly ProofOutputUtxo[];
        numOutputs: number;
        perOutputAmount: bigint;
        blindingSeed: Bytes32;
        payerPublicKeyHash: Bytes32;
    }>);
    bundlePlaintext(assets: AssetRegistry): import("../serialization/codecs.js").SplitBundlePlaintext;
    /**
     * The owner's confidential view tag. It tags the bundle at slot 0 and every
     * covered real output, and equals the bundle view tag because the split is
     * self-owned.
     */
    ownerViewTag(): Bytes32;
    finalize(input: Readonly<{
        txViewingPublicKey: P256PublicKey;
        salt: Bytes16;
        payload: Readonly<{
            viewTag: Bytes32;
            data: Uint8Array;
        }>;
    }>): SppProofInputs;
}
