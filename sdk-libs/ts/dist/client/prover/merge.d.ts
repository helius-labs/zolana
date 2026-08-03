import type { Address, Bytes32, MergeTransactInstructionData, RequestContext } from "../../interface/types.js";
import { NullifierKey } from "../../keypair/nullifier-key.js";
import { ShieldedPublicKey } from "../../keypair/public-key.js";
import { PreparedMerge } from "../../transaction/instructions/builders.js";
import type { ZolanaClient } from "../client.js";
import type { NonInclusionProof, SpendProof } from "../rpc.js";
import type { MergeInputs } from "./types.js";
export interface MergeMaterialInput {
    readonly signingPublicKey: ShieldedPublicKey;
    readonly nullifierKey: NullifierKey;
}
export interface MergeAssembly {
    readonly proverInputs: MergeInputs;
    readonly expiryUnixTs: bigint;
    readonly outputHash: Bytes32;
    readonly nullifiers: readonly Bytes32[];
    readonly utxoTreeRootIndexes: readonly number[];
    readonly nullifierTreeRootIndexes: readonly number[];
    readonly privateTxHash: Bytes32;
    readonly publicInputHash: Bytes32;
    readonly externalDataHash: Bytes32;
    readonly eddsaOwner: boolean;
    instructionData(proof: MergeTransactInstructionData["proof"]): MergeTransactInstructionData;
}
export declare function assembleMerge(prepared: PreparedMerge, material: MergeMaterialInput, indexer: Pick<ZolanaClient, "getInputMerkleProofs" | "getNonInclusionProofs">, tree: Address, context?: RequestContext): Promise<MergeAssembly>;
export declare function assembleMergeWithProofs(prepared: PreparedMerge, material: MergeMaterialInput, proofs: readonly SpendProof[], tree: Address, dummyNullifierProofs?: readonly NonInclusionProof[]): MergeAssembly;
