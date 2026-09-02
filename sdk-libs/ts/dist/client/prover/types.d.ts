import type { Bytes32, Bytes64, Bytes128, TransactInstructionData, TransactProof } from "../../interface/types.js";
import type { ProofInputUtxo } from "../../transaction/utxo.js";
import type { SpendProof } from "../rpc.js";
export type Shape = Readonly<{
    inputs: number;
    outputs: number;
}>;
export type Field = bigint & {
    readonly __bn254Field: unique symbol;
};
export interface TransferInput {
    readonly utxo: ProofInputUtxo;
    readonly isDummy: Field;
    readonly statePathElements: readonly Field[];
    readonly statePathIndex: Field;
    readonly nullifierLowValue: Field;
    readonly nullifierNextValue: Field;
    readonly nullifierLowPathElements: readonly Field[];
    readonly nullifierLowPathIndex: Field;
    readonly utxoTreeRoot: Field;
    readonly nullifierTreeRoot: Field;
    readonly nullifier: Field;
    readonly ownerPublicKeyHash: Field;
    readonly nullifierSecret: Field;
}
export interface TransferOutput {
    readonly utxo: ProofInputUtxo;
    readonly isDummy: Field;
    readonly hash: Field;
    readonly ownerPublicKeyHash: Field;
    readonly nullifierPublicKey: Field;
}
export interface TransferInputs {
    readonly inputs: readonly TransferInput[];
    readonly outputs: readonly TransferOutput[];
    readonly externalDataHash: Field;
    readonly privateTxHash: Field;
    readonly publicAssets: readonly Field[];
    readonly publicAmounts: readonly Field[];
    readonly zoneProgramId: Field;
    readonly signerPublicKeyHashes: readonly Field[];
    readonly allowDummyInputs: Field;
    readonly publishedOutputOwnerPublicKeyHashes: readonly Field[];
    readonly publicInputHash: Field;
}
export interface MergeInputs {
    readonly inputs: readonly TransferInput[];
    readonly output: TransferOutput;
    readonly ownerPublicKeyHash: Field;
    readonly userNullifierPublicKey: Field;
    readonly userNullifierSecret: Field;
    readonly externalDataHash: Field;
    readonly privateTxHash: Field;
    readonly allowDummyInputs: Field;
    readonly publicInputHash: Field;
    readonly outputZoneDataHash: Field;
    readonly zoneProgramId: Field;
}
export type ProverInputs = Readonly<{
    circuit: "transfer";
    payload: TransferInputs;
}>;
export interface AssembledTransfer {
    readonly instructionData: TransactInstructionData;
    readonly proverInputs: ProverInputs;
    readonly publicInputHash: Bytes32;
    readonly nullifiers: readonly Bytes32[];
    readonly outputHashes: readonly Bytes32[];
    readonly privateTxHash: Bytes32;
    readonly inputRootIndexes: readonly (readonly [number, number])[];
    withProof(proof: TransactProof): TransactInstructionData;
}
export interface Proof {
    readonly a: Bytes64;
    readonly b: Bytes128;
    readonly c: Bytes64;
}
export interface CompressedProof {
    readonly a: Bytes32;
    readonly b: Bytes64;
    readonly c: Bytes32;
    toTransactProof(): TransactProof;
}
export type { SpendProof };
