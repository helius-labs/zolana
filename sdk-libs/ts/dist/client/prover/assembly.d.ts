import type { Bytes32 } from "../../interface/types.js";
import { SppProofInputs } from "../../transaction/instructions/transact.js";
import { ProofInputUtxo, type ProofOutputUtxo } from "../../transaction/utxo.js";
import type { NonInclusionProof, SpendProof } from "../rpc.js";
import type { AssembledTransfer, Field, ProverInputs, TransferInput, TransferOutput } from "./types.js";
interface CircuitUtxo {
    readonly domain: Field;
    readonly owner: Field;
    readonly asset: Field;
    readonly amount: Field;
    readonly blinding: Field;
    readonly dataHash: Field;
    readonly zoneDataHash: Field;
    readonly zoneProgramId: Field;
}
export declare function circuitUtxo(value: object): CircuitUtxo;
export declare function intoProver(proofInputs: SppProofInputs, spendProofs: readonly SpendProof[], dummyNullifierProofs?: readonly NonInclusionProof[]): ProverInputs;
export declare function assemble(proofInputs: SppProofInputs, spendProofs: readonly SpendProof[], dummyNullifierProofs?: readonly NonInclusionProof[]): AssembledTransfer;
export interface AssembledSlots {
    readonly transferInputs: readonly TransferInput[];
    readonly inputHashes: readonly bigint[];
    readonly nullifiers: readonly Bytes32[];
    readonly utxoRoots: readonly bigint[];
    readonly nullifierRoots: readonly bigint[];
    readonly inputOwnerFields: readonly bigint[];
    readonly rootIndexes: readonly (readonly [number, number])[];
}
export declare function assembleSlots(proofInputs: SppProofInputs, spendProofs: readonly SpendProof[], dummyNullifierProofs: readonly NonInclusionProof[], ownerField: (input: ProofInputUtxo, index: number) => bigint): AssembledSlots;
export declare function createRealInput(input: ProofInputUtxo, proof: SpendProof, ownerPublicKeyHash: bigint): TransferInput;
export declare function createDummyTransferInput(input: ProofInputUtxo, utxoRoot: bigint, proof: NonInclusionProof, nullifier?: Bytes32): TransferInput;
export declare function createOutput(output: ProofOutputUtxo): TransferOutput;
export declare function validateSpendProof(input: ProofInputUtxo, proof: SpendProof, index: number): void;
export declare function signedField(value: bigint, name: string): bigint;
export declare function asField(value: bigint): Field;
export declare function asInteger(value: bigint): Field;
export {};
