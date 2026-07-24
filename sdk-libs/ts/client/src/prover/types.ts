import type {
  Bytes32,
  Bytes64,
  Bytes128,
  TransactInstructionData,
  TransactProof,
} from "@zolana/interface";
import type { ProofInputUtxo } from "@zolana/transaction";

import type { SpendProof } from "../rpc.js";

export type Shape = Readonly<{ inputs: number; outputs: number }>;
export type Field = bigint & { readonly __bn254Field: unique symbol };

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
  readonly publicSolAmount: Field;
  readonly publicSplAmount: Field;
  readonly publicSplAssetPublicKey: Field;
  readonly zoneProgramId: Field;
  readonly payerPublicKeyHash: Field;
  readonly publicInputHash: Field;
}

export interface TransferP256Inputs extends TransferInputs {
  readonly p256PublicKeyX: Field;
  readonly p256PublicKeyY: Field;
  readonly p256SignatureR: Field;
  readonly p256SignatureS: Field;
  readonly p256MessageHashLow: Field;
  readonly p256MessageHashHigh: Field;
  readonly p256SigningPublicKeyField: Field;
}

export type ProverInputs =
  | Readonly<{ circuit: "transfer"; payload: TransferInputs }>
  | Readonly<{ circuit: "transferP256"; payload: TransferP256Inputs }>;

export interface AssembledTransfer {
  readonly instructionData: TransactInstructionData;
  readonly proverInputs: ProverInputs;
  withProof(proof: TransactProof): TransactInstructionData;
}

export interface Proof {
  readonly a: Bytes64;
  readonly b: Bytes128;
  readonly c: Bytes64;
  readonly commitment?: Readonly<{
    readonly commitment: Bytes64;
    readonly commitmentPok: Bytes64;
  }>;
}

export interface CompressedProof {
  readonly a: Bytes32;
  readonly b: Bytes64;
  readonly c: Bytes32;
  readonly commitment?: Readonly<{
    readonly commitment: Bytes32;
    readonly commitmentPok: Bytes32;
  }>;
  toTransactProof(): TransactProof;
}

export type { SpendProof };
