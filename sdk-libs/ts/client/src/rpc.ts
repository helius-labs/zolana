import { PublicKey, Transaction, VersionedTransaction } from "@solana/web3.js";
import { ProofCompressed } from "./prover.js";

export const STATE_TREE_HEIGHT = 32;
export const NULLIFIER_TREE_HEIGHT = 40;

export interface Context {
  slot: bigint | number;
}

export interface MerkleContext {
  treeType: number;
  tree: PublicKey;
}

export interface OutputContext {
  hash: Uint8Array;
  tree: PublicKey;
  leafIndex: bigint | number;
}

export interface OutputSlot {
  viewTag: Uint8Array;
  outputContext: OutputContext;
  payload: Uint8Array;
}

export interface EncryptedUtxoMatch {
  slot: bigint | number;
  txSignature: string;
  outputSlot: OutputSlot;
  txViewingPk?: Uint8Array;
  salt?: Uint8Array;
}

export interface GetEncryptedUtxosByTagsResponse {
  context: Context;
  matches: EncryptedUtxoMatch[];
  nextCursor?: Uint8Array;
}

export interface ShieldedTransaction {
  slot: bigint | number;
  txSignature: string;
  txViewingPk?: Uint8Array;
  salt?: Uint8Array;
  outputSlots: OutputSlot[];
  nullifiers: Uint8Array[];
  proofless: boolean;
}

export interface GetShieldedTransactionsByTagsResponse {
  context: Context;
  transactions: ShieldedTransaction[];
  nextCursor?: Uint8Array;
}

export interface MerkleProof {
  leaf: Uint8Array;
  merkleContext: MerkleContext;
  path: Uint8Array[];
  leafIndex: bigint | number;
  root: Uint8Array;
  rootSeq: bigint | number;
  rootIndex: number;
}

export interface NonInclusionProof {
  leaf: Uint8Array;
  merkleContext: MerkleContext;
  path: Uint8Array[];
  lowElement: Uint8Array;
  lowElementIndex: bigint | number;
  highElement: Uint8Array;
  highElementIndex: bigint | number;
  root: Uint8Array;
  rootSeq: bigint | number;
  rootIndex: number;
}

export interface GetMerkleProofsResponse {
  context: Context;
  proofs: MerkleProof[];
}

export interface GetNonInclusionProofsResponse {
  context: Context;
  proofs: NonInclusionProof[];
}

export interface ProveResult {
  proof: ProofCompressed;
  publicInputs: Uint8Array[];
  circuitId: number;
}

export abstract class Rpc {
  async getAccount(_address: PublicKey): Promise<unknown | undefined> {
    throw unsupported("getAccount");
  }

  async getMultipleAccounts(_addresses: PublicKey[]): Promise<(unknown | undefined)[]> {
    throw unsupported("getMultipleAccounts");
  }

  async getBalance(_address: PublicKey): Promise<bigint> {
    throw unsupported("getBalance");
  }

  async sendTransaction(_transaction: Transaction): Promise<string> {
    throw unsupported("sendTransaction");
  }

  async sendVersionedTransaction(_transaction: VersionedTransaction): Promise<string> {
    throw unsupported("sendVersionedTransaction");
  }

  async getEncryptedUtxosByTags(
    _tags: Uint8Array[],
    _cursor?: Uint8Array,
    _limit?: number,
  ): Promise<GetEncryptedUtxosByTagsResponse> {
    throw unsupported("getEncryptedUtxosByTags");
  }

  async getShieldedTransactionsByTags(
    _tags: Uint8Array[],
    _cursor?: Uint8Array,
    _limit?: number,
  ): Promise<GetShieldedTransactionsByTagsResponse> {
    throw unsupported("getShieldedTransactionsByTags");
  }

  async getMerkleProofs(_treeAccount: PublicKey, _leaves: Uint8Array[]): Promise<GetMerkleProofsResponse> {
    throw unsupported("getMerkleProofs");
  }

  async getNonInclusionProofs(
    _treeAccount: PublicKey,
    _leaves: Uint8Array[],
  ): Promise<GetNonInclusionProofsResponse> {
    throw unsupported("getNonInclusionProofs");
  }

  async prove(_transaction: unknown): Promise<ProveResult> {
    throw unsupported("prove");
  }
}

function unsupported(method: string): Error {
  return new Error(`rpc backend does not implement method \`${method}\``);
}
