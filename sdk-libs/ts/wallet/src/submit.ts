import type { Rpc, ZolanaClient } from "@zolana/client";
import type { Address, Bytes32, RequestContext, Signature, Transaction } from "@zolana/interface";
import { createAssociatedTokenAccountInstruction } from "@zolana/interface/instructions";
import type { MergeTransactInstructionData } from "@zolana/interface/instructions";
import { associatedTokenAddress } from "@zolana/interface/pda";
import type {
  NullifierKey,
  P256PublicKey,
  ShieldedKeypair,
  ShieldedPublicKey,
} from "@zolana/keypair";
import {
  ProofInputUtxo,
  type PreparedMerge,
  type Wallet,
  type WalletUtxo,
} from "@zolana/transaction";
import { Merge } from "@zolana/transaction/instructions";

import { WalletError, wrapWalletError } from "./error.js";
import { bytesKey, compileTransaction, equalBytes } from "./internal.js";
import {
  internalMergingEnabled,
  internalUserRecordAddress,
  resolveRegisteredAddress,
} from "./registry.js";

export interface TransactionSigner {
  readonly address: Address;
  signNativeTransaction(transaction: Transaction): Promise<Transaction>;
}

export async function createAssociatedTokenAccount(
  input: Readonly<{
    rpc: Rpc;
    payer: TransactionSigner;
    owner: Address;
    mint: Address;
  }>,
  context?: RequestContext,
): Promise<Readonly<{ signature: Signature; address: Address }>> {
  try {
    const address = associatedTokenAddress(input.owner, input.mint);
    const latest = await input.rpc.getLatestBlockhash(context);
    const transaction = compileTransaction({
      feePayer: input.payer.address,
      recentBlockhash: latest.blockhash,
      instructions: [
        createAssociatedTokenAccountInstruction({
          payer: input.payer.address,
          owner: input.owner,
          mint: input.mint,
        }),
      ],
    });
    const signed = await input.payer.signNativeTransaction(transaction);
    const signature = await input.rpc.sendTransaction(signed, context);
    return Object.freeze({ signature, address });
  } catch (cause) {
    throw wrapWalletError("WALLET_CREATE_ASSOCIATED_TOKEN_ACCOUNT", cause);
  }
}

export interface MergeParams {
  readonly wallet: Wallet;
  readonly keypair: ShieldedKeypair;
  readonly asset: Address;
  readonly inputs?: readonly Bytes32[];
}

export interface CreatedMerge {
  readonly prepared: PreparedMerge;
  readonly numInputs: number;
  readonly mergedAmount: bigint;
  readonly tree: Address;
}

export function createMerge(params: MergeParams): CreatedMerge {
  const eligible = params.wallet
    .utxos()
    .filter((entry) => !entry.spent && entry.utxo.asset === params.asset);
  const selected = selectMergeEntries(eligible, params.inputs);
  const tree = selected[0]?.outputContext.tree;
  if (tree === undefined) throw new WalletError("WALLET_NOTHING_TO_MERGE");
  if (selected.some((entry) => entry.outputContext.tree !== tree)) {
    throw new WalletError("WALLET_INPUT_UTXO_TREE_MISMATCH");
  }
  const nullifierKey = params.keypair.nullifierKey();
  const inputs = selected.map(
    (entry) =>
      new ProofInputUtxo({
        utxo: entry.utxo,
        nullifierKey,
        ...(entry.dataHash === undefined ? {} : { dataHash: entry.dataHash }),
        ...(entry.zoneDataHash === undefined ? {} : { zoneDataHash: entry.zoneDataHash }),
      }),
  );
  const prepared = new Merge(params.keypair, inputs).prepare();
  return Object.freeze({
    prepared,
    numInputs: selected.length,
    mergedAmount: prepared.output.amount,
    tree,
  });
}

function isPlain(entry: WalletUtxo): boolean {
  return (
    entry.utxo.zoneProgramId === undefined &&
    entry.dataHash === undefined &&
    entry.zoneDataHash === undefined &&
    entry.utxo.data.isEmpty()
  );
}

function selectMergeEntries(
  entries: readonly WalletUtxo[],
  hashes: readonly Bytes32[] | undefined,
): readonly WalletUtxo[] {
  if (hashes !== undefined) {
    if (hashes.length < 2) throw new WalletError("WALLET_NOTHING_TO_MERGE");
    if (hashes.length > 8) {
      throw new WalletError("WALLET_TOO_MANY_INPUTS", {
        details: { got: hashes.length, max: 8 },
      });
    }
    const seen = new Set<string>();
    return hashes.map((hash) => {
      const key = bytesKey(hash);
      if (seen.has(key)) throw new WalletError("WALLET_DUPLICATE_INPUT_UTXO");
      seen.add(key);
      const entry = entries.find((candidate) => equalBytes(candidate.outputContext.hash, hash));
      if (entry === undefined) throw new WalletError("WALLET_INPUT_UTXO_UNAVAILABLE");
      return entry;
    });
  }
  const plain = entries.filter(isPlain);
  const trees = new Set(plain.map((entry) => entry.outputContext.tree));
  if (trees.size > 1) throw new WalletError("WALLET_MULTIPLE_INPUT_TREES");
  const selected = [...plain]
    .sort((left, right) =>
      left.utxo.amount < right.utxo.amount ? -1 : left.utxo.amount > right.utxo.amount ? 1 : 0,
    )
    .slice(0, 8);
  if (selected.length < 2) throw new WalletError("WALLET_NOTHING_TO_MERGE");
  return selected;
}

export class MergeMaterial {
  readonly signingPublicKey: ShieldedPublicKey;
  readonly viewingPublicKey: P256PublicKey;
  readonly nullifierKey: NullifierKey;

  constructor(
    input: Readonly<{
      signingPublicKey: ShieldedPublicKey;
      viewingPublicKey: P256PublicKey;
      nullifierKey: NullifierKey;
    }>,
  ) {
    this.signingPublicKey = input.signingPublicKey;
    this.viewingPublicKey = input.viewingPublicKey;
    this.nullifierKey = input.nullifierKey;
  }

  static fromKeypair(keypair: ShieldedKeypair): MergeMaterial {
    return new MergeMaterial({
      signingPublicKey: keypair.signingPublicKey(),
      viewingPublicKey: keypair.viewingPublicKey(),
      nullifierKey: keypair.nullifierKey(),
    });
  }
}

export interface SubmitMergeTransaction {
  readonly rpc: Rpc;
  readonly indexer: Rpc;
  readonly owner: Address;
  readonly payer: TransactionSigner;
  readonly material: MergeMaterial;
  readonly tree: Address;
  readonly proverUrl: string;
  readonly prepared: PreparedMerge;
}

export interface SubmittedMerge {
  readonly signature: Signature;
  readonly outputHash: Bytes32;
}

interface MergeClient extends Rpc {
  readonly tree: Address;
  proveMerge(
    input: Readonly<{
      prepared: PreparedMerge;
      material: MergeMaterial;
      indexer: Pick<Rpc, "getInputMerkleProofs">;
    }>,
    context?: RequestContext,
  ): Promise<ProvedMerge>;
  finishMergeSubmissionUnsigned(
    input: Readonly<{
      proved: ProvedMerge;
      feePayer: Address;
      userRecord: Address;
      recentBlockhash: string;
    }>,
  ): Transaction;
}

interface ProvedMerge {
  readonly data: MergeTransactInstructionData;
  readonly outputHash: Bytes32;
}

function mergeClient(rpc: Rpc): MergeClient {
  const candidate = rpc as Partial<ZolanaClient>;
  if (
    typeof candidate.proveMerge !== "function" ||
    typeof candidate.finishMergeSubmissionUnsigned !== "function"
  ) {
    throw new WalletError("WALLET_MERGE_CLIENT_REQUIRED");
  }
  return rpc as MergeClient;
}

export async function submitMergeTransaction(
  request: SubmitMergeTransaction,
  context?: RequestContext,
): Promise<SubmittedMerge> {
  try {
    if (!(await internalMergingEnabled({ rpc: request.rpc, owner: request.owner }, context))) {
      throw new WalletError("WALLET_MERGE_DISABLED", {
        details: { owner: request.owner },
      });
    }
    const registered = await resolveRegisteredAddress(
      { rpc: request.rpc, owner: request.owner },
      context,
    );
    if (
      registered === undefined ||
      !equalBytes(
        registered.address.signingPublicKey.toBytes(),
        request.material.signingPublicKey.toBytes(),
      ) ||
      !equalBytes(
        registered.address.viewingPublicKey.toBytes(),
        request.material.viewingPublicKey.toBytes(),
      ) ||
      !equalBytes(registered.address.nullifierPublicKey, request.material.nullifierKey.publicKey())
    ) {
      throw new WalletError("WALLET_MERGE_MATERIAL_MISMATCH");
    }
    const client = mergeClient(request.rpc);
    if (client.tree !== request.tree) {
      throw new WalletError("WALLET_MERGE_TREE_MISMATCH", {
        details: { proofTree: client.tree, submitTree: request.tree },
      });
    }
    const proved = await client.proveMerge(
      {
        prepared: request.prepared,
        material: request.material,
        indexer: request.indexer,
      },
      context,
    );
    const latest = await request.rpc.getLatestBlockhash(context);
    const transaction = client.finishMergeSubmissionUnsigned({
      proved,
      feePayer: request.payer.address,
      userRecord: await internalUserRecordAddress(request.owner),
      recentBlockhash: latest.blockhash,
    });
    const signed = await request.payer.signNativeTransaction(transaction);
    const signature = await request.rpc.sendTransaction(signed, context);
    return Object.freeze({ signature, outputHash: proved.outputHash });
  } catch (cause) {
    throw wrapWalletError("WALLET_SUBMIT_MERGE", cause);
  }
}
