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
import { bytesKey, compileTransaction, decodeBase58, equalBytes } from "./internal.js";
import {
  internalMergeSubmissionRecord,
  internalUserRecordAddress,
  type MergeSubmissionRecord,
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
    // The compiled message reserves one slot per required signer. Sending a
    // transaction with an unfilled slot wastes a round trip on a message the
    // cluster rejects.
    const missing = signed.signatures.findIndex((signature) => signature === undefined);
    if (signed.signatures.length !== transaction.signatures.length || missing !== -1) {
      throw new WalletError("WALLET_INCOMPLETE_SIGNATURES", {
        details: {
          required: transaction.signatures.length,
          provided: signed.signatures.length,
          ...(missing === -1 ? {} : { missingIndex: missing }),
        },
      });
    }
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
  // Named inputs bind the spend to the first named utxo's tree and the rest
  // must match it; an auto-sweep resolves the tree over the plain utxos. Rust
  // settles the tree before it counts the named hashes, so a single unknown
  // hash reports the utxo and not the input count.
  const first = params.inputs?.[0];
  const tree =
    first === undefined ? sweepTree(eligible, params.asset) : namedInputTree(eligible, first);
  const selected = selectMergeEntries(eligible, tree, params.asset, params.inputs);
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

function namedInputTree(entries: readonly WalletUtxo[], hash: Bytes32): Address {
  const entry = entries.find((candidate) => equalBytes(candidate.outputContext.hash, hash));
  if (entry === undefined) {
    throw new WalletError("WALLET_INPUT_UTXO_UNAVAILABLE", { details: { hash } });
  }
  return entry.outputContext.tree;
}

function sweepTree(entries: readonly WalletUtxo[], asset: Address): Address {
  const trees = new Set(entries.filter(isPlain).map((entry) => entry.outputContext.tree));
  if (trees.size === 0) {
    throw new WalletError("WALLET_INSUFFICIENT_BALANCE", {
      details: { requested: "1", available: "0" },
    });
  }
  if (trees.size !== 1) {
    throw new WalletError("WALLET_MULTIPLE_INPUT_TREES", {
      details: { asset, treeCount: trees.size },
    });
  }
  return [...trees][0] as Address;
}

function selectMergeEntries(
  entries: readonly WalletUtxo[],
  tree: Address,
  asset: Address,
  hashes: readonly Bytes32[] | undefined,
): readonly WalletUtxo[] {
  if (hashes !== undefined) {
    if (hashes.length > 8) {
      throw new WalletError("WALLET_TOO_MANY_INPUTS", {
        details: { got: hashes.length, max: 8 },
      });
    }
    if (hashes.length < 2) throw new WalletError("WALLET_NOTHING_TO_MERGE", { details: { asset } });
    const seen = new Set<string>();
    return hashes.map((hash) => {
      const key = bytesKey(hash);
      if (seen.has(key)) {
        throw new WalletError("WALLET_DUPLICATE_INPUT_UTXO", { details: { hash } });
      }
      seen.add(key);
      const entry = entries.find((candidate) => equalBytes(candidate.outputContext.hash, hash));
      if (entry === undefined) {
        throw new WalletError("WALLET_INPUT_UTXO_UNAVAILABLE", { details: { hash } });
      }
      // A named utxo on another tree is a mismatch, not an unknown hash: the
      // owner can see it in their own listing.
      if (entry.outputContext.tree !== tree) {
        throw new WalletError("WALLET_INPUT_UTXO_TREE_MISMATCH", {
          details: { hash, utxoTree: entry.outputContext.tree, spendTree: tree },
        });
      }
      return entry;
    });
  }
  // Smallest first: a sweep clears dust and leaves large utxos intact.
  const selected = entries
    .filter((entry) => entry.outputContext.tree === tree && isPlain(entry))
    .sort((left, right) =>
      left.utxo.amount < right.utxo.amount ? -1 : left.utxo.amount > right.utxo.amount ? 1 : 0,
    )
    .slice(0, 8);
  if (selected.length < 2) throw new WalletError("WALLET_NOTHING_TO_MERGE", { details: { asset } });
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

/**
 * `rpc` must be a `ZolanaClient`: it both sends the transaction and owns the
 * prover connection, so no prover URL is passed separately here.
 */
export interface SubmitMergeTransaction {
  readonly rpc: Rpc;
  readonly indexer: Rpc;
  readonly owner: Address;
  readonly payer: TransactionSigner;
  readonly material: MergeMaterial;
  readonly tree: Address;
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

/**
 * The registry record commits the identity the on-chain program checks, so a
 * mismatch can only fail after a proof has been paid for. Each key is reported
 * separately because they fail for unrelated reasons.
 */
function validateMergeSubmission(
  record: MergeSubmissionRecord,
  owner: Address,
  material: MergeMaterial,
): void {
  if (!record.mergingEnabled) {
    throw new WalletError("WALLET_MERGE_DISABLED", { details: { owner } });
  }
  const signingPublicKey = material.signingPublicKey;
  if (signingPublicKey.signatureType() === "p256") {
    if (
      record.ownerP256 === undefined ||
      !equalBytes(record.ownerP256, signingPublicKey.p256().toBytes())
    ) {
      throw new WalletError("WALLET_MERGE_SIGNING_KEY_MISMATCH");
    }
  } else if (
    record.ownerP256 !== undefined ||
    !equalBytes(signingPublicKey.ed25519(), decodeBase58(owner, 32, "owner"))
  ) {
    throw new WalletError("WALLET_MERGE_SIGNING_KEY_MISMATCH");
  }
  if (!equalBytes(record.nullifierPublicKey, material.nullifierKey.publicKey())) {
    throw new WalletError("WALLET_MERGE_NULLIFIER_KEY_MISMATCH");
  }
  if (!equalBytes(record.viewingPublicKey, material.viewingPublicKey.toBytes())) {
    throw new WalletError("WALLET_MERGE_VIEWING_KEY_MISMATCH", { details: { owner } });
  }
}

/**
 * A merge proof only verifies against the tree its input proofs were resolved
 * from, so an indexer answering from another tree must be rejected before the
 * proof is paid for.
 */
function treeCheckedIndexer(
  indexer: Pick<Rpc, "getInputMerkleProofs">,
  submitTree: Address,
): Pick<Rpc, "getInputMerkleProofs"> {
  return {
    getInputMerkleProofs: async (commitments, config, context) => {
      const proofs = await indexer.getInputMerkleProofs(commitments, config, context);
      for (const proof of proofs) {
        for (const proofTree of [
          proof.state.merkleContext.tree,
          proof.nullifier.merkleContext.tree,
        ])
          if (proofTree !== submitTree) {
            throw new WalletError("WALLET_MERGE_TREE_MISMATCH", {
              details: { proofTree, submitTree },
            });
          }
      }
      return proofs;
    },
  };
}

export async function submitMergeTransaction(
  request: SubmitMergeTransaction,
  context?: RequestContext,
): Promise<SubmittedMerge> {
  try {
    validateMergeSubmission(
      await internalMergeSubmissionRecord({ rpc: request.rpc, owner: request.owner }, context),
      request.owner,
      request.material,
    );
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
        indexer: treeCheckedIndexer(request.indexer, request.tree),
      },
      context,
    );
    const latest = await request.rpc.getLatestBlockhash(context);
    const transaction = client.finishMergeSubmissionUnsigned({
      proved,
      feePayer: request.payer.address,
      userRecord: internalUserRecordAddress(request.owner),
      recentBlockhash: latest.blockhash,
    });
    const signed = await request.payer.signNativeTransaction(transaction);
    const signature = await request.rpc.sendTransaction(signed, context);
    return Object.freeze({ signature, outputHash: proved.outputHash });
  } catch (cause) {
    throw wrapWalletError("WALLET_SUBMIT_MERGE", cause);
  }
}
