import { getAddressEncoder, signTransactionWithSigners, type TransactionSigner } from "@solana/kit";

export type { TransactionSigner } from "@solana/kit";

import { isTransactionSignOnlySigner } from "../client/kit.js";
import type { ZolanaClient } from "../client/client.js";
import type { TransactionSignOnlySigner } from "../client/kit.js";
import type { Address, Bytes32, RequestContext, Signature } from "../interface/types.js";
import { createAssociatedTokenAccountInstruction } from "../interface/instructions/index.js";
import { associatedTokenAddress } from "../interface/pda/index.js";
import type { NullifierKey } from "../keypair/nullifier-key.js";
import type { P256PublicKey, ShieldedPublicKey } from "../keypair/public-key.js";
import { ShieldedAddress, type ShieldedKeypair } from "../keypair/shielded.js";
import { Merge, type PreparedMerge } from "../transaction/instructions/builders.js";
import { ProofInputUtxo } from "../transaction/utxo.js";
import type { WalletAuthority, WalletSyncMaterial } from "../transaction/wallet/authority.js";
import { SOL_MINT } from "../transaction/wallet/asset.js";
import type { Wallet, WalletUtxo } from "../transaction/wallet/state.js";

import { WalletError, wrapWalletError } from "./error.js";
import { bytesKey, equalBytes } from "./internal.js";
import { internalMergeSubmissionRecord, type MergeSubmissionRecord } from "./registry.js";

const addressEncoder = getAddressEncoder();

export async function createAssociatedTokenAccount(
  input: Readonly<{
    client: Pick<ZolanaClient, "signAndSendInstructions">;
    payer: TransactionSigner;
    owner: Address;
    mint: Address;
  }>,
  context?: RequestContext,
): Promise<Readonly<{ signature: Signature; address: Address }>> {
  try {
    const associatedAccount = await associatedTokenAddress(input.owner, input.mint);
    const instruction = await createAssociatedTokenAccountInstruction({
      payer: input.payer,
      owner: input.owner,
      mint: input.mint,
    });
    const signature = await input.client.signAndSendInstructions(
      { feePayer: input.payer, instructions: [instruction] },
      context,
    );
    return Object.freeze({ signature, address: associatedAccount });
  } catch (cause) {
    throw wrapWalletError("WALLET_CREATE_ASSOCIATED_TOKEN_ACCOUNT", cause);
  }
}

export interface MergeParams {
  readonly wallet: Wallet;
  readonly material: MergeMaterial;
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
  const nullifierKey = params.material.nullifierKey;
  const inputs = selected.map(
    (entry) =>
      new ProofInputUtxo({
        utxo: entry.utxo,
        nullifierKey,
        ...(entry.dataHash === undefined ? {} : { dataHash: entry.dataHash }),
        ...(entry.zoneDataHash === undefined ? {} : { zoneDataHash: entry.zoneDataHash }),
      }),
  );
  const prepared = new Merge(
    {
      address: ShieldedAddress.fromPublicKeys(
        params.material.signingPublicKey,
        params.material.nullifierKey.publicKey(),
        params.material.viewingPublicKey,
      ),
      nullifierKey,
    },
    inputs,
  ).prepare();
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

  static fromSyncMaterial(material: WalletSyncMaterial): MergeMaterial {
    return new MergeMaterial({
      signingPublicKey: material.identity.signingPublicKey,
      viewingPublicKey: material.identity.viewingPublicKey,
      nullifierKey: material.nullifierKey,
    });
  }
}

type MergeSubmissionClient = Pick<
  ZolanaClient,
  | "tree"
  | "getAccount"
  | "getInputMerkleProofs"
  | "proveMerge"
  | "finishMergeSubmissionUnsigned"
  | "sendTransaction"
>;

export interface SubmitMergeTransaction {
  readonly client: MergeSubmissionClient;
  readonly owner: Address;
  readonly payer: TransactionSignOnlySigner;
  readonly material: MergeMaterial;
  readonly tree: Address;
  readonly prepared: PreparedMerge;
  readonly skipPreflight?: boolean;
  readonly onReadyToSubmit?: () => void;
}

export interface SubmittedMerge {
  readonly signature: Signature;
  readonly outputHash: Bytes32;
  readonly outputTag: Bytes32;
}

export interface MergeActionParams {
  readonly client: MergeSubmissionClient & Pick<ZolanaClient, "confirmPrivateTransaction">;
  readonly wallet: Wallet;
  readonly authority: WalletAuthority;
  readonly feePayer: TransactionSignOnlySigner;
  readonly asset?: Address;
  readonly inputs?: readonly Bytes32[];
  readonly skipPreflight?: boolean;
  readonly waitForIndexer?: boolean;
}

export interface SubmittedMergeAction extends SubmittedMerge {
  readonly numInputs: number;
  readonly mergedAmount: bigint;
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
    !equalBytes(signingPublicKey.ed25519(), new Uint8Array(addressEncoder.encode(owner)))
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
  indexer: Pick<ZolanaClient, "getInputMerkleProofs">,
  submitTree: Address,
): Pick<ZolanaClient, "getInputMerkleProofs"> {
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
    if (!isTransactionSignOnlySigner(request.payer)) {
      throw new WalletError("WALLET_UNSUPPORTED_TRANSACTION_SIGNER");
    }
    const record = await internalMergeSubmissionRecord(
      { rpc: request.client, owner: request.owner },
      context,
    );
    validateMergeSubmission(record, request.owner, request.material);
    const client = request.client;
    if (client.tree !== request.tree) {
      throw new WalletError("WALLET_MERGE_TREE_MISMATCH", {
        details: { proofTree: client.tree, submitTree: request.tree },
      });
    }
    const proved = await client.proveMerge(
      {
        prepared: request.prepared,
        material: request.material,
        indexer: treeCheckedIndexer(client, request.tree),
      },
      context,
    );
    const transaction = await client.finishMergeSubmissionUnsigned(
      {
        proved,
        feePayer: request.payer.address,
        userRecord: record.recordAddress,
      },
      context,
    );
    const signed = await signTransactionWithSigners(
      [request.payer],
      transaction,
      context?.signal === undefined ? undefined : { abortSignal: context.signal },
    );
    request.onReadyToSubmit?.();
    const signature = await client.sendTransaction(
      signed,
      request.skipPreflight === undefined ? {} : { skipPreflight: request.skipPreflight },
      context,
    );
    return Object.freeze({
      signature,
      outputHash: proved.outputHash,
      outputTag: request.material.signingPublicKey.confidentialViewTag(),
    });
  } catch (cause) {
    throw wrapWalletError("WALLET_SUBMIT_MERGE", cause);
  }
}

export async function merge(
  input: MergeActionParams,
  context?: RequestContext,
): Promise<SubmittedMergeAction> {
  try {
    if (!isTransactionSignOnlySigner(input.feePayer)) {
      throw new WalletError("WALLET_UNSUPPORTED_TRANSACTION_SIGNER");
    }
    const owner = input.authority.solanaPublicKey();
    const material = MergeMaterial.fromSyncMaterial(await input.authority.syncMaterial());
    const created = createMerge({
      wallet: input.wallet,
      material,
      asset: input.asset ?? SOL_MINT,
      ...(input.inputs === undefined ? {} : { inputs: input.inputs }),
    });
    const reservation = input.wallet._reserveSubmission(
      created.prepared.inputUtxoHashes().map(({ utxoHash }) => utxoHash),
    );
    let committed = false;
    try {
      await input.authority.requestUserApproval({
        solanaPublicKey: owner,
        summary: `merge ${String(created.numInputs)} private inputs`,
      });
      const submitted = await submitMergeTransaction(
        {
          client: input.client,
          owner,
          payer: input.feePayer,
          material,
          tree: created.tree,
          prepared: created.prepared,
          ...(input.skipPreflight === undefined ? {} : { skipPreflight: input.skipPreflight }),
          onReadyToSubmit: () => {
            input.wallet._commitSubmission(reservation);
            committed = true;
          },
        },
        context,
      );
      if (!committed) {
        input.wallet._commitSubmission(reservation);
        committed = true;
      }
      if (input.waitForIndexer !== false) {
        await input.client.confirmPrivateTransaction(
          submitted.signature,
          [submitted.outputTag],
          context,
        );
      }
      return Object.freeze({
        ...submitted,
        numInputs: created.numInputs,
        mergedAmount: created.mergedAmount,
      });
    } catch (cause) {
      if (!committed) input.wallet._releaseSubmission(reservation);
      throw cause;
    }
  } catch (cause) {
    throw wrapWalletError("WALLET_SUBMIT_MERGE", cause);
  }
}
