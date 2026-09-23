import type { RingMergeClient, WalletKeys } from "../client/ports.js";
import { assembleMerge } from "../client/prover/merge.js";
import { compressProof } from "../client/prover/proof.js";
import { compileUnsignedTransaction } from "../flows/compile.js";
import { reserveEntries, reservedUtxoKeys, unreserved } from "../flows/reserve.js";
import { selectUtxos } from "../flows/select.js";
import { initializePoseidon } from "../hasher/index.js";
import { MERGE_INPUT_COUNT } from "../interface/constants.js";
import type { SignerAccount } from "../interface/instructions/index.js";
import type { Address, Bytes32, RequestContext, Transaction } from "../interface/types.js";
import { SOL_MINT } from "../transaction/asset.js";
import { prepareMerge } from "../flows/merge.js";
import { checkKeysIdentity } from "../transaction/wallet/keys.js";
import type { Wallet } from "../transaction/wallet/state.js";
import {
  approveUnattended,
  checkIntentApproval,
  intentHash,
  ownerSolanaAccount,
  type ApprovalHandler,
  type TransactionIntent,
} from "../transaction/wallet/intent.js";
import { equalBytes } from "../wallet/internal.js";
import { fetchRingCoSigner } from "./config.js";
import { checkRingCoSigner, TRANSFER_DEMAND } from "./cosign.js";
import { RingError, wrapRingError } from "./error.js";
import { ringMergeInstruction } from "./instructions.js";
import {
  RingTransactionSubmission,
  checkRetainedEntries,
  type RingSubmissionAttempt,
  type RingSubmissionBuildState,
} from "./submission.js";
import { ringProofInput, ringSelectionErrors, ringIntentMismatch } from "./transfer.js";
import { resolveRingOutputTree } from "./trees.js";

export interface RingMergeTransactionParams {
  readonly client: RingMergeClient;
  readonly ringProgramId: Address;
  readonly wallet: Wallet;
  readonly keys: WalletKeys;
  readonly feePayer: Address;
  readonly asset?: Address;
  readonly outputTree?: Address;
  readonly cosigner?: SignerAccount;
  readonly approve?: ApprovalHandler;
}

export async function buildRingMergeTransaction(
  params: RingMergeTransactionParams,
  context?: RequestContext,
): Promise<Transaction> {
  return (await buildRingMerge(params, {}, context)).transaction;
}

export function createRingMergeSubmission(
  params: RingMergeTransactionParams,
  context?: RequestContext,
): Promise<RingTransactionSubmission> {
  return RingTransactionSubmission.fromBuilder(
    {
      wallet: params.wallet,
      build: (retry, context) => buildRingMerge(params, retry, context),
      windowChanged: async () => false,
    },
    context,
  );
}

async function buildRingMerge(
  params: RingMergeTransactionParams,
  retry: RingSubmissionBuildState,
  context?: RequestContext,
): Promise<RingSubmissionAttempt> {
  try {
    await initializePoseidon();
    checkKeysIdentity(params.keys, params.wallet.identity);
    const [coSigner, outputTree] = await Promise.all([
      fetchRingCoSigner(params.client, params.ringProgramId, context),
      resolveRingOutputTree(params.client, params.outputTree, context),
    ]);
    checkRingCoSigner({
      ringProgramId: params.ringProgramId,
      configured: coSigner,
      supplied: params.cosigner,
      demand: TRANSFER_DEMAND,
      approvalRequired: false,
    });
    const asset = params.asset ?? SOL_MINT;
    const reserved = reservedUtxoKeys(params.wallet);
    if (retry.entries !== undefined) checkRetainedEntries(params.wallet, retry.entries);
    const entries =
      retry.entries ??
      selectUtxos({
        wallet: params.wallet,
        asset,
        target: { kind: "consolidate", minInputs: 2 },
        policy: {
          eligible: (entry) =>
            unreserved(reserved)(entry) &&
            entry.utxo.ringProgramId === params.ringProgramId &&
            entry.dataHash === undefined &&
            entry.utxo.data.records().every((record) => record.kind !== "utxoData"),
          ordering: "smallestFirst",
          maxInputs: MERGE_INPUT_COUNT,
          tree: { kind: "fixed", tree: params.client.tree },
          errors: {
            ...ringSelectionErrors,
            tooFewUtxos: () => new RingError("RING_NOTHING_TO_MERGE"),
          },
        },
      }).entries;
    retry.entries = entries;
    retry.reservation ??= reserveEntries(params.wallet, entries, retry.lifetime);
    const owner = params.keys.address();
    const inputs = entries.map((entry) => ringProofInput(entry, owner, params.client));
    const prepared = await prepareMerge(
      {
        keys: params.keys,
        inputs,
        outputTreeId: outputTree.treeId,
        ring: { programId: params.ringProgramId },
        invalidAnswers: () => ringIntentMismatch("keyAnswers"),
      },
      context,
    );
    const expectedHash = prepared.outputHash();
    const intent: TransactionIntent = {
      kind: "ringMerge",
      ringProgramId: params.ringProgramId,
      outputTree: outputTree.tree,
      asset,
      numInputs: inputs.length,
      mergedAmount: prepared.output.amount,
    };
    const planned = intentHash(intent);
    if (retry.intent !== undefined && !equalBytes(retry.intent, planned))
      throw ringIntentMismatch("retryIntent");
    retry.intent = planned;
    const approval = await (params.approve ?? approveUnattended)({
      solanaPublicKey: ownerSolanaAccount(owner, params.feePayer),
      intent,
      summary: `merge ${String(inputs.length)} inputs in ring ${params.ringProgramId}`,
    });
    checkIntentApproval(approval, intent, ringIntentMismatch);
    const assembled = await assembleMerge(prepared, params.client, params.client.tree, context);
    if (!equalBytes(assembled.outputHash, expectedHash)) throw ringIntentMismatch("output");
    const proof = await params.keys.proveMerge(assembled.proverInputs, context);
    const compressed = compressProof(proof);
    const data = assembled.instructionData({ a: compressed.a, b: compressed.b, c: compressed.c });
    if (!equalBytes(data.outputUtxoHash, expectedHash)) throw ringIntentMismatch("output");
    const [instruction, lifetime] = await Promise.all([
      ringMergeInstruction({
        ringProgramId: params.ringProgramId,
        inputTree: params.client.tree,
        outputTree: outputTree.tree,
        payer: params.feePayer,
        data,
        outputRingDataHash: new Uint8Array(32) as Bytes32,
        ...(params.cosigner === undefined ? {} : { cosigner: params.cosigner }),
      }),
      params.client.getLatestBlockhash(context),
    ]);
    return {
      transaction: compileUnsignedTransaction({
        feePayer: params.feePayer,
        lifetime,
        instructions: [instruction],
        computeUnitLimit: 1_400_000,
      }),
      lastValidBlockHeight: lifetime.lastValidBlockHeight,
      intentHash: planned,
      ringInstructionIndex: 0,
    };
  } catch (cause) {
    if (retry.reservation !== undefined) params.wallet._releaseReservation(retry.reservation.id);
    throw wrapRingError("RING_BUILD_MERGE", cause);
  }
}
