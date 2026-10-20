import { blockhash } from "@solana/kit";
import type { RingMergeClient, RingMergeRegistryProof, WalletKeys } from "../client/ports.js";
import type { LatestBlockhash } from "../client/kit.js";
import { prepareMerge as prepareMergeProof } from "../client/prover/merge.js";
import { compileUnsignedTransaction } from "../flows/compile.js";
import { reserveEntries, reservedUtxoKeys, unreserved } from "../flows/reserve.js";
import { selectUtxos } from "../flows/select.js";
import { initializePoseidon } from "../hasher/index.js";
import {
  MAX_RING_MERGE_INPUTS,
  MERGE_INPUT_COUNT,
  mergePaddedInputCount,
} from "../interface/constants.js";
import type { SignerAccount } from "../interface/instructions/index.js";
import type {
  Address,
  Bytes32,
  Bytes128,
  MergeTransactInstructionData,
  RequestContext,
  Transaction,
} from "../interface/types.js";
import type { NullifierKey } from "../keypair/nullifier-key.js";
import { ZERO_32 } from "../transaction/internal.js";
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
import { bytesKey, equalBytes } from "../wallet/internal.js";
import { fetchRingCoSigner, fetchRingProgramConfig } from "./config.js";
import { openRingEscrowedKeys } from "./key-escrow.js";
import { fetchRingMemberRecord } from "./member-record.js";
import {
  checkAnonymousMergeWidth,
  emptyRingMergeDisclosure,
  ringMergeDisclosureRequest,
  wipeRingMergeDisclosureRequest,
  type RingMergeDisclosure,
} from "./merge-disclosure.js";
import { memberOfIdentity } from "./policy.js";
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
import { withProofDataRetry } from "../client/retry.js";

export interface RingMergeTransactionParams {
  readonly client: RingMergeClient;
  readonly ringProgramId: Address;
  readonly wallet: Wallet;
  readonly keys: WalletKeys;
  readonly feePayer: Address;
  readonly asset?: Address;
  /** The most notes merged, smallest first, from 2 through `MAX_RING_MERGE_INPUTS`, default `MERGE_INPUT_COUNT`. */
  readonly maxInputs?: number;
  readonly outputTree?: Address;
  readonly cosigner?: SignerAccount;
  readonly approve?: ApprovalHandler;
  /** Required in an anonymous ring, whose merge disclosure proves the owner's nullifier key. */
  readonly nullifierKey?: NullifierKey;
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
      registry: params.client,
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
    const maxInputs = mergeWidth(params.maxInputs);
    const [config, coSigner, outputTree] = await Promise.all([
      fetchRingProgramConfig(params.client, params.ringProgramId, context),
      fetchRingCoSigner(params.client, params.ringProgramId, context),
      resolveRingOutputTree(params.client, params.outputTree, context),
    ]);
    const anonymous = config.mode === "anonymous";
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
          maxInputs,
          tree: { kind: "fixed", tree: params.client.tree },
          errors: {
            ...ringSelectionErrors,
            tooFewUtxos: () => new RingError("RING_NOTHING_TO_MERGE"),
          },
        },
      }).entries;
    if (anonymous)
      checkAnonymousMergeWidth(mergePaddedInputCount(entries.length) ?? entries.length);
    retry.entries = entries;
    retry.reservation ??= reserveEntries(params.wallet, entries, retry.lifetime);
    const owner = params.keys.address();
    const ownerPkHash = owner.signingPublicKey.ownerProofInputHash();
    const nullifierKey = params.nullifierKey;
    if (
      nullifierKey !== undefined &&
      !equalBytes(nullifierKey.publicKey(), owner.nullifierPublicKey)
    )
      throw new RingError("RING_NULLIFIER_KEY_MISMATCH");
    if (anonymous && nullifierKey === undefined)
      throw new RingError("RING_ANONYMOUS_NULLIFIER_KEY_REQUIRED");
    const registry = anonymous
      ? await openAnonymousMember(params, ownerPkHash, context)
      : await openEscrowedMember(params, ownerPkHash, owner.nullifierPublicKey, context);
    const ringRegistry = registry.proof;
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
    const compile = async (
      data: MergeTransactInstructionData,
      lifetime: LatestBlockhash,
      disclosure: RingMergeDisclosure | undefined,
    ): Promise<Transaction> =>
      compileUnsignedTransaction({
        feePayer: params.feePayer,
        lifetime,
        instructions: [
          await ringMergeInstruction({
            ringProgramId: params.ringProgramId,
            inputTree: params.client.tree,
            outputTree: outputTree.tree,
            payer: params.feePayer,
            data,
            outputRingDataHash: prepared.output.ringDataHash ?? ZERO_32,
            memberRegistryRootIndex: registry.rootIndex,
            ...(disclosure === undefined ? {} : { disclosure }),
            ...(params.cosigner === undefined ? {} : { cosigner: params.cosigner }),
          }),
        ],
        computeUnitLimit: 1_400_000,
      });
    // Compile the real account layout with fixed-size proof placeholders before
    // requesting a proof. A co-signer or separate tree can exceed the byte limit
    // even when the input count fits. Final assembly uses the same compiler.
    const proofInputs = prepareMergeProof(prepared, params.client.tree, undefined, ringRegistry);
    const preview = proofInputs.finish({
      slot: { id: prepared.inputTreeId, utxoRoot: ZERO_32, nullifierRoot: ZERO_32 },
      utxoRootIndex: 0,
      nullifierRootIndex: 0,
    });
    await compile(
      preview.instructionData({ a: ZERO_32, b: new Uint8Array(128) as Bytes128, c: ZERO_32 }),
      { blockhash: blockhash("11111111111111111111111111111111"), lastValidBlockHeight: 0n },
      anonymous ? emptyRingMergeDisclosure(prepared.inputs.length) : undefined,
    );
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
    const { data } = await withProofDataRetry(
      params.client.proofDataSource,
      (attempt) => params.client.proveMerge({ prepared, keys: params.keys, ringRegistry }, attempt),
      context,
    );
    if (!equalBytes(data.outputUtxoHash, expectedHash)) throw ringIntentMismatch("output");
    const disclosure =
      ringRegistry.anonymous === true && nullifierKey !== undefined
        ? await proveMergeDisclosure(
            {
              client: params.client,
              ringProgramId: params.ringProgramId,
              auditor: config.auditorPublicKey,
              prepared,
              slots: proofInputs.inputs.payload,
              nullifierKey,
              registry: ringRegistry,
              spp: data,
            },
            context,
          )
        : undefined;
    const lifetime = await params.client.getLatestBlockhash(context);
    return {
      transaction: await compile(data, lifetime, disclosure),
      lastValidBlockHeight: lifetime.lastValidBlockHeight,
      intentHash: planned,
      ringInstructionIndex: 0,
      memberRegistryRoot: {
        ringProgramId: params.ringProgramId,
        index: registry.rootIndex,
        root: ringRegistry.root,
      },
    };
  } catch (cause) {
    if (retry.reservation !== undefined) params.wallet._releaseReservation(retry.reservation.id);
    throw wrapRingError("RING_BUILD_MERGE", cause);
  }
}

interface MemberMerge {
  readonly proof: RingMergeRegistryProof;
  readonly rootIndex: number;
}

/** An ordinary ring proves the owner's escrowed key against its record. */
async function openEscrowedMember(
  params: RingMergeTransactionParams,
  ownerPkHash: Bytes32,
  nullifierPk: Bytes32,
  context: RequestContext | undefined,
): Promise<MemberMerge> {
  const escrow = await openRingEscrowedKeys(
    {
      client: params.client,
      ringProgramId: params.ringProgramId,
      owners: [{ ownerPkHash, nullifierPk }],
      // A merge needs the opening even when the spend paths come from the prover.
      proofDataSource: "client",
    },
    context,
  );
  const key = escrow.keys[0];
  if (key === undefined) throw new RingError("RING_UNREGISTERED_OUTPUT_KEY");
  return { proof: { root: escrow.root, key }, rootIndex: escrow.rootIndex };
}

/** An anonymous member escrows nothing, its merge disclosure proves the owner to the auditor. */
async function openAnonymousMember(
  params: RingMergeTransactionParams,
  ownerPkHash: Bytes32,
  context: RequestContext | undefined,
): Promise<MemberMerge> {
  const read = await fetchRingMemberRecord(
    {
      client: params.client,
      ringProgramId: params.ringProgramId,
      member: memberOfIdentity(ownerPkHash),
    },
    context,
  );
  if (!read.opening.present)
    throw new RingError("RING_UNREGISTERED_OUTPUT_KEY", {
      details: { owner: bytesKey(ownerPkHash) },
    });
  const { record, index, path } = read.opening;
  return {
    proof: {
      root: read.registry.root,
      record: { next: record.next, lists: record.lists, escrowKey: record.escrowKey, index, path },
      anonymous: true,
    },
    rootIndex: read.registry.historyCursor,
  };
}

async function proveMergeDisclosure(
  input: Parameters<typeof ringMergeDisclosureRequest>[0] & Readonly<{ client: RingMergeClient }>,
  context: RequestContext | undefined,
): Promise<RingMergeDisclosure> {
  const { request, disclosure } = ringMergeDisclosureRequest(input);
  try {
    const proof = await input.client.proveCustomRingMergeAnonymous(request, context);
    return Object.freeze({ ...disclosure, proof });
  } finally {
    wipeRingMergeDisclosureRequest(request);
  }
}

function mergeWidth(maxInputs = MERGE_INPUT_COUNT): number {
  if (maxInputs > MAX_RING_MERGE_INPUTS) {
    throw new RingError("RING_TOO_MANY_INPUTS", {
      details: { selected: maxInputs, maximum: MAX_RING_MERGE_INPUTS },
    });
  }
  if (!Number.isSafeInteger(maxInputs) || maxInputs < 2) {
    throw new RingError("RING_NOTHING_TO_MERGE");
  }
  return maxInputs;
}
