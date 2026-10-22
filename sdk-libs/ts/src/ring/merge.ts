import type { Instruction } from "@solana/kit";

import type {
  PreparedMergeInputs,
  ProofDataSourceContext,
  RingMergeClient,
  RingMergeRegistryProof,
  WalletKeys,
} from "../client/ports.js";
import type { LatestBlockhash } from "../client/kit.js";
import { prepareMerge as prepareMergeProof } from "../client/prover/merge.js";
import { compressG2, compressProof } from "../client/prover/proof.js";
import { withProofDataRetry } from "../client/retry.js";
import { SIZE_PROBE_LIFETIME, compileUnsignedTransaction } from "../flows/compile.js";
import { prepareMerge } from "../flows/merge.js";
import { reserveEntries, reservedUtxoKeys, unreserved } from "../flows/reserve.js";
import { selectUtxos } from "../flows/select.js";
import { initializePoseidon } from "../hasher/index.js";
import { encodeMergeTransactInstructionData } from "../interface/codecs/index.js";
import {
  MAX_RING_MERGE_INPUTS,
  MERGE_INPUT_COUNT,
  mergePaddedInputCount,
} from "../interface/constants.js";
import {
  SYSTEM_PROGRAM,
  instruction,
  meta,
  signerAddress,
  type SignerAccount,
} from "../interface/instructions/index.js";
import { Writer } from "../interface/internal.js";
import {
  nullifierPdaAddress,
  ringAuthAddress,
  ringConfigAddress,
  ringMemberRegistryAddress,
} from "../interface/pda/index.js";
import { InstructionTag, SHIELDED_POOL_PROGRAM_ID } from "../interface/program.js";
import type {
  Address,
  Bytes32,
  Bytes128,
  MergeTransactInstructionData,
  RequestContext,
  Transaction,
} from "../interface/types.js";
import type { ShieldedAddress } from "../keypair/shielded.js";
import type { X25519PublicKey } from "../keypair/x25519.js";
import { SOL_MINT } from "../transaction/asset.js";
import type { PreparedMerge } from "../transaction/instructions/builders.js";
import { ZERO_32 } from "../transaction/internal.js";
import {
  approveUnattended,
  checkIntentApproval,
  intentHash,
  ownerSolanaAccount,
  type ApprovalHandler,
  type TransactionIntent,
} from "../transaction/wallet/intent.js";
import { checkKeysIdentity } from "../transaction/wallet/keys.js";
import type { Wallet } from "../transaction/wallet/state.js";
import { equalBytes } from "../wallet/internal.js";

import { checkSignersHideOwner } from "./anonymous.js";
import { fetchRingProgramConfig } from "./config.js";
import { TRANSFER_DEMAND, checkRingCoSigner } from "./cosign.js";
import { RingError, wrapRingError } from "./error.js";
import {
  checkAnonymousMergeWidth,
  emptyRingMergeDisclosure,
  ringMergeDisclosureRequest,
  wipeRingMergeDisclosureRequest,
  writeRingMergeDisclosure,
  type RingMergeDisclosure,
} from "./merge-disclosure.js";
import { readRegisteredRecord } from "./registered-record.js";
import {
  RingTransactionSubmission,
  checkRetainedEntries,
  type RingSubmissionAttempt,
  type RingSubmissionBuildState,
} from "./submission.js";
import { ringIntentMismatch, ringProofInput, ringSelectionErrors } from "./selection.js";
import { resolveRingOutputTree } from "./trees.js";

/** Rust `compute_unit_limit(Merge)`. */
export const RING_MERGE_COMPUTE_UNIT_LIMIT = 1_400_000;
/** `expiry_unix_ts u64 ‖ proof.a` ahead of `proof.b` in the SPP merge body, Rust `MERGE_B_OFFSET`. */
const MERGE_B_OFFSET = 8 + 32;

export interface RingMergeTransactionParams {
  readonly client: RingMergeClient & ProofDataSourceContext;
  readonly ringProgramId: Address;
  readonly wallet: Wallet;
  /** An anonymous ring's disclosure proof reaches the nullifier secret only through `proveRingWithSecret`. */
  readonly keys: WalletKeys;
  readonly feePayer: Address;
  readonly asset?: Address;
  /** The most notes merged, smallest first, from 2 through `MAX_RING_MERGE_INPUTS`, default `MERGE_INPUT_COUNT`. */
  readonly maxInputs?: number;
  readonly outputTree?: Address;
  /** Signs when the config's scope covers transfers. */
  readonly cosigner?: SignerAccount;
  readonly approve?: ApprovalHandler;
}

export async function buildRingMergeTransaction(
  params: RingMergeTransactionParams,
  context?: RequestContext,
): Promise<Transaction> {
  return (await buildRingMerge(params, {}, context)).transaction;
}

/** A rebuild proves the same notes again under the registry's newest root. */
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

/**
 * `MERGE ‖ registry_root_index ‖ output_ring_data_hash ‖ disclosure? ‖ body` with the body's
 * `proof.b` compressed, the accounts `[config, registry?, co_signer?]` ahead of SPP's merge list.
 */
export async function ringMergeInstruction(
  input: Readonly<{
    ringProgramId: Address;
    inputTree: Address;
    outputTree: Address;
    payer: SignerAccount;
    data: MergeTransactInstructionData;
    outputRingDataHash: Bytes32;
    /** The co-signer the config demands for transfers. */
    cosigner?: SignerAccount;
  }> &
    (
      | Readonly<{ registryRootIndex: number; disclosure?: undefined }>
      /** An anonymous ring reads no registry, its disclosure proves the owner instead. */
      | Readonly<{ disclosure: RingMergeDisclosure; registryRootIndex?: undefined }>
    ),
): Promise<Instruction> {
  const [config, registry, auth, nullifiers] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    input.disclosure === undefined ? ringMemberRegistryAddress(input.ringProgramId) : undefined,
    ringAuthAddress(input.ringProgramId),
    Promise.all(input.data.nullifiers.map((value) => nullifierPdaAddress(input.inputTree, value))),
  ]);
  const body = encodeMergeTransactInstructionData(input.data);
  return instruction(
    writeRingMergeDisclosure(
      new Writer()
        .u8(InstructionTag.ringMergeTransact, "instructionTag")
        .u8(input.registryRootIndex ?? 0, "registryRootIndex")
        .bytes(input.outputRingDataHash, 32, "outputRingDataHash"),
      input.disclosure,
    )
      .bytes(body.subarray(0, MERGE_B_OFFSET))
      .bytes(compressG2(body.slice(MERGE_B_OFFSET, MERGE_B_OFFSET + 128) as Bytes128), 64)
      .bytes(body.subarray(MERGE_B_OFFSET + 128))
      .finish(),
    [
      meta(config, false, false),
      ...(registry === undefined ? [] : [meta(registry, false, false)]),
      ...(input.cosigner === undefined ? [] : [meta(input.cosigner, true, false)]),
      meta(input.inputTree, false, true),
      meta(input.outputTree, false, true),
      meta(auth, false, false),
      meta(input.payer, true, true),
      meta(SYSTEM_PROGRAM, false, false),
      meta(SHIELDED_POOL_PROGRAM_ID, false, false),
      ...nullifiers.map((key) => meta(key, false, true)),
    ],
    input.ringProgramId,
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
    const [config, outputTree] = await Promise.all([
      fetchRingProgramConfig(params.client, params.ringProgramId, context),
      resolveRingOutputTree(params.client, params.outputTree, context),
    ]);
    const anonymous = config.mode === "anonymous";
    const cosigner = checkRingCoSigner({
      ringProgramId: params.ringProgramId,
      configured: config.coSigner,
      supplied: params.cosigner,
      demand: TRANSFER_DEMAND,
      approvalRequired: false,
    });
    const owner = params.keys.address();
    if (anonymous)
      checkSignersHideOwner(owner.signingPublicKey.ed25519(), [
        params.feePayer,
        cosigner === undefined ? undefined : signerAddress(cosigner),
      ]);
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
    const registered = anonymous ? undefined : await registeredMember(params, owner, context);
    const ringRegistry: RingMergeRegistryProof = registered?.proof ?? ANONYMOUS_MERGE;
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
      binding:
        | Readonly<{ registryRootIndex: number }>
        | Readonly<{ disclosure: RingMergeDisclosure }>,
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
            ...binding,
            ...(cosigner === undefined ? {} : { cosigner }),
          }),
        ],
        computeUnitLimit: RING_MERGE_COMPUTE_UNIT_LIMIT,
      });
    // Zeroed proofs over the real accounts size the transaction before any proof request.
    const proofInputs = prepareMergeProof(prepared, params.client.tree, undefined, ringRegistry);
    const preview = proofInputs.finish({
      slot: { id: prepared.inputTreeId, utxoRoot: ZERO_32, nullifierRoot: ZERO_32 },
      utxoRootIndex: 0,
      nullifierRootIndex: 0,
    });
    await compile(
      preview.instructionData({ a: ZERO_32, b: new Uint8Array(128) as Bytes128, c: ZERO_32 }),
      SIZE_PROBE_LIFETIME,
      registered === undefined
        ? { disclosure: emptyRingMergeDisclosure(prepared.inputs.length) }
        : { registryRootIndex: registered.index },
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
    const binding =
      registered === undefined
        ? {
            disclosure: await proveMergeDisclosure(
              {
                keys: params.keys,
                ringProgramId: params.ringProgramId,
                auditor: config.auditorPublicKey,
                prepared,
                slots: proofInputs.inputs.payload,
                spp: data,
              },
              context,
            ),
          }
        : { registryRootIndex: registered.index };
    const lifetime = await params.client.getLatestBlockhash(context);
    return {
      transaction: await compile(data, lifetime, binding),
      lastValidBlockHeight: lifetime.lastValidBlockHeight,
      intentHash: planned,
      ringInstructionIndex: 0,
      roots:
        registered === undefined
          ? []
          : [
              {
                ringProgramId: params.ringProgramId,
                rootIndex: registered.index,
                root: registered.proof.root,
              },
            ],
    };
  } catch (cause) {
    if (retry.reservation !== undefined) params.wallet._releaseReservation(retry.reservation.id);
    throw wrapRingError("RING_BUILD_MERGE", cause);
  }
}

/** An anonymous merge reads no record, Rust `MergeRegistration::anonymous`. */
const ANONYMOUS_MERGE: RingMergeRegistryProof = Object.freeze({ anonymous: true });

/** The owner's record and the escrow its merge proves. */
async function registeredMember(
  params: RingMergeTransactionParams,
  owner: ShieldedAddress,
  context: RequestContext | undefined,
): Promise<
  Readonly<{ proof: Extract<RingMergeRegistryProof, { ctHash: Bytes32 }>; index: number }>
> {
  const read = await readRegisteredRecord(
    {
      client: params.client,
      ringProgramId: params.ringProgramId,
      member: owner.signingPublicKey.ownerProofInputHash(),
      escrowed: owner.nullifierPublicKey,
    },
    context,
  );
  return Object.freeze({
    proof: Object.freeze({ root: read.root, record: read.record, ctHash: read.ctHash }),
    index: read.index,
  });
}

/** Only the key holder adds the nullifier secret. */
async function proveMergeDisclosure(
  input: Readonly<{
    keys: WalletKeys;
    ringProgramId: Address;
    auditor: X25519PublicKey;
    prepared: PreparedMerge;
    slots: PreparedMergeInputs;
    spp: MergeTransactInstructionData;
  }>,
  context: RequestContext | undefined,
): Promise<RingMergeDisclosure> {
  const { request, disclosure } = ringMergeDisclosureRequest(input);
  try {
    const proof = await input.keys.proveRingWithSecret(request, context);
    return Object.freeze({ ...disclosure, proof: compressProof(proof).toCustomRingProof() });
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
