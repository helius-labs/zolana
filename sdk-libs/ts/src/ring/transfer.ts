import type {
  BlockhashProvider,
  Prover,
  SlotReader,
  TreeContext,
  RingHeadReader,
  RingHeadTransferProof,
} from "../client/ports.js";
import { bigintToBytes, hashChain4 } from "../client/internal.js";
import { ownerSignerAddresses, ringOpenings } from "../client/prover/assembly.js";
import {
  RING_INLINE_ASSET_SLOTS,
  RING_INPUT_SLOTS,
  RING_RULE_SLOTS,
  velocityProofInputOff,
  type CustomRingSourceOwner,
  type CustomRingVelocityProofInput,
  type CustomRingPolicyProofRequest,
} from "../client/prover/types.js";
import { hashBytes } from "../hasher/index.js";
import { addressBytes } from "../interface/internal.js";
import { InstructionTag } from "../interface/program.js";
import { compileUnsignedTransaction } from "../flows/compile.js";
import type {
  Address,
  Bytes32,
  Instruction,
  RequestContext,
  Transaction,
  TransactInstructionData,
  TransactWithdrawal,
} from "../interface/types.js";
import { initializePoseidon } from "../hasher/index.js";
import {
  auditPublicInputHash,
  policyPublicInputHash,
  parseAuditorMessage,
} from "../keypair/audit.js";
import type { P256PublicKey } from "../keypair/public-key.js";
import { ShieldedAddress } from "../keypair/shielded.js";
import { ViewingKey } from "../keypair/viewing-key.js";
import {
  ConfidentialTransfer,
  SppProofInputs,
  createExternalData,
  type PreparedTransfer,
} from "../transaction/instructions/transact.js";
import {
  EncryptedScheme,
  encodeConfidential,
  encodeOutputData,
} from "../transaction/serialization/codecs.js";
import { Data } from "../transaction/data.js";
import { ProofInputUtxo } from "../transaction/utxo.js";
import type { SpendSession, WalletAuthority } from "../transaction/wallet/authority.js";
import {
  checkIntentApproval,
  checkPreparedTransfer,
  checkTransactData,
  withdrawalIntentRecipient,
  intentHash,
  type TransactionIntent,
} from "../transaction/wallet/intent.js";
import { SOL_ASSET_ID, SOL_MINT, type AssetRegistry } from "../transaction/asset.js";
import type { UtxoReservation, Wallet, WalletUtxo } from "../transaction/wallet/state.js";
import { resolveWithdrawalSettlement, withdrawalSetupInstructions } from "../flows/settlement.js";
import { resolveShieldedRecipient } from "../wallet/registry.js";

import { RING_COSIGN_TRANSFERS, RING_COSIGN_WITHDRAWALS, type RingPolicyConfig } from "./codecs.js";
import { provePolicyAnswers, type RingPolicyAnswerClient } from "./answers.js";
import {
  memberOfIdentity,
  policySourceOwners,
  verifiedRuleTable,
  type RuleTable,
} from "./policy.js";
import {
  fetchRingCoSigner,
  fetchRingConfigs,
  ringPolicyNamespaceAddress,
  windowedPolicy,
} from "./config.js";
import { TRANSFER_DEMAND, checkRingCoSigner, type CoSignDemand } from "./cosign.js";
import { selectUtxos, type SpendSelectionErrors } from "../flows/select.js";
import { reserveEntries, reservedUtxoKeys, unreserved } from "../flows/reserve.js";
import { RingError, wrapRingError } from "./error.js";
import type { SignerAccount } from "../interface/instructions/index.js";

import { ringTransactInstruction, type RingTransactTrees } from "./instructions.js";
import { chargeRows, planVelocity, readVelocityFacts, type VelocityPlan } from "./velocity.js";
import { verifyHeadMapTransfer } from "./head-map.js";
import {
  checkRetainedEntries,
  RingTransactionSubmission,
  windowChangedOn,
  type RingSubmissionAttempt,
  type RingSubmissionBuildState,
} from "./submission.js";
import { equalBytes } from "../wallet/internal.js";

/** Rust `TRANSACT_COMPUTE_UNIT_LIMIT`. The custom-ring transact verifies two proofs. */
export const RING_TRANSACT_COMPUTE_UNIT_LIMIT = 1_400_000;
/** Borsh `Encrypted` tag, its length, the scheme byte and the embedded P-256 key. */
const CONFIDENTIAL_BODY_OVERHEAD = 1 + 4 + 1 + 33;

export type RingTransferClient = TreeContext &
  BlockhashProvider &
  RingPolicyAnswerClient &
  SlotReader &
  RingHeadReader &
  Pick<
    Prover,
    | "proveRingTransact"
    | "proveCustomRingPolicy"
    | "proveCustomRingCompressedPolicy"
    | "proveCustomRingBase"
  >;

export interface RingTransferTransactionParams {
  readonly client: RingTransferClient;
  readonly ringProgramId: Address;
  readonly wallet: Wallet;
  readonly authority: WalletAuthority;
  readonly feePayer: Address;
  readonly recipient: Address | ShieldedAddress;
  readonly asset?: Address;
  readonly amount: bigint;
  /** `"default"` funds only from default UTXOs. `"ring-or-default"` mixes both pools. */
  readonly inputs?: "ring" | "ring-or-default" | "default";
  /** Receives every private output, defaults to `client.tree`. */
  readonly outputTree?: Address;
  /** The ring's co-signer when its scope covers the operation. */
  readonly cosigner?: SignerAccount;
  readonly computeUnitLimit?: number;
  readonly priorityFeeLamports?: bigint;
}

export type RingEntryTransactionParams = Omit<
  RingTransferTransactionParams,
  "recipient" | "inputs"
>;

export interface RingWithdrawalTransactionParams {
  readonly client: RingTransferClient;
  readonly ringProgramId: Address;
  readonly wallet: Wallet;
  readonly authority: WalletAuthority;
  readonly feePayer: Address;
  /** Any Solana account. It needs no registry record and need not exist yet. */
  readonly recipient: Address;
  readonly asset?: Address;
  readonly amount: bigint;
  /** SPL Token or Token-2022 for non-SOL assets, the settlement lands in the recipient's ATA. */
  readonly splTokenProgram?: Address;
  /** Receives the private change, defaults to `client.tree`. */
  readonly outputTree?: Address;
  /** The ring's co-signer when its scope covers the withdrawal. */
  readonly cosigner?: SignerAccount;
  readonly computeUnitLimit?: number;
  readonly priorityFeeLamports?: bigint;
}

/** Mirrors Rust `CustomRingTransferInput`. `prepared` is what `ConfidentialTransfer.prepare` returned. */
export interface CustomRingTransferParams {
  readonly client: RingTransferClient;
  readonly ringProgramId: Address;
  readonly prepared: PreparedTransfer;
  readonly session: Pick<SpendSession, "encryptCustomRingTransfer" | "openSealedMessage">;
  readonly assets: AssetRegistry;
  /** Must equal `client.tree`. */
  readonly tree: Address;
  /** Receives every private output, defaults to `tree`. */
  readonly outputTree?: Address;
}

export type RingDelegateProofClient = TreeContext &
  RingPolicyAnswerClient &
  Pick<
    Prover,
    "proveRingAuthorityTransact" | "proveCustomRingDelegatePolicy" | "proveCustomRingBase"
  >;
export type CustomRingDelegateTransferParams = Omit<CustomRingTransferParams, "client"> &
  Readonly<{ client: RingDelegateProofClient }>;

/** Mirrors Rust `ProvenTransfer`. */
export type ProvenRingTransfer = RingTransactTrees &
  Readonly<{
    data: TransactInstructionData;
    proof: Uint8Array;
    txViewingPublicKey: P256PublicKey;
    payer: Address;
    approvalRequired: boolean;
    /** History entries the ring proof binds, sent on the tag-3 wire. */
    stateRootIndex: number;
    nullifierRootIndex: number;
    /** Non-payer ed25519 input owners, they sign the transaction beside the fee payer. */
    ownerSigners: readonly Address[];
    /** The head transition must commit with the record spend. */
    headTransition?: Readonly<{ oldRoot: Bytes32; newRoot: Bytes32 }>;
    window?: Readonly<{ index: bigint; slots: bigint }>;
  }>;

/** Unsigned, the fee payer and any co-signer sign. */
export async function buildRingTransferTransaction(
  input: RingTransferTransactionParams,
  context?: RequestContext,
): Promise<Transaction> {
  const params = normalizeRingTransferParams(input);
  return (await buildRingSend({ params, destination: "ring", retry: {} }, context)).transaction;
}

export async function createRingTransferSubmission(
  input: RingTransferTransactionParams,
  context?: RequestContext,
): Promise<RingTransactionSubmission> {
  const params = normalizeRingTransferParams(input);
  return RingTransactionSubmission.fromBuilder(
    {
      wallet: params.wallet,
      build: (retry, context) => buildRingSend({ params, destination: "ring", retry }, context),
      windowChanged: windowChangedOn(params.client),
    },
    context,
  );
}

export async function createRingExitSubmission(
  input: Omit<RingTransferTransactionParams, "inputs">,
  context?: RequestContext,
): Promise<RingTransactionSubmission> {
  const params: RingTransferTransactionParams = {
    ...normalizeRingTransferBase(input),
    recipient: input.recipient,
    inputs: "ring",
  };
  return RingTransactionSubmission.fromBuilder(
    {
      wallet: params.wallet,
      build: (retry, context) => buildRingSend({ params, destination: "default", retry }, context),
      windowChanged: windowChangedOn(params.client),
    },
    context,
  );
}

export async function createRingWithdrawalSubmission(
  input: RingWithdrawalTransactionParams,
  context?: RequestContext,
): Promise<RingTransactionSubmission> {
  const params = normalizeRingWithdrawalParams(input);
  return RingTransactionSubmission.fromBuilder(
    {
      wallet: params.wallet,
      build: (retry, context) => buildRingWithdrawal({ params, retry }, context),
      windowChanged: windowChangedOn(params.client),
    },
    context,
  );
}

export async function buildRingEntryTransaction(
  input: RingEntryTransactionParams,
  context?: RequestContext,
): Promise<Transaction> {
  const normalized = normalizeRingEntryParams(input);
  const attempt = await buildRingSpend(
    {
      params: normalized,
      retry: {},
      strategy: {
        errorCode: "RING_BUILD_ENTRY",
        selection: "default",
        changeRing: "default",
        resolve: () => Promise.resolve(undefined),
        configure: ({ transfer, owner, asset }) => {
          transfer.sendToRing(owner, asset, normalized.amount, normalized.ringProgramId);
          return {
            intent: {
              kind: "ringEntry",
              ringProgramId: normalized.ringProgramId,
              asset,
              amount: normalized.amount,
            },
            summary: `ring entry of ${String(normalized.amount)} ${assetLabel(asset)} into ring ${normalized.ringProgramId}`,
            demand: TRANSFER_DEMAND,
          };
        },
      },
    },
    context,
  );
  return attempt.transaction;
}

/**
 * Value leaves the ring to a default-ring UTXO of the recipient, and the
 * custom-ring proof still covers the exit. Only ring-bound UTXOs fund it. An
 * all-default transact must not reach the audit as an exit.
 */
export async function buildRingExitTransaction(
  input: Omit<RingTransferTransactionParams, "inputs">,
  context?: RequestContext,
): Promise<Transaction> {
  const params = {
    ...normalizeRingTransferBase(input),
    recipient: input.recipient,
    inputs: "ring",
  } as const;
  return (await buildRingSend({ params, destination: "default", retry: {} }, context)).transaction;
}

async function buildRingSend(
  input: Readonly<{
    params: RingTransferTransactionParams;
    destination: "ring" | "default";
    retry: RingSubmissionBuildState;
  }>,
  context?: RequestContext,
): Promise<RingSubmissionAttempt> {
  const { params, destination } = input;
  return buildRingSpend(
    {
      params,
      retry: input.retry,
      strategy: {
        errorCode: "RING_BUILD_TRANSFER",
        selection: params.inputs ?? "ring",
        changeRing: "ring",
        resolve: () => resolveRecipient(params, context),
        configure: ({ transfer, resolved: recipient, selected, asset }) => {
          if (destination === "ring") {
            transfer.send(recipient, asset, params.amount);
          } else {
            transfer.sendDefaultRing(recipient, asset, params.amount);
          }
          // Change of a default UTXO becomes ring bound.
          const defaultFunding = selected
            .filter((entry) => entry.utxo.ringProgramId === undefined)
            .reduce((sum, entry) => sum + entry.utxo.amount, 0n);
          const boundary =
            destination === "default" ? "exit" : defaultFunding > 0n ? "entry" : "transfer";
          const crossing =
            defaultFunding === 0n
              ? ""
              : `, moves ${String(defaultFunding)} ${assetLabel(asset)} of default UTXOs into the ring`;
          return {
            intent: {
              kind: "ringTransfer",
              ringProgramId: params.ringProgramId,
              asset,
              amount: params.amount,
              recipient,
              boundary,
              defaultFunding,
            },
            summary: `ring ${boundary} of ${String(params.amount)} ${assetLabel(asset)} in ring ${params.ringProgramId} to a shielded address${crossing}`,
            demand: TRANSFER_DEMAND,
          };
        },
      },
    },
    context,
  );
}

type RingSpendParams = Pick<
  RingTransferTransactionParams,
  | "client"
  | "ringProgramId"
  | "wallet"
  | "authority"
  | "feePayer"
  | "asset"
  | "amount"
  | "outputTree"
  | "cosigner"
  | "computeUnitLimit"
  | "priorityFeeLamports"
>;

interface RingSpendPlan {
  readonly intent: TransactionIntent;
  readonly summary: string;
  readonly demand: CoSignDemand;
  readonly withdrawal?: TransactWithdrawal;
  readonly setupInstructions?: readonly Instruction[];
}

interface RingSpendStrategy<R> {
  readonly errorCode: "RING_BUILD_ENTRY" | "RING_BUILD_TRANSFER" | "RING_BUILD_WITHDRAWAL";
  readonly selection: "ring" | "ring-or-default" | "default";
  readonly changeRing: "ring" | "default";
  resolve(): Promise<R>;
  configure(
    input: Readonly<{
      transfer: ConfidentialTransfer;
      resolved: R;
      selected: readonly WalletUtxo[];
      asset: Address;
      owner: ShieldedAddress;
    }>,
  ): RingSpendPlan;
}

async function buildRingSpend<R>(
  input: Readonly<{
    params: RingSpendParams;
    strategy: RingSpendStrategy<R>;
    retry: RingSubmissionBuildState;
  }>,
  context?: RequestContext,
): Promise<RingSubmissionAttempt> {
  const { params, strategy, retry } = input;
  return params.authority.withSpendSession(async (session) => {
    let inputs: readonly ProofInputUtxo[] = [];
    let reservation: UtxoReservation | undefined;
    try {
      await initializePoseidon();
      const asset = params.asset ?? SOL_MINT;
      const nullifierKey = session.nullifierKey();
      const [resolved, address] = await Promise.all([
        strategy.resolve(),
        params.authority.shieldedAddress(),
      ]);
      const [ringConfigs, coSigner] = await Promise.all([
        fetchRingConfigs(params.client, params.ringProgramId, context),
        fetchRingCoSigner(params.client, params.ringProgramId, context),
      ]);
      // A windowed ring appends the spend record as the last input slot.
      const maxInputs =
        windowedPolicy(ringConfigs) === undefined ? RING_INPUT_SLOTS : RING_INPUT_SLOTS - 1;
      if (retry.entries !== undefined) checkRetainedEntries(params.wallet, retry.entries);
      const selected =
        retry.entries ??
        selectRingInputs({
          wallet: params.wallet,
          ringProgramId: params.ringProgramId,
          asset,
          amount: params.amount,
          inputs: strategy.selection,
          tree: params.client.tree,
          maxInputs,
        });
      reservation = retry.reservation ?? reserveEntries(params.wallet, selected);
      retry.entries = selected;
      retry.reservation = reservation;
      inputs = selected.map(
        (entry) =>
          new ProofInputUtxo({
            utxo: entry.utxo,
            treeId: params.client.treeId,
            nullifierKey,
            ...(entry.dataHash === undefined ? {} : { dataHash: entry.dataHash }),
            ...(entry.ringDataHash === undefined ? {} : { ringDataHash: entry.ringDataHash }),
          }),
      );
      const transfer = new ConfidentialTransfer(
        address,
        inputs,
        params.feePayer,
      ).withCompactChange();
      if (strategy.changeRing === "ring") {
        transfer.withRingProgramId(params.ringProgramId);
      }
      const plan = strategy.configure({ transfer, resolved, selected, asset, owner: address });
      const plannedIntent = intentHash(plan.intent);
      if (retry.intent !== undefined && !equalBytes(retry.intent, plannedIntent))
        throw ringIntentMismatch("retryIntent");
      retry.intent = plannedIntent;
      const coSigning = {
        ringProgramId: params.ringProgramId,
        configured: coSigner,
        supplied: params.cosigner,
        demand: plan.demand,
      };
      checkRingCoSigner({ ...coSigning, approvalRequired: false });
      const approval = await params.authority.requestUserApproval({
        solanaPublicKey: params.authority.solanaPublicKey(),
        intent: plan.intent,
        summary: plan.summary,
      });
      checkIntentApproval(approval, plan.intent, ringIntentMismatch);
      const prepared = transfer.prepare();
      checkPreparedTransfer(prepared, plan.intent, ringIntentMismatch);
      const proven = await proveCustomRingTransfer(
        {
          client: params.client,
          ringProgramId: params.ringProgramId,
          prepared,
          session,
          assets: params.wallet.registry,
          tree: params.client.tree,
          ...(params.outputTree === undefined ? {} : { outputTree: params.outputTree }),
        },
        context,
      );
      checkTransactData(proven.data, plan.intent, ringIntentMismatch);
      if (proven.approvalRequired) checkRingCoSigner({ ...coSigning, approvalRequired: true });
      const [instruction, lifetime] = await Promise.all([
        ringTransactInstruction({
          ringProgramId: params.ringProgramId,
          payer: proven.payer,
          inputTree: proven.tree,
          outputTree: proven.outputTree,
          hasPolicy: proven.hasPolicy,
          ...(proven.hasPolicy ? { entriesTree: proven.entriesTree } : {}),
          proof: proven.proof,
          stateRootIndex: proven.stateRootIndex,
          nullifierRootIndex: proven.nullifierRootIndex,
          data: proven.data,
          approvalRequired: proven.approvalRequired,
          ...(proven.ownerSigners.length === 0 ? {} : { ownerSigners: proven.ownerSigners }),
          ...(plan.withdrawal === undefined ? {} : { withdrawal: plan.withdrawal }),
          ...(params.cosigner === undefined ? {} : { cosigner: params.cosigner }),
          ...(proven.headTransition === undefined ? {} : { headTransition: proven.headTransition }),
        }),
        params.client.getLatestBlockhash(context),
      ]);
      const transaction = compileUnsignedTransaction({
        feePayer: params.feePayer,
        lifetime,
        computeUnitLimit: params.computeUnitLimit ?? RING_TRANSACT_COMPUTE_UNIT_LIMIT,
        ...(params.priorityFeeLamports === undefined
          ? {}
          : { priorityFeeLamports: params.priorityFeeLamports }),
        instructions: [...(plan.setupInstructions ?? []), instruction],
        sizeShape: {
          inputs: proven.data.inputs.length,
          outputs: proven.data.outputs.length,
        },
      });
      return Object.freeze({
        transaction,
        lastValidBlockHeight: lifetime.lastValidBlockHeight,
        intentHash: plannedIntent,
        ringInstructionIndex: plan.setupInstructions?.length ?? 0,
        ...(proven.window === undefined ? {} : { window: proven.window }),
      });
    } catch (cause) {
      if (reservation !== undefined) params.wallet._releaseReservation(reservation.id);
      throw wrapRingError(strategy.errorCode, cause);
    } finally {
      for (const proofInput of inputs) proofInput.destroy();
    }
  });
}

/**
 * Value leaves the ring to a plain Solana account. The recipient, the amount
 * and the asset are public, and the custom-ring proof still covers the exit.
 */
export async function buildRingWithdrawalTransaction(
  input: RingWithdrawalTransactionParams,
  context?: RequestContext,
): Promise<Transaction> {
  const params = normalizeRingWithdrawalParams(input);
  return (await buildRingWithdrawal({ params, retry: {} }, context)).transaction;
}

async function buildRingWithdrawal(
  input: Readonly<{ params: RingWithdrawalTransactionParams; retry: RingSubmissionBuildState }>,
  context?: RequestContext,
): Promise<RingSubmissionAttempt> {
  const { params } = input;
  return buildRingSpend(
    {
      params,
      retry: input.retry,
      strategy: {
        errorCode: "RING_BUILD_WITHDRAWAL",
        selection: "ring",
        changeRing: "ring",
        resolve: async () => {
          const asset = params.asset ?? SOL_MINT;
          const settlement = await resolveWithdrawalSettlement(
            params.recipient,
            asset,
            params.splTokenProgram,
          );
          const setupInstructions = await withdrawalSetupInstructions({
            payer: params.feePayer,
            recipient: params.recipient,
            asset,
            ...(params.splTokenProgram === undefined
              ? {}
              : { splTokenProgram: params.splTokenProgram }),
          });
          return { settlement, setupInstructions };
        },
        configure: ({ transfer, resolved, asset }) => {
          transfer.withdraw(asset, params.amount, resolved.settlement.target);
          return {
            intent: {
              kind: "ringWithdrawal",
              ringProgramId: params.ringProgramId,
              asset,
              amount: params.amount,
              recipient: withdrawalIntentRecipient(resolved.settlement.target),
            },
            summary: `public withdrawal of ${String(params.amount)} ${assetLabel(asset)} from ring ${params.ringProgramId} to ${params.recipient}`,
            demand: {
              classes: RING_COSIGN_TRANSFERS | RING_COSIGN_WITHDRAWALS,
              withdrawal: { mint: asset, amount: params.amount },
            },
            withdrawal: resolved.settlement.accounts,
            setupInstructions: resolved.setupInstructions,
          };
        },
      },
    },
    context,
  );
}

/** Mirrors Rust `CustomRingTransfer::prove`, the auditor message enters the external data before the SPP proof folds it into `privateTxHash`. */
export async function proveCustomRingTransfer(
  input: CustomRingTransferParams,
  context?: RequestContext,
): Promise<ProvenRingTransfer> {
  return proveRingTransferStatement(input, { kind: "member", client: input.client }, context);
}

/** Delegate proofs exclude velocity charges. */
export async function proveCustomRingDelegateTransfer(
  input: CustomRingDelegateTransferParams,
  context?: RequestContext,
): Promise<ProvenRingTransfer> {
  return proveRingTransferStatement(input, { kind: "delegate", client: input.client }, context);
}

async function proveRingTransferStatement(
  input: Omit<CustomRingTransferParams, "client">,
  flow:
    | Readonly<{ kind: "member"; client: RingTransferClient }>
    | Readonly<{ kind: "delegate"; client: RingDelegateProofClient }>,
  context?: RequestContext,
): Promise<ProvenRingTransfer> {
  await initializePoseidon();
  // The prover fetches merkle proofs from the client tree only.
  if (input.tree !== flow.client.tree) {
    throw new RingError("RING_TREE_MISMATCH", {
      details: { tree: input.tree, clientTree: flow.client.tree },
    });
  }
  const configs = await fetchRingConfigs(flow.client, input.ringProgramId, context);
  const config = configs.config;
  const policy = configs.hasPolicy ? policyContext(configs.policy) : undefined;
  // A padded change slot pushes the custom-ring instruction past the packet limit
  // even behind an address lookup table.
  if (input.prepared.changeLayout !== "compact") {
    throw new RingError("RING_PADDED_CHANGE", {
      details: { remedy: "prepare the transfer with ConfidentialTransfer.withCompactChange" },
    });
  }
  let prepared = input.prepared;
  checkRingMembership(prepared, input.ringProgramId);
  const ringId = hashBytes(addressBytes(input.ringProgramId, "ringProgramId")) as Bytes32;
  // Captured before a windowed ring appends the record as the last output.
  const moneyOutputs = prepared.outputs;

  let velocity: CustomRingVelocityProofInput | undefined;
  let plan: VelocityPlan | undefined;
  let head: RingHeadTransferProof | undefined;
  let headTransition: Readonly<{ oldRoot: Bytes32; newRoot: Bytes32 }> | undefined;
  if (policy !== undefined && flow.kind === "delegate") {
    const outputTree = input.outputTree ?? input.tree;
    if (policy.table.windowSlots !== 0n && outputTree !== policy.config.entriesTree) {
      throw new RingError("RING_TREE_MISMATCH", {
        details: {
          tree: outputTree,
          entriesTree: policy.config.entriesTree,
          reason: "delegateRecordTree",
        },
      });
    }
    velocity = {
      ...velocityProofInputOff({ ringId, namespaceOwnerHash: policy.config.namespaceOwnerHash }),
      rows: policy.table.velocity,
      windowSlots: policy.table.windowSlots,
    };
  }
  if (policy !== undefined && policy.table.velocity.length !== 0 && flow.kind === "member") {
    const sender = memberOfIdentity(prepared.owner.signingPublicKey.ownerProofInputHash());
    const movement = {
      sender,
      ringProgramId: input.ringProgramId,
      inputs: prepared.inputs,
      outputs: moneyOutputs,
    };
    if (policy.table.windowSlots === 0n) {
      velocity = chargeRows({
        movement,
        rows: policy.table.velocity,
        namespaceOwnerHash: policy.config.namespaceOwnerHash,
      });
    } else {
      const entriesTree = policy.config.entriesTree;
      if (input.tree !== entriesTree || (input.outputTree ?? input.tree) !== entriesTree) {
        throw new RingError("RING_TREE_MISMATCH", {
          details: { tree: input.tree, entriesTree, reason: "velocityRecord" },
        });
      }
      const facts = await readVelocityFacts(
        {
          client: flow.client,
          ringProgramId: input.ringProgramId,
          session: input.session,
          namespace: await ringPolicyNamespaceAddress(input.ringProgramId),
          entriesTree,
          entriesTreeId: policy.config.entriesTreeId,
          windowSlots: policy.table.windowSlots,
          rows: policy.table.velocity,
          sender,
        },
        context,
      );
      plan = planVelocity({
        facts,
        movement,
        firstNullifier: prepared.firstNullifier,
        outputBlindingSeed: prepared.outputBlindingSeed(),
        moneyShape: prepared.shape,
      });
      prepared = prepared.withAppendedSlot({
        shape: plan.shape,
        input: plan.recordInput,
        output: plan.recordOutput,
      });
      velocity = plan.proofInput;
      head = facts.head;
      headTransition = {
        oldRoot: head.root,
        newRoot: verifyHeadMapTransfer({
          root: head.root,
          member: sender,
          next: head.next,
          spent: facts.live.nullifier,
          successor: plan.nextNullifier,
          index: head.index,
          proof: head.proof,
        }),
      };
    }
  }
  const approvalRequired = velocity?.approvalRequired ?? false;

  const encrypted = await input.session.encryptCustomRingTransfer({
    firstNullifier: prepared.firstNullifier,
    outputs: prepared.outputs,
    assets: input.assets,
    auditorPublicKey: config.auditorPublicKey,
    ...(plan === undefined
      ? {}
      : {
          counterMessage: plan.countersSeal,
          recordOutputIndex: prepared.outputs.length - 1,
        }),
  });
  try {
    const messages = [
      ...(plan === undefined ? [] : [plan.recordMessage]),
      ...encrypted.sealedMessages,
      encrypted.auditorMessage,
    ];
    const proofInputs = frameDummyOutputs(
      prepared.finalize({
        txViewingPublicKey: encrypted.txViewingPublicKey,
        salt: encrypted.salt,
        payload: encrypted.payload,
        messages,
        instructionDiscriminator:
          flow.kind === "delegate"
            ? InstructionTag.ringAuthorityTransact
            : InstructionTag.ringTransact,
      }),
    );
    const openings = ringOpenings(proofInputs);
    // The record slot is the last input and output, never a rule subject.
    const subjectInputs =
      plan === undefined ? proofInputs.inputUtxos : proofInputs.inputUtxos.slice(0, -1);
    const subjectOutputs =
      plan === undefined ? proofInputs.outputs : proofInputs.outputs.slice(0, -1);
    const policyRound =
      policy === undefined
        ? undefined
        : {
            ...policy,
            ...(await provePolicyAnswers(
              {
                client: flow.client,
                table: policy.table,
                config: policy.config,
                inputs: subjectInputs,
                outputs: subjectOutputs,
              },
              context,
            )),
          };
    const { data } =
      flow.kind === "delegate"
        ? await flow.client.proveRingAuthorityTransact(proofInputs, input.ringProgramId, context)
        : await flow.client.proveRingTransact(proofInputs, input.ringProgramId, undefined, context);
    // The audit statement rehashes the auditor message SPP already folded into privateTxHash.
    const message = parseAuditorMessage(encrypted.auditorMessage.data);
    const common = {
      data,
      txViewingPublicKey: encrypted.txViewingPublicKey,
      payer: prepared.payer,
      tree: input.tree,
      outputTree: input.outputTree ?? input.tree,
      ownerSigners:
        flow.kind === "delegate" ? [] : ownerSignerAddresses(prepared.inputs, prepared.payer),
    } as const;

    if (policyRound === undefined) {
      const proof = await flow.client.proveCustomRingBase(
        {
          publicInputHash: auditPublicInputHash({
            privateTxHash: data.privateTxHash,
            txViewingPublicKey: encrypted.txViewingPublicKey,
            auditorPublicKey: config.auditorPublicKey,
            message,
          }),
          privateTxHash: data.privateTxHash,
          txViewingSecret: encrypted.audit.txViewingSecret,
          ephemeralSecret: encrypted.audit.ephemeralSecret,
          auditorPublicKey: config.auditorPublicKey.toUncompressed(),
        },
        context,
      );
      return Object.freeze({
        ...common,
        proof,
        approvalRequired,
        hasPolicy: false,
        stateRootIndex: 0,
        nullifierRootIndex: 0,
      });
    }

    const { answers, roots } = policyRound;
    const velocityProofInput =
      velocity ??
      velocityProofInputOff({
        ringId,
        namespaceOwnerHash: policyRound.config.namespaceOwnerHash,
      });
    const policyRequest: CustomRingPolicyProofRequest = {
      publicInputHash: policyPublicInputHash({
        privateTxHash: data.privateTxHash,
        txViewingPublicKey: encrypted.txViewingPublicKey,
        auditorPublicKey: config.auditorPublicKey,
        message,
        policyHash: policyRound.config.policyHash,
        stateRoot: roots.stateRoot,
        nullifierRoot: roots.nullifierRoot,
        entriesTreeId: policyRound.config.entriesTreeId,
        ringId: velocityProofInput.ringId,
        namespaceOwnerHash: velocityProofInput.namespaceOwnerHash,
        windowIndex: velocityProofInput.windowIndex,
        approvalRequired: velocityProofInput.approvalRequired,
        ...(headTransition === undefined ? {} : { headTransition }),
      }),
      privateTxHash: data.privateTxHash,
      txViewingSecret: encrypted.audit.txViewingSecret,
      ephemeralSecret: encrypted.audit.ephemeralSecret,
      auditorPublicKey: config.auditorPublicKey.toUncompressed(),
      nIn: openings.nIn,
      nOut: openings.nOut,
      inputs: openings.inputs,
      outputs: openings.outputs,
      // Both MUST equal the preimage the SPP assembly folds into
      // `privateTxHash`, else the gnark witness is unsatisfiable.
      addressChain: ringAddressChain(openings.nIn),
      externalDataHash: proofInputs.externalData.hash(),
      privateTxBlinding: proofInputs.privateTxBlinding(),
      sources: policyRound.sources,
      policyLen: policyRound.config.ruleCount,
      rules: paddedRows(policyRound.config.rules, RING_RULE_SLOTS),
      inlineAssets: paddedRows(policyRound.config.inlineAssets, RING_INLINE_ASSET_SLOTS),
      inlineLimits: Object.freeze(
        Array.from(
          { length: RING_INLINE_ASSET_SLOTS },
          (_, index) => policyRound.config.inlineLimits[index] ?? 0n,
        ),
      ),
      inlineCount: policyRound.config.inlineCount,
      stateRoot: roots.stateRoot,
      nullifierRoot: roots.nullifierRoot,
      entriesTreeId: policyRound.config.entriesTreeId,
      velocity: velocityProofInput,
      answers,
    };
    const proof =
      flow.kind === "delegate"
        ? await flow.client.proveCustomRingDelegatePolicy(policyRequest, context)
        : headTransition === undefined || head === undefined
          ? await flow.client.proveCustomRingPolicy(policyRequest, context)
          : await flow.client.proveCustomRingCompressedPolicy(
              {
                policy: policyRequest,
                headOldRoot: headTransition.oldRoot,
                headNewRoot: headTransition.newRoot,
                headNext: head.next,
                headIndex: head.index,
                headProof: head.proof,
              },
              context,
            );
    return Object.freeze({
      ...common,
      proof,
      approvalRequired,
      entriesTree: policyRound.config.entriesTree,
      hasPolicy: true,
      stateRootIndex: roots.stateRootIndex,
      nullifierRootIndex: roots.nullifierRootIndex,
      ...(headTransition === undefined ? {} : { headTransition }),
      ...(plan === undefined
        ? {}
        : {
            window: {
              index: plan.proofInput.windowIndex,
              slots: plan.proofInput.windowSlots,
            },
          }),
    });
  } finally {
    encrypted.audit.txViewingSecret.fill(0);
    encrypted.audit.ephemeralSecret.fill(0);
  }
}

interface PolicyContext {
  readonly config: RingPolicyConfig;
  readonly table: RuleTable;
  readonly sources: readonly CustomRingSourceOwner[];
}

function policyContext(config: RingPolicyConfig): PolicyContext {
  const sources = policySourceOwners(config.sources);
  return Object.freeze({ config, table: verifiedRuleTable(config, sources), sources });
}

function paddedRows(rows: readonly Bytes32[], width: number): readonly Bytes32[] {
  return Object.freeze(
    Array.from({ length: width }, (_, index) => rows[index] ?? (new Uint8Array(32) as Bytes32)),
  );
}

/**
 * SPP folds one zero address slot per input into `privateTxHash`, the ring
 * proof binds the same chain over `nIn` zero fields. Mirrors Rust `proof.rs`.
 * @internal
 */
export function ringAddressChain(nIn: number): Bytes32 {
  return bigintToBytes(hashChain4(Array.from({ length: nIn }, () => 0n))) as Bytes32;
}

/** Mirrors Rust `RingMembership::validate`. @internal */
export function checkRingMembership(prepared: PreparedTransfer, ringProgramId: Address): void {
  const utxos = [
    ...prepared.inputs.map((input) => ({
      ring: input.utxo.ringProgramId,
      data: input.ringDataHash,
    })),
    ...prepared.outputs.map((output) => ({
      ring: output.ringProgramId,
      data: output.ringDataHash,
    })),
  ];
  const foreign = utxos.find((utxo) => utxo.ring !== undefined && utxo.ring !== ringProgramId);
  if (foreign?.ring !== undefined) {
    throw new RingError("RING_FOREIGN_RING", { details: { ringProgramId: foreign.ring } });
  }
  if (utxos.some((utxo) => utxo.ring === undefined && utxo.data !== undefined)) {
    throw new RingError("RING_DATA_OUTSIDE_RING");
  }
}

/** A dummy copies the length of a real slot with its ring binding, else of the first real slot, mirrors Rust `frame_dummy_outputs`. */
export function frameDummyOutputs(proofInputs: SppProofInputs): SppProofInputs {
  const external = proofInputs.externalData;
  const templates = proofInputs.outputs.flatMap((output, index) => {
    if (output.isDummy()) return [];
    const length = external.outputs[index]?.data?.length;
    if (length === undefined) {
      throw new RingError("RING_BUILD_TRANSFER", { details: { reason: "invalid dummy output" } });
    }
    return [{ inRing: output.ringProgramId !== undefined, length }];
  });
  const outputs = external.outputs.map((encoded, index) => {
    const output = proofInputs.outputs[index];
    if (output === undefined || !output.isDummy()) return encoded;
    const inRing = output.ringProgramId !== undefined;
    const template = templates.find((candidate) => candidate.inRing === inRing) ?? templates[0];
    const ciphertextLength =
      template === undefined
        ? encodeConfidential({
            assetId: SOL_ASSET_ID,
            amount: 0n,
            blinding: new Uint8Array(32) as Bytes32,
            data: new Data(),
            ...(output.ringProgramId === undefined ? {} : { ringProgramId: output.ringProgramId }),
          }).length
        : template.length - CONFIDENTIAL_BODY_OVERHEAD;
    if (ciphertextLength <= 0) {
      throw new RingError("RING_BUILD_TRANSFER", { details: { reason: "invalid dummy output" } });
    }
    const key = ViewingKey.generate();
    const body = new Uint8Array(33 + ciphertextLength);
    try {
      body.set(key.publicKey().toBytes(), 0);
    } finally {
      key.destroy();
    }
    globalThis.crypto.getRandomValues(body.subarray(33));
    const scheme = inRing ? EncryptedScheme.ringConfidential : EncryptedScheme.confidential;
    return { ...encoded, data: encodeOutputData(scheme, body, "encrypted") };
  });
  return new SppProofInputs({
    payer: proofInputs.payer,
    inputUtxos: proofInputs.inputUtxos,
    outputs: proofInputs.outputs,
    externalData: createExternalData({ ...external, outputs }),
    blindingSeed: proofInputs.blindingSeed,
    outputTreeId: proofInputs.outputTreeId,
  });
}

function normalizeRingTransferBase(input: RingSpendParams): RingSpendParams {
  const asset = input.asset;
  const outputTree = input.outputTree;
  const cosigner = input.cosigner;
  const computeUnitLimit = input.computeUnitLimit;
  const priorityFeeLamports = input.priorityFeeLamports;
  return Object.freeze({
    client: input.client,
    ringProgramId: input.ringProgramId,
    wallet: input.wallet,
    authority: input.authority,
    feePayer: input.feePayer,
    amount: input.amount,
    ...(asset === undefined ? {} : { asset }),
    ...(outputTree === undefined ? {} : { outputTree }),
    ...(cosigner === undefined ? {} : { cosigner }),
    ...(computeUnitLimit === undefined ? {} : { computeUnitLimit }),
    ...(priorityFeeLamports === undefined ? {} : { priorityFeeLamports }),
  });
}

function normalizeRingTransferParams(
  input: RingTransferTransactionParams,
): RingTransferTransactionParams {
  const base = normalizeRingTransferBase(input);
  const inputs = input.inputs;
  return Object.freeze({
    ...base,
    recipient: input.recipient,
    ...(inputs === undefined ? {} : { inputs }),
  });
}

function normalizeRingEntryParams(input: RingEntryTransactionParams): RingEntryTransactionParams {
  return normalizeRingTransferBase(input);
}

function normalizeRingWithdrawalParams(
  input: RingWithdrawalTransactionParams,
): RingWithdrawalTransactionParams {
  const base = normalizeRingTransferBase(input);
  const splTokenProgram = input.splTokenProgram;
  return Object.freeze({
    ...base,
    recipient: input.recipient,
    ...(splTokenProgram === undefined ? {} : { splTokenProgram }),
  });
}

function resolveRecipient(
  input: RingTransferTransactionParams,
  context: RequestContext | undefined,
): Promise<ShieldedAddress> {
  return resolveShieldedRecipient(
    { rpc: input.client, recipient: input.recipient },
    (recipient) =>
      new RingError("RING_BUILD_TRANSFER", {
        details: { reason: "recipient not registered", recipient },
      }),
    context,
  );
}

function assetLabel(asset: Address): string {
  return asset === SOL_MINT ? "SOL" : asset;
}

/**
 * UTXOs on `tree` that the mode admits.
 *
 * @internal Exported for tests only.
 */
export function selectRingInputs(
  input: Readonly<{
    wallet: Wallet;
    ringProgramId: Address;
    asset: Address;
    amount: bigint;
    inputs: "ring" | "ring-or-default" | "default";
    tree: Address;
    maxInputs: number;
  }>,
): readonly WalletUtxo[] {
  const { wallet, ringProgramId, asset, amount, inputs } = input;
  // Zero selects a UTXO whose whole change would cross the ring boundary.
  if (amount <= 0n) {
    throw new RingError("RING_ZERO_AMOUNT", { details: { asset } });
  }
  const reserved = reservedUtxoKeys(wallet);
  return selectUtxos({
    wallet,
    asset,
    target: { kind: "cover", amount },
    policy: {
      eligible: (entry) => {
        if (!unreserved(reserved)(entry)) return false;
        if (entry.utxo.ringProgramId === ringProgramId) return inputs !== "default";
        return (
          inputs !== "ring" &&
          entry.utxo.ringProgramId === undefined &&
          entry.ringDataHash === undefined
        );
      },
      ordering: "largestFirst",
      allowWideBalance: true,
      maxInputs: input.maxInputs,
      tree: { kind: "fixed", tree: input.tree },
      errors: ringSelectionErrors,
    },
  }).entries;
}

/** @internal */
export function ringIntentMismatch(field: string): RingError {
  return new RingError("RING_INTENT_MISMATCH", { details: { field } });
}

/** @internal */
export const ringSelectionErrors: SpendSelectionErrors = {
  insufficient: ({ asset, requested, available }) =>
    new RingError("RING_INSUFFICIENT_BALANCE", {
      details: { asset, requested: requested.toString(), available: available.toString() },
    }),
  tooManyInputs: ({ eligible, max }) =>
    new RingError("RING_TOO_MANY_INPUTS", { details: { selected: eligible, maximum: max } }),
  overflow: ({ available }) =>
    new RingError("RING_SELECTED_BALANCE_OVERFLOW", {
      details: { available: available.toString() },
    }),
};
