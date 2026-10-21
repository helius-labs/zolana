import { blockhash } from "@solana/kit";
import { ZERO_32 } from "../transaction/internal.js";
import { RING_POLICY_MAX_INPUTS, validateRingPolicyShape, type Shape } from "../interface/shape.js";
import { InterfaceError } from "../interface/errors.js";
import { shareMemberSubtree } from "../interface/member-registry.js";
import { withProofDataRetry } from "../client/retry.js";
import type {
  BlockhashProvider,
  IndexerReader,
  ProofAuthority,
  ProvenRingTransact,
  Prover,
  RingMemberRegistryReader,
  SlotReader,
  TreeContext,
  WalletKeys,
} from "../client/ports.js";
import { inputTreeAddress } from "../client/internal.js";
import {
  ownerSignerAddresses,
  ringOpenings,
  ringSlotOpenings,
  prepareTransfer,
} from "../client/prover/assembly.js";
import {
  RING_INLINE_ASSET_SLOTS,
  RING_OUTPUT_SLOTS,
  RING_RULE_SLOTS,
  outflowLimitsOff,
  type CustomRingOutflowLimit,
  type CustomRingOutflowLimitProofInput,
  type CustomRingSourceOwner,
  type CustomRingSubjectWitness,
  type CustomRingPolicyProofRequest,
  type TransferCircuit,
} from "../client/prover/types.js";
import { hashBytes } from "../hasher/index.js";
import { addressBytes } from "../interface/internal.js";
import { InstructionTag } from "../interface/program.js";
import { compileUnsignedTransaction } from "../flows/compile.js";
import type {
  Address,
  Bytes32,
  Bytes128,
  Instruction,
  RequestContext,
  Transaction,
  TransactInstructionData,
  TransactWithdrawal,
} from "../interface/types.js";
import { initializePoseidon } from "../hasher/index.js";
import {
  AUDIT_INPUT_SLOTS,
  BASE_ANONYMOUS_INPUT_SLOTS,
  auditPublicInputHash,
  policyPublicInputHash,
  policyIndexedInputs,
  parseAuditorMessage,
  type CustomRingBasePublicInput,
} from "../keypair/audit.js";
import type { X25519PublicKey } from "../keypair/x25519.js";
import { ShieldedAddress } from "../keypair/shielded.js";
import { ViewingKey } from "../keypair/viewing-key.js";
import {
  ConfidentialTransfer,
  SppProofInputs,
  createExternalData,
  inputTreeIds,
  privateTxAddressChain,
  ringSpendMessage,
  sppPrivateTxHashInput,
  type PreparedTransfer,
} from "../transaction/instructions/transact.js";
import {
  EncryptedScheme,
  encodeConfidential,
  encodeOutputData,
} from "../transaction/serialization/codecs.js";
import { Data } from "../transaction/data.js";
import { ProofInputUtxo, type ProofOutputUtxo } from "../transaction/utxo.js";
import {
  encryptCustomRingTransfer,
  type EncryptedCustomRingTransfer,
} from "../transaction/wallet/encrypt-rails.js";
import {
  encryptAnonymousRingTransfer,
  type EncryptedAnonymousRingTransfer,
} from "../transaction/wallet/anonymous-ring.js";
import {
  approveUnattended,
  checkIntentApproval,
  checkPreparedTransfer,
  checkTransactData,
  ownerSolanaAccount,
  withdrawalIntentRecipient,
  intentHash,
  type ApprovalHandler,
  type TransactionIntent,
} from "../transaction/wallet/intent.js";
import { withTransactionKey } from "../wallet/private-transaction.js";
import { SOL_ASSET_ID, SOL_MINT, type AssetRegistry } from "../transaction/asset.js";
import type { UtxoReservation, Wallet, WalletUtxo } from "../transaction/wallet/state.js";
import { resolveWithdrawalSettlement, withdrawalSetupInstructions } from "../flows/settlement.js";
import { resolveShieldedRecipient } from "../wallet/registry.js";

import {
  RING_COSIGN_TRANSFERS,
  RING_COSIGN_WITHDRAWALS,
  type RingPolicyConfig,
  type RingProgramConfig,
} from "./codecs.js";
import { provePolicyAnswers, type PolicyAnswers, type RingPolicyAnswerClient } from "./answers.js";
import {
  memberOfAsset,
  memberOfIdentity,
  policySourceOwners,
  verifiedRuleTable,
  type Member,
  type RuleTable,
} from "./policy.js";
import { fetchRingCoSigner, fetchRingConfigs } from "./config.js";
import {
  anonymousAuditInputs,
  anonymousExitTokenOwner,
  anonymousIdentities,
  anonymousSlotTags,
  checkAnonymousOutputs,
  checkAnonymousSigner,
  checkAnonymousSlots,
  type AnonymousPreparedTransfer,
  type AnonymousSpendSigner,
} from "./anonymous.js";
import { TRANSFER_DEMAND, checkRingCoSigner, type CoSignDemand } from "./cosign.js";
import type { LatestBlockhash } from "../client/kit.js";
import { selectUtxos, type SpendSelectionErrors } from "../flows/select.js";
import { reserveEntries, reservedUtxoKeys, unreserved } from "../flows/reserve.js";
import { RingError, wrapRingError } from "./error.js";
import { signerAddress, type SignerAccount } from "../interface/instructions/index.js";

import {
  ringTransactInstruction,
  ringDelegateTransactInstruction,
  type RingTransactPolicy,
  type RingTransactTrees,
} from "./instructions.js";
import { ringEscrowedOwners, unregisteredOutputKey } from "./key-escrow.js";
import {
  boundRegistryRoot,
  checkRetainedEntries,
  RingTransactionSubmission,
  type RingSubmissionAttempt,
  type RingSubmissionBuildState,
} from "./submission.js";
import { equalBytes } from "../wallet/internal.js";
import { resolveRingOutputTree } from "./trees.js";
import { treeAddress } from "../interface/pda/index.js";

/** Rust `TRANSACT_COMPUTE_UNIT_LIMIT`. The custom-ring transact verifies two proofs. */
export const RING_TRANSACT_COMPUTE_UNIT_LIMIT = 1_400_000;
/** Borsh `Encrypted` tag, its length, the scheme byte and the embedded X25519 key. */
const CONFIDENTIAL_BODY_OVERHEAD = 1 + 4 + 1 + 33;

export type RingTransferClient = import("../client/ports.js").IndexedPolicyClient &
  TreeContext &
  BlockhashProvider &
  RingPolicyAnswerClient &
  SlotReader &
  Pick<RingMemberRegistryReader, "getRingMemberRecord"> &
  Pick<Prover, "proveRingTransact" | "proveCustomRingPolicy" | "proveCustomRingBase">;

export interface RingTransferTransactionParams {
  readonly client: RingTransferClient;
  readonly ringProgramId: Address;
  readonly wallet: Wallet;
  readonly keys: WalletKeys;
  readonly feePayer: Address;
  readonly approve?: ApprovalHandler;
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
  readonly keys: WalletKeys;
  readonly feePayer: Address;
  readonly approve?: ApprovalHandler;
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
  /** Include the final signers, settlement accounts and setup instructions in the size check before proving. */
  readonly transaction?: Readonly<{
    cosigner?: SignerAccount;
    delegate?: SignerAccount;
    withdrawal?: TransactWithdrawal;
    setupInstructions?: readonly Instruction[];
    priorityFeeLamports?: bigint;
  }>;
  readonly keys: WalletKeys;
  readonly assets: AssetRegistry;
  /** Must equal `client.tree`. */
  readonly tree: Address;
  /** Receives every private output, defaults to `tree`. */
  readonly outputTree?: Address;
}

export type RingDelegateProofClient = import("../client/ports.js").IndexedPolicyClient &
  TreeContext &
  RingPolicyAnswerClient &
  Pick<RingMemberRegistryReader, "getRingMemberRecord"> &
  Pick<
    Prover,
    "proveRingAuthorityTransact" | "proveCustomRingDelegatePolicy" | "proveCustomRingBase"
  >;

/** Proofs over the source's nullifier key and a sealing key per transaction, the source's viewing key stays with its holder. */
export interface RingDelegateSpender {
  readonly proofs: ProofAuthority;
  withTransactionKey<T>(
    firstNullifier: Bytes32,
    use: (tx: ViewingKey) => T extends Promise<unknown> ? never : T,
    context?: RequestContext,
  ): Promise<T>;
}

export type CustomRingDelegateTransferParams = Omit<CustomRingTransferParams, "client" | "keys"> &
  Readonly<{ client: RingDelegateProofClient; spender: RingDelegateSpender }>;

/** Mirrors Rust `ProvenTransfer`. */
export type ProvenRingTransfer = RingTransactTrees &
  Readonly<{
    twoByThree?: boolean;
    policyShape?: "general" | "subtree";
    data: TransactInstructionData;
    proof: Uint8Array;
    txViewingPublicKey: X25519PublicKey;
    payer: Address;
    approvalRequired: boolean;
    /** Absent on an audit-only ring. */
    policy?: RingTransactPolicy;
    /**
     * The Ed25519 and PDA owners of inputs and of outputs that carry data, in
     * signer-vector order, the fee payer too when it is one of them.
     */
    ownerSigners: readonly Address[];
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
      registry: params.client,
      build: (retry, context) => buildRingSend({ params, destination: "ring", retry }, context),
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
      registry: params.client,
      build: (retry, context) => buildRingSend({ params, destination: "default", retry }, context),
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
      registry: params.client,
      build: (retry, context) => buildRingWithdrawal({ params, retry }, context),
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
  | "keys"
  | "feePayer"
  | "approve"
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
  let reservation: UtxoReservation | undefined;
  try {
    await initializePoseidon();
    const asset = params.asset ?? SOL_MINT;
    const address = params.keys.address();
    const [resolved, coSigner, outputTree] = await Promise.all([
      strategy.resolve(),
      fetchRingCoSigner(params.client, params.ringProgramId, context),
      resolveRingOutputTree(params.client, params.outputTree, context),
    ]);
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
        maxInputs: RING_POLICY_MAX_INPUTS,
      });
    reservation = retry.reservation ?? reserveEntries(params.wallet, selected, retry.lifetime);
    retry.entries = selected;
    retry.reservation = reservation;
    const inputs = selected.map((entry) => ringProofInput(entry, address, params.client));
    const transfer = new ConfidentialTransfer(address, inputs, params.feePayer).withOutputTreeId(
      outputTree.treeId,
    );
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
    const approval = await (params.approve ?? approveUnattended)({
      solanaPublicKey: ownerSolanaAccount(address, params.feePayer),
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
        keys: params.keys,
        assets: params.wallet.registry,
        transaction: {
          ...(params.cosigner === undefined ? {} : { cosigner: params.cosigner }),
          ...(plan.withdrawal === undefined ? {} : { withdrawal: plan.withdrawal }),
          ...(plan.setupInstructions === undefined
            ? {}
            : { setupInstructions: plan.setupInstructions }),
          ...(params.priorityFeeLamports === undefined
            ? {}
            : { priorityFeeLamports: params.priorityFeeLamports }),
        },
        tree: params.client.tree,
        ...(params.outputTree === undefined ? {} : { outputTree: params.outputTree }),
      },
      context,
    );
    checkTransactData(proven.data, plan.intent, ringIntentMismatch);
    if (proven.approvalRequired) checkRingCoSigner({ ...coSigning, approvalRequired: true });
    const { transaction, lifetime } = await provenRingTransaction(
      {
        client: params.client,
        ringProgramId: params.ringProgramId,
        feePayer: params.feePayer,
        proven,
        ...(params.cosigner === undefined ? {} : { cosigner: params.cosigner }),
        ...(plan.withdrawal === undefined ? {} : { withdrawal: plan.withdrawal }),
        ...(plan.setupInstructions === undefined
          ? {}
          : { setupInstructions: plan.setupInstructions }),
        ...(params.computeUnitLimit === undefined
          ? {}
          : { computeUnitLimit: params.computeUnitLimit }),
        ...(params.priorityFeeLamports === undefined
          ? {}
          : { priorityFeeLamports: params.priorityFeeLamports }),
      },
      context,
    );
    return Object.freeze({
      transaction,
      lastValidBlockHeight: lifetime.lastValidBlockHeight,
      intentHash: plannedIntent,
      ringInstructionIndex: plan.setupInstructions?.length ?? 0,
      ...boundRegistryRoot(params.ringProgramId, proven.policy),
    });
  } catch (cause) {
    if (reservation !== undefined) params.wallet._releaseReservation(reservation.id);
    throw wrapRingError(strategy.errorCode, cause);
  }
}

/** The ring transact of a proven transfer behind its setup instructions, unsigned. */
async function provenRingTransaction(
  input: Readonly<{
    client: BlockhashProvider;
    ringProgramId: Address;
    feePayer: Address;
    proven: ProvenRingTransfer;
    cosigner?: SignerAccount;
    withdrawal?: TransactWithdrawal;
    setupInstructions?: readonly Instruction[];
    computeUnitLimit?: number;
    priorityFeeLamports?: bigint;
  }>,
  context: RequestContext | undefined,
): Promise<Readonly<{ transaction: Transaction; lifetime: LatestBlockhash }>> {
  const { proven } = input;
  const [instruction, lifetime] = await Promise.all([
    ringTransactInstruction({
      ringProgramId: input.ringProgramId,
      payer: proven.payer,
      inputTrees: proven.inputTrees,
      outputTree: proven.outputTree,
      ...(proven.policy === undefined ? {} : { policy: proven.policy }),
      proof: proven.proof,
      twoByThree: proven.twoByThree === true,
      ...(proven.policyShape === undefined ? {} : { policyShape: proven.policyShape }),
      data: proven.data,
      approvalRequired: proven.approvalRequired,
      ...(proven.ownerSigners.length === 0 ? {} : { ownerSigners: proven.ownerSigners }),
      ...(input.withdrawal === undefined ? {} : { withdrawal: input.withdrawal }),
      ...(input.cosigner === undefined ? {} : { cosigner: input.cosigner }),
    }),
    input.client.getLatestBlockhash(context),
  ]);
  const transaction = compileUnsignedTransaction({
    feePayer: input.feePayer,
    lifetime,
    computeUnitLimit: input.computeUnitLimit ?? RING_TRANSACT_COMPUTE_UNIT_LIMIT,
    ...(input.priorityFeeLamports === undefined
      ? {}
      : { priorityFeeLamports: input.priorityFeeLamports }),
    instructions: [...(input.setupInstructions ?? []), instruction],
    sizeShape: {
      inputs: proven.data.inputs.length,
      outputs: proven.data.outputs.length,
    },
  });
  return Object.freeze({ transaction, lifetime });
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

/** Mirrors Rust `CustomRingTransfer::prove`: the auditor message enters the external data before the SPP proof commits to it. */
export async function proveCustomRingTransfer(
  input: CustomRingTransferParams,
  context?: RequestContext,
): Promise<ProvenRingTransfer> {
  return withProofDataRetry(
    input.client.proofDataSource,
    (attempt) =>
      proveRingTransferStatement(
        input,
        { kind: "member", client: input.client, keys: input.keys },
        attempt,
      ),
    context,
  );
}

export type AnonymousRingTransferClient = Omit<RingTransferClient, "proveRingTransact"> &
  Pick<IndexerReader, "getShieldedTransactionsByTags"> &
  Pick<Prover, "proveAnonymousRingTransact">;

/** Mirrors Rust `RingTransfer<Anonymous>`, every ring output owner other than the sender is a payment of `prepared`. */
export type AnonymousRingTransferParams = Omit<CustomRingTransferParams, "client" | "prepared"> &
  Readonly<{
    client: AnonymousRingTransferClient;
    prepared: AnonymousPreparedTransfer;
    /** Must be the sender's signing key, it signs inside the proof only. */
    signer: AnonymousSpendSigner;
    /** The sender's long-lived viewing key, borrowed for the call. */
    viewingKey: ViewingKey;
  }>;

/** The hidden owner of an anonymous ring signs inside the SPP proof, no transaction signer names it. */
export async function proveAnonymousRingTransfer(
  input: AnonymousRingTransferParams,
  context?: RequestContext,
): Promise<ProvenRingTransfer> {
  return withProofDataRetry(
    input.client.proofDataSource,
    (attempt) =>
      proveRingTransferStatement(
        { ...input, prepared: input.prepared.transfer },
        {
          kind: "anonymous",
          client: input.client,
          keys: input.keys,
          signer: input.signer,
          viewingKey: input.viewingKey,
          payments: input.prepared,
        },
        attempt,
      ),
    context,
  );
}

/** Unsigned, the fee payer and the co-signer the outflow limits or the ring's scope demand sign. */
export async function buildAnonymousRingTransferTransaction(
  input: AnonymousRingTransferParams & Readonly<{ computeUnitLimit?: number }>,
  context?: RequestContext,
): Promise<Transaction> {
  const [proven, configured] = await Promise.all([
    proveAnonymousRingTransfer(input, context),
    fetchRingCoSigner(input.client, input.ringProgramId, context),
  ]);
  const options = input.transaction;
  checkRingCoSigner({
    ringProgramId: input.ringProgramId,
    configured,
    supplied: options?.cosigner,
    demand: spendDemand(input.prepared.transfer),
    approvalRequired: proven.approvalRequired,
  });
  const { transaction } = await provenRingTransaction(
    {
      client: input.client,
      ringProgramId: input.ringProgramId,
      feePayer: input.prepared.transfer.payer,
      proven,
      ...(options?.cosigner === undefined ? {} : { cosigner: options.cosigner }),
      ...(options?.withdrawal === undefined ? {} : { withdrawal: options.withdrawal }),
      ...(options?.setupInstructions === undefined
        ? {}
        : { setupInstructions: options.setupInstructions }),
      ...(input.computeUnitLimit === undefined ? {} : { computeUnitLimit: input.computeUnitLimit }),
      ...(options?.priorityFeeLamports === undefined
        ? {}
        : { priorityFeeLamports: options.priorityFeeLamports }),
    },
    context,
  );
  return transaction;
}

/** A public withdrawal of the prepared transfer widens the co-signer's scope to its mint and amount. */
function spendDemand(prepared: PreparedTransfer): CoSignDemand {
  const withdrawal = prepared.interfaceTransfers.find((transfer) => !transfer.isDeposit);
  if (withdrawal === undefined) return TRANSFER_DEMAND;
  return {
    classes: RING_COSIGN_TRANSFERS | RING_COSIGN_WITHDRAWALS,
    withdrawal: {
      mint: withdrawal.kind === "sol" ? SOL_MINT : withdrawal.mint,
      amount: withdrawal.amount,
    },
  };
}

/** Delegate proofs commit the limits without bounding the move. */
export async function proveCustomRingDelegateTransfer(
  input: CustomRingDelegateTransferParams,
  context?: RequestContext,
): Promise<ProvenRingTransfer> {
  return withProofDataRetry(
    input.client.proofDataSource,
    (attempt) =>
      proveRingTransferStatement(
        input,
        { kind: "delegate", client: input.client, spender: input.spender },
        attempt,
      ),
    context,
  );
}

type RingTransferFlow =
  | Readonly<{ kind: "member"; client: RingTransferClient; keys: WalletKeys }>
  | Readonly<{ kind: "delegate"; client: RingDelegateProofClient; spender: RingDelegateSpender }>
  | Readonly<{
      kind: "anonymous";
      client: AnonymousRingTransferClient;
      keys: WalletKeys;
      signer: AnonymousSpendSigner;
      viewingKey: ViewingKey;
      payments: AnonymousPreparedTransfer;
    }>;

/** The anonymous rail past staging, its blinding seed and slot tags fixed. */
type RingTransferRail =
  | Exclude<RingTransferFlow, { kind: "anonymous" }>
  | (Extract<RingTransferFlow, { kind: "anonymous" }> & Readonly<{ staged: AnonymousStage }>);

interface AnonymousStage {
  readonly prepared: PreparedTransfer;
  /** The hidden owner's Ed25519 key. */
  readonly owner: Bytes32;
  readonly slots: Awaited<ReturnType<typeof anonymousSlotTags>>;
  /** The ring's configured co-signer, the proof binds it apart from the owner. */
  readonly cosigner: Address | undefined;
  /** The owner SPP reads from the SPL withdrawal's token account. */
  readonly exitTokenOwner: Address | undefined;
}

/** The sealed slots and the audit secrets, one shape for every rail. */
type SealedRingTransfer =
  | Readonly<{ kind: "confidential"; encrypted: EncryptedCustomRingTransfer }>
  | Readonly<{ kind: "anonymous"; encrypted: EncryptedAnonymousRingTransfer }>;

async function proveRingTransferStatement(
  input: Omit<CustomRingTransferParams, "client" | "keys">,
  flow: RingTransferFlow,
  context?: RequestContext,
): Promise<ProvenRingTransfer> {
  if (
    input.transaction !== undefined &&
    (input.transaction === null || typeof input.transaction !== "object")
  )
    throw new RingError("RING_BUILD_TRANSFER", { details: { reason: "transaction options" } });
  await initializePoseidon();
  // Money inputs spend from the client tree.
  if (input.tree !== flow.client.tree) {
    throw new RingError("RING_TREE_MISMATCH", {
      details: { tree: input.tree, clientTree: flow.client.tree },
    });
  }
  const outputTree: TreeContext = {
    tree: input.outputTree ?? input.tree,
    treeId: input.prepared.outputTreeId,
  };
  if (treeAddress(outputTree.treeId) !== outputTree.tree)
    throw new RingError("RING_TREE_MISMATCH", { details: { tree: outputTree.tree } });
  const configs = await fetchRingConfigs(flow.client, input.ringProgramId, context);
  // 1. Pin the ring tier and policy before extending the transaction statement.
  const config = configs.config;
  checkRingMode(config, flow.kind);
  // Mirrors the program's `DelegateRequiresPolicy` and escrow checks, before any prover round.
  if (flow.kind === "delegate" && !(configs.hasPolicy && config.keyEscrow)) {
    throw new RingError("RING_DELEGATE_INVALID", { details: { reason: "keyEscrow" } });
  }
  const policy = configs.hasPolicy ? policyContext(configs.policy) : undefined;
  if (policy !== undefined) {
    try {
      validateRingPolicyShape(
        input.prepared.shape.inputs,
        input.prepared.shape.outputs,
        input.prepared.shape,
      );
    } catch (cause) {
      if (!(cause instanceof InterfaceError) || cause.code !== "INTERFACE_INVALID_SHAPE")
        throw cause;
      throw new RingError("RING_POLICY_SHAPE_UNSUPPORTED");
    }
  }
  checkRingMembership(input.prepared, input.ringProgramId);
  const rail: RingTransferRail =
    flow.kind === "anonymous"
      ? { ...flow, staged: await stageAnonymous(input, flow, context) }
      : flow;
  const prepared = rail.kind === "anonymous" ? rail.staged.prepared : input.prepared;
  const ringId = hashBytes(addressBytes(input.ringProgramId, "ringProgramId")) as Bytes32;

  let limits: CustomRingOutflowLimitProofInput | undefined;
  if (policy !== undefined && rail.kind === "delegate") {
    limits = {
      ...outflowLimitsOff({ ringId, namespaceOwnerHash: policy.config.namespaceOwnerHash }),
      limits: policy.table.limits,
    };
  }
  if (policy !== undefined && policy.table.limits.length !== 0 && rail.kind !== "delegate") {
    // 2. Bound the member's outflow per limited mint before any prover round.
    limits = boundOutflowLimits({
      sender: memberOfIdentity(prepared.owner.signingPublicKey.ownerProofInputHash()),
      ringProgramId: input.ringProgramId,
      inputs: prepared.inputs,
      outputs: prepared.outputs,
      limits: policy.table.limits,
      namespaceOwnerHash: policy.config.namespaceOwnerHash,
    });
  }
  const approvalRequired = limits?.approvalRequired ?? false;

  // 3. Bind the audit message to the SPP transaction hash.
  const outputs = prepared.proofOutputs().filter((output) => !output.isCompact());
  const sealed: SealedRingTransfer =
    rail.kind === "anonymous"
      ? {
          kind: "anonymous",
          encrypted: await withTransactionKey(
            rail.keys,
            prepared.firstNullifier,
            (tx) =>
              encryptAnonymousRingTransfer(tx, {
                sender: rail.viewingKey,
                senderIdentity: rail.staged.owner,
                ringProgramId: input.ringProgramId,
                auditorPublicKey: config.auditorPublicKey,
                outputs,
                slots: rail.staged.slots,
                inputs: anonymousAuditInputs(prepared),
                assets: input.assets,
              }),
            context,
          ),
        }
      : {
          kind: "confidential",
          encrypted: await sealConfidential(input, rail, prepared, config, outputTree, context),
        };
  const encrypted = sealed.encrypted;
  try {
    const proofInputs =
      sealed.kind === "anonymous"
        ? prepared.finalize({
            txViewingPublicKey: encrypted.txViewingPublicKey,
            salt: encrypted.salt,
            payload: sealed.encrypted.payload,
            messages: [encrypted.auditorMessage],
            instructionDiscriminator: InstructionTag.ringTransact,
            anonymous: true,
          })
        : frameDummyOutputs(
            prepared.finalize({
              txViewingPublicKey: encrypted.txViewingPublicKey,
              salt: encrypted.salt,
              payload: sealed.encrypted.payload,
              messages: [...sealed.encrypted.sealedMessages, encrypted.auditorMessage],
              instructionDiscriminator:
                rail.kind === "delegate"
                  ? InstructionTag.ringAuthorityTransact
                  : InstructionTag.ringTransact,
            }),
          );
    if (sealed.kind === "anonymous") checkAnonymousOutputs(proofInputs);
    const shape = policy === undefined ? undefined : prepared.shape;
    const openings =
      sealed.kind === "anonymous" && shape === undefined
        ? ringSlotOpenings(proofInputs, anonymousBaseCapacity(proofInputs))
        : ringOpenings(proofInputs, shape);
    const subjectOutputs = proofInputs.outputs.filter((output) => !output.isCompact());
    const policyRound =
      policy === undefined
        ? undefined
        : {
            ...policy,
            ...(await provePolicyAnswers(
              {
                client: rail.client,
                proofDataSource: rail.client.proofDataSource,
                ringProgramId: input.ringProgramId,
                keyEscrow: config.keyEscrow,
                ...(shape === undefined ? {} : { shape }),
                table: policy.table,
                config: policy.config,
                inputs: proofInputs.inputUtxos,
                outputs: subjectOutputs,
              },
              context,
            )),
          };
    const escrowOwners =
      policyRound !== undefined && config.keyEscrow
        ? ringEscrowedOwners(openings.outputs, policyRound.config.namespaceOwnerHash)
        : undefined;
    const circuit = await railCircuit(rail, input.ringProgramId, proofInputs, context);
    const ownerSigners =
      rail.kind === "member" ? ownerSignerAddresses(prepared.inputs, proofInputs.outputs) : [];
    await assertRingTransferFits({
      input,
      flow: rail,
      circuit,
      ownerSigners,
      prepared,
      proofInputs,
      outputTree,
      policyRound,
      approvalRequired,
    });
    // 4. Prove the SPP spend and bind the ring proof to that same transaction.
    const { data } = await proveRailSpend(
      { rail, circuit, proofInputs, ringProgramId: input.ringProgramId, outputTree },
      context,
    );
    // The audit statement rehashes the auditor message SPP already hashed into the external data hash.
    const message = parseAuditorMessage(encrypted.auditorMessage.data, {
      anonymous: sealed.kind === "anonymous",
      inputs: openings.nIn,
      outputs: openings.nOut,
    });
    const delivery =
      sealed.kind === "anonymous"
        ? Object.freeze({
            identities: anonymousIdentities(prepared.owner, proofInputs.outputs),
            delivery: Object.freeze({
              ringProgramId: input.ringProgramId,
              outputs: sealed.encrypted.delivery,
            }),
          })
        : undefined;
    const bodyBinding =
      sealed.kind === "anonymous"
        ? { outputBodyHashes: sealed.encrypted.outputBodyHashes, anonymous: true }
        : {};
    const common = {
      data,
      txViewingPublicKey: encrypted.txViewingPublicKey,
      payer: prepared.payer,
      inputTrees: Object.freeze(
        inputTreeIds(proofInputs.inputUtxos).map((treeId) => inputTreeAddress(rail.client, treeId)),
      ),
      outputTree: outputTree.tree,
      ownerSigners,
    } as const;

    if (policyRound === undefined) {
      const proof = await rail.client.proveCustomRingBase(
        {
          publicInputHash: auditPublicInputHash({
            privateTxHash: data.privateTxHash,
            txViewingPublicKey: encrypted.txViewingPublicKey,
            auditorPublicKey: config.auditorPublicKey,
            message,
            outputHashes: publishedOutputHashes(proofInputs),
            salt: encrypted.salt,
            ...bodyBinding,
          }),
          privateTxHash: data.privateTxHash,
          txViewingSecret: encrypted.audit.txViewingSecret,
          ephemeralSecret: encrypted.audit.ephemeralSecret,
          auditorPublicKey: config.auditorPublicKey.u(),
          salt: encrypted.salt,
          nOut: openings.nOut,
          nIn: openings.nIn,
          outputs: openings.outputs,
          ...(delivery === undefined
            ? {}
            : {
                anonymous: {
                  ...delivery,
                  inputs: openings.inputs,
                  anonymousOutputs: openings.outputs,
                  privateTxBlinding: proofInputs.privateTxBlinding(),
                },
              }),
        },
        context,
      );
      return Object.freeze({ ...common, proof, approvalRequired });
    }

    const { statement, policyRequest, twoByThree, policyShape } = buildPolicyProofRequest({
      policyRound,
      config,
      data,
      encrypted,
      openings,
      proofInputs,
      limits,
      ringId,
      shape,
      message,
      proofDataSource: rail.client.proofDataSource,
      ...(delivery === undefined ? {} : { anonymous: delivery }),
      bodyBinding,
    });
    let indexed:
      | Awaited<ReturnType<NonNullable<typeof rail.client.proveIndexedRingPolicy>>>
      | undefined;
    if (rail.client.proofDataSource === "prover") {
      if (rail.client.proveIndexedRingPolicy === undefined)
        throw new RingError("RING_ENTRY_PROOF_INCOMPLETE");
      try {
        indexed = await rail.client.proveIndexedRingPolicy(
          {
            circuit:
              rail.kind === "delegate" ? "custom-ring-delegate-policy" : "custom-ring-policy",
            policy: policyRequest,
            publicInputs: policyIndexedInputs(statement),
            trees: policyRound.treeSlots.map((slot, index) => ({
              tree: policyRound.policyTrees[index]!,
              id: slot.id,
              utxoRoot: slot.utxoRoot,
              nullifierRoot: slot.nullifierRoot,
              utxoRootIndex: policyRound.treeContexts[index]!.utxoTreeRootIndex,
              nullifierRootIndex: policyRound.treeContexts[index]!.nullifierTreeRootIndex,
            })),
            registry: policyRound.registry,
            ...(policyRound.foreign === undefined
              ? {}
              : { foreignRegistry: policyRound.foreign.indexed }),
          },
          context,
        );
      } catch (cause) {
        throw unregisteredOutputKey(cause, escrowOwners ?? []);
      }
    }
    const proof =
      indexed?.proof ??
      (rail.kind === "delegate"
        ? await rail.client.proveCustomRingDelegatePolicy(policyRequest, context)
        : await rail.client.proveCustomRingPolicy(policyRequest, context));
    return Object.freeze({
      ...common,
      proof,
      approvalRequired,
      twoByThree,
      ...(policyShape === undefined ? {} : { policyShape }),
      policy: Object.freeze({
        trees: policyRound.policyTrees,
        treeContexts:
          indexed === undefined
            ? policyRound.treeContexts
            : indexed.resolution.trees.map((tree) => ({
                utxoTreeRootIndex: tree.utxoRootIndex,
                nullifierTreeRootIndex: tree.nullifierRootIndex,
              })),
        memberRegistryRootIndex: policyRound.rootIndex,
        memberRegistryRoot: policyRound.registry.root,
        ...(policyRound.foreign === undefined
          ? {}
          : {
              foreignRegistry: policyRound.foreign.registry,
              foreignRootIndex: policyRound.foreign.rootIndex,
              foreignRoot: policyRound.foreign.indexed.root,
            }),
      }),
    });
  } finally {
    encrypted.audit.txViewingSecret.fill(0);
    encrypted.audit.ephemeralSecret.fill(0);
  }
}

/** An anonymous ring admits only the hidden owner's proof, the delegate rail never runs on it. */
function checkRingMode(config: RingProgramConfig, flow: RingTransferFlow["kind"]): void {
  const anonymous = config.mode === "anonymous";
  if (flow === "anonymous" && !anonymous) throw new RingError("RING_NOT_ANONYMOUS");
  if (flow === "member" && anonymous) throw new RingError("RING_ANONYMOUS_SIGNER_REQUIRED");
  if (flow === "delegate" && anonymous) throw new RingError("RING_ANONYMOUS_REFUSED");
}

function sealConfidential(
  input: Omit<CustomRingTransferParams, "client" | "keys">,
  flow: Exclude<RingTransferRail, { kind: "anonymous" }>,
  prepared: PreparedTransfer,
  config: RingProgramConfig,
  outputTree: TreeContext,
  context: RequestContext | undefined,
): Promise<EncryptedCustomRingTransfer> {
  const seal = (tx: ViewingKey): EncryptedCustomRingTransfer =>
    encryptCustomRingTransfer(tx, {
      outputs: prepared.proofOutputs().filter((output) => !output.isCompact()),
      inputCount: prepared.shape?.inputs ?? prepared.inputs.length,
      assets: input.assets,
      auditorPublicKey: config.auditorPublicKey,
      outputTreeId: outputTree.treeId,
    });
  return flow.kind === "member"
    ? withTransactionKey(flow.keys, prepared.firstNullifier, seal, context)
    : flow.spender.withTransactionKey(prepared.firstNullifier, seal, context);
}

/** The hidden owner signs the final digest, the ring program appends its configured co-signer. */
async function railCircuit(
  rail: RingTransferRail,
  ringProgramId: Address,
  proofInputs: SppProofInputs,
  context: RequestContext | undefined,
): Promise<TransferCircuit> {
  switch (rail.kind) {
    case "member":
      return { kind: "ring", ring: ringProgramId };
    case "delegate":
      return { kind: "ringAuthority", ring: ringProgramId };
    case "anonymous": {
      const signature = await rail.signer.sign(
        ringSpendMessage(ringProgramId, proofInputs.messageHash()),
        context,
      );
      return {
        kind: "ringAnonymous",
        ring: ringProgramId,
        owner: { publicKey: rail.staged.owner, signature },
        ...(rail.staged.cosigner === undefined ? {} : { cosigner: rail.staged.cosigner }),
        ...(rail.staged.exitTokenOwner === undefined
          ? {}
          : { exitTokenOwner: rail.staged.exitTokenOwner }),
      };
    }
  }
}

function proveRailSpend(
  input: Readonly<{
    rail: RingTransferRail;
    circuit: TransferCircuit;
    proofInputs: SppProofInputs;
    ringProgramId: Address;
    outputTree: TreeContext;
  }>,
  context: RequestContext | undefined,
): Promise<ProvenRingTransact> {
  const { rail, circuit, proofInputs, ringProgramId, outputTree } = input;
  switch (rail.kind) {
    case "member":
      return rail.client.proveRingTransact(
        proofInputs,
        ringProgramId,
        rail.keys,
        { outputTree },
        context,
      );
    case "delegate":
      return rail.client.proveRingAuthorityTransact(
        proofInputs,
        ringProgramId,
        rail.spender.proofs,
        context,
        outputTree,
      );
    case "anonymous":
      if (circuit.kind !== "ringAnonymous") throw new RingError("RING_BUILD_TRANSFER");
      return rail.client.proveAnonymousRingTransact(
        {
          proofInputs,
          ringProgramId,
          owner: circuit.owner,
          ...(circuit.cosigner === undefined ? {} : { cosigner: circuit.cosigner }),
          ...(circuit.exitTokenOwner === undefined
            ? {}
            : { exitTokenOwner: circuit.exitTokenOwner }),
          keys: rail.keys,
          config: { outputTree },
        },
        context,
      );
  }
}

/** Mirrors Rust `Anonymous::stage`, the slot order is fixed before any stream is read. */
async function stageAnonymous(
  input: Omit<CustomRingTransferParams, "client" | "keys">,
  flow: Extract<RingTransferFlow, { kind: "anonymous" }>,
  context: RequestContext | undefined,
): Promise<AnonymousStage> {
  const sender = flow.keys.address();
  const supplied = input.transaction?.cosigner;
  const owner = checkAnonymousSigner({
    signer: flow.signer,
    viewingKey: flow.viewingKey,
    sender,
    payer: input.prepared.payer,
    cosigner: supplied === undefined ? undefined : signerAddress(supplied),
  });
  checkAnonymousSlots(input.prepared);
  const exitTokenOwner = await anonymousExitTokenOwner(
    { client: flow.client, transfers: input.prepared.interfaceTransfers, hiddenOwner: owner },
    context,
  );
  // The recipient and the sender's own recovery rederive every blinding from the viewing key.
  const prepared = input.prepared.withBlindingSeed(
    flow.viewingKey.ringBlindingSeed(input.prepared.firstNullifier),
  );
  const [slots, configured] = await Promise.all([
    anonymousSlotTags(
      {
        indexer: flow.client,
        viewingKey: flow.viewingKey,
        sender,
        ringProgramId: input.ringProgramId,
        prepared: flow.payments,
      },
      context,
    ),
    fetchRingCoSigner(flow.client, input.ringProgramId, context),
  ]);
  return Object.freeze({ prepared, owner, slots, cosigner: configured?.signer, exitTokenOwner });
}

/** Rust `BaseCircuit::select`, the wide anonymous key opens every disclosed input. */
function anonymousBaseCapacity(proofInputs: SppProofInputs): Shape {
  return {
    inputs:
      proofInputs.inputUtxos.length > BASE_ANONYMOUS_INPUT_SLOTS
        ? AUDIT_INPUT_SLOTS
        : BASE_ANONYMOUS_INPUT_SLOTS,
    outputs: RING_OUTPUT_SLOTS,
  };
}

/** Check the final instruction size before invoking either prover. */
async function assertRingTransferFits({
  input,
  flow,
  circuit,
  ownerSigners,
  prepared,
  proofInputs,
  outputTree,
  policyRound,
  approvalRequired,
}: Readonly<{
  input: Omit<CustomRingTransferParams, "client" | "keys">;
  flow: Readonly<{ kind: RingTransferFlow["kind"]; client: TreeContext }>;
  circuit: TransferCircuit;
  ownerSigners: readonly Address[];
  prepared: PreparedTransfer;
  proofInputs: SppProofInputs;
  outputTree: TreeContext;
  policyRound: PolicyRound | undefined;
  approvalRequired: boolean;
}>): Promise<void> {
  // Proof bytes have a fixed length, so this catches oversized payloads before either prover runs.
  const preparedProof = prepareTransfer(proofInputs, circuit);
  const preview = preparedProof.finish(
    prepared.inputTreeIds.map((id) => ({
      treeId: id,
      slot: { id, utxoRoot: ZERO_32, nullifierRoot: ZERO_32 },
      utxoRootIndex: 0,
      nullifierRootIndex: 0,
    })),
  );
  const previewData = preview.withProof(
    { a: ZERO_32, b: new Uint8Array(128) as Bytes128, c: ZERO_32 },
    circuit.kind === "ringAnonymous" ? { commitment: ZERO_32, commitmentPok: ZERO_32 } : undefined,
  );
  const previewPolicy =
    policyRound === undefined
      ? undefined
      : {
          trees: policyRound.policyTrees,
          treeContexts: policyRound.treeContexts,
          memberRegistryRootIndex: policyRound.rootIndex,
          memberRegistryRoot: policyRound.registry.root,
          ...(policyRound.foreign === undefined
            ? {}
            : {
                foreignRegistry: policyRound.foreign.registry,
                foreignRootIndex: policyRound.foreign.rootIndex,
                foreignRoot: policyRound.foreign.indexed.root,
              }),
        };
  const previewCommon = {
    ringProgramId: input.ringProgramId,
    payer: prepared.payer,
    inputTrees: prepared.inputTreeIds.map((id) => inputTreeAddress(flow.client, id)),
    outputTree: outputTree.tree,
    proof: new Uint8Array(192),
    data: previewData,
    approvalRequired,
    ...(previewPolicy === undefined ? {} : { policy: previewPolicy }),
    ...(input.transaction?.cosigner === undefined ? {} : { cosigner: input.transaction.cosigner }),
  };
  const previewInstruction =
    flow.kind === "delegate"
      ? await ringDelegateTransactInstruction({
          ...previewCommon,
          delegate: input.transaction?.delegate ?? prepared.payer,
        })
      : await ringTransactInstruction({
          ...previewCommon,
          ...(ownerSigners.length === 0 ? {} : { ownerSigners }),
          ...(input.transaction?.withdrawal === undefined
            ? {}
            : { withdrawal: input.transaction.withdrawal }),
        });
  compileUnsignedTransaction({
    feePayer: prepared.payer,
    lifetime: {
      blockhash: blockhash("11111111111111111111111111111111"),
      lastValidBlockHeight: 0n,
    },
    instructions: [...(input.transaction?.setupInstructions ?? []), previewInstruction],
    computeUnitLimit: RING_TRANSACT_COMPUTE_UNIT_LIMIT,
    ...(input.transaction?.priorityFeeLamports === undefined
      ? {}
      : { priorityFeeLamports: input.transaction.priorityFeeLamports }),
    sizeShape: prepared.shape,
  });
}

/** Build the policy statement and witness from the pinned spend and registry reads. */
function buildPolicyProofRequest({
  policyRound,
  config,
  data,
  encrypted,
  openings,
  proofInputs,
  limits,
  ringId,
  shape,
  message,
  proofDataSource,
  anonymous,
  bodyBinding,
}: Readonly<{
  policyRound: PolicyRound;
  config: RingProgramConfig;
  data: TransactInstructionData;
  encrypted: Pick<EncryptedCustomRingTransfer, "txViewingPublicKey" | "salt" | "audit">;
  openings: ReturnType<typeof ringOpenings>;
  proofInputs: SppProofInputs;
  limits: CustomRingOutflowLimitProofInput | undefined;
  ringId: Bytes32;
  shape: Shape | undefined;
  message: ReturnType<typeof parseAuditorMessage>;
  proofDataSource: RingTransferClient["proofDataSource"];
  anonymous?: CustomRingPolicyProofRequest["anonymous"];
  bodyBinding: Pick<CustomRingBasePublicInput, "outputBodyHashes" | "anonymous">;
}>) {
  const limitProofInput =
    limits ??
    outflowLimitsOff({
      ringId,
      namespaceOwnerHash: policyRound.config.namespaceOwnerHash,
    });
  const memberRegistryRoot = {
    keyEscrow: config.keyEscrow,
    memberRegistryRoot: policyRound.registry.root,
    foreignRoot: policyRound.foreign?.indexed.root ?? ZERO_32,
  };
  const statement = {
    privateTxHash: data.privateTxHash,
    txViewingPublicKey: encrypted.txViewingPublicKey,
    auditorPublicKey: config.auditorPublicKey,
    message,
    outputHashes: publishedOutputHashes(proofInputs),
    salt: encrypted.salt,
    ...bodyBinding,
    policyHash: policyRound.config.policyHash,
    treeSlots: policyRound.treeSlots,
    addressTreeId: policyRound.config.addressTreeId,
    ringId: limitProofInput.ringId,
    namespaceOwnerHash: limitProofInput.namespaceOwnerHash,
    approvalRequired: limitProofInput.approvalRequired,
    ...memberRegistryRoot,
  };
  const privateTxPreimage = sppPrivateTxHashInput(proofInputs);
  const registrySubtree =
    proofDataSource !== "prover" &&
    [policyRound.subjects, policyRound.foreignSubjects].every((subjects) =>
      shareMemberSubtree(
        subjects.flatMap((subject) => (subject === undefined ? [] : [subject.index])),
      ),
    );
  const twoByThree = registrySubtree && openings.nIn === 2 && openings.nOut === 3;
  const requestOpenings = twoByThree ? ringOpenings(proofInputs) : openings;
  const requestSubjects = (subjects: readonly (CustomRingSubjectWitness | undefined)[]) =>
    twoByThree && shape !== undefined ? twoByThreePolicySubjects(subjects, shape) : subjects;
  const policyShape: ProvenRingTransfer["policyShape"] = twoByThree
    ? undefined
    : registrySubtree
      ? "subtree"
      : "general";
  const policyRequest: CustomRingPolicyProofRequest = {
    twoByThree,
    ...(twoByThree || shape === undefined ? {} : { shape, registrySubtree }),
    publicInputHash: policyPublicInputHash(statement),
    privateTxHash: data.privateTxHash,
    txViewingSecret: encrypted.audit.txViewingSecret,
    ephemeralSecret: encrypted.audit.ephemeralSecret,
    auditorPublicKey: config.auditorPublicKey.u(),
    salt: encrypted.salt,
    nIn: openings.nIn,
    nOut: openings.nOut,
    inputs: requestOpenings.inputs,
    outputs: requestOpenings.outputs.map((opening, index) => ({
      ...opening,
      ctHash: policyRound.ctHashes[index] ?? ZERO_32,
    })),
    addressChain: privateTxAddressChain(privateTxPreimage),
    privateTxBlinding: privateTxPreimage.blinding,
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
    treeSlots: policyRound.treeSlots,
    addressTreeId: policyRound.config.addressTreeId,
    limits: limitProofInput,
    ...memberRegistryRoot,
    subjects: requestSubjects(policyRound.subjects),
    foreignSubjects: requestSubjects(policyRound.foreignSubjects),
    ...(anonymous === undefined ? {} : { anonymous }),
  };
  return { statement, policyRequest, twoByThree, policyShape };
}

function twoByThreePolicySubjects(
  subjects: readonly (CustomRingSubjectWitness | undefined)[],
  shape: Shape,
): readonly (CustomRingSubjectWitness | undefined)[] {
  return Object.freeze([
    ...Array.from({ length: 5 }, (_, index) =>
      index < shape.inputs ? subjects[index] : undefined,
    ),
    ...Array.from({ length: 4 }, (_, index) =>
      index < shape.outputs ? subjects[shape.inputs + index] : undefined,
    ),
    ...Array.from({ length: 4 }, (_, index) =>
      index < shape.outputs ? subjects[shape.inputs + shape.outputs + index] : undefined,
    ),
  ]);
}

/** Mirrors Rust `limits::bound`, the outflow is the inputs of the mint less the sender's change in the ring. */
function boundOutflowLimits(
  input: Readonly<{
    sender: Member;
    ringProgramId: Address;
    inputs: readonly ProofInputUtxo[];
    outputs: readonly ProofOutputUtxo[];
    limits: readonly CustomRingOutflowLimit[];
    namespaceOwnerHash: Bytes32;
  }>,
): CustomRingOutflowLimitProofInput {
  let approvalRequired = false;
  for (const limit of input.limits) {
    const outflow = senderOutflow(input, limit.asset);
    if (limit.cosignAbove !== 0n && outflow > limit.cosignAbove) approvalRequired = true;
    if (limit.cap !== 0n && outflow > limit.cap) {
      throw new RingError("RING_OUTFLOW_CAP_EXCEEDED", {
        details: { asset: limit.asset, cap: limit.cap, outflow },
      });
    }
  }
  return Object.freeze({
    ...outflowLimitsOff({
      ringId: hashBytes(addressBytes(input.ringProgramId, "ringProgramId")) as Bytes32,
      namespaceOwnerHash: input.namespaceOwnerHash,
    }),
    limits: Object.freeze(input.limits.map((limit) => Object.freeze({ ...limit }))),
    approvalRequired,
  });
}

function senderOutflow(
  transfer: Readonly<{
    sender: Member;
    ringProgramId: Address;
    inputs: readonly ProofInputUtxo[];
    outputs: readonly ProofOutputUtxo[];
  }>,
  asset: Bytes32,
): bigint {
  let inflow = 0n;
  for (const input of transfer.inputs) {
    if (input.isDummy()) continue;
    if (equalBytes(memberOfAsset(input.utxo.asset), asset)) inflow += input.utxo.amount;
  }
  let change = 0n;
  for (const output of transfer.outputs) {
    const owner = output.ownerAddress;
    if (owner === undefined) continue;
    const sameAsset = equalBytes(memberOfAsset(output.asset), asset);
    const sameOwner = equalBytes(
      memberOfIdentity(owner.signingPublicKey.ownerProofInputHash()),
      transfer.sender,
    );
    const inRing =
      output.ringProgramId !== undefined && output.ringProgramId === transfer.ringProgramId;
    if (sameAsset && sameOwner && inRing) change += output.amount;
  }
  if (change > inflow) throw new RingError("RING_OUTFLOW_OVERFLOW", { details: { asset } });
  const outflow = inflow - change;
  if (outflow > U64_MAX) throw new RingError("RING_OUTFLOW_OVERFLOW", { details: { asset } });
  return outflow;
}

const U64_MAX = (1n << 64n) - 1n;

type PolicyRound = PolicyContext & PolicyAnswers;

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

/** The program hashes only the outputs the transaction carries, so compact padding stays out. */
function publishedOutputHashes(proofInputs: SppProofInputs): Bytes32[] {
  return proofInputs.outputs
    .filter((output) => !output.isCompact())
    .map((output) => output.hash(proofInputs.outputTreeId));
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
    keys: input.keys,
    feePayer: input.feePayer,
    ...(input.approve === undefined ? {} : { approve: input.approve }),
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

/** Ring notes are spent from the client's tree, the stored nullifier was derived for that tree. @internal */
export function ringProofInput(
  entry: WalletUtxo,
  owner: ShieldedAddress,
  client: TreeContext,
): ProofInputUtxo {
  if (entry.outputContext.tree !== client.tree) {
    throw new RingError("RING_TREE_MISMATCH", {
      details: { tree: entry.outputContext.tree, clientTree: client.tree },
    });
  }
  return new ProofInputUtxo({
    utxo: entry.utxo,
    nullifierPublicKey: owner.nullifierPublicKey,
    nullifier: entry.nullifier,
    treeId: client.treeId,
    ...(entry.dataHash === undefined ? {} : { dataHash: entry.dataHash }),
    ...(entry.ringDataHash === undefined ? {} : { ringDataHash: entry.ringDataHash }),
  });
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
