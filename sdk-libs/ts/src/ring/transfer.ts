/** Ring transfers from a wallet, every flow selects, reserves, approves, proves and compiles through one driver. */
import type { Instruction } from "@solana/kit";

import type { BlockhashProvider, WalletKeys } from "../client/ports.js";
import { compileUnsignedTransaction } from "../flows/compile.js";
import { reserveEntries, reservedUtxoKeys, unreserved } from "../flows/reserve.js";
import { selectUtxos } from "../flows/select.js";
import { resolveWithdrawalSettlement, withdrawalSetupInstructions } from "../flows/settlement.js";
import { initializePoseidon } from "../hasher/index.js";
import { signerAddress, type SignerAccount } from "../interface/instructions/index.js";
import { MAX_TRANSACT_INPUTS, SPP_SUPPORTED_SHAPES } from "../interface/shape.js";
import { anonymousAuditKey } from "../interface/ring-disclosure-layout.js";
import type {
  Address,
  RequestContext,
  Transaction,
  TransactWithdrawal,
} from "../interface/types.js";
import { RingAddress } from "../keypair/ring-address.js";
import type { ShieldedAddress } from "../keypair/shielded.js";
import { SOL_MINT } from "../transaction/asset.js";
import { ConfidentialTransfer } from "../transaction/instructions/transact.js";
import type { AnonymousRingState } from "../transaction/wallet/anonymous-state.js";
import {
  approveUnattended,
  checkIntentApproval,
  checkPreparedTransfer,
  intentHash,
  ownerSolanaAccount,
  withdrawalIntentRecipient,
  type ApprovalHandler,
  type TransactionIntent,
} from "../transaction/wallet/intent.js";
import type { UtxoReservation, Wallet, WalletUtxo } from "../transaction/wallet/state.js";
import { equalBytes } from "../wallet/internal.js";
import { resolveShieldedRecipient } from "../wallet/registry.js";

import { RingInstructionTag, ringComputeUnitLimit } from "./admin.js";
import type { AnonymousPayment, AnonymousSpendSigner } from "./anonymous.js";
import { fetchRingProgramConfig } from "./config.js";
import { RingError, wrapRingError } from "./error.js";
import { boundState } from "./pipeline.js";
import {
  CustomRingTransfer,
  type AnonymousTransferClient,
  type CustomRingTransferClient,
  type RingTransferApproval,
} from "./rails.js";
import {
  provenWithinTransaction,
  ringIntentMismatch,
  ringProofInput,
  ringSelectionErrors,
} from "./selection.js";
import {
  RingTransactionSubmission,
  checkRetainedEntries,
  type RingSubmissionAttempt,
  type RingSubmissionBuildState,
} from "./submission.js";
import { resolveRingOutputTree } from "./trees.js";

/** Both rails, the ring's mode picks one when the transfer is built. */
export type RingTransferClient = CustomRingTransferClient &
  AnonymousTransferClient &
  BlockhashProvider;

/** The hidden owner's signer and stream state, required exactly on an anonymous ring. */
export interface AnonymousRingSpend {
  readonly signer: AnonymousSpendSigner;
  readonly state: AnonymousRingState;
  /** A missing SPL exit token account must be the owner's associated token account. */
  readonly exitTokenOwner?: Address;
}

/** What every ring spend names, each flow adds its recipient. */
export interface RingSpendParams {
  readonly client: RingTransferClient;
  readonly ringProgramId: Address;
  readonly wallet: Wallet;
  readonly keys: WalletKeys;
  readonly feePayer: Address;
  readonly approve?: ApprovalHandler;
  readonly asset?: Address;
  readonly amount: bigint;
  /** Receives every private output, defaults to `client.tree`. */
  readonly outputTree?: Address;
  /** The ring's co-signer when its scope or the approval bit demands it. */
  readonly cosigner?: SignerAccount;
  readonly anonymous?: AnonymousRingSpend;
  readonly priorityFeeLamports?: bigint;
}

export interface RingTransferTransactionParams extends RingSpendParams {
  /** A ring address on an anonymous ring, a shielded address or a registered owner on any other. */
  readonly recipient: Address | ShieldedAddress | RingAddress;
  /** `"default"` funds only from default UTXOs. `"ring-or-default"` mixes both pools, an anonymous ring funds from one pool alone. */
  readonly inputs?: "ring" | "ring-or-default" | "default";
}

export type RingEntryTransactionParams = RingSpendParams;

export interface RingExitTransactionParams extends RingSpendParams {
  readonly recipient: Address | ShieldedAddress;
}

export interface RingWithdrawalTransactionParams extends RingSpendParams {
  /** Any Solana account. It needs no registry record and need not exist yet. */
  readonly recipient: Address;
  /** SPL Token or Token-2022 for non-SOL assets, the settlement lands in the recipient's ATA. */
  readonly splTokenProgram?: Address;
}

/** Unsigned, the fee payer and any co-signer sign. */
export async function buildRingTransferTransaction(
  input: RingTransferTransactionParams,
  context?: RequestContext,
): Promise<Transaction> {
  return (await buildRingSend({ params: input, destination: "ring", retry: {} }, context))
    .transaction;
}

export function createRingTransferSubmission(
  input: RingTransferTransactionParams,
  context?: RequestContext,
): Promise<RingTransactionSubmission> {
  return RingTransactionSubmission.fromBuilder(
    {
      wallet: input.wallet,
      registry: input.client,
      clock: input.client,
      build: (retry, buildContext) =>
        buildRingSend({ params: input, destination: "ring", retry }, buildContext),
    },
    context,
  );
}

/**
 * Value leaves the ring to a default-ring UTXO of the recipient, and the audit proof still covers
 * the exit. Only ring-bound UTXOs fund it.
 */
export async function buildRingExitTransaction(
  input: RingExitTransactionParams,
  context?: RequestContext,
): Promise<Transaction> {
  return (await buildRingSend({ params: input, destination: "default", retry: {} }, context))
    .transaction;
}

export function createRingExitSubmission(
  input: RingExitTransactionParams,
  context?: RequestContext,
): Promise<RingTransactionSubmission> {
  return RingTransactionSubmission.fromBuilder(
    {
      wallet: input.wallet,
      registry: input.client,
      clock: input.client,
      build: (retry, buildContext) =>
        buildRingSend({ params: input, destination: "default", retry }, buildContext),
    },
    context,
  );
}

/** Default UTXOs of the sender enter the ring as its own ring notes. */
export async function buildRingEntryTransaction(
  input: RingEntryTransactionParams,
  context?: RequestContext,
): Promise<Transaction> {
  const attempt = await buildRingSpend(
    {
      params: input,
      retry: {},
      strategy: {
        errorCode: "RING_BUILD_ENTRY",
        selection: "default",
        resolve: () => Promise.resolve(undefined),
        configure: ({ transfer, owner, asset }) => {
          transfer.sendToRing(owner, asset, input.amount, input.ringProgramId);
          return {
            intent: {
              kind: "ringEntry",
              ringProgramId: input.ringProgramId,
              asset,
              amount: input.amount,
            },
            summary: `ring entry of ${String(input.amount)} ${assetLabel(asset)} into ring ${input.ringProgramId}`,
          };
        },
      },
    },
    context,
  );
  return attempt.transaction;
}

/**
 * Value leaves the ring to a plain Solana account. The recipient, the amount and the asset are
 * public, and the audit proof still covers the exit.
 */
export async function buildRingWithdrawalTransaction(
  input: RingWithdrawalTransactionParams,
  context?: RequestContext,
): Promise<Transaction> {
  return (await buildRingWithdrawal({ params: input, retry: {} }, context)).transaction;
}

export function createRingWithdrawalSubmission(
  input: RingWithdrawalTransactionParams,
  context?: RequestContext,
): Promise<RingTransactionSubmission> {
  return RingTransactionSubmission.fromBuilder(
    {
      wallet: input.wallet,
      registry: input.client,
      clock: input.client,
      build: (retry, buildContext) => buildRingWithdrawal({ params: input, retry }, buildContext),
    },
    context,
  );
}

/** UTXOs on `tree` the mode admits, largest first, at most `maxInputs`. */
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
  if (amount <= 0n) throw new RingError("RING_ZERO_AMOUNT", { details: { asset } });
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

async function buildRingSend(
  input: Readonly<{
    params: RingTransferTransactionParams | RingExitTransactionParams;
    destination: "ring" | "default";
    retry: RingSubmissionBuildState;
  }>,
  context: RequestContext | undefined,
): Promise<RingSubmissionAttempt> {
  const { params, destination } = input;
  const selection = "inputs" in params ? (params.inputs ?? "ring") : "ring";
  return buildRingSpend(
    {
      params,
      retry: input.retry,
      strategy: {
        errorCode: "RING_BUILD_TRANSFER",
        selection,
        resolve: () => resolveSendRecipient(params, destination, context),
        configure: ({ transfer, resolved, selected, asset, payment }) => {
          // Change of a default UTXO becomes ring bound.
          const defaultFunding = selected
            .filter((entry) => entry.utxo.ringProgramId === undefined)
            .reduce((sum, entry) => sum + entry.utxo.amount, 0n);
          const crossing =
            defaultFunding === 0n
              ? ""
              : `, moves ${String(defaultFunding)} ${assetLabel(asset)} of default UTXOs into the ring`;
          if (resolved instanceof RingAddress) {
            payment(resolved, asset, params.amount);
            return {
              intent: {
                kind: "ringAnonymousTransfer",
                ringProgramId: params.ringProgramId,
                asset,
                amount: params.amount,
                recipient: resolved,
                defaultFunding,
              },
              summary: `anonymous ring payment of ${String(params.amount)} ${assetLabel(asset)} in ring ${params.ringProgramId}${crossing}`,
            };
          }
          if (destination === "ring") transfer.send(resolved, asset, params.amount);
          else transfer.sendDefaultRing(resolved, asset, params.amount);
          const boundary =
            destination === "default" ? "exit" : defaultFunding > 0n ? "entry" : "transfer";
          return {
            intent: {
              kind: "ringTransfer",
              ringProgramId: params.ringProgramId,
              asset,
              amount: params.amount,
              recipient: resolved,
              boundary,
              defaultFunding,
            },
            summary: `ring ${boundary} of ${String(params.amount)} ${assetLabel(asset)} in ring ${params.ringProgramId} to a shielded address${crossing}`,
          };
        },
      },
    },
    context,
  );
}

async function buildRingWithdrawal(
  input: Readonly<{ params: RingWithdrawalTransactionParams; retry: RingSubmissionBuildState }>,
  context: RequestContext | undefined,
): Promise<RingSubmissionAttempt> {
  const { params } = input;
  return buildRingSpend(
    {
      params,
      retry: input.retry,
      strategy: {
        errorCode: "RING_BUILD_WITHDRAWAL",
        selection: "ring",
        resolve: async () => {
          const asset = params.asset ?? SOL_MINT;
          const [settlement, setupInstructions] = await Promise.all([
            resolveWithdrawalSettlement(params.recipient, asset, params.splTokenProgram),
            withdrawalSetupInstructions({
              payer: params.feePayer,
              recipient: params.recipient,
              asset,
              ...(params.splTokenProgram === undefined
                ? {}
                : { splTokenProgram: params.splTokenProgram }),
            }),
          ]);
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
            withdrawal: resolved.settlement.accounts,
            setupInstructions: resolved.setupInstructions,
          };
        },
      },
    },
    context,
  );
}

interface RingSpendPlan {
  readonly intent: TransactionIntent;
  readonly summary: string;
  readonly withdrawal?: TransactWithdrawal;
  readonly setupInstructions?: readonly Instruction[];
}

interface RingSpendStrategy<R> {
  readonly errorCode: "RING_BUILD_ENTRY" | "RING_BUILD_TRANSFER" | "RING_BUILD_WITHDRAWAL";
  readonly selection: "ring" | "ring-or-default" | "default";
  resolve(): Promise<R>;
  configure(
    input: Readonly<{
      transfer: ConfidentialTransfer;
      resolved: R;
      selected: readonly WalletUtxo[];
      asset: Address;
      owner: ShieldedAddress;
      /** Pays a ring address on the anonymous rail. */
      payment: (to: RingAddress, asset: Address, amount: bigint) => void;
    }>,
  ): RingSpendPlan;
}

/** One build attempt, the reservation `retry` holds survives every rebuild of a submission. */
async function buildRingSpend<R>(
  input: Readonly<{
    params: RingSpendParams;
    strategy: RingSpendStrategy<R>;
    retry: RingSubmissionBuildState;
  }>,
  context: RequestContext | undefined,
): Promise<RingSubmissionAttempt> {
  const { params, strategy, retry } = input;
  let reservation: UtxoReservation | undefined;
  try {
    await initializePoseidon();
    const asset = params.asset ?? SOL_MINT;
    const owner = params.keys.address();
    const [resolved, config, outputTree] = await Promise.all([
      strategy.resolve(),
      fetchRingProgramConfig(params.client, params.ringProgramId, context),
      resolveRingOutputTree(params.client, params.outputTree, context),
    ]);
    const anonymousRing = config.mode === "anonymous";
    if (anonymousRing !== (params.anonymous !== undefined))
      throw new RingError(anonymousRing ? "RING_ANONYMOUS_SIGNER_REQUIRED" : "RING_NOT_ANONYMOUS", {
        details: { ringProgramId: params.ringProgramId },
      });
    if (retry.entries !== undefined) checkRetainedEntries(params.wallet, retry.entries);
    const pool = {
      wallet: params.wallet,
      ringProgramId: params.ringProgramId,
      asset,
      amount: params.amount,
      tree: params.client.tree,
    };
    const selected =
      retry.entries ??
      (anonymousRing
        ? selectAnonymousInputs(pool, strategy.selection)
        : selectRingInputs({
            ...pool,
            inputs: strategy.selection,
            maxInputs: MAX_TRANSACT_INPUTS,
          }));
    reservation = retry.reservation ?? reserveEntries(params.wallet, selected, retry.lifetime);
    retry.entries = selected;
    retry.reservation = reservation;
    const transfer = new ConfidentialTransfer(
      owner,
      selected.map((entry) => ringProofInput(entry, owner, params.client)),
      params.feePayer,
    ).withOutputTreeId(outputTree.treeId);
    const ownerRail = CustomRingTransfer.new({
      ringProgramId: params.ringProgramId,
      keys: params.keys,
      transfer,
      assets: params.wallet.registry,
    });
    let anonymousPayment: AnonymousPayment | undefined;
    const plan = strategy.configure({
      transfer,
      resolved,
      selected,
      asset,
      owner,
      payment: (to, paidAsset, amount) => {
        if (!anonymousRing || anonymousPayment !== undefined)
          throw new RingError("RING_NOT_ANONYMOUS", {
            details: { ringProgramId: params.ringProgramId },
          });
        anonymousPayment = { to, asset: paidAsset, amount };
      },
    });
    const planned = intentHash(plan.intent);
    if (retry.intent !== undefined && !equalBytes(retry.intent, planned))
      throw ringIntentMismatch("retryIntent");
    retry.intent = planned;
    const approval: RingTransferApproval = {
      transaction: {
        ...(params.priorityFeeLamports === undefined
          ? {}
          : { priorityFeeLamports: params.priorityFeeLamports }),
        ...(plan.setupInstructions === undefined
          ? {}
          : { setupInstructions: plan.setupInstructions }),
      },
      approve: async ({ prepared, coSigner }) => {
        checkDemandedCoSigner(params.ringProgramId, params.cosigner, coSigner);
        const approved = await (params.approve ?? approveUnattended)({
          solanaPublicKey: ownerSolanaAccount(owner, params.feePayer),
          intent: plan.intent,
          summary: plan.summary,
        });
        checkIntentApproval(approved, plan.intent, ringIntentMismatch);
        checkPreparedTransfer(prepared, plan.intent, ringIntentMismatch);
      },
    };
    const withWithdrawal =
      plan.withdrawal === undefined ? ownerRail : ownerRail.withWithdrawalAccounts(plan.withdrawal);
    const proven = await provenWithinTransaction(selected.length, () => {
      if (params.anonymous === undefined)
        return withWithdrawal.proveApproved(params.client, approval, context);
      let anonymous = withWithdrawal.withAnonymousSigner(
        params.anonymous.signer,
        params.anonymous.state,
      );
      if (anonymousPayment !== undefined) anonymous = anonymous.withPayment(anonymousPayment);
      if (params.anonymous.exitTokenOwner !== undefined)
        anonymous = anonymous.withExitTokenOwner(params.anonymous.exitTokenOwner);
      return anonymous.proveApproved(params.client, approval, context);
    });
    const [instruction, lifetime] = await Promise.all([
      proven.epoch === undefined
        ? proven.instruction()
        : params.client.getSlot(context).then((slot) => proven.instructionAt(slot)),
      params.client.getLatestBlockhash(context),
    ]);
    const transaction = compileUnsignedTransaction({
      ...approval.transaction,
      feePayer: params.feePayer,
      lifetime,
      computeUnitLimit: ringComputeUnitLimit(RingInstructionTag.transact),
      instructions: [instruction],
    });
    return Object.freeze({
      transaction,
      lastValidBlockHeight: lifetime.lastValidBlockHeight,
      intentHash: planned,
      ringInstructionIndex: plan.setupInstructions?.length ?? 0,
      ...boundState(proven),
      firstContacts: proven.firstContacts,
    });
  } catch (cause) {
    if (reservation !== undefined) params.wallet._releaseReservation(reservation.id);
    throw wrapRingError(strategy.errorCode, cause);
  }
}

/** A spend pays its recipient or exit and returns change. */
const SPEND_OUTPUTS = 2;

/** The prover refuses a spend mixing ring and default-ring UTXOs, ring UTXOs alone fund it first. */
function selectAnonymousInputs(
  pool: Omit<Parameters<typeof selectRingInputs>[0], "inputs" | "maxInputs">,
  selection: "ring" | "ring-or-default" | "default",
): readonly WalletUtxo[] {
  const select = (inputs: "ring" | "default") =>
    selectRingInputs({ ...pool, inputs, maxInputs: anonymousInputCap(inputs) });
  if (selection !== "ring-or-default") return select(selection);
  try {
    return select("ring");
  } catch (ringAlone) {
    if (!unfunded(ringAlone)) throw ringAlone;
    try {
      return select("default");
    } catch (defaultAlone) {
      if (!unfunded(defaultAlone)) throw defaultAlone;
      throw ringAlone;
    }
  }
}

function unfunded(cause: unknown): boolean {
  return (
    cause instanceof RingError &&
    (cause.code === "RING_INSUFFICIENT_BALANCE" || cause.code === "RING_TOO_MANY_INPUTS")
  );
}

/** Padded inputs are published, the widest two-output shape an anonymous key serves bounds a spend. */
function anonymousInputCap(selection: "ring" | "default"): number {
  const spendsDefaultRing = selection === "default";
  return Math.max(
    ...SPP_SUPPORTED_SHAPES.filter(
      (shape) =>
        shape.outputs === SPEND_OUTPUTS &&
        anonymousAuditKey({ inputs: shape.inputs, outputs: shape.outputs, spendsDefaultRing }) !==
          undefined,
    ).map((shape) => shape.inputs),
  );
}

/** @internal The co-signer a proven transfer demands is the one the caller supplied. */
export function checkDemandedCoSigner(
  ringProgramId: Address,
  supplied: SignerAccount | undefined,
  demanded: Address | undefined,
): void {
  if (demanded === undefined) return;
  const reason =
    supplied === undefined
      ? "missing"
      : signerAddress(supplied) === demanded
        ? undefined
        : "mismatch";
  if (reason !== undefined)
    throw new RingError("RING_COSIGNER_REQUIRED", {
      details: { ringProgramId, reason, expected: demanded },
    });
}

/** A ring address pays on the anonymous rail, any other recipient resolves to its shielded address. */
async function resolveSendRecipient(
  params: RingTransferTransactionParams | RingExitTransactionParams,
  destination: "ring" | "default",
  context: RequestContext | undefined,
): Promise<ShieldedAddress | RingAddress> {
  const { recipient } = params;
  if (recipient instanceof RingAddress) {
    if (destination !== "ring" || recipient.ringProgramId !== params.ringProgramId)
      throw new RingError("RING_FOREIGN_RING", {
        details: { address: recipient.ringProgramId, ring: params.ringProgramId },
      });
    return recipient;
  }
  return resolveShieldedRecipient(
    { rpc: params.client, recipient },
    (unregistered) =>
      new RingError("RING_BUILD_TRANSFER", {
        details: { reason: "recipient not registered", recipient: unregistered },
      }),
    context,
  );
}

function assetLabel(asset: Address): string {
  return asset === SOL_MINT ? "SOL" : asset;
}
