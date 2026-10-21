import {
  assertIsFullySignedTransaction,
  assertIsTransactionWithinSizeLimit,
  getSignatureFromTransaction,
  isSolanaError,
  sendTransactionWithoutConfirmingFactory,
  signTransactionWithSigners,
  SOLANA_ERROR__INSTRUCTION_ERROR__CUSTOM,
  SOLANA_ERROR__JSON_RPC__SERVER_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE,
  type Signature,
  type TransactionPartialSigner,
} from "@solana/kit";
import { isClientError } from "../client/error.js";
import { runKitRpc } from "../client/kit.js";
import type {
  ChainReader,
  KitRpcAccess,
  RingSubmissionStatus,
  RingSubmissionTransport,
  SlotReader,
} from "../client/ports.js";
import { savePersistedWallet, type WalletPersistence } from "../wallet/persisted.js";
import type { Bytes32, RequestContext, Transaction } from "../interface/types.js";
import { tagEpoch } from "../keypair/ring-stream.js";
import {
  hex,
  type UtxoReservation,
  type Wallet,
  type WalletUtxo,
  type PendingWalletSubmission,
} from "../transaction/wallet/state.js";
import { equalBytes } from "../wallet/internal.js";
import { assertVersion1Transaction } from "../flows/compile.js";
import { fetchRingMemberRegistry } from "./config.js";
import { RingError, RingProgramError } from "./error.js";
import type { PendingFirstContact, RingBoundState } from "./pipeline.js";
import { anchorHolds } from "./trees.js";

/** Keeps the signed intent and validity bounds of one transaction attempt. */
export interface RingSubmissionAttempt extends RingBoundState {
  readonly transaction: Transaction;
  readonly lastValidBlockHeight: bigint;
  readonly intentHash: Bytes32;
  readonly ringInstructionIndex: number;
  /** Each inbox payment of an anonymous transfer, recorded with the leaf it lands at. */
  readonly firstContacts?: readonly PendingFirstContact[];
}

export type RingSubmissionResult =
  | Readonly<{
      kind: "confirmed";
      signature: Signature;
      slot: bigint;
      attempts: number;
      /** Those of the attempt that landed, none for a reconciled submission. */
      firstContacts: readonly PendingFirstContact[];
    }>
  | Readonly<{ kind: "unknown"; signature: Signature; attempts: number }>
  | Readonly<{
      kind: "failed";
      signature: Signature;
      attempts: number;
      instructionIndex?: number;
      customCode?: number;
    }>;

/** @internal Retains the same notes and intent across proof rebuilds. */
export interface RingSubmissionBuildState {
  lifetime?: "submission";
  entries?: readonly WalletUtxo[];
  reservation?: UtxoReservation;
  intent?: Bytes32;
}

/** Keeps selected notes unavailable until submission resolves. */
export interface ReservationHold {
  release(): void;
  extend(): void;
}

export type RingSubmissionBuild = (context?: RequestContext) => Promise<RingSubmissionAttempt>;

const MAX_ATTEMPTS = 3;
/** Rust `retryable`, a fresh proof fixes a root under a raised floor, an emptied slot or a batch that no longer fits. */
const STALE_PROOF_CODES: ReadonlySet<number> = new Set([
  RingProgramError.rootBelowFloor,
  RingProgramError.curatorRootStale,
  RingProgramError.rootIndexEmpty,
  RingProgramError.authorityBatchTooLarge,
]);
const NO_RESERVATION: ReservationHold = Object.freeze({ release() {}, extend() {} });

/** Resolves each broadcast before retrying an unchanged payment intent. */
export class RingTransactionSubmission {
  readonly #intent: Bytes32;
  readonly #build: RingSubmissionBuild;
  readonly #reservation: ReservationHold;
  readonly #registry: Pick<ChainReader, "getAccount"> | undefined;
  readonly #clock: SlotReader | undefined;
  readonly #wallet: Wallet | undefined;
  readonly #id: string;
  readonly #utxoHashes: readonly Bytes32[];
  #persistence: WalletPersistence | undefined;
  #persistedSignature: Signature | undefined;
  #attempt: RingSubmissionAttempt;
  #pending: Signature | undefined;
  #attempts = 0;
  #terminal = false;
  #busy = false;

  constructor(
    input: Readonly<{
      first: RingSubmissionAttempt;
      build: RingSubmissionBuild;
      reservation?: ReservationHold;
      /** Reads the bound registries and anchor tree when a proof fails. */
      registry?: Pick<ChainReader, "getAccount">;
      /** Reads the slot when a proof of a bound epoch fails. */
      clock?: SlotReader;
      wallet?: Wallet;
      reservationId?: string;
      utxoHashes?: readonly Bytes32[];
    }>,
  ) {
    this.#attempt = input.first;
    this.#intent = new Uint8Array(input.first.intentHash) as Bytes32;
    this.#build = input.build;
    this.#reservation = input.reservation ?? NO_RESERVATION;
    this.#registry = input.registry;
    this.#clock = input.clock;
    this.#wallet = input.wallet;
    this.#id = input.reservationId ?? hex(crypto.getRandomValues(new Uint8Array(16)));
    this.#utxoHashes = (input.utxoHashes ?? []).map((hash) => new Uint8Array(hash) as Bytes32);
  }

  /** @internal The reservation `build` records outlives every attempt. */
  static async fromBuilder(
    input: Readonly<{
      wallet: Wallet;
      build: (
        retry: RingSubmissionBuildState,
        context?: RequestContext,
      ) => Promise<RingSubmissionAttempt>;
      registry?: Pick<ChainReader, "getAccount">;
      clock?: SlotReader;
    }>,
    context?: RequestContext,
  ): Promise<RingTransactionSubmission> {
    const retry: RingSubmissionBuildState = { lifetime: "submission" };
    const build: RingSubmissionBuild = (context) => input.build(retry, context);
    let first: RingSubmissionAttempt;
    try {
      first = await build(context);
    } catch (cause) {
      if (retry.reservation !== undefined) input.wallet._releaseReservation(retry.reservation.id);
      throw cause;
    }
    return new RingTransactionSubmission({
      first,
      build,
      wallet: input.wallet,
      ...(input.registry === undefined ? {} : { registry: input.registry }),
      ...(input.clock === undefined ? {} : { clock: input.clock }),
      ...(retry.reservation === undefined
        ? {}
        : {
            reservationId: retry.reservation.id,
            utxoHashes: retry.reservation.utxoHashes,
          }),
      reservation: {
        release: () => {
          if (retry.reservation !== undefined) {
            input.wallet._releaseReservation(retry.reservation.id);
          }
        },
        extend: () => {
          if (retry.entries !== undefined) checkRetainedEntries(input.wallet, retry.entries);
        },
      },
    });
  }

  async sendPersisted(
    input: WalletPersistence & Readonly<{ transport: RingSubmissionTransport }>,
    context?: RequestContext,
  ): Promise<RingSubmissionResult> {
    if (
      this.#busy ||
      (this.#wallet !== undefined && this.#wallet !== input.wallet) ||
      (this.#persistence !== undefined &&
        (this.#persistence.wallet !== input.wallet ||
          this.#persistence.store !== input.store ||
          this.#persistence.cipher !== input.cipher))
    )
      throw new RingError("RING_SUBMISSION_PENDING");
    this.#persistence = input;
    return this.send(input.transport, context);
  }

  async #checkpoint(signature: Signature): Promise<void> {
    const wallet = this.#wallet ?? this.#persistence?.wallet;
    wallet?._setPendingSubmission({
      id: this.#id,
      intentHash: this.#intent,
      utxoHashes: this.#utxoHashes,
      attempts: this.#attempts,
      signature,
      lastValidBlockHeight: this.#attempt.lastValidBlockHeight,
    });
    if (this.#persistence !== undefined) {
      await savePersistedWallet(this.#persistence);
      this.#persistedSignature = signature;
    }
  }

  /** Rust `BoundState::moved`. */
  async #moved(context?: RequestContext): Promise<boolean> {
    const { roots = [], policy, anchor, epoch } = this.#attempt;
    const chain = this.#registry;
    if (chain !== undefined) {
      for (const bound of roots) {
        const registry = await fetchRingMemberRegistry(chain, bound.ringProgramId, context);
        const held = registry.history[bound.rootIndex];
        if (held === undefined || !equalBytes(held.root, bound.root)) return true;
      }
      if (policy !== undefined) {
        const registry = await fetchRingMemberRegistry(chain, policy.ringProgramId, context);
        if (!equalBytes(registry.policyHash, policy.policyHash)) return true;
      }
      if (anchor !== undefined && !(await anchorHolds(chain, anchor, context))) return true;
    }
    if (epoch === undefined || this.#clock === undefined) return false;
    return tagEpoch(await this.#clock.getSlot(context)) > epoch;
  }

  async #settleFailed(): Promise<void> {
    (this.#wallet ?? this.#persistence?.wallet)?._removePendingSubmission(this.#id);
    if (this.#persistence !== undefined) await savePersistedWallet(this.#persistence);
  }

  cancel(): void {
    if (this.#busy || this.#pending !== undefined) throw new RingError("RING_SUBMISSION_PENDING");
    this.#terminal = true;
    this.#reservation.release();
  }

  /** Unknown submissions must resolve before another broadcast. */
  async send(
    transport: RingSubmissionTransport,
    context?: RequestContext,
  ): Promise<RingSubmissionResult> {
    if (this.#busy || this.#terminal) throw new RingError("RING_SUBMISSION_PENDING");
    this.#busy = true;
    try {
      if (
        this.#pending !== undefined &&
        this.#persistence !== undefined &&
        this.#persistedSignature !== this.#pending
      )
        await this.#checkpoint(this.#pending);
      for (;;) {
        let status: RingSubmissionStatus | undefined;
        if (this.#pending === undefined) {
          if (!equalBytes(this.#intent, this.#attempt.intentHash))
            throw new RingError("RING_INTENT_MISMATCH");
          this.#reservation.extend();
          const approvedMessage = new Uint8Array(this.#attempt.transaction.messageBytes);
          const signed = await transport.sign(this.#attempt.transaction, context);
          if (!equalBytes(new Uint8Array(signed.messageBytes), approvedMessage))
            throw new RingError("RING_INTENT_MISMATCH");
          assertIsFullySignedTransaction(signed);
          const signature = getSignatureFromTransaction(signed);
          this.#attempts += 1;
          await this.#checkpoint(signature);
          this.#pending = signature;
          try {
            status = await transport.send(signed, context);
          } catch (cause) {
            // A send error leaves the signature pending.
            if (isClientError(cause) && cause.code === "CLIENT_ABORTED") throw cause;
          }
        }
        const signature = this.#pending;
        if (status === undefined) {
          try {
            status = await transport.status(
              { signature, lastValidBlockHeight: this.#attempt.lastValidBlockHeight },
              context,
            );
          } catch {
            status = { kind: "unknown" };
          }
        }
        if (status.kind === "unknown") {
          return { kind: "unknown", signature, attempts: this.#attempts };
        }
        if (status.kind === "confirmed") {
          this.#terminal = true;
          return {
            kind: "confirmed",
            signature,
            slot: status.slot,
            attempts: this.#attempts,
            firstContacts: this.#attempt.firstContacts ?? [],
          };
        }
        const ringCode =
          status.kind === "failed" && status.instructionIndex === this.#attempt.ringInstructionIndex
            ? status.customCode
            : undefined;
        // A failed registry, tree or slot read keeps the signature pending for the next call.
        const moved =
          ringCode === RingProgramError.proofVerificationFailed && (await this.#moved(context));
        this.#pending = undefined;
        await this.#settleFailed();
        const retry =
          status.kind === "expired" ||
          moved ||
          (ringCode !== undefined && STALE_PROOF_CODES.has(ringCode));
        if (!retry || this.#attempts >= MAX_ATTEMPTS) {
          this.#terminal = true;
          this.#reservation.release();
          return {
            kind: "failed",
            signature,
            attempts: this.#attempts,
            ...(status.kind !== "failed" || status.instructionIndex === undefined
              ? {}
              : { instructionIndex: status.instructionIndex }),
            ...(status.kind !== "failed" || status.customCode === undefined
              ? {}
              : { customCode: status.customCode }),
          };
        }
        this.#attempt = await this.#build(context);
      }
    } catch (cause) {
      if (this.#pending === undefined) {
        (this.#wallet ?? this.#persistence?.wallet)?._removePendingSubmission(this.#id);
        this.#terminal = true;
        this.#reservation.release();
      }
      throw cause;
    } finally {
      this.#busy = false;
    }
  }
}

export async function reconcileRingSubmissions(
  input: WalletPersistence & Readonly<{ transport: Pick<RingSubmissionTransport, "status"> }>,
  context?: RequestContext,
): Promise<readonly RingSubmissionResult[]> {
  const results: RingSubmissionResult[] = [];
  for (const pending of input.wallet.pendingSubmissions()) {
    const status = await input.transport.status(pending, context);
    const current = input.wallet.pendingSubmissions().find((entry) => entry.id === pending.id);
    if (current?.signature !== pending.signature) continue;
    if (status.kind === "unknown") {
      results.push({ kind: "unknown", signature: pending.signature, attempts: pending.attempts });
      continue;
    }
    if (status.kind === "confirmed") {
      const unspent = new Set(
        input.wallet
          .utxos()
          .filter((entry) => !entry.spent)
          .map((entry) => hex(entry.outputContext.hash)),
      );
      if (!pending.utxoHashes.some((hash) => unspent.has(hex(hash)))) {
        input.wallet._releaseReservation(pending.id);
        input.wallet._removePendingSubmission(pending.id);
      }
      results.push({
        kind: "confirmed",
        signature: pending.signature,
        attempts: pending.attempts,
        slot: status.slot,
        firstContacts: [],
      });
    } else {
      input.wallet._releaseReservation(pending.id);
      input.wallet._removePendingSubmission(pending.id);
      results.push(failedSubmission(pending, status));
    }
  }
  await savePersistedWallet(input);
  return results;
}

function failedSubmission(
  pending: PendingWalletSubmission,
  status: Extract<RingSubmissionStatus, { kind: "failed" | "expired" }>,
): RingSubmissionResult {
  return {
    kind: "failed",
    signature: pending.signature,
    attempts: pending.attempts,
    ...(status.kind !== "failed" || status.instructionIndex === undefined
      ? {}
      : { instructionIndex: status.instructionIndex }),
    ...(status.kind !== "failed" || status.customCode === undefined
      ? {}
      : { customCode: status.customCode }),
  };
}

/** @internal */
export function checkRetainedEntries(wallet: Wallet, entries: readonly WalletUtxo[]): void {
  const current = wallet.utxos();
  for (const entry of entries) {
    const unspent = current.some(
      (known) => !known.spent && equalBytes(known.outputContext.hash, entry.outputContext.hash),
    );
    if (!unspent) {
      throw new RingError("RING_RESERVED_INPUT_SPENT", {
        details: { utxoHash: hex(entry.outputContext.hash) },
      });
    }
  }
}

export function createKitRingSubmissionTransport(
  client: KitRpcAccess,
  signers: readonly TransactionPartialSigner[],
): RingSubmissionTransport {
  const heldSigners = [...signers];
  const send = sendTransactionWithoutConfirmingFactory({ rpc: client.solanaRpc });
  return {
    sign: async (transaction, context) =>
      runKitRpc("signTransaction", context, (abortSignal) =>
        signTransactionWithSigners(heldSigners, transaction, { abortSignal }),
      ),
    send: async (transaction, context) => {
      assertIsFullySignedTransaction(transaction);
      assertIsTransactionWithinSizeLimit(transaction);
      assertVersion1Transaction(transaction);
      return runKitRpc("sendTransaction", context, async (abortSignal) => {
        try {
          await send(transaction, { commitment: client.commitment, abortSignal });
          return undefined;
        } catch (cause) {
          const refusal = preflightRefusal(cause);
          if (refusal === undefined) throw cause;
          return refusal;
        }
      });
    },
    status: async (pending, context) => {
      const status = await readSignatureStatus(client, pending.signature, context);
      if (status !== null) return status;
      const height = await runKitRpc("getBlockHeight", context, (abortSignal) =>
        client.solanaRpc.getBlockHeight({ commitment: client.commitment }).send({ abortSignal }),
      );
      if (height <= pending.lastValidBlockHeight) return { kind: "unknown" };
      // Expiry cannot settle an absence observed before the last valid block.
      return (
        (await readSignatureStatus(client, pending.signature, context)) ?? {
          kind: "expired",
        }
      );
    },
  };
}

async function readSignatureStatus(
  client: KitRpcAccess,
  signature: Signature,
  context?: RequestContext,
): Promise<RingSubmissionStatus | null> {
  const response = await runKitRpc("getSignatureStatuses", context, (abortSignal) =>
    client.solanaRpc
      .getSignatureStatuses([signature], { searchTransactionHistory: true })
      .send({ abortSignal }),
  );
  if (response.value.length !== 1) return { kind: "unknown" };
  const status = response.value[0];
  if (status === undefined) return { kind: "unknown" };
  if (status === null) return null;
  if (status.confirmationStatus !== "confirmed" && status.confirmationStatus !== "finalized")
    return { kind: "unknown" };
  if (status.err === null) return { kind: "confirmed", slot: status.slot };
  return failedStatus(status.err);
}

/** The node's simulation refused the transaction, nothing was broadcast. */
function preflightRefusal(cause: unknown): RingSubmissionStatus | undefined {
  if (
    !isSolanaError(cause, SOLANA_ERROR__JSON_RPC__SERVER_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE)
  )
    return undefined;
  const refusal: unknown = cause.cause;
  if (isSolanaError(refusal, SOLANA_ERROR__INSTRUCTION_ERROR__CUSTOM)) {
    return {
      kind: "failed",
      instructionIndex: refusal.context.index,
      customCode: refusal.context.code,
    };
  }
  return { kind: "failed" };
}

/** Only `InstructionError: [index, { Custom }]` carries a program code. */
function failedStatus(error: unknown): RingSubmissionStatus {
  if (
    typeof error !== "object" ||
    error === null ||
    !("InstructionError" in error) ||
    !Array.isArray(error.InstructionError)
  )
    return { kind: "failed" };
  const [index, detail] = error.InstructionError;
  if (
    typeof index !== "number" ||
    !Number.isSafeInteger(index) ||
    index < 0 ||
    typeof detail !== "object" ||
    detail === null ||
    !("Custom" in detail) ||
    typeof detail.Custom !== "number" ||
    !Number.isSafeInteger(detail.Custom)
  )
    return { kind: "failed" };
  return { kind: "failed", instructionIndex: index, customCode: detail.Custom };
}
