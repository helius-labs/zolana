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
  KitRpcAccess,
  RingSubmissionStatus,
  RingSubmissionTransport,
  SlotReader,
} from "../client/ports.js";
import { extendReservation } from "../flows/reserve.js";
import type { Bytes32, RequestContext, Transaction } from "../interface/types.js";
import {
  hex,
  type UtxoReservation,
  type Wallet,
  type WalletUtxo,
} from "../transaction/wallet/state.js";
import { equalBytes } from "../wallet/internal.js";
import { RingError, RingProgramError } from "./error.js";

export interface RingSubmissionAttempt {
  readonly transaction: Transaction;
  readonly lastValidBlockHeight: bigint;
  readonly intentHash: Bytes32;
  readonly ringInstructionIndex: number;
  readonly window?: Readonly<{ index: bigint; slots: bigint }>;
}

export type RingSubmissionResult =
  | Readonly<{ kind: "confirmed"; signature: Signature; slot: bigint; attempts: number }>
  | Readonly<{ kind: "unknown"; signature: Signature; attempts: number }>
  | Readonly<{
      kind: "failed";
      signature: Signature;
      attempts: number;
      instructionIndex?: number;
      customCode?: number;
    }>;

/** @internal */
export interface RingSubmissionBuildState {
  entries?: readonly WalletUtxo[];
  reservation?: UtxoReservation;
  intent?: Bytes32;
}

export interface ReservationHold {
  release(): void;
  extend(): void;
}

type BuildAttempt = (context?: RequestContext) => Promise<RingSubmissionAttempt>;
type WindowChanged = (
  window: NonNullable<RingSubmissionAttempt["window"]>,
  context?: RequestContext,
) => Promise<boolean>;

const MAX_ATTEMPTS = 3;
const NO_RESERVATION: ReservationHold = Object.freeze({ release() {}, extend() {} });

export class RingTransactionSubmission {
  readonly #intent: Bytes32;
  readonly #build: BuildAttempt;
  readonly #reservation: ReservationHold;
  readonly #windowChanged: WindowChanged;
  #attempt: RingSubmissionAttempt;
  #pending: Signature | undefined;
  #attempts = 0;
  #terminal = false;
  #busy = false;

  constructor(
    input: Readonly<{
      first: RingSubmissionAttempt;
      build: BuildAttempt;
      windowChanged: WindowChanged;
      reservation?: ReservationHold;
    }>,
  ) {
    this.#attempt = input.first;
    this.#intent = new Uint8Array(input.first.intentHash) as Bytes32;
    this.#build = input.build;
    this.#reservation = input.reservation ?? NO_RESERVATION;
    this.#windowChanged = input.windowChanged;
  }

  /** @internal The reservation `build` records outlives every attempt. */
  static async fromBuilder(
    input: Readonly<{
      wallet: Wallet;
      build: (
        retry: RingSubmissionBuildState,
        context?: RequestContext,
      ) => Promise<RingSubmissionAttempt>;
      windowChanged: WindowChanged;
    }>,
    context?: RequestContext,
  ): Promise<RingTransactionSubmission> {
    const retry: RingSubmissionBuildState = {};
    const build: BuildAttempt = (context) => input.build(retry, context);
    return new RingTransactionSubmission({
      first: await build(context),
      build,
      windowChanged: input.windowChanged,
      reservation: {
        release: () => {
          if (retry.reservation !== undefined) {
            input.wallet._releaseReservation(retry.reservation.id);
          }
        },
        extend: () => {
          if (retry.reservation !== undefined)
            extendReservation(input.wallet, retry.reservation.id);
        },
      },
    });
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
          this.#pending = getSignatureFromTransaction(signed);
          this.#attempts += 1;
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
          this.#reservation.extend();
          return { kind: "unknown", signature, attempts: this.#attempts };
        }
        this.#pending = undefined;
        if (status.kind === "confirmed") {
          this.#terminal = true;
          this.#reservation.release();
          return { kind: "confirmed", signature, slot: status.slot, attempts: this.#attempts };
        }
        // Only a confirmed stale-root or changed-window failure permits a rebuild.
        const ringFailure = status.instructionIndex === this.#attempt.ringInstructionIndex;
        let retry =
          ringFailure &&
          (status.customCode === RingProgramError.staleHeadMapRoot ||
            status.customCode === RingProgramError.staleKeyRegistryRoot);
        if (
          ringFailure &&
          status.customCode === RingProgramError.proofVerificationFailed &&
          this.#attempt.window !== undefined
        )
          retry = await this.#windowChanged(this.#attempt.window, context);
        if (!retry || this.#attempts >= MAX_ATTEMPTS) {
          this.#terminal = true;
          this.#reservation.release();
          return {
            kind: "failed",
            signature,
            attempts: this.#attempts,
            ...(status.instructionIndex === undefined
              ? {}
              : { instructionIndex: status.instructionIndex }),
            ...(status.customCode === undefined ? {} : { customCode: status.customCode }),
          };
        }
        this.#attempt = await this.#build(context);
      }
    } catch (cause) {
      if (this.#pending === undefined) {
        this.#terminal = true;
        this.#reservation.release();
      }
      throw cause;
    } finally {
      this.#busy = false;
    }
  }
}

/** @internal A rejected policy proof is rebuilt only once the slot clock left its window. */
export function windowChangedOn(client: SlotReader): WindowChanged {
  return async (window, context) => (await client.getSlot(context)) / window.slots !== window.index;
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
      const response = await runKitRpc("getSignatureStatuses", context, (abortSignal) =>
        client.solanaRpc
          .getSignatureStatuses([pending.signature], { searchTransactionHistory: true })
          .send({ abortSignal }),
      );
      const status = response.value[0];
      if (status === undefined || status === null) {
        const height = await runKitRpc("getBlockHeight", context, (abortSignal) =>
          client.solanaRpc.getBlockHeight({ commitment: client.commitment }).send({ abortSignal }),
        );
        return height > pending.lastValidBlockHeight ? { kind: "failed" } : { kind: "unknown" };
      }
      if (status.confirmationStatus !== "confirmed" && status.confirmationStatus !== "finalized")
        return { kind: "unknown" };
      if (status.err === null) return { kind: "confirmed", slot: status.slot };
      return failedStatus(status.err);
    },
  };
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
