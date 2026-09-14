import {
  assertIsFullySignedTransaction,
  assertIsTransactionWithinSizeLimit,
  getSignatureFromTransaction,
  sendTransactionWithoutConfirmingFactory,
  signTransactionWithSigners,
  type Signature,
  type TransactionPartialSigner,
} from "@solana/kit";
import { runKitRpc } from "../client/kit.js";
import type {
  KitRpcAccess,
  RingSubmissionStatus,
  RingSubmissionTransport,
} from "../client/ports.js";
import type { Bytes32, RequestContext, Transaction } from "../interface/types.js";
import { equalBytes } from "../wallet/internal.js";
import { RingError } from "./error.js";

/** Binds a prepared transaction to the intent retained across retries. */
export interface RingSubmissionAttempt {
  readonly transaction: Transaction;
  readonly intentHash: Bytes32;
  readonly ringInstructionIndex: number;
  readonly window?: Readonly<{ index: bigint; slots: bigint }>;
}

/** Reports whether the submission owner can release its reservation. */
export type RingSubmissionResult =
  | Readonly<{ kind: "confirmed"; signature: Signature; slot: bigint; attempts: number }>
  | Readonly<{ kind: "unknown"; signature: Signature; attempts: number }>
  | Readonly<{ kind: "failed"; signature: Signature; attempts: number }>;

/** Retains intent and reservations until a broadcast has a known outcome. */
export class RingTransactionSubmission {
  readonly #intent: Bytes32;
  readonly #build: (context?: RequestContext) => Promise<RingSubmissionAttempt>;
  readonly #release: () => void;
  readonly #windowChanged: (
    window: NonNullable<RingSubmissionAttempt["window"]>,
    context?: RequestContext,
  ) => Promise<boolean>;
  #attempt: RingSubmissionAttempt;
  #pending: Signature | undefined;
  #attempts = 0;
  #terminal = false;
  #busy = false;

  constructor(
    input: Readonly<{
      first: RingSubmissionAttempt;
      build: (context?: RequestContext) => Promise<RingSubmissionAttempt>;
      release: () => void;
      windowChanged: (
        window: NonNullable<RingSubmissionAttempt["window"]>,
        context?: RequestContext,
      ) => Promise<boolean>;
    }>,
  ) {
    this.#attempt = input.first;
    this.#intent = new Uint8Array(input.first.intentHash) as Bytes32;
    this.#build = input.build;
    this.#release = input.release;
    this.#windowChanged = input.windowChanged;
  }

  cancel(): void {
    if (this.#busy || this.#pending !== undefined) throw new RingError("RING_SUBMISSION_PENDING");
    this.#terminal = true;
    this.#release();
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
        // 1. Sign the retained intent only when no broadcast remains unresolved.
        if (this.#pending === undefined) {
          if (!equalBytes(this.#intent, this.#attempt.intentHash))
            throw new RingError("RING_INTENT_MISMATCH");
          const approvedMessage = new Uint8Array(this.#attempt.transaction.messageBytes);
          const signed = await transport.sign(this.#attempt.transaction, context);
          if (!equalBytes(new Uint8Array(signed.messageBytes), approvedMessage))
            throw new RingError("RING_INTENT_MISMATCH");
          assertIsFullySignedTransaction(signed);
          this.#pending = getSignatureFromTransaction(signed);
          this.#attempts += 1;
          try {
            await transport.send(signed, context);
          } catch {
            /* The local signature remains authoritative after a send error. */
          }
        }
        // 2. Resolve the locally derived signature before releasing its reservation.
        const signature = this.#pending;
        let status: RingSubmissionStatus;
        try {
          status = await transport.status(signature, context);
        } catch {
          return { kind: "unknown", signature, attempts: this.#attempts };
        }
        if (status.kind === "unknown")
          return { kind: "unknown", signature, attempts: this.#attempts };
        this.#pending = undefined;
        if (status.kind === "confirmed") {
          this.#terminal = true;
          this.#release();
          return { kind: "confirmed", signature, slot: status.slot, attempts: this.#attempts };
        }
        // 3. Rebuild only after a confirmed stale-head or changed-window failure.
        let retry =
          status.instructionIndex === this.#attempt.ringInstructionIndex &&
          status.customCode === 8166;
        if (
          status.instructionIndex === this.#attempt.ringInstructionIndex &&
          status.customCode === 8101 &&
          this.#attempt.window !== undefined
        )
          retry = await this.#windowChanged(this.#attempt.window, context);
        if (!retry || this.#attempts >= 3) {
          this.#terminal = true;
          this.#release();
          return { kind: "failed", signature, attempts: this.#attempts };
        }
        this.#attempt = await this.#build(context);
      }
    } catch (cause) {
      if (this.#pending === undefined) {
        this.#terminal = true;
        this.#release();
      }
      throw cause;
    } finally {
      this.#busy = false;
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
      await runKitRpc("sendTransaction", context, (abortSignal) =>
        send(transaction, { commitment: client.commitment, abortSignal }),
      );
    },
    status: async (signature, context) => {
      const response = await runKitRpc("getSignatureStatuses", context, (abortSignal) =>
        client.solanaRpc
          .getSignatureStatuses([signature], { searchTransactionHistory: true })
          .send({ abortSignal }),
      );
      const status = response.value[0];
      if (
        status === undefined ||
        status === null ||
        (status.confirmationStatus !== "confirmed" && status.confirmationStatus !== "finalized")
      )
        return { kind: "unknown" };
      if (status.err === null) return { kind: "confirmed", slot: status.slot };
      const error: unknown = status.err;
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
    },
  };
}
