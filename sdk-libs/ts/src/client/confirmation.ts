import type { Commitment, Signature } from "@solana/kit";
import { wireDecoder } from "../interface/decode.js";
import type { RequestContext } from "../interface/types.js";
import { ClientError, isClientError, type ClientErrorCode } from "./error.js";
import { runWithDeadline, sleep } from "./internal.js";
import { runKitRpc } from "./kit.js";
import type { KitRpcAccess, PrivateTransactionReader } from "./ports.js";
import type { GetShieldedTransactionsBySignatureResponse } from "./rpc.js";
import { backoff, isRetryable, type IndexerPollConfig } from "./retry.js";
import { decodeTransactionError, UNRECOGNIZED_TRANSACTION_ERROR } from "./transaction-error.js";

const DEFAULT_WAIT_TIMEOUT_MS = 60_000;
const MAX_U64 = 0xffff_ffff_ffff_ffffn;

/** Only the evidence needed for confirmation; server error text never escapes. */
interface SignatureStatus {
  readonly slot: bigint;
  readonly commitment: Commitment | null;
  /** The transaction's error in Solana's JSON encoding, `null` when it succeeded. */
  readonly error: string | null;
  /**
   * `err` was present and not a known Solana variant. A confirmed status is
   * still a chain failure; the response text is not retained.
   */
  readonly unrecognizedError: boolean;
}

export async function readSignatureStatus(
  client: KitRpcAccess,
  signature: Signature,
  context?: RequestContext,
  searchTransactionHistory = false,
): Promise<SignatureStatus | null> {
  const response: unknown = await runKitRpc("getSignatureStatuses", context, (abortSignal) =>
    (searchTransactionHistory
      ? client.solanaRpc.getSignatureStatuses([signature], { searchTransactionHistory })
      : client.solanaRpc.getSignatureStatuses([signature])
    ).send({ abortSignal }),
  );
  const decode = wireDecoder((path) => invalidResponse("getSignatureStatuses", path));
  const values = decode.list(decode.record(response, "result")["value"], "result.value");
  if (values.length !== 1) throw invalidResponse("getSignatureStatuses", "result.value");
  if (values[0] === null) return null;
  const status = decode.record(values[0], "result.value[0]");
  const reached = status["confirmationStatus"];
  if (
    reached !== undefined &&
    reached !== null &&
    reached !== "processed" &&
    reached !== "confirmed" &&
    reached !== "finalized"
  )
    throw invalidResponse("getSignatureStatuses", "confirmationStatus");
  if (!Object.hasOwn(status, "err")) throw invalidResponse("getSignatureStatuses", "err");
  const transactionError = decodeTransactionError(status["err"]);
  return {
    slot: rpcU64(status["slot"], "getSignatureStatuses"),
    commitment: reached ?? null,
    error: transactionError.kind === "failed" ? transactionError.text : null,
    unrecognizedError: transactionError.kind === "unrecognized",
  };
}

export function commitmentReached(reached: Commitment | null, required: Commitment): boolean {
  if (reached === null) return false;
  return (
    reached === "finalized" ||
    (required !== "finalized" && (reached === "confirmed" || required === "processed"))
  );
}

export function transactionFailed(signature: Signature, transactionError: string): ClientError {
  return new ClientError("CLIENT_TRANSACTION_FAILED", {
    details: { signature, transactionError },
  });
}

/** What one round learned from Solana. */
interface ChainRound {
  /** Neither the status cache nor the ledger holds the signature. */
  unseen: boolean;
  /** A lookup failed this round; the next round asks again. */
  cause?: ClientErrorCode;
  /** A method the RPC lacks, which no round can answer. */
  unsupported?: ClientError;
}

type IndexerAnswer =
  | Readonly<{ response: GetShieldedTransactionsBySignatureResponse }>
  | Readonly<{ error: unknown }>;

/**
 * Photon persists every event of a transaction atomically. One visible event
 * therefore proves its private effects are indexed, even after the RPC cache
 * forgets it. An empty answer is evidence only after the expiry watermark.
 *
 * Each round asks Solana and the indexer at once. A lookup that failed is
 * asked again next round, unless waiting cannot fix it: an RPC without the
 * method, or an indexer answer that is malformed or not retryable. That error
 * ends the wait as itself, after the round's indexer answer had its chance to
 * prove success.
 */
export async function waitForPrivateTransaction(
  client: KitRpcAccess & PrivateTransactionReader,
  signature: Signature,
  lastValidBlockHeight: bigint | undefined,
  poll: IndexerPollConfig,
  context?: RequestContext,
): Promise<void> {
  if (
    lastValidBlockHeight !== undefined &&
    (typeof lastValidBlockHeight !== "bigint" ||
      lastValidBlockHeight < 0n ||
      lastValidBlockHeight > MAX_U64)
  ) {
    throw new ClientError("CLIENT_INVALID_CONFIG", { details: { field: "lastValidBlockHeight" } });
  }
  let confirmed = false;
  let indexed = false;
  let expiredAt: bigint | undefined;
  let causeCode: ClientErrorCode | undefined;
  let chainFailure: ClientError | undefined;
  // One ledger search after the blockhash expires is enough: it can no longer land.
  let ledgerMiss = false;
  const unresolved = (): ClientError =>
    new ClientError(
      confirmed ? "CLIENT_TRANSACTION_NOT_INDEXED" : "CLIENT_TRANSACTION_OUTCOME_UNKNOWN",
      { details: { signature, ...(causeCode === undefined ? {} : { causeCode }) } },
    );

  // A failed RPC lookup is no evidence either way, and the indexer can still
  // prove success; only a method the RPC lacks cannot recover by waiting.
  const failedLookup = (error: unknown, round: ChainRound): void => {
    if (!isClientError(error)) throw error;
    if (error.code === "CLIENT_ABORTED" || error.code === "CLIENT_INVALID_CONTEXT") throw error;
    if (error.code === "CLIENT_UNSUPPORTED_RPC_METHOD") round.unsupported = error;
    else round.cause ??= error.code;
  };

  // The recent cache is polled every round. The ledger is searched when that
  // cache misses and the signature may already have left it.
  const chainRound = async (attemptContext: RequestContext): Promise<ChainRound> => {
    const round: ChainRound = { unseen: false };
    // A confirmed transaction neither fails nor expires later.
    if (confirmed) return round;

    // `true` when this lookup decided the round. Absence is `false`.
    const apply = (status: SignatureStatus | null): boolean => {
      if (status === null) return false;
      if (commitmentReached(status.commitment, "confirmed")) {
        if (status.unrecognizedError || status.error !== null) {
          chainFailure = transactionFailed(
            signature,
            status.error ?? UNRECOGNIZED_TRANSACTION_ERROR,
          );
          throw chainFailure;
        }
        confirmed = true;
      }
      return true;
    };
    const read = async (history: boolean): Promise<SignatureStatus | null | undefined> => {
      try {
        return await readSignatureStatus(client, signature, attemptContext, history);
      } catch (error) {
        failedLookup(error, round);
        return undefined;
      }
    };

    const cached = await read(false);
    if (cached === undefined || apply(cached)) return round;
    if (ledgerMiss) {
      round.unseen = true;
      return round;
    }
    if (lastValidBlockHeight === undefined) {
      const historic = await read(true);
      if (historic !== undefined && !apply(historic)) round.unseen = true;
      return round;
    }
    try {
      // Height and slot of one bank: a transaction with this blockhash
      // landed before that slot or never will.
      const bank = await readEpochInfo(client, attemptContext);
      if (bank.blockHeight <= lastValidBlockHeight) {
        round.unseen = true;
        return round;
      }
      if (expiredAt === undefined) expiredAt = bank.absoluteSlot;
      const historic = await read(true);
      if (historic !== undefined && !apply(historic)) {
        round.unseen = true;
        ledgerMiss = true;
      }
    } catch (error) {
      failedLookup(error, round);
    }
    return round;
  };

  const schedule = [0n, ...backoff(poll)];
  try {
    await runWithDeadline(
      { ...context, timeoutMs: context?.timeoutMs ?? DEFAULT_WAIT_TIMEOUT_MS },
      "waitForPrivateTransaction",
      async (attemptContext) => {
        const controller = new AbortController();
        const waitContext: RequestContext = {
          signal:
            attemptContext.signal === undefined
              ? controller.signal
              : AbortSignal.any([attemptContext.signal, controller.signal]),
        };
        try {
          for (const delay of schedule) {
            if (waitContext.signal?.aborted) throw new ClientError("CLIENT_ABORTED");
            if (delay !== 0n) await sleep(delay, waitContext);
            const [chain, found] = await Promise.all([
              // A confirmed failure rejects immediately, even if the indexer hangs.
              chainRound(waitContext),
              // This loop owns freshness. A nested requireSlot poll could consume its deadline.
              client
                .getShieldedTransactionsBySignature(signature, { poll }, waitContext)
                .then((response) => {
                  if (waitContext.signal?.aborted) throw new ClientError("CLIENT_ABORTED");
                  if (
                    response.transactions.some(
                      (event) => event.transaction.txSignature !== signature,
                    )
                  ) {
                    throw invalidResponse("getShieldedTransactionsBySignature", "transactions");
                  }
                  indexed = response.transactions.length > 0;
                  return response;
                })
                .then(
                  (response): IndexerAnswer => ({ response }),
                  (error: unknown): IndexerAnswer => ({ error }),
                ),
            ]);
            // A finished round is evidence. Cancellation applies to the next one.
            causeCode = chain.cause;
            if ("error" in found) {
              const { error } = found;
              if (!isClientError(error) || error.code === "CLIENT_ABORTED") throw error;
              if (error.code === "CLIENT_INVALID_RPC_RESPONSE" || !isRetryable(error)) throw error;
              causeCode ??= error.code;
            } else if (indexed) {
              // Photon commits every private event of a transaction atomically.
              return;
            } else if (
              chain.unseen &&
              expiredAt !== undefined &&
              found.response.context.slot >= expiredAt
            ) {
              throw new ClientError("CLIENT_TRANSACTION_EXPIRED", { details: { signature } });
            }
            if (chain.unsupported !== undefined) throw chain.unsupported;
          }
          throw unresolved();
        } finally {
          // Stop a pending sibling request when a definitive chain failure wins.
          controller.abort();
        }
      },
      () => {
        causeCode = "CLIENT_TIMEOUT";
        return unresolved();
      },
    );
  } catch (error) {
    // A failure already read beats the deadline. Indexed success beats a
    // deadline whose RPC request never answered. Caller cancellation does not.
    if (chainFailure !== undefined) throw chainFailure;
    if (
      indexed &&
      causeCode === "CLIENT_TIMEOUT" &&
      isClientError(error) &&
      (error.code === "CLIENT_TRANSACTION_NOT_INDEXED" ||
        error.code === "CLIENT_TRANSACTION_OUTCOME_UNKNOWN")
    ) {
      return;
    }
    throw error;
  }
}

async function readEpochInfo(
  client: KitRpcAccess,
  context: RequestContext,
): Promise<{ readonly blockHeight: bigint; readonly absoluteSlot: bigint }> {
  const response: unknown = await runKitRpc("getEpochInfo", context, (abortSignal) =>
    client.solanaRpc.getEpochInfo({ commitment: "confirmed" }).send({ abortSignal }),
  );
  const decode = wireDecoder((path) => invalidResponse("getEpochInfo", path));
  const info = decode.record(response, "result");
  return {
    blockHeight: rpcU64(info["blockHeight"], "getEpochInfo"),
    absoluteSlot: rpcU64(info["absoluteSlot"], "getEpochInfo"),
  };
}

function rpcU64(value: unknown, method: string): bigint {
  if (typeof value !== "bigint" || value < 0n || value > MAX_U64)
    throw invalidResponse(method, "result");
  return value;
}

function invalidResponse(method: string, path: string): ClientError {
  return new ClientError("CLIENT_INVALID_RPC_RESPONSE", { details: { method, path } });
}
