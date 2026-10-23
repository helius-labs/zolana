import type { Commitment, Signature } from "@solana/kit";
import { wireDecoder } from "../interface/decode.js";
import type { RequestContext } from "../interface/types.js";
import { ClientError, isClientError, type ClientErrorCode } from "./error.js";
import { runWithDeadline } from "./internal.js";
import { runKitRpc } from "./kit.js";
import type { KitRpcAccess, PrivateTransactionReader } from "./ports.js";
import { isRetryable, pollUntil, type IndexerPollConfig } from "./retry.js";

const DEFAULT_WAIT_TIMEOUT_MS = 60_000;
const MAX_U64 = 0xffff_ffff_ffff_ffffn;

/** Only the evidence needed for confirmation; server error text never escapes. */
interface SignatureStatus {
  readonly slot: bigint;
  readonly commitment: Commitment | null;
  readonly failed: boolean;
}

export async function readSignatureStatus(
  client: KitRpcAccess,
  signature: Signature,
  context?: RequestContext,
): Promise<SignatureStatus | null> {
  const response: unknown = await runKitRpc("getSignatureStatuses", context, (abortSignal) =>
    client.solanaRpc.getSignatureStatuses([signature]).send({ abortSignal }),
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
  const error = status["err"];
  if (
    error === undefined ||
    (error !== null &&
      typeof error !== "string" &&
      (typeof error !== "object" || Array.isArray(error)))
  ) {
    throw invalidResponse("getSignatureStatuses", "err");
  }
  return {
    slot: rpcU64(status["slot"], "getSignatureStatuses"),
    commitment: reached ?? null,
    failed: error !== null,
  };
}

export function commitmentReached(reached: Commitment | null, required: Commitment): boolean {
  if (reached === null) return false;
  return (
    reached === "finalized" ||
    (required !== "finalized" && (reached === "confirmed" || required === "processed"))
  );
}

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
  let expiredAt: bigint | undefined;
  let causeCode: ClientErrorCode | undefined;
  const unresolved = (): ClientError =>
    new ClientError(
      confirmed ? "CLIENT_TRANSACTION_NOT_INDEXED" : "CLIENT_TRANSACTION_OUTCOME_UNKNOWN",
      { details: { signature, ...(causeCode === undefined ? {} : { causeCode }) } },
    );
  // A malformed response stops the wait. It must never become evidence of absence.
  const rememberFailure = (error: unknown): void => {
    if (!isClientError(error)) throw error;
    if (error.code === "CLIENT_ABORTED" || error.code === "CLIENT_INVALID_CONTEXT") throw error;
    causeCode = error.code;
    if (error.code === "CLIENT_INVALID_RPC_RESPONSE" || !isRetryable(error)) throw unresolved();
  };
  try {
    await runWithDeadline(
      { ...context, timeoutMs: context?.timeoutMs ?? DEFAULT_WAIT_TIMEOUT_MS },
      "waitForPrivateTransaction",
      async (attemptContext) => {
        await pollUntil(
          async () => {
            if (attemptContext.signal?.aborted) throw new ClientError("CLIENT_ABORTED");
            let unseen = false;
            let status: SignatureStatus | null | undefined;
            try {
              status = await readSignatureStatus(client, signature, attemptContext);
            } catch (error) {
              rememberFailure(error);
            }
            if (
              status !== undefined &&
              status !== null &&
              commitmentReached(status.commitment, "confirmed")
            ) {
              if (status.failed)
                throw new ClientError("CLIENT_RPC", {
                  details: { method: "getSignatureStatuses", reason: "transaction failed" },
                });
              confirmed = true;
            } else if (status === null) {
              unseen = !confirmed;
            }
            if (unseen && expiredAt === undefined && lastValidBlockHeight !== undefined) {
              try {
                const height = rpcU64(
                  await runKitRpc("getBlockHeight", attemptContext, (abortSignal) =>
                    client.solanaRpc
                      .getBlockHeight({ commitment: "confirmed" })
                      .send({ abortSignal }),
                  ),
                  "getBlockHeight",
                );
                if (height > lastValidBlockHeight) {
                  expiredAt = rpcU64(
                    await runKitRpc("getSlot", attemptContext, (abortSignal) =>
                      client.solanaRpc.getSlot({ commitment: "confirmed" }).send({ abortSignal }),
                    ),
                    "getSlot",
                  );
                }
              } catch (error) {
                rememberFailure(error);
              }
            }
            if (attemptContext.signal?.aborted) throw new ClientError("CLIENT_ABORTED");
            // This loop owns freshness. A nested requireSlot poll could consume its deadline.
            let found;
            try {
              found = await client.getShieldedTransactionsBySignature(
                signature,
                { poll },
                attemptContext,
              );
            } catch (error) {
              rememberFailure(error);
              return false;
            }
            if (attemptContext.signal?.aborted) throw new ClientError("CLIENT_ABORTED");
            if (found.transactions.some((event) => event.transaction.txSignature !== signature)) {
              causeCode = "CLIENT_INVALID_RPC_RESPONSE";
              throw unresolved();
            }
            // Photon commits every private event of a transaction atomically.
            if (found.transactions.length > 0) return true;
            if (unseen && expiredAt !== undefined && found.context.slot >= expiredAt) {
              throw new ClientError("CLIENT_TRANSACTION_EXPIRED", { details: { signature } });
            }
            causeCode = undefined;
            return false;
          },
          (indexed) => indexed,
          { config: poll, context: attemptContext, retryErrors: false, onTimeout: unresolved },
        );
      },
    );
  } catch (error) {
    if (isClientError(error) && error.code === "CLIENT_TIMEOUT") {
      causeCode = error.code;
      throw unresolved();
    }
    throw error;
  }
}

function rpcU64(value: unknown, method: string): bigint {
  if (typeof value !== "bigint" || value < 0n || value > MAX_U64)
    throw invalidResponse(method, "result");
  return value;
}

function invalidResponse(method: string, path: string): ClientError {
  return new ClientError("CLIENT_INVALID_RPC_RESPONSE", { details: { method, path } });
}
