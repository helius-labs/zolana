import { appendTransactionMessageInstructions, compileTransaction, createSolanaRpc, createSolanaRpcSubscriptions, createTransactionMessage, isSolanaError, pipe, setTransactionMessageFeePayer, setTransactionMessageLifetimeUsingBlockhash, SOLANA_ERROR__JSON_RPC__METHOD_NOT_FOUND, } from "@solana/kit";
import { ClientError, isClientError } from "./error.js";
import { composeSignal } from "./internal.js";
export function createKitClients(input) {
    const rpcUrl = urlString(input.solanaRpcUrl, "solanaRpcUrl", ["http:", "https:"]);
    const subscriptionsUrl = input.solanaRpcSubscriptionsUrl === undefined
        ? defaultSolanaRpcSubscriptionsUrl(rpcUrl)
        : urlString(input.solanaRpcSubscriptionsUrl, "solanaRpcSubscriptionsUrl", ["ws:", "wss:"]);
    return Object.freeze({
        solanaRpc: createSolanaRpc(rpcUrl),
        solanaRpcSubscriptions: createSolanaRpcSubscriptions(subscriptionsUrl),
    });
}
export function buildUnsignedTransaction(input) {
    const message = pipe(createTransactionMessage({ version: 0 }), (transactionMessage) => setTransactionMessageFeePayer(input.feePayer, transactionMessage), (transactionMessage) => setTransactionMessageLifetimeUsingBlockhash(input.lifetime, transactionMessage), (transactionMessage) => appendTransactionMessageInstructions(input.instructions, transactionMessage));
    return compileTransaction(message);
}
export async function runKitRpc(method, context, operation) {
    const signal = composeSignal(context, method);
    try {
        return await operation(signal.signal);
    }
    catch (cause) {
        throw operationError(method, signal, cause);
    }
    finally {
        signal.cleanup();
    }
}
function operationError(method, signal, cause) {
    if (isClientError(cause))
        return cause;
    if (isSolanaError(cause, SOLANA_ERROR__JSON_RPC__METHOD_NOT_FOUND)) {
        return new ClientError("CLIENT_UNSUPPORTED_RPC_METHOD", {
            details: { method },
            cause,
        });
    }
    if (signal.timedOut()) {
        return new ClientError("CLIENT_TIMEOUT", {
            details: { method, retryable: true },
            cause,
        });
    }
    if (signal.signal.aborted) {
        return new ClientError("CLIENT_ABORTED", {
            details: { method, retryable: false },
            cause,
        });
    }
    return new ClientError("CLIENT_RPC", {
        details: { method },
        cause,
    });
}
function urlString(value, field, protocols) {
    let url;
    try {
        url = new URL(value instanceof URL ? value.href : value);
    }
    catch {
        throw invalidUrl(field);
    }
    if (!protocols.includes(url.protocol) ||
        url.username !== "" ||
        url.password !== "" ||
        url.hash !== "") {
        throw invalidUrl(field);
    }
    return url.href;
}
export function defaultSolanaRpcSubscriptionsUrl(value) {
    const url = new URL(value);
    if (url.port !== "") {
        const port = Number(url.port);
        if (!Number.isSafeInteger(port) || port >= 65_535) {
            throw invalidUrl("solanaRpcUrl");
        }
        url.port = String(port + 1);
    }
    if (url.protocol === "http:")
        url.protocol = "ws:";
    else if (url.protocol === "https:")
        url.protocol = "wss:";
    return url.href;
}
function invalidUrl(field) {
    return new ClientError("CLIENT_INVALID_CONFIG", { details: { field } });
}
