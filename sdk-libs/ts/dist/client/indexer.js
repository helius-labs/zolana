import { ZolanaApi } from "../api/index.js";
import { base64String, hash, hashBytes, limit } from "../indexer/scalars.js";
import { P256PublicKey } from "../keypair/public-key.js";
import { ClientError, isClientError } from "./error.js";
import { decodeBase64 } from "./internal.js";
import { DEFAULT_INDEXER_POLL_CONFIG, pollUntil, validatePollConfig, } from "./retry.js";
import {} from "./rpc.js";
export class ZolanaIndexer {
    #api;
    constructor(api) {
        if (!(api instanceof ZolanaApi)) {
            throw new ClientError("CLIENT_INVALID_INDEXER", {
                details: { field: "api" },
            });
        }
        this.#api = api;
    }
    getEncryptedUtxosByTags(request, config, context) {
        const owned = copyTagRequest(request);
        return pollIndexer(config, context, async () => {
            const method = "getEncryptedUtxosByTags";
            try {
                const response = await this.#api.getEncryptedUtxosByTags({
                    tags: owned.tags.map((tag) => hash(tag)),
                    ...(owned.cursor === undefined ? {} : { cursor: base64String(owned.cursor) }),
                    ...(owned.limit === undefined ? {} : { limit: limit(BigInt(owned.limit)) }),
                }, context);
                return convertEncryptedUtxosResponse(response, method);
            }
            catch (cause) {
                throw wrapIndexer(cause, method);
            }
        });
    }
    getShieldedTransactionsByTags(request, config, context) {
        const owned = copyTagRequest(request);
        return pollIndexer(config, context, async () => {
            const method = "getShieldedTransactionsByTags";
            try {
                const response = await this.#api.getShieldedTransactionsByTags({
                    tags: owned.tags.map((tag) => hash(tag)),
                    ...(owned.cursor === undefined ? {} : { cursor: base64String(owned.cursor) }),
                    ...(owned.limit === undefined ? {} : { limit: limit(BigInt(owned.limit)) }),
                }, context);
                return convertShieldedTransactionsResponse(response, method);
            }
            catch (cause) {
                throw wrapIndexer(cause, method);
            }
        });
    }
    getShieldedTransactionsByNullifiers(request, config, context) {
        const owned = copyNullifierRequest(request);
        return pollIndexer(config, context, async () => {
            const method = "getShieldedTransactionsByNullifiers";
            try {
                const response = await this.#api.getShieldedTransactionsByNullifiers({
                    nullifiers: owned.nullifiers.map((nullifier) => hash(nullifier)),
                    ...(owned.cursor === undefined ? {} : { cursor: base64String(owned.cursor) }),
                    ...(owned.limit === undefined ? {} : { limit: limit(BigInt(owned.limit)) }),
                }, context);
                return convertShieldedTransactionsByNullifiersResponse(response, method);
            }
            catch (cause) {
                throw wrapIndexer(cause, method);
            }
        });
    }
    getShieldedTransactionsBySignature(signature, config, context) {
        return pollIndexer(config, context, async () => {
            const method = "getShieldedTransactionsBySignature";
            try {
                const response = await this.#api.getShieldedTransactionsBySignature({ txSignature: signature }, context);
                return convertShieldedTransactionsBySignatureResponse(response, method);
            }
            catch (cause) {
                throw wrapIndexer(cause, method);
            }
        });
    }
    getMerkleProofs(treeAccount, leaves, config, context) {
        const requested = copyLeaves(leaves);
        return pollIndexer(config, context, async () => {
            const method = "getMerkleProofs";
            try {
                const response = await this.#api.getMerkleProofs({ treeAccount, leaves: requested.map((leaf) => hash(leaf)) }, context);
                return Object.freeze({
                    context: Object.freeze({ blockTime: response.context.blockTime }),
                    proofs: Object.freeze(response.proofs.map(convertMerkleProof)),
                });
            }
            catch (cause) {
                throw wrapIndexer(cause, method);
            }
        });
    }
    getNonInclusionProofs(treeAccount, leaves, config, context) {
        const requested = copyLeaves(leaves);
        return pollIndexer(config, context, async () => {
            const method = "getNonInclusionProofs";
            try {
                const response = await this.#api.getNonInclusionProofs({ treeAccount, leaves: requested.map((leaf) => hash(leaf)) }, context);
                return Object.freeze({
                    context: Object.freeze({ blockTime: response.context.blockTime }),
                    proofs: Object.freeze(response.proofs.map(convertNonInclusionProof)),
                });
            }
            catch (cause) {
                throw wrapIndexer(cause, method);
            }
        });
    }
}
function copyTagRequest(request) {
    if (request.cursor !== undefined && !(request.cursor instanceof Uint8Array)) {
        throw new ClientError("CLIENT_INVALID_CONFIG", { details: { field: "cursor" } });
    }
    return Object.freeze({
        tags: copyFixedBytes(request.tags, 32, "tags"),
        ...(request.cursor === undefined ? {} : { cursor: new Uint8Array(request.cursor) }),
        ...(request.limit === undefined ? {} : { limit: checkedPageLimit(request.limit) }),
    });
}
function copyNullifierRequest(request) {
    if (request.cursor !== undefined && !(request.cursor instanceof Uint8Array)) {
        throw new ClientError("CLIENT_INVALID_CONFIG", { details: { field: "cursor" } });
    }
    return Object.freeze({
        nullifiers: copyFixedBytes(request.nullifiers, 32, "nullifiers"),
        ...(request.cursor === undefined ? {} : { cursor: new Uint8Array(request.cursor) }),
        ...(request.limit === undefined ? {} : { limit: checkedPageLimit(request.limit) }),
    });
}
function checkedPageLimit(value) {
    if (!Number.isSafeInteger(value) || value < 1 || value > 1000) {
        throw new ClientError("CLIENT_INVALID_INTEGER", {
            details: { field: "limit", value: String(value) },
        });
    }
    return value;
}
function copyLeaves(leaves) {
    return copyFixedBytes(leaves, 32, "leaves");
}
function copyFixedBytes(values, expected, field) {
    return Object.freeze(values.map((value, index) => {
        if (!(value instanceof Uint8Array) || value.length !== expected) {
            throw new ClientError("CLIENT_INVALID_LENGTH", {
                details: {
                    field: `${field}[${String(index)}]`,
                    expected,
                    actual: value instanceof Uint8Array ? value.length : -1,
                },
            });
        }
        return new Uint8Array(value);
    }));
}
function convertMerkleProof(proof) {
    return Object.freeze({
        leaf: copyHash(proof.leaf),
        merkleContext: Object.freeze({ ...proof.merkleContext }),
        path: Object.freeze(proof.path.map(copyHash)),
        leafIndex: proof.leafIndex,
        root: copyHash(proof.root),
        rootSeq: proof.rootSeq,
        rootIndex: proof.rootIndex,
    });
}
function convertNonInclusionProof(proof) {
    return Object.freeze({
        leaf: copyHash(proof.leaf),
        merkleContext: Object.freeze({ ...proof.merkleContext }),
        path: Object.freeze(proof.path.map(copyHash)),
        lowElement: copyHash(proof.lowElement),
        lowElementIndex: proof.lowElementIndex,
        highElement: copyHash(proof.highElement),
        highElementIndex: proof.highElementIndex,
        root: copyHash(proof.root),
        rootSeq: proof.rootSeq,
        rootIndex: proof.rootIndex,
    });
}
function copyHash(value) {
    return new Uint8Array(hashBytes(value));
}
function convertEncryptedUtxosResponse(response, method) {
    return Object.freeze({
        context: Object.freeze({ blockTime: response.context.blockTime }),
        matches: Object.freeze(response.matches.map((item, index) => convertEncryptedUtxoMatch(item, method, `$.matches[${String(index)}]`))),
        ...(response.nextCursor === undefined
            ? {}
            : { nextCursor: decodeBase64(response.nextCursor, "next_cursor") }),
    });
}
function convertEncryptedUtxoMatch(item, method, path) {
    return Object.freeze({
        slot: item.slot,
        txSignature: item.txSignature,
        outputSlot: convertOutputSlot(item.outputSlot),
        ...(item.txViewingPk === undefined
            ? {}
            : { txViewingPk: decodeP256(item.txViewingPk, method, `${path}.tx_viewing_pk`) }),
        ...(item.salt === undefined ? {} : { salt: decodeSalt(item.salt, method, `${path}.salt`) }),
    });
}
function convertShieldedTransactionsResponse(response, method) {
    return Object.freeze({
        context: Object.freeze({ blockTime: response.context.blockTime }),
        transactions: Object.freeze(response.transactions.map((item, index) => convertShieldedTransaction(item, method, `$.transactions[${String(index)}]`))),
        ...(response.nextCursor === undefined
            ? {}
            : { nextCursor: decodeBase64(response.nextCursor, "next_cursor") }),
    });
}
function convertShieldedTransactionsByNullifiersResponse(response, method) {
    return convertShieldedTransactionsResponse(response, method);
}
function convertShieldedTransactionsBySignatureResponse(response, method) {
    return Object.freeze({
        context: Object.freeze({ blockTime: response.context.blockTime }),
        transactions: Object.freeze(response.transactions.map((item, index) => Object.freeze({
            eventIndex: item.eventIndex,
            transaction: convertShieldedTransaction(item.transaction, method, `$.transactions[${String(index)}].transaction`),
        }))),
    });
}
function convertShieldedTransaction(item, method, path) {
    return Object.freeze({
        slot: item.slot,
        txSignature: item.txSignature,
        ...(item.txViewingPk === undefined
            ? {}
            : {
                txViewingPublicKey: decodeP256(item.txViewingPk, method, `${path}.tx_viewing_pk`),
            }),
        ...(item.salt === undefined ? {} : { salt: decodeSalt(item.salt, method, `${path}.salt`) }),
        outputSlots: Object.freeze(item.outputSlots.map(convertOutputSlot)),
        messages: Object.freeze(item.messages.map((message) => Object.freeze({
            viewTag: copyHash(message.viewTag),
            data: decodeBase64(message.payload, "message.payload"),
        }))),
        nullifiers: Object.freeze(item.nullifiers.map(copyHash)),
        proofless: item.proofless,
    });
}
function convertOutputSlot(slot) {
    return Object.freeze({
        viewTag: copyHash(slot.viewTag),
        outputContext: Object.freeze({
            hash: copyHash(slot.outputContext.hash),
            tree: slot.outputContext.tree,
            leafIndex: slot.outputContext.leafIndex,
        }),
        payload: decodeBase64(slot.payload, "output_slot.payload"),
    });
}
function decodeP256(value, method, path) {
    const bytes = decodeBase64(value, path);
    if (bytes.length !== 33)
        throw invalidResponse(method, path, 33, bytes.length);
    try {
        return P256PublicKey.fromBytes(bytes);
    }
    catch {
        throw invalidResponse(method, path);
    }
}
function decodeSalt(value, method, path) {
    const bytes = decodeBase64(value, path);
    if (bytes.length !== 16)
        throw invalidResponse(method, path, 16, bytes.length);
    return bytes;
}
async function pollIndexer(config, context, request) {
    const rawConfig = config;
    if (rawConfig !== undefined &&
        (typeof rawConfig !== "object" ||
            rawConfig === null ||
            typeof rawConfig["waitForIndexer"] !== "boolean")) {
        throw new ClientError("CLIENT_INVALID_POLL_CONFIG", {
            details: { field: "waitForIndexer" },
        });
    }
    const waitForIndexer = config?.waitForIndexer ?? false;
    if (!waitForIndexer)
        return request();
    const poll = validatePollConfig(config?.poll ?? DEFAULT_INDEXER_POLL_CONFIG);
    const attempts = poll.numRetries + 1;
    const target = BigInt(Math.floor(Date.now() / 1000));
    let latest;
    let responses = 0;
    try {
        return await pollUntil(request, (response) => {
            responses++;
            latest = response.context.blockTime;
            return latest >= target;
        }, { config: poll, ...(context === undefined ? {} : { context }) });
    }
    catch (cause) {
        // Fewer responses than attempts means the schedule ended on a failure, so
        // `cause` already carries the precise reason and its structured cause.
        if (latest === undefined || responses !== attempts)
            throw cause;
        if (!isClientError(cause) || cause.code !== "CLIENT_POLL_TIMED_OUT")
            throw cause;
        throw new ClientError("CLIENT_INDEXER_NOT_CAUGHT_UP", {
            details: {
                target: target.toString(),
                latest: latest.toString(),
                attempts,
            },
        });
    }
}
function wrapIndexer(cause, method) {
    if (isClientError(cause))
        return cause;
    const code = externalCode(cause);
    if (code === "API_ABORTED")
        return new ClientError("CLIENT_ABORTED", { details: { method } });
    if (code === "API_TIMEOUT") {
        return new ClientError("CLIENT_TIMEOUT", {
            details: { method, retryable: true },
            cause,
        });
    }
    if (code === "API_REQUEST") {
        return new ClientError("CLIENT_REQUEST", {
            details: { method, retryable: true },
            cause,
        });
    }
    if (code === "API_INVALID_RESULT") {
        return new ClientError("CLIENT_INVALID_RPC_RESPONSE", {
            details: { method, ...safePath(cause) },
            cause,
        });
    }
    return new ClientError("CLIENT_INDEXER", {
        details: { method, retryable: apiRetryable(cause) },
        cause,
    });
}
// The API layer already classified the failure. An unrecognized shape counts as
// fatal so a rejected request cannot consume the whole polling schedule.
function apiRetryable(cause) {
    if (typeof cause !== "object" || cause === null || !("details" in cause))
        return false;
    const details = cause.details;
    return (typeof details === "object" &&
        details !== null &&
        "retryable" in details &&
        details.retryable === true);
}
function externalCode(cause) {
    if (typeof cause === "object" &&
        cause !== null &&
        "code" in cause &&
        typeof cause.code === "string") {
        return cause.code;
    }
    return undefined;
}
function safePath(cause) {
    if (typeof cause !== "object" || cause === null || !("details" in cause))
        return {};
    const details = cause.details;
    if (typeof details !== "object" || details === null || !("path" in details))
        return {};
    return typeof details.path === "string" ? { path: details.path } : {};
}
function invalidResponse(method, path, expected, actual) {
    return new ClientError("CLIENT_INVALID_RPC_RESPONSE", {
        details: {
            method,
            path,
            ...(expected === undefined ? {} : { expected }),
            ...(actual === undefined ? {} : { actual }),
        },
    });
}
