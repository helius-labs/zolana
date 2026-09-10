import type { RequestContext } from "../interface/types.js";
import { ClientError, type RetryErrorCause } from "./error.js";
export type { RetryErrorCause } from "./error.js";
export interface IndexerPollConfig {
    readonly numRetries: number;
    readonly delayMs: bigint;
    readonly maxDelayMs: bigint;
}
export interface IndexerRpcConfig {
    readonly waitForIndexer: boolean;
    readonly poll: IndexerPollConfig;
}
export declare const DEFAULT_INDEXER_POLL_CONFIG: IndexerPollConfig;
export declare const DEFAULT_INDEXER_RPC_CONFIG: IndexerRpcConfig;
export declare function createIndexerPollConfig(numRetries: number, delayMs: bigint, maxDelayMs: bigint): IndexerPollConfig;
export declare function createIndexerRpcConfig(waitForIndexer?: boolean, poll?: IndexerPollConfig): IndexerRpcConfig;
export declare function waitForIndexer(poll?: IndexerPollConfig): IndexerRpcConfig;
export declare function validatePollConfig(config: IndexerPollConfig): IndexerPollConfig;
export declare function attempts(config: IndexerPollConfig): number;
export declare function backoff(config: IndexerPollConfig): IterableIterator<bigint>;
export interface PollUntilOptions {
    readonly config?: IndexerPollConfig;
    readonly context?: RequestContext;
}
export declare function pollUntil<T>(request: () => Promise<T>, accept: (response: T) => boolean, options?: PollUntilOptions): Promise<T>;
export declare function retryCause(error: unknown): RetryErrorCause | undefined;
export declare function isRetryable(cause: unknown): cause is ClientError;
