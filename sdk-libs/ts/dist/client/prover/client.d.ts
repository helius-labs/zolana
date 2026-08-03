import type { RequestContext } from "../../interface/types.js";
import type { MergeInputs, Proof, ProverInputs } from "./types.js";
export interface AsyncPollConfig {
    readonly pollIntervalMs: number;
    readonly maxWaitMs: number;
}
export declare class ProverClient {
    #private;
    constructor(input: Readonly<{
        url: URL | string;
        fetch?: typeof globalThis.fetch;
        asyncPoll?: AsyncPollConfig;
    }>);
    prove(inputs: ProverInputs, context?: RequestContext): Promise<Proof>;
    proveMerge(inputs: MergeInputs, context?: RequestContext): Promise<Proof>;
}
