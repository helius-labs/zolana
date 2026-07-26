import { ZolanaApi } from "@zolana/api";
import { ProverClient } from "@zolana/client/prover";
import { SolanaRpc, ZolanaClient, ZolanaIndexer } from "@zolana/client";
import { DEFAULT_TREE_ADDRESS, type Address } from "@zolana/interface";

import type { LocalStack } from "./index.js";

export interface E2eHarness {
  readonly stack: LocalStack;
  readonly rpc: SolanaRpc;
  readonly indexer: ZolanaIndexer;
  readonly prover: ProverClient;
  readonly client: ZolanaClient;
  stop(): Promise<void>;
}

export function createE2eHarness(
  stack: LocalStack,
  tree: Address = DEFAULT_TREE_ADDRESS,
): E2eHarness {
  const rpc = new SolanaRpc({ url: stack.rpcUrl });
  const indexer = new ZolanaIndexer(new ZolanaApi({ url: stack.indexerUrl }));
  const prover = new ProverClient({ url: stack.proverUrl });
  const client = new ZolanaClient({ rpc, indexer, prover, tree });
  return Object.freeze({
    stack,
    rpc,
    indexer,
    prover,
    client,
    stop: () => stack.stop(),
  });
}
