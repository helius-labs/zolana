import { address, blockhash, type Commitment } from "@solana/kit";

import type { ChainReader, IndexerReader, KitRpcAccess } from "../../src/client/index.js";
import type { LatestBlockhash, SolanaRpc } from "../../src/client/kit.js";
import type {
  GetEncryptedUtxosByTagsResponse,
  GetShieldedTransactionsBySignatureResponse,
  GetShieldedTransactionsByTagsResponse,
  RpcContext,
} from "../../src/client/rpc.js";
import type { RingAuditReader } from "../../src/ring/audit.js";
import type { RingTransferClient } from "../../src/ring/transfer.js";
import type {
  DepositClient,
  PrivateTransactionClient,
  SyncClient,
} from "../../src/wallet/index.js";

const CONTEXT: RpcContext = Object.freeze({ blockTime: 1_700_000_000n, slot: 0n });
const TREE = address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");
const BLOCKHASH: LatestBlockhash = Object.freeze({
  blockhash: blockhash("11111111111111111111111111111111"),
  lastValidBlockHeight: 1n,
});

export function transactionsPage(
  overrides: Partial<GetShieldedTransactionsByTagsResponse> = {},
): GetShieldedTransactionsByTagsResponse {
  return { context: CONTEXT, transactions: [], ...overrides };
}

export function matchesPage(
  overrides: Partial<GetEncryptedUtxosByTagsResponse> = {},
): GetEncryptedUtxosByTagsResponse {
  return { context: CONTEXT, matches: [], ...overrides };
}

export function signaturesPage(
  overrides: Partial<GetShieldedTransactionsBySignatureResponse> = {},
): GetShieldedTransactionsBySignatureResponse {
  return { context: CONTEXT, transactions: [], ...overrides };
}

function notImplemented(member: string): () => never {
  return () => {
    throw new Error(`fake client member ${member} must not be called`);
  };
}

/** Kit's `Rpc` proxy has no structural stand-in, the one cast the guard admits. */
export function solanaRpcReads(members: object): SolanaRpc {
  return members as SolanaRpc;
}

export function syncReads(overrides: Partial<SyncClient> = {}): SyncClient {
  return {
    getShieldedTransactionsByTags: async () => transactionsPage(),
    getEncryptedUtxosByTags: async () => matchesPage(),
    getShieldedTransactionsByNullifiers: async () => transactionsPage(),
    ...overrides,
  };
}

export function kitReads(
  input: Readonly<{ solanaRpc: object; commitment?: Commitment }>,
): KitRpcAccess {
  return {
    solanaRpc: solanaRpcReads(input.solanaRpc),
    commitment: input.commitment ?? "confirmed",
  };
}

export function accountReads(
  reads: Pick<ChainReader, "getProgramAccounts">,
): Pick<ChainReader, "getProgramAccounts"> {
  return reads;
}

export function signatureReads(
  reads: Pick<IndexerReader, "getShieldedTransactionsBySignature">,
): Pick<IndexerReader, "getShieldedTransactionsBySignature"> {
  return reads;
}

export function depositClient(overrides: Partial<DepositClient> = {}): DepositClient {
  return {
    tree: TREE,
    getLatestBlockhash: async () => BLOCKHASH,
    getAccount: async () => undefined,
    ...overrides,
  };
}

export function privateTransactionClient(
  overrides: Partial<PrivateTransactionClient> = {},
): PrivateTransactionClient {
  return {
    getAccount: async () => undefined,
    assembleAuthorizedPrivateTransaction: notImplemented("assembleAuthorizedPrivateTransaction"),
    ...overrides,
  };
}

export function ringTransferClient(
  overrides: Partial<RingTransferClient> = {},
): RingTransferClient {
  return {
    tree: TREE,
    getLatestBlockhash: async () => BLOCKHASH,
    getAccount: async () => undefined,
    proveRingTransact: notImplemented("proveRingTransact"),
    proveCustomRing: notImplemented("proveCustomRing"),
    solanaRpc: solanaRpcReads({}),
    commitment: "confirmed",
    ...overrides,
  };
}

export function ringAuditReader(
  input: Readonly<{
    getShieldedTransactionsByTags: RingAuditReader["getShieldedTransactionsByTags"];
    solanaRpc?: object;
    commitment?: Commitment;
  }>,
): RingAuditReader {
  return {
    getShieldedTransactionsByTags: input.getShieldedTransactionsByTags,
    solanaRpc: solanaRpcReads(input.solanaRpc ?? {}),
    commitment: input.commitment ?? "confirmed",
  };
}
