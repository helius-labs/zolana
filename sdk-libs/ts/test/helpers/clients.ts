import type { ChainReader, IndexerReader, KitRpcAccess } from "../../src/client/index.js";
import type { RingAuditReader } from "../../src/ring/audit.js";
import type { RingTransferClient } from "../../src/ring/transfer.js";
import type {
  DepositClient,
  PrivateTransactionClient,
  SyncClient,
} from "../../src/wallet/index.js";

/** The one place a partial client fake becomes a port, `test/casts.test.ts` bans it elsewhere. */
function fake<T>(members: object): T {
  return members as T;
}

export function syncReads(members: object): SyncClient {
  return fake(members);
}

export function kitReads(members: object): KitRpcAccess {
  return fake(members);
}

export function accountReads(members: object): Pick<ChainReader, "getProgramAccounts"> {
  return fake(members);
}

export function signatureReads(
  members: object,
): Pick<IndexerReader, "getShieldedTransactionsBySignature"> {
  return fake(members);
}

export function depositClient(members: object): DepositClient {
  return fake(members);
}

export function privateTransactionClient(members: object): PrivateTransactionClient {
  return fake(members);
}

export function ringTransferClient(members: object): RingTransferClient {
  return fake(members);
}

export function ringAuditReader(members: object): RingAuditReader {
  return fake(members);
}
