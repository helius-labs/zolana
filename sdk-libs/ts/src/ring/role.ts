import type { ZolanaClient } from "../client/client.js";
import type { RpcAccount } from "../client/rpc.js";
import type { Address, RequestContext } from "../interface/types.js";

import { decodeRingProgramConfig } from "./codecs.js";
import { ringConfigAddress } from "./config.js";
import { RingError } from "./error.js";
import {
  decodeReaderRecord,
  readerKeyEquals,
  readerRecordAddress,
  type ReaderKey,
} from "./reader.js";

type AccountReader = Pick<ZolanaClient, "getMultipleAccounts">;

export type RingRole = "authority" | "delegated reader" | "participant only";

/** What a ring's config and reader records say about one key. */
export async function ringRole(
  input: Readonly<{ rpc: AccountReader; ring: Address; reader: ReaderKey }>,
  context?: RequestContext,
): Promise<RingRole> {
  const [config, record] = await Promise.all([
    ringConfigAddress(input.ring),
    readerRecordAddress(input.ring, input.reader),
  ]);
  const [configAccount, recordAccount] = await input.rpc.getMultipleAccounts(
    [config, record],
    context,
  );
  const configData = owned(configAccount, input.ring);
  if (configData === undefined) {
    throw new RingError("RING_CONFIG_INVALID", { details: { reason: "ring has no config" } });
  }
  if (readerKeyEquals(decodeRingProgramConfig(configData).authority, input.reader)) {
    return "authority";
  }
  const recordData = owned(recordAccount, input.ring);
  if (recordData && readerKeyEquals(decodeReaderRecord(recordData).reader, input.reader)) {
    return "delegated reader";
  }
  return "participant only";
}

/** An account another program owns says nothing about this ring. */
function owned(account: RpcAccount | undefined, owner: Address): Uint8Array | undefined {
  return account === undefined || account.owner !== owner ? undefined : account.data;
}
