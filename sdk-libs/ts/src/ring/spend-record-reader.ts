import type { RingSpendRecordReader } from "../client/ports.js";
import type { Address, RequestContext } from "../interface/types.js";
import type { TreeId } from "../transaction/utxo.js";
import { RingError } from "./error.js";
import { currentRingSpendRecord, type LiveSpendRecord, type Member } from "./policy.js";

export interface ReadCurrentSpendRecordInput {
  readonly client: RingSpendRecordReader;
  readonly ringProgramId: Address;
  readonly namespace: Address;
  readonly entriesTree: Address;
  readonly entriesTreeId: TreeId;
  readonly sender: Member;
}

/** `undefined` until the member registers, a stale answer fails only on chain. */
export async function findCurrentSpendRecord(
  input: ReadCurrentSpendRecordInput,
  context?: RequestContext,
): Promise<LiveSpendRecord | undefined> {
  const { record } = await input.client.getRingSpendRecord(
    { ringProgramId: input.ringProgramId, member: input.sender },
    context,
  );
  if (record === null) return undefined;
  return currentRingSpendRecord({
    record,
    entriesTree: input.entriesTree,
    entriesTreeId: input.entriesTreeId,
    namespace: input.namespace,
    member: input.sender,
  });
}

export async function readCurrentSpendRecord(
  input: ReadCurrentSpendRecordInput,
  context?: RequestContext,
): Promise<LiveSpendRecord> {
  const live = await findCurrentSpendRecord(input, context);
  if (live === undefined) throw new RingError("RING_SPEND_RECORD_MISSING");
  return live;
}
