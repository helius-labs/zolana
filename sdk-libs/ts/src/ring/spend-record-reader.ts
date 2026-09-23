import { ClientError } from "../client/error.js";
import type { ChainReader, RingSpendRecordReader } from "../client/ports.js";
import { nullifierPdaAddress } from "../interface/pda/index.js";
import type { Address, RequestContext } from "../interface/types.js";
import { RingError } from "./error.js";
import {
  currentRingSpendRecord,
  type LiveSpendRecord,
  type Member,
  type RingRecordTrees,
} from "./policy.js";
import { SPEND_RECORD_PROJECTION_ERRORS, waitForRingProjection } from "./projection.js";

export interface ReadCurrentSpendRecordInput extends RingRecordTrees {
  readonly client: RingSpendRecordReader & Pick<ChainReader, "getAccount">;
  readonly ringProgramId: Address;
  readonly namespace: Address;
  readonly sender: Member;
}

/** `undefined` until the member registers. */
export async function findCurrentSpendRecord(
  input: ReadCurrentSpendRecordInput,
  context?: RequestContext,
): Promise<LiveSpendRecord | undefined> {
  return waitForRingProjection(
    async (attempt) => {
      const { record } = await input.client.getRingSpendRecord(
        { ringProgramId: input.ringProgramId, member: input.sender },
        attempt,
      );
      if (record === null) return undefined;
      const live = await currentRingSpendRecord({
        record,
        addressTreeId: input.addressTreeId,
        resolveTreeId: input.resolveTreeId,
        namespace: input.namespace,
        member: input.sender,
      });
      // A spent record has a nullifier PDA, the projection has not reached its successor.
      const spent = await input.client.getAccount(
        await nullifierPdaAddress(live.tree, live.nullifier),
        attempt,
      );
      if (spent !== undefined) {
        throw new ClientError("CLIENT_SPEND_RECORD_OUT_OF_SYNC", {
          details: { method: "getRingSpendRecord" },
        });
      }
      return live;
    },
    SPEND_RECORD_PROJECTION_ERRORS,
    context,
  );
}

export async function readCurrentSpendRecord(
  input: ReadCurrentSpendRecordInput,
  context?: RequestContext,
): Promise<LiveSpendRecord> {
  const live = await findCurrentSpendRecord(input, context);
  if (live === undefined) throw new RingError("RING_SPEND_RECORD_MISSING");
  return live;
}
