import type { ChainReader, RingHeadReader } from "../client/ports.js";
import type { Address, RequestContext } from "../interface/types.js";
import type { TreeId } from "../transaction/utxo.js";
import { equalBytes } from "../wallet/internal.js";
import { fetchRingHeadMapRoot } from "./config.js";
import { RingError } from "./error.js";
import { verifyHeadMapTransfer } from "./head-map.js";
import { currentRingSpendRecord, type Member } from "./policy.js";
import { HEAD_MAP_PROJECTION_ERRORS, waitForRingProjection } from "./projection.js";

export async function readCurrentSpendRecord(
  input: Readonly<{
    client: Pick<ChainReader, "getAccount"> & Pick<RingHeadReader, "getRingHeadTransferProof">;
    ringProgramId: Address;
    namespace: Address;
    entriesTree: Address;
    entriesTreeId: TreeId;
    sender: Member;
  }>,
  context?: RequestContext,
) {
  return waitForRingProjection(
    (attemptContext) => readCurrentSpendRecordOnce(input, attemptContext),
    HEAD_MAP_PROJECTION_ERRORS,
    context,
  );
}

async function readCurrentSpendRecordOnce(
  input: Readonly<{
    client: Pick<ChainReader, "getAccount"> & Pick<RingHeadReader, "getRingHeadTransferProof">;
    ringProgramId: Address;
    namespace: Address;
    entriesTree: Address;
    entriesTreeId: TreeId;
    sender: Member;
  }>,
  context?: RequestContext,
) {
  // The chain account is authoritative. Refetch it on every projection retry so
  // a concurrent spend cannot leave the next request pinned to an obsolete root.
  const root = await fetchRingHeadMapRoot(input.client, input.ringProgramId, context);
  const head = await input.client.getRingHeadTransferProof(
    {
      ringProgramId: input.ringProgramId,
      member: input.sender,
      expectedRoot: root.root,
      expectedNextIndex: root.nextIndex,
    },
    context,
  );
  if (
    !equalBytes(head.root, root.root) ||
    head.nextIndex !== root.nextIndex ||
    !equalBytes(head.member, input.sender) ||
    head.index >= root.nextIndex
  )
    throw new RingError("RING_HEAD_MAP_STALE");
  verifyHeadMapTransfer({
    root: root.root,
    member: input.sender,
    next: head.next,
    spent: head.nullifier,
    successor: head.nullifier,
    index: head.index,
    proof: head.proof,
  });
  const live = currentRingSpendRecord({
    proof: head,
    entriesTree: input.entriesTree,
    entriesTreeId: input.entriesTreeId,
    namespace: input.namespace,
    member: input.sender,
  });
  return { head, live };
}
