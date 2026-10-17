import type { RingMemberRegistryReader, ChainReader } from "../client/ports.js";
import type { Address, Bytes32, RequestContext } from "../interface/types.js";
import { equalBytes } from "../wallet/internal.js";
import { ZERO_32 } from "../transaction/internal.js";
import { waitForProjection } from "../client/retry.js";
import { MEMBER_REGISTRY_PROJECTION_ERRORS } from "./projection.js";
import { fetchRingMemberRegistryRoot } from "./config.js";
import type { RingMemberRegistryRoot } from "./codecs.js";
import { verifyMemberOpening, type MemberOpening } from "./member-registry-tree.js";
import { RingError } from "./error.js";
import type { RingSealedNullifierKey as SealedNullifierKey } from "../client/ports.js";

export interface MemberRecordRead {
  readonly member: Bytes32;
  readonly registry: RingMemberRegistryRoot;
  readonly opening: MemberOpening;
  readonly sealed: SealedNullifierKey | null;
}
export async function readRingMemberRecord(
  input: Readonly<{
    client: Pick<RingMemberRegistryReader, "getRingMemberRecord">;
    ringProgramId: Address;
    member: Bytes32;
    registry: RingMemberRegistryRoot;
  }>,
  context?: RequestContext,
): Promise<MemberRecordRead> {
  const { registry, member } = input;
  const response = await input.client.getRingMemberRecord(
    {
      ringProgramId: input.ringProgramId,
      member,
      expectedRoot: registry.root,
      expectedNextIndex: registry.nextIndex,
    },
    context,
  );
  if (
    !equalBytes(response.root, registry.root) ||
    response.nextIndex !== registry.nextIndex ||
    response.rootIndex !== registry.historyCursor
  )
    throw new RingError("RING_MEMBER_REGISTRY_STALE");
  let opening: MemberOpening,
    sealed: SealedNullifierKey | null = null;
  if (response.present && response.record !== null && response.low === null) {
    const record = response.record;
    if (response.index === 0n || response.index >= registry.nextIndex)
      throw new RingError("RING_MEMBER_REGISTRY_INVALID");
    if (record.ephemeralPublicKey !== null && record.ciphertext !== null)
      sealed = { ephemeralPublicKey: record.ephemeralPublicKey, ciphertext: record.ciphertext };
    else if (
      record.ephemeralPublicKey !== null ||
      record.ciphertext !== null ||
      !equalBytes(record.escrowKey, ZERO_32)
    )
      throw new RingError("RING_MEMBER_REGISTRY_INVALID");
    opening = { present: true, record, index: response.index, path: response.path };
  } else if (
    !response.present &&
    response.record === null &&
    response.low !== null &&
    response.index === 0n &&
    response.path.length === 0
  ) {
    if (response.low.index >= registry.nextIndex)
      throw new RingError("RING_MEMBER_REGISTRY_INVALID");
    opening = {
      present: false,
      low: response.low,
      index: response.low.index,
      path: response.low.path,
    };
  } else throw new RingError("RING_MEMBER_REGISTRY_INVALID");
  verifyMemberOpening(registry.root, member, opening);
  return { member, registry, opening, sealed };
}
export async function fetchRingMemberRecord(
  input: Readonly<{
    client: Pick<ChainReader, "getAccount"> & Pick<RingMemberRegistryReader, "getRingMemberRecord">;
    ringProgramId: Address;
    member: Bytes32;
  }>,
  context?: RequestContext,
): Promise<MemberRecordRead> {
  return waitForProjection(
    async (context) =>
      readRingMemberRecord(
        {
          ...input,
          registry: await fetchRingMemberRegistryRoot(input.client, input.ringProgramId, context),
        },
        context,
      ),
    MEMBER_REGISTRY_PROJECTION_ERRORS,
    context,
  );
}
