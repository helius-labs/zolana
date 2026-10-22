import type { ChainReader, RingRecordReader } from "../client/ports.js";
import type { PresentRecordOpening } from "../client/prover/types.js";
import { waitForProjection } from "../client/retry.js";
import { MAX_RING_MEMBER_BATCH } from "../interface/indexer-limits.js";
import type { Address, Bytes32, RequestContext } from "../interface/types.js";
import type { ShieldedAddress } from "../keypair/shielded.js";
import { equalBytes } from "../wallet/internal.js";

import { registryCurrentRoot } from "./codecs.js";
import { fetchRingMemberRegistry, fetchRingProgramConfig } from "./config.js";
import { RingError } from "./error.js";
import { MemberOpeningRead, ownerEscrowed } from "./member-registry.js";
import { MEMBER_REGISTRY_PROJECTION_ERRORS } from "./projection.js";

export type RingRecordReadClient = Pick<ChainReader, "getAccount"> &
  Pick<RingRecordReader, "getRingMemberOpenings">;

/** A member's present record under the registry's newest root. */
export interface RegisteredRecord {
  readonly root: Bytes32;
  /** The root's history slot, the program reads the bound root back through it. */
  readonly index: number;
  readonly record: PresentRecordOpening;
  /** `hash_bytes` of the escrowed key ciphertext, the record's escrow key binds it. */
  readonly ctHash: Bytes32;
}

/** Members' records under the registry's newest root, in member order, Rust `MemberRecords::read`. */
export function readMemberRecords(
  input: Readonly<{
    client: RingRecordReadClient;
    ringProgramId: Address;
    members: readonly Bytes32[];
  }>,
  context?: RequestContext,
): Promise<readonly MemberOpeningRead[]> {
  return waitForProjection(
    async (attempt) => (await readNewest(input, attempt)).reads,
    MEMBER_REGISTRY_PROJECTION_ERRORS,
    context,
  );
}

/** Under key escrow the first recipient without an escrowed nullifier key is refused, Rust `EscrowedRecipients::check`. */
export async function checkEscrowedRecipients(
  input: Readonly<{
    client: RingRecordReadClient;
    ringProgramId: Address;
    recipients: readonly ShieldedAddress[];
  }>,
  context?: RequestContext,
): Promise<void> {
  const config = await fetchRingProgramConfig(input.client, input.ringProgramId, context);
  if (config.mode !== "registry") return;
  const owners = input.recipients.map((recipient) =>
    recipient.signingPublicKey.ownerProofInputHash(),
  );
  const reads = await readMemberRecords(
    { client: input.client, ringProgramId: input.ringProgramId, members: owners },
    context,
  );
  input.recipients.forEach((recipient, index) => {
    const owner = owners[index];
    if (owner !== undefined) ownerEscrowed(owner, reads[index], recipient.nullifierPublicKey);
  });
}

/** One opening per member in member order, each verified against `root`, Rust `RecordReads::read`. */
export async function readMemberOpenings(
  input: Readonly<{
    client: Pick<RingRecordReader, "getRingMemberOpenings">;
    ringProgramId: Address;
    root: Bytes32;
    members: readonly Bytes32[];
  }>,
  context?: RequestContext,
): Promise<readonly MemberOpeningRead[]> {
  const reads: MemberOpeningRead[] = [];
  for (let offset = 0; offset < input.members.length; offset += MAX_RING_MEMBER_BATCH) {
    const chunk = input.members.slice(offset, offset + MAX_RING_MEMBER_BATCH);
    const response = await input.client.getRingMemberOpenings(
      { ringProgramId: input.ringProgramId, members: chunk, expectedRoot: input.root },
      context,
    );
    if (response.openings.length !== chunk.length || !equalBytes(response.root.root, input.root))
      throw new RingError("RING_MEMBER_REGISTRY_INVALID", { details: { reason: "openings" } });
    chunk.forEach((member, index) => {
      const opening = response.openings[index];
      if (opening === undefined)
        throw new RingError("RING_MEMBER_REGISTRY_INVALID", { details: { reason: "openings" } });
      reads.push(MemberOpeningRead.verify(opening, input.root, member));
    });
  }
  return reads;
}

/** The indexer's opening checked against the chain's newest root, Rust `MemberMerge::read`. */
export function readRegisteredRecord(
  input: Readonly<{
    client: Pick<ChainReader, "getAccount"> & Pick<RingRecordReader, "getRingMemberRecord">;
    ringProgramId: Address;
    member: Bytes32;
    /** The nullifier key the record must escrow. */
    escrowed: Bytes32;
  }>,
  context?: RequestContext,
): Promise<RegisteredRecord> {
  return waitForProjection(
    async (attempt) => {
      const registry = await fetchRingMemberRegistry(input.client, input.ringProgramId, attempt);
      const { root } = registryCurrentRoot(registry);
      const read = await input.client.getRingMemberRecord(
        {
          ringProgramId: input.ringProgramId,
          member: input.member,
          expectedRoot: root,
          expectedNextIndex: registry.nextIndex,
        },
        attempt,
      );
      const escrowed = ownerEscrowed(
        input.member,
        MemberOpeningRead.verify(read.opening, root, input.member),
        input.escrowed,
      );
      return Object.freeze({
        root,
        index: registry.historyCursor,
        record: Object.freeze({
          kind: "present" as const,
          record: escrowed.record,
          path: escrowed.path,
        }),
        ctHash: escrowed.ctHash,
      });
    },
    MEMBER_REGISTRY_PROJECTION_ERRORS,
    context,
  );
}

/** @internal The registry's newest root, its history slot and every member's read under it. */
export async function readNewest(
  input: Readonly<{
    client: RingRecordReadClient;
    ringProgramId: Address;
    members: readonly Bytes32[];
  }>,
  context: RequestContext | undefined,
): Promise<Readonly<{ root: Bytes32; reads: readonly MemberOpeningRead[] }>> {
  const registry = await fetchRingMemberRegistry(input.client, input.ringProgramId, context);
  const { root } = registryCurrentRoot(registry);
  const reads = await readMemberOpenings({ ...input, root }, context);
  return { root, reads };
}
