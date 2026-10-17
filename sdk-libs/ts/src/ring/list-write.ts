import type {
  BlockhashProvider,
  ChainReader,
  RingMemberRegistryReader,
  Prover,
} from "../client/ports.js";
import { compileUnsignedTransaction } from "../flows/compile.js";
import { addressBytes } from "../interface/internal.js";
import type { Address, RequestContext, Transaction, Bytes32 } from "../interface/types.js";
import type {
  MemberRecord,
  MemberOpening,
  MemberUpdate,
  RecordUpdateWitness,
} from "../interface/member-registry.js";
import { ZERO_32, bytesToBigInt } from "../transaction/internal.js";
import { bytesKey, equalBytes } from "../wallet/internal.js";
import { waitForProjection } from "../client/retry.js";
import {
  fetchRingProgramConfig,
  fetchRingMemberRegistryRoot,
  fetchRingPolicyConfig,
} from "./config.js";
import { readRingMemberRecord, type MemberRecordRead } from "./member-record.js";
import {
  MemberRegistryOverlay,
  updateMemberRecord,
  updateMembersPublicInputHash,
  MAX_MEMBER_BATCH,
} from "./member-registry-tree.js";
import { RingError, wrapRingError } from "./error.js";
import {
  updateRingMembersInstruction,
  RING_ENTRY_MUTATION_COMPUTE_UNIT_LIMIT,
} from "./instructions.js";
import { listWriter, memberOfTag, listIdFromByte, type ListId, type Member } from "./policy.js";
import { MEMBER_REGISTRY_PROJECTION_ERRORS } from "./projection.js";

export type RingListWriteClient = BlockhashProvider &
  Pick<ChainReader, "getAccount"> &
  RingMemberRegistryReader &
  Pick<Prover, "proveCustomRingUpdateMembers">;
export interface RingMemberWrite {
  readonly member: Member;
  readonly set: readonly ListId[];
  readonly clear: readonly ListId[];
}
export interface RingMemberUpdateTransactionParams {
  readonly client: RingListWriteClient;
  readonly ringProgramId: Address;
  readonly payer: Address;
  readonly signers: readonly Address[];
  readonly writes: readonly RingMemberWrite[];
  readonly computeUnitLimit?: number;
  readonly priorityFeeLamports?: bigint;
}
export type RingMemberUpdate =
  | Readonly<{ kind: "unchanged"; records: readonly MemberRecordRead[] }>
  | Readonly<{ kind: "transaction"; transaction: Transaction; items: readonly MemberUpdate[] }>;
export interface RingListWriteTransactionParams {
  readonly client: RingListWriteClient;
  readonly ringProgramId: Address;
  readonly payer: Address;
  readonly listId: ListId;
  readonly member: Member;
  readonly state: "active" | "cleared";
  readonly computeUnitLimit?: number;
  readonly priorityFeeLamports?: bigint;
}
export type RingListWrite = RingMemberUpdate;
export async function buildRingListWriteTransaction(
  params: RingListWriteTransactionParams,
  context?: RequestContext,
): Promise<RingListWrite> {
  if (params.state !== "active" && params.state !== "cleared")
    throw new RingError("RING_ENTRY_INVALID");
  return buildRingMemberUpdateTransaction(
    {
      ...params,
      signers: [params.payer],
      writes: [
        {
          member: params.member,
          set: params.state === "active" ? [params.listId] : [],
          clear: params.state === "cleared" ? [params.listId] : [],
        },
      ],
    },
    context,
  );
}

export async function buildRingMemberUpdateTransaction(
  params: RingMemberUpdateTransactionParams,
  context?: RequestContext,
): Promise<RingMemberUpdate> {
  try {
    const config = await fetchRingProgramConfig(params.client, params.ringProgramId, context);
    if (!Array.isArray(params.writes) || params.writes.length === 0)
      throw new RingError("RING_MEMBER_REGISTRY_INVALID");
    const merged = new Map<string, { member: Member; set: bigint; clear: bigint }>();
    for (const write of params.writes) {
      const key = bytesKey(write.member);
      const held = merged.get(key) ?? { member: write.member, set: 0n, clear: 0n };
      for (const [ids, field] of [
        [write.set, "set"],
        [write.clear, "clear"],
      ] as const)
        for (const id of ids) {
          if (listIdFromByte(id) === undefined) throw new RingError("RING_POLICY_SOURCE_INVALID");
          const authorized =
            listWriter(id) === "authority"
              ? params.signers.includes(config.authority)
              : params.signers.some((signer) =>
                  equalBytes(memberOfTag(addressBytes(signer)), write.member),
                );
          if (!authorized)
            throw new RingError("RING_LIST_WRITER_UNAUTHORIZED", {
              details: { listId: id, writer: listWriter(id) },
            });
          held[field] |= 1n << BigInt(id - 1);
        }
      if ((held.set & held.clear) !== 0n)
        throw new RingError("RING_MEMBER_REGISTRY_INVALID", {
          details: { reason: "conflictingWrites" },
        });
      merged.set(key, held);
    }
    if (merged.size > MAX_MEMBER_BATCH)
      throw new RingError("RING_MEMBER_REGISTRY_INVALID", { details: { reason: "batchLength" } });
    if (config.hasPolicy) {
      const policy = await fetchRingPolicyConfig(params.client, params.ringProgramId, context);
      for (const write of merged.values())
        for (const source of policy.sources)
          if (
            source.listId !== 0 &&
            ((write.set | write.clear) & (1n << BigInt(source.listId - 1))) !== 0n &&
            !equalBytes(addressBytes(source.registry), ZERO_32)
          )
            throw new RingError("RING_LIST_SHARED", {
              details: { listId: source.listId, namespace: source.registry },
            });
    }
    return await waitForProjection(
      async (context) => {
        const registry = await fetchRingMemberRegistryRoot(
          params.client,
          params.ringProgramId,
          context,
        );
        const writes = [...merged.values()].sort((a, b) =>
          bytesToBigInt(a.member) < bytesToBigInt(b.member) ? -1 : 1,
        );
        const records = await Promise.all(
          writes.map((write) =>
            readRingMemberRecord(
              {
                client: params.client,
                ringProgramId: params.ringProgramId,
                member: write.member,
                registry,
              },
              context,
            ),
          ),
        );
        const pending = writes
          .map((write, index) => {
            const read = records[index]!;
            const oldLists = read.opening.present ? read.opening.record.lists : 0n;
            return { write, read, lists: (oldLists | write.set) & ~write.clear, oldLists };
          })
          .filter((item) => item.lists !== item.oldLists);
        if (pending.length === 0) return { kind: "unchanged", records } as const;
        const tip = await params.client.getRingMemberRegistryRoot(
          { ringProgramId: params.ringProgramId },
          context,
        );
        if (
          !equalBytes(tip.root, registry.root) ||
          tip.nextIndex !== registry.nextIndex ||
          tip.rootIndex !== registry.historyCursor
        )
          throw new RingError("RING_MEMBER_REGISTRY_STALE");
        const overlay = new MemberRegistryOverlay(
          registry.root,
          registry.nextIndex,
          tip.appendPath,
        );
        const known = new Map<
          string,
          { record: MemberRecord; index: bigint; basePath?: readonly Bytes32[] }
        >();
        for (const read of records) {
          const opening = read.opening,
            record = opening.present ? opening.record : opening.low;
          known.set(bytesKey(record.member), {
            record,
            index: opening.index,
            basePath: opening.path,
          });
        }
        const items: Array<MemberUpdate & Readonly<{ update: RecordUpdateWitness }>> = [];
        let root = registry.root,
          nextIndex = registry.nextIndex;
        for (const { write, lists } of pending) {
          const existing = known.get(bytesKey(write.member));
          let opening: MemberOpening;
          if (existing !== undefined)
            opening = {
              present: true,
              record: existing.record,
              index: existing.index,
              path: overlay.path(existing.index, existing.basePath),
            };
          else {
            const low = [...known.values()]
              .filter((value) => bytesToBigInt(value.record.member) < bytesToBigInt(write.member))
              .sort((a, b) =>
                bytesToBigInt(a.record.member) > bytesToBigInt(b.record.member) ? -1 : 1,
              )[0];
            if (low === undefined) throw new RingError("RING_MEMBER_REGISTRY_INVALID");
            opening = {
              present: false,
              low: low.record,
              index: low.index,
              path: overlay.path(low.index, low.basePath),
            };
          }
          const escrowKey = existing?.record.escrowKey ?? ZERO_32;
          const changed = updateMemberRecord({
            root,
            nextIndex,
            member: write.member,
            opening,
            lists,
            escrowKey,
            overlay,
          });
          items.push({ ...changed.item, update: changed.update });
          root = changed.root;
          if (!opening.present) {
            const low = known.get(bytesKey(opening.low.member))!;
            known.set(bytesKey(opening.low.member), {
              ...low,
              record: { ...low.record, next: write.member },
            });
            nextIndex++;
          }
          known.set(bytesKey(write.member), {
            record: { member: write.member, next: changed.update.next, lists, escrowKey },
            index: changed.item.index,
            ...(existing?.basePath === undefined ? {} : { basePath: existing.basePath }),
          });
        }
        const proof = await params.client.proveCustomRingUpdateMembers(
          {
            publicInputHash: updateMembersPublicInputHash(registry.root, root, items),
            oldRoot: registry.root,
            newRoot: root,
            items,
          },
          context,
        );
        const instruction = await updateRingMembersInstruction({
          ringProgramId: params.ringProgramId,
          proof,
          oldRootIndex: registry.historyCursor,
          newRoot: root,
          items,
          signers: params.signers,
        });
        const lifetime = await params.client.getLatestBlockhash(context);
        return {
          kind: "transaction",
          items,
          transaction: compileUnsignedTransaction({
            feePayer: params.payer,
            lifetime,
            instructions: [instruction],
            computeUnitLimit: params.computeUnitLimit ?? RING_ENTRY_MUTATION_COMPUTE_UNIT_LIMIT,
            ...(params.priorityFeeLamports === undefined
              ? {}
              : { priorityFeeLamports: params.priorityFeeLamports }),
          }),
        } as const;
      },
      MEMBER_REGISTRY_PROJECTION_ERRORS,
      context,
    );
  } catch (cause) {
    throw wrapRingError("RING_BUILD_LIST_WRITE", cause);
  }
}
