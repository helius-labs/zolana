import type { AccountMeta, Address, Instruction } from "@solana/kit";

import { ClientError } from "../client/error.js";
import type { ChainReader, Prover, RingRecordReader, SlotReader } from "../client/ports.js";
import type { ApplyRecordsProofRequest } from "../client/prover/ring.js";
import { waitForProjection } from "../client/retry.js";
import {
  SYSTEM_PROGRAM,
  meta,
  signerAddress,
  type SignerAccount,
} from "../interface/instructions/index.js";
import { Writer } from "../interface/internal.js";
import {
  APPLY_BATCH,
  type ApplyProofInputs,
  type QueueEntry,
} from "../interface/member-registry.js";
import {
  ringConfigAddress,
  ringMemberRegistryAddress,
  ringRecordQueueAddress,
} from "../interface/pda/index.js";
import type { Bytes32, RequestContext } from "../interface/types.js";
import { ZERO_32, equal } from "../transaction/internal.js";

import { RingInstructionTag } from "./admin.js";
import {
  checkedCustomRingProof,
  queueApplyDue,
  queueChainTail,
  queuePending,
  registryCurrentRoot,
  type RingMemberRegistry,
  type RingProgramConfig,
  type RingRecordQueue,
} from "./codecs.js";
import { fetchRingMemberRegistry, fetchRingProgramConfig, fetchRingRecordQueue } from "./config.js";
import { RingError, wrapRingError } from "./error.js";
import {
  applyRecordsStatement,
  checkMember,
  queueChain,
  replayRecordWrites,
} from "./member-registry.js";
import { LIST_IDS, ListId, listWriter, recordBit, type Member } from "./policy.js";
import { MEMBER_REGISTRY_PROJECTION_ERRORS } from "./projection.js";
import { applyRecordsStatementHash } from "./statement.js";

/** Rust `ListWrite`, the lists one write sets and clears. */
export interface ListWrite {
  readonly set: readonly ListId[];
  readonly clear: readonly ListId[];
}

/** Rust `ListSet::MEMBER_WRITES`, a member writes the escrow list only through `RegisterKey`. */
export const MEMBER_WRITABLE_LISTS: readonly ListId[] = Object.freeze(
  LIST_IDS.filter((id) => listWriter(id) === "member" && id !== ListId.escrow),
);
/** Rust `ListSet::AUTHORITY_WRITES`. */
export const AUTHORITY_WRITABLE_LISTS: readonly ListId[] = Object.freeze(
  LIST_IDS.filter((id) => listWriter(id) === "authority"),
);

/** Rust `ListWrite::new`, a write changes at least one list and never sets and clears one. */
export function listWrite(
  input: Readonly<{ set?: readonly ListId[]; clear?: readonly ListId[] }>,
): ListWrite {
  const set = Object.freeze([...new Set(input.set ?? [])]);
  const clear = Object.freeze([...new Set(input.clear ?? [])]);
  if (set.length + clear.length === 0) throw listWriteInvalid("Empty");
  if (set.some((id) => clear.includes(id))) throw listWriteInvalid("SetAndCleared");
  return Object.freeze({ set, clear });
}

/** The queue and root an application's statement binds, a later write or application moves them. */
export interface RecordQueueBinding {
  readonly ringProgramId: Address;
  readonly tail: bigint;
  readonly chainTail: Bytes32;
  readonly root: Bytes32;
}

/** A record write's instruction and the chain state its proof binds. */
export interface ProvenRecordWrite {
  readonly instruction: Instruction;
  readonly bound: RecordQueueBinding;
}

export type RingRecordWriteClient = Pick<ChainReader, "getAccount"> &
  Pick<RingRecordReader, "getRingApplyProofInputs"> &
  Pick<Prover, "proveRing">;

export type RingRecordApplicationClient = RingRecordWriteClient & SlotReader;

/** Rust `MemberListWrite::instruction`, the fee accounts follow only when `config` charges `member`. */
export async function memberListWriteInstruction(
  write: Readonly<{
    ringProgramId: Address;
    /** Pays the insert fee the config charges a member. */
    payer: SignerAccount;
    member: SignerAccount;
    lists: ListWrite;
  }>,
  config: RingProgramConfig,
): Promise<Instruction> {
  checkWriter(write.lists, "member");
  const member = signerAddress(write.member);
  const accounts = await recordAccounts(write.ringProgramId, write.member, false);
  const data = new Writer().u8(RingInstructionTag.writeRecords, "tag");
  writeLists(data, write.lists);
  return {
    programAddress: write.ringProgramId,
    accounts: [...accounts, ...feeAccounts(config, member, write.payer)],
    data: data.finish(),
  };
}

/** Rust `AuthorityListWrite`, the authority's writes applied in one proof beside every pending member write. */
export class AuthorityListWrite {
  readonly #ringProgramId: Address;
  readonly #authority: Address;
  #writes: readonly Readonly<{ member: Member; write: ListWrite }>[] = Object.freeze([]);

  constructor(input: Readonly<{ ringProgramId: Address; authority: Address }>) {
    this.#ringProgramId = input.ringProgramId;
    this.#authority = input.authority;
  }

  /** `member` is any record key, an owner identity or an asset. */
  withWrite(member: Member, write: ListWrite): AuthorityListWrite {
    checkWriter(write, "authority");
    checkMember(member);
    if (this.#writes.some((known) => equal(known.member, member)))
      throw listWriteInvalid("Duplicate");
    return this.#holding([...this.#writes, Object.freeze({ member, write })]);
  }

  writes(): readonly Readonly<{ member: Member; write: ListWrite }>[] {
    return this.#writes;
  }

  /** Rust `AuthorityListWrite::batches`, the first fills the batch beside `pending` member writes. */
  batches(pending: bigint): readonly AuthorityListWrite[] {
    let size = APPLY_BATCH - Math.min(Number(pending), APPLY_BATCH);
    const batches: AuthorityListWrite[] = [];
    for (let start = 0; start < this.#writes.length; size = APPLY_BATCH) {
      const batch = this.#writes.slice(start, start + size);
      if (batch.length > 0) batches.push(this.#holding(batch));
      start += size;
    }
    return Object.freeze(batches);
  }

  /** One batch against the registry and queue as the chain holds them. */
  async prove(client: RingRecordWriteClient, context?: RequestContext): Promise<ProvenRecordWrite> {
    try {
      if (this.#writes.length === 0) throw listWriteInvalid("Empty");
      const config = await fetchRingProgramConfig(client, this.#ringProgramId, context);
      if (config.authority !== this.#authority)
        throw new RingError("RING_UNAUTHORIZED_AUTHORITY", {
          details: { authority: this.#authority },
        });
      const entries = this.#writes.map(({ member, write }) => queueEntry(member, write));
      const application = await waitForProjection(
        async (attemptContext) => {
          const { registry, queue } = await chainState(client, this.#ringProgramId, attemptContext);
          const pending = queuePending(queue);
          if (pending + BigInt(entries.length) > BigInt(APPLY_BATCH))
            throw new RingError("RING_AUTHORITY_BATCH_SPLIT", {
              details: {
                writes: entries.length,
                pending,
                batches: this.batches(pending).length,
              },
            });
          return readApplication(
            { client, ringProgramId: this.#ringProgramId, registry, queue, authority: entries },
            attemptContext,
          );
        },
        MEMBER_REGISTRY_PROJECTION_ERRORS,
        context,
      );
      const data = new Writer()
        .u8(RingInstructionTag.authorityWriteRecords, "tag")
        .u8(entries.length, "writes.length");
      for (const { member, write } of this.#writes)
        writeLists(data.bytes(member, 32, "member"), write);
      data.bytes(await proveApplication(client, application.inputs, context));
      return Object.freeze({
        instruction: {
          programAddress: this.#ringProgramId,
          accounts: await recordAccounts(this.#ringProgramId, this.#authority, true),
          data: data.finish(),
        },
        bound: application.bound,
      });
    } catch (cause) {
      throw wrapRingError("RING_BUILD_LIST_WRITE", cause);
    }
  }

  /** `writes` passed `withWrite`. */
  #holding(writes: readonly Readonly<{ member: Member; write: ListWrite }>[]): AuthorityListWrite {
    const next = new AuthorityListWrite({
      ringProgramId: this.#ringProgramId,
      authority: this.#authority,
    });
    next.#writes = Object.freeze(writes);
    return next;
  }
}

/** Rust `RecordApplication`, anyone applies a queue that is full or aged. */
export class RecordApplication {
  readonly #ringProgramId: Address;

  constructor(ringProgramId: Address) {
    this.#ringProgramId = ringProgramId;
  }

  /** `undefined` while the queue is empty, neither full nor aged, or inside the delay after the last application. */
  async prove(
    client: RingRecordApplicationClient,
    context?: RequestContext,
  ): Promise<ProvenRecordWrite | undefined> {
    try {
      const application = await waitForProjection(
        async (attemptContext) => {
          const { registry, queue } = await chainState(client, this.#ringProgramId, attemptContext);
          if (!queueApplyDue(queue, await client.getSlot(attemptContext))) return undefined;
          return readApplication(
            { client, ringProgramId: this.#ringProgramId, registry, queue, authority: [] },
            attemptContext,
          );
        },
        MEMBER_REGISTRY_PROJECTION_ERRORS,
        context,
      );
      if (application === undefined) return undefined;
      const [registry, queue, apply] = await Promise.all([
        ringMemberRegistryAddress(this.#ringProgramId),
        ringRecordQueueAddress(this.#ringProgramId),
        proveApplication(client, application.inputs, context),
      ]);
      return Object.freeze({
        instruction: {
          programAddress: this.#ringProgramId,
          accounts: [meta(registry, false, true), meta(queue, false, true)],
          data: Uint8Array.of(RingInstructionTag.applyRecords, ...apply),
        },
        bound: application.bound,
      });
    } catch (cause) {
      throw wrapRingError("RING_BUILD_LIST_WRITE", cause);
    }
  }
}

/** `[payer, authority, system]` when `config` charges `writer` the insert fee. */
export function feeAccounts(
  config: RingProgramConfig,
  writer: Address,
  payer: SignerAccount,
): readonly AccountMeta[] {
  if (config.insertFee === 0n || writer === config.authority) return [];
  return [
    meta(payer, true, true),
    meta(config.authority, false, true),
    meta(SYSTEM_PROGRAM, false, false),
  ];
}

interface Application {
  readonly inputs: ApplyProofInputs;
  readonly bound: RecordQueueBinding;
}

async function chainState(
  client: Pick<ChainReader, "getAccount">,
  ringProgramId: Address,
  context: RequestContext,
): Promise<Readonly<{ registry: RingMemberRegistry; queue: RingRecordQueue }>> {
  const [registry, queue] = await Promise.all([
    fetchRingMemberRegistry(client, ringProgramId, context),
    fetchRingRecordQueue(client, ringProgramId, context),
  ]);
  return { registry, queue };
}

/**
 * Rust `Application::new`, the indexer's inputs start where the chain's registry and queue stand
 * and end with the authority's own entries, else the projection lags.
 */
async function readApplication(
  input: Readonly<{
    client: Pick<RingRecordReader, "getRingApplyProofInputs">;
    ringProgramId: Address;
    registry: RingMemberRegistry;
    queue: RingRecordQueue;
    authority: readonly QueueEntry[];
  }>,
  context: RequestContext,
): Promise<Application> {
  const { registry, queue, authority } = input;
  const response = await input.client.getRingApplyProofInputs(
    {
      ringProgramId: input.ringProgramId,
      authorityWrites: authority.map(({ member, mask, value }) => ({ member, mask, value })),
    },
    context,
  );
  const served = response.inputs;
  // The witness must fold to what it claims, a lagging projection is only a stale start.
  const inputs = replayRecordWrites(served);
  if (
    !equal(inputs.newRoot, served.newRoot) ||
    inputs.newNextIndex !== served.newNextIndex ||
    !equal(inputs.chainEnd, served.chainEnd)
  )
    throw new RingError("RING_MEMBER_REGISTRY_INVALID", { details: { reason: "ApplyInputs" } });
  const pending = Number(queuePending(queue));
  const chainEnd = authority.reduce(queueChain, queueChainTail(queue));
  const root = registryCurrentRoot(registry).root;
  const tail = inputs.writes.slice(pending);
  if (
    !equal(inputs.oldRoot, root) ||
    inputs.oldNextIndex !== registry.nextIndex ||
    !equal(inputs.chainStart, queue.chainHead) ||
    !equal(inputs.chainEnd, chainEnd) ||
    inputs.writes.length !== pending + authority.length ||
    !tail.every((write, index) => sameEntry(write.entry, authority[index]))
  )
    throw new ClientError("CLIENT_MEMBER_REGISTRY_OUT_OF_SYNC", {
      details: { method: "getRingApplyProofInputs" },
    });
  return Object.freeze({
    inputs,
    bound: Object.freeze({
      ringProgramId: input.ringProgramId,
      tail: queue.tail,
      chainTail: queueChainTail(queue),
      root,
    }),
  });
}

/** Rust `Application::prove`, `proof ‖ new_root ‖ u32le(new_next_index)`. */
async function proveApplication(
  client: Pick<Prover, "proveRing">,
  inputs: ApplyProofInputs,
  context: RequestContext | undefined,
): Promise<Uint8Array> {
  const request: ApplyRecordsProofRequest = {
    kind: "applyRecords",
    publicInputHash: applyRecordsStatementHash(applyRecordsStatement(inputs)),
    ...inputs,
  };
  const proof = checkedCustomRingProof(await client.proveRing(request, context));
  return new Writer()
    .bytes(proof)
    .bytes(inputs.newRoot, 32, "newRoot")
    .u32(inputs.newNextIndex, "newNextIndex")
    .finish();
}

/** `[signer, config, registry, queue]`, the authority's write also writes the registry. */
async function recordAccounts(
  ringProgramId: Address,
  signer: SignerAccount,
  authority: boolean,
): Promise<readonly AccountMeta[]> {
  const [config, registry, queue] = await Promise.all([
    ringConfigAddress(ringProgramId),
    ringMemberRegistryAddress(ringProgramId),
    ringRecordQueueAddress(ringProgramId),
  ]);
  return [
    meta(signer, true, false),
    meta(config, false, false),
    meta(registry, false, authority),
    meta(queue, false, true),
  ];
}

/** Rust `RecordWriteData::entry`, an authority write carries no escrow key. */
function queueEntry(member: Member, write: ListWrite): QueueEntry {
  return Object.freeze({
    member,
    mask: listMask(write),
    value: listBits(write.set),
    escrowKey: ZERO_32,
  });
}

/** Rust `WriteRecordsIxData`, `u64le(mask) ‖ u64le(value)`. */
function writeLists(writer: Writer, write: ListWrite): Writer {
  return writer.u64(listMask(write), "mask").u64(listBits(write.set), "value");
}

function listMask(write: ListWrite): bigint {
  return listBits([...write.set, ...write.clear]);
}

function listBits(ids: readonly ListId[]): bigint {
  return ids.reduce((bits, id) => bits | recordBit(id), 0n);
}

/** Rust `check_writer`, every masked list is the writer's. */
function checkWriter(write: ListWrite, writer: "member" | "authority"): void {
  const writable = writer === "member" ? MEMBER_WRITABLE_LISTS : AUTHORITY_WRITABLE_LISTS;
  const refused = [...write.set, ...write.clear].find((id) => !writable.includes(id));
  if (refused !== undefined)
    throw new RingError("RING_LIST_WRITER_UNAUTHORIZED", { details: { listId: refused, writer } });
}

function sameEntry(entry: QueueEntry, expected: QueueEntry | undefined): boolean {
  return (
    expected !== undefined &&
    equal(entry.member, expected.member) &&
    entry.mask === expected.mask &&
    entry.value === expected.value &&
    equal(entry.escrowKey, expected.escrowKey)
  );
}

function listWriteInvalid(reason: "Empty" | "SetAndCleared" | "Duplicate"): RingError {
  return new RingError("RING_LIST_WRITE_INVALID", { details: { reason } });
}
