import { address, type Address } from "@solana/kit";
import { beforeAll, describe, expect, it, vi } from "vitest";

import records from "../../../test-vectors/ring-records.json" with { type: "json" };
import type { RingApplyProofInputs, RingRecordReader } from "../src/client/ports.js";
import type { RingProofRequest } from "../src/client/prover/ring.js";
import type { RpcAccount } from "../src/client/rpc.js";
import { initializePoseidon } from "../src/hasher/index.js";
import { SYSTEM_PROGRAM } from "../src/interface/instructions/index.js";
import type {
  ApplyProofInputs,
  MemberRecord,
  QuadPath,
  RecordWriteProofInput,
} from "../src/interface/member-registry.js";
import {
  ringConfigPda,
  ringMemberRegistryPda,
  ringRecordQueuePda,
} from "../src/interface/pda/index.js";
import type { Bytes32 } from "../src/interface/types.js";
import { X25519Keypair } from "../src/keypair/x25519.js";
import { decodeRingProgramConfig } from "../src/ring/codecs.js";
import { LIST_IDS, ListId, memberOfIdentity, recordBit } from "../src/ring/policy.js";
import { MEMBER_REGISTRY_CAPACITY } from "../src/interface/member-registry.js";
import { queueChain } from "../src/ring/member-registry.js";
import {
  AuthorityListWrite,
  RecordApplication,
  listWrite,
  memberListWriteInstruction,
  type ListWrite,
} from "../src/ring/records.js";
import { recordTree } from "./helpers/member-registry.js";
import {
  memberRegistryData,
  ownedAccount,
  recordQueueData,
  ringProgramConfigData,
} from "./helpers/ring-accounts.js";
import { itemAt } from "./helpers/ring-pipeline.js";

type Application = (typeof records.applications)[number];
type VectorPath = Application["writes"][number]["slot"];
type VectorRecord = Application["writes"][number]["low"];

const RING = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
const AUTHORITY = address("4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7D4xWLs4gDB4T");
const MEMBER = address("CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8");
const PAYER = address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");
const PROOF = Uint8Array.from({ length: 192 }, (_, index) => index);
const QUEUED_SLOT = 1_000n;

beforeAll(initializePoseidon);

function field(value: string): Bytes32 {
  return Uint8Array.from(Buffer.from(value, "hex")) as Bytes32;
}

function hex(value: Uint8Array): string {
  return Buffer.from(value).toString("hex");
}

function u64le(value: bigint): number[] {
  return Array.from({ length: 8 }, (_, index) => Number((value >> BigInt(8 * index)) & 0xffn));
}

function u32le(value: number): number[] {
  return u64le(BigInt(value)).slice(0, 4);
}

/** The lists a vector mask and value set and clear. */
function vectorWrite(mask: number, value: number): ListWrite {
  return listWrite({
    set: LIST_IDS.filter((id) => (BigInt(value) & recordBit(id)) !== 0n),
    clear: LIST_IDS.filter(
      (id) => (BigInt(mask) & recordBit(id)) !== 0n && (BigInt(value) & recordBit(id)) === 0n,
    ),
  });
}

function path(vector: VectorPath): QuadPath {
  return { index: vector.index, siblings: vector.siblings.map((level) => level.map(field)) };
}

function record(vector: VectorRecord): MemberRecord {
  return {
    member: field(vector.member),
    next: field(vector.next),
    lists: BigInt(vector.lists),
    escrowKey: field(vector.escrow_key),
  };
}

function inputs(application: Application): ApplyProofInputs {
  const writes: RecordWriteProofInput[] = application.writes.map((write) => ({
    entry: {
      member: field(write.member),
      mask: BigInt(write.mask),
      value: BigInt(write.value),
      escrowKey: field(write.escrow_key),
    },
    exists: write.exists,
    oldNext: field(write.old_next),
    oldLists: BigInt(write.old_lists),
    oldEscrow: field(write.old_escrow),
    slot: path(write.slot),
    low: record(write.low),
    lowPath: path(write.low_path),
  }));
  return {
    oldRoot: field(application.old_root),
    newRoot: field(application.new_root),
    oldNextIndex: application.old_next_index,
    newNextIndex: application.new_next_index,
    chainStart: field(application.chain_start),
    chainEnd: field(application.chain_end),
    writes,
  };
}

function application(index: number): Application {
  const found = records.applications[index];
  if (found === undefined) throw new Error("vector has no application");
  return found;
}

/** The chain holding the registry and queue an application starts from. */
async function chain(
  vector: Application,
  options: Readonly<{ nextIndex?: number; nextApplySlot?: bigint; insertFee?: bigint }> = {},
): Promise<Map<Address, RpcAccount>> {
  const [[config, configBump], [registry, registryBump], [queue, queueBump]] = await Promise.all([
    ringConfigPda(RING),
    ringMemberRegistryPda(RING),
    ringRecordQueuePda(RING),
  ]);
  const head = BigInt(vector.pending[0]?.position ?? vector.authority_writes[0]?.position ?? 0);
  return new Map([
    [config, ownedAccount(RING, configBytes(configBump, options.insertFee ?? 0n))],
    [
      registry,
      ownedAccount(
        RING,
        memberRegistryData({
          bump: registryBump,
          history: [{ root: field(vector.old_root), applied: head, slot: 1n }],
          nextIndex: options.nextIndex ?? vector.old_next_index,
          floor: head,
        }),
      ),
    ],
    [
      queue,
      ownedAccount(
        RING,
        recordQueueData({
          bump: queueBump,
          head,
          tail: head + BigInt(vector.pending.length),
          chainHead: field(vector.chain_start),
          checkpoints: vector.pending.map((write) => ({
            position: BigInt(write.position),
            chain: field(write.chain),
            slot: QUEUED_SLOT,
          })),
          ...(options.nextApplySlot === undefined ? {} : { nextApplySlot: options.nextApplySlot }),
        }),
      ),
    ],
  ]);
}

const AUDITOR = X25519Keypair.generate().publicKey().toBytes();

function configBytes(bump: number, insertFee: bigint): Uint8Array {
  return ringProgramConfigData({
    authority: AUTHORITY,
    auditorPublicKey: AUDITOR,
    bump,
    hasPolicy: true,
    insertFee,
  });
}

function client(accounts: Map<Address, RpcAccount>, served: ApplyProofInputs, slot = 0n) {
  const getRingApplyProofInputs = vi.fn<RingRecordReader["getRingApplyProofInputs"]>(
    async (): Promise<RingApplyProofInputs> => ({
      context: { slot: 1n, blockTime: 1n },
      inputs: served,
    }),
  );
  const proveRing = vi.fn(async (_request: RingProofRequest) => PROOF);
  return {
    getAccount: async (account: Address) => accounts.get(account),
    getRingApplyProofInputs,
    proveRing,
    getSlot: async () => slot,
  };
}

function authorityWrite(vector: Application, writes = vector.authority_writes): AuthorityListWrite {
  return writes.reduce(
    (built, write) =>
      built.withWrite(memberOfIdentity(field(write.member)), vectorWrite(write.mask, write.value)),
    new AuthorityListWrite({ ringProgramId: RING, authority: AUTHORITY }),
  );
}

describe("member list writes", () => {
  it("queues the member's own lists and pays the insert fee to the authority", async () => {
    const [config, bump] = await ringConfigPda(RING);
    const [registry] = await ringMemberRegistryPda(RING);
    const [queue] = await ringRecordQueuePda(RING);
    const lists = listWrite({ set: [ListId.ringViewing], clear: [ListId.recovery] });
    const charged = decodeRingProgramConfig(configBytes(bump, 1_000_000n));
    const instruction = await memberListWriteInstruction(
      { ringProgramId: RING, payer: PAYER, member: MEMBER, lists },
      charged,
    );
    expect(instruction.data).toEqual(
      Uint8Array.of(
        39,
        ...u64le(recordBit(ListId.ringViewing) | recordBit(ListId.recovery)),
        ...u64le(recordBit(ListId.ringViewing)),
      ),
    );
    expect(instruction.accounts?.map(({ address, role }) => [address, role])).toEqual([
      [MEMBER, 2],
      [config, 0],
      [registry, 0],
      [queue, 1],
      [PAYER, 3],
      [AUTHORITY, 1],
      [SYSTEM_PROGRAM, 0],
    ]);
  });

  it("takes no fee accounts from the authority or under a zero fee", async () => {
    const [, bump] = await ringConfigPda(RING);
    const lists = listWrite({ set: [ListId.recovery] });
    const charged = decodeRingProgramConfig(configBytes(bump, 1_000_000n));
    const free = decodeRingProgramConfig(configBytes(bump, 0n));
    const own = await memberListWriteInstruction(
      { ringProgramId: RING, payer: PAYER, member: AUTHORITY, lists },
      charged,
    );
    const unpaid = await memberListWriteInstruction(
      { ringProgramId: RING, payer: PAYER, member: MEMBER, lists },
      free,
    );
    expect(own.accounts).toHaveLength(4);
    expect(unpaid.accounts).toHaveLength(4);
  });

  it("refuses a list the member does not write and a write that changes nothing or both ways", async () => {
    const [, bump] = await ringConfigPda(RING);
    const config = decodeRingProgramConfig(configBytes(bump, 0n));
    for (const listId of [ListId.allow, ListId.escrow])
      await expect(
        memberListWriteInstruction(
          {
            ringProgramId: RING,
            payer: PAYER,
            member: MEMBER,
            lists: listWrite({ set: [listId] }),
          },
          config,
        ),
      ).rejects.toMatchObject({ code: "RING_LIST_WRITER_UNAUTHORIZED", details: { listId } });
    expect(() => listWrite({})).toThrow(
      expect.objectContaining({ code: "RING_LIST_WRITE_INVALID", details: { reason: "Empty" } }),
    );
    expect(() => listWrite({ set: [ListId.allow], clear: [ListId.allow] })).toThrow(
      expect.objectContaining({ details: { reason: "SetAndCleared" } }),
    );
  });
});

describe("authority list writes", () => {
  it("proves the vector's authority inserts into an empty queue", async () => {
    const vector = application(0);
    const served = inputs(vector);
    const reader = client(await chain(vector), served);
    const proven = await authorityWrite(vector).prove(reader);
    const [config] = await ringConfigPda(RING);
    const [registry] = await ringMemberRegistryPda(RING);
    const [queue] = await ringRecordQueuePda(RING);
    expect(proven.instruction.data).toEqual(
      Uint8Array.of(
        40,
        vector.authority_writes.length,
        ...vector.authority_writes.flatMap((write) => [
          ...field(write.member),
          ...u64le(BigInt(write.mask)),
          ...u64le(BigInt(write.value)),
        ]),
        ...PROOF,
        ...field(vector.new_root),
        ...u32le(vector.new_next_index),
      ),
    );
    expect(proven.instruction.accounts?.map(({ address, role }) => [address, role])).toEqual([
      [AUTHORITY, 2],
      [config, 0],
      [registry, 1],
      [queue, 1],
    ]);
    expect(reader.getRingApplyProofInputs.mock.calls[0]?.[0].authorityWrites).toEqual(
      vector.authority_writes.map((write) => ({
        member: field(write.member),
        mask: BigInt(write.mask),
        value: BigInt(write.value),
      })),
    );
    const request = reader.proveRing.mock.calls[0]?.[0];
    expect(request?.kind).toBe("applyRecords");
    expect(hex(request?.publicInputHash ?? new Uint8Array())).toBe(vector.statement_hash);
    expect(proven.bound).toEqual({
      ringProgramId: RING,
      tail: 0n,
      chainTail: field(vector.chain_start),
      root: field(vector.old_root),
    });
  });

  it("proves eight authority writes beside eight pending member writes", async () => {
    const vector = application(2);
    const reader = client(await chain(vector), inputs(vector));
    await authorityWrite(vector).prove(reader);
    const request = reader.proveRing.mock.calls[0]?.[0];
    expect(hex(request?.publicInputHash ?? new Uint8Array())).toBe(vector.statement_hash);
  });

  it("splits writes the batch beside the pending ones cannot hold", async () => {
    const vector = application(2);
    const write = authorityWrite(vector);
    const extra = write.withWrite(
      memberOfIdentity(field("01".repeat(32))),
      listWrite({ set: [ListId.block] }),
    );
    const reader = client(await chain(vector), inputs(vector));
    await expect(extra.prove(reader)).rejects.toMatchObject({
      code: "RING_BUILD_LIST_WRITE",
      causeCode: "RING_AUTHORITY_BATCH_SPLIT",
    });
    expect(reader.proveRing).not.toHaveBeenCalled();
    expect(extra.batches(8n).map((batch) => batch.writes().length)).toEqual([8, 1]);
    expect(extra.batches(16n).map((batch) => batch.writes().length)).toEqual([9]);
    expect(extra.batches(0n).map((batch) => batch.writes().length)).toEqual([9]);
  });

  it("refuses a member list, a repeated member and another authority", async () => {
    const vector = application(0);
    const member = memberOfIdentity(field(vector.authority_writes[0]?.member ?? ""));
    const write = new AuthorityListWrite({ ringProgramId: RING, authority: AUTHORITY });
    expect(() => write.withWrite(member, listWrite({ set: [ListId.recovery] }))).toThrow(
      expect.objectContaining({ code: "RING_LIST_WRITER_UNAUTHORIZED" }),
    );
    const once = write.withWrite(member, listWrite({ set: [ListId.allow] }));
    expect(() => once.withWrite(member, listWrite({ set: [ListId.block] }))).toThrow(
      expect.objectContaining({
        code: "RING_LIST_WRITE_INVALID",
        details: { reason: "Duplicate" },
      }),
    );
    const reader = client(await chain(vector), inputs(vector));
    await expect(
      new AuthorityListWrite({ ringProgramId: RING, authority: MEMBER })
        .withWrite(member, listWrite({ set: [ListId.allow] }))
        .prove(reader),
    ).rejects.toMatchObject({ causeCode: "RING_UNAUTHORIZED_AUTHORITY" });
    expect(reader.getRingApplyProofInputs).not.toHaveBeenCalled();
  });

  it("reads again when the projection lags the chain and proves only the matching inputs", async () => {
    const vector = application(0);
    const fresh = await chain(vector);
    const accounts = new Map(await chain(vector, { nextIndex: 2 }));
    const reader = client(accounts, inputs(vector));
    reader.getRingApplyProofInputs.mockImplementationOnce(async () => {
      for (const [account, data] of fresh) accounts.set(account, data);
      return { context: { slot: 1n, blockTime: 1n }, inputs: inputs(vector) };
    });
    const proven = await authorityWrite(vector).prove(reader);
    expect(reader.getRingApplyProofInputs).toHaveBeenCalledTimes(2);
    expect(reader.proveRing).toHaveBeenCalledOnce();
    expect(proven.bound.root).toEqual(field(vector.old_root));
  });

  it("refuses inputs whose writes fold to another root", async () => {
    const vector = application(0);
    const served = { ...inputs(vector), newRoot: field(vector.old_root) };
    const reader = client(await chain(vector), served);
    await expect(authorityWrite(vector).prove(reader)).rejects.toMatchObject({
      causeCode: "RING_MEMBER_REGISTRY_INVALID",
    });
    expect(reader.getRingApplyProofInputs).toHaveBeenCalledOnce();
    expect(reader.proveRing).not.toHaveBeenCalled();
  });
});

describe("full registry", () => {
  /** A registry at capacity holding `member`, the authority's write applied against it. */
  async function fullRegistry(member: Bytes32) {
    const tree = recordTree([{ member, lists: recordBit(ListId.allow) }]);
    const [[config, configBump], [registry, registryBump], [queue, queueBump]] = await Promise.all([
      ringConfigPda(RING),
      ringMemberRegistryPda(RING),
      ringRecordQueuePda(RING),
    ]);
    const accounts = new Map<Address, RpcAccount>([
      [config, ownedAccount(RING, configBytes(configBump, 0n))],
      [
        registry,
        ownedAccount(
          RING,
          memberRegistryData({
            bump: registryBump,
            history: [{ root: tree.root, applied: 0n, slot: 1n }],
            nextIndex: FULL,
          }),
        ),
      ],
      [
        queue,
        ownedAccount(
          RING,
          recordQueueData({ bump: queueBump, head: 0n, tail: 0n, chainHead: ZERO }),
        ),
      ],
    ]);
    return { tree, accounts };
  }

  const FULL = Number(MEMBER_REGISTRY_CAPACITY);
  const ZERO = new Uint8Array(32) as Bytes32;
  const BLOCK = recordBit(ListId.block);

  it("applies an authority write to a present member and refuses an insert before any proof", async () => {
    const present = memberOfIdentity(field("02".repeat(32)));
    const { tree, accounts } = await fullRegistry(present);
    const entry = { member: present, mask: BLOCK, value: BLOCK, escrowKey: ZERO };
    const record = itemAt(tree.rows, 1);
    const update = client(accounts, {
      oldRoot: tree.root,
      newRoot: recordTree([{ member: present, lists: record.lists | BLOCK }]).root,
      oldNextIndex: FULL,
      newNextIndex: FULL,
      chainStart: ZERO,
      chainEnd: queueChain(ZERO, entry),
      writes: [
        {
          entry,
          exists: true,
          oldNext: record.next,
          oldLists: record.lists,
          oldEscrow: ZERO,
          slot: tree.path(1),
          low: { member: ZERO, next: ZERO, lists: 0n, escrowKey: ZERO },
          lowPath: tree.path(0),
        },
      ],
    });
    const write = new AuthorityListWrite({ ringProgramId: RING, authority: AUTHORITY });
    await write.withWrite(present, listWrite({ set: [ListId.block] })).prove(update);
    expect(update.proveRing).toHaveBeenCalledOnce();

    const absent = memberOfIdentity(field("01".repeat(32)));
    const inserted = { member: absent, mask: BLOCK, value: BLOCK, escrowKey: ZERO };
    const insert = client(accounts, {
      oldRoot: tree.root,
      newRoot: tree.root,
      oldNextIndex: FULL,
      newNextIndex: FULL + 1,
      chainStart: ZERO,
      chainEnd: queueChain(ZERO, inserted),
      writes: [
        {
          entry: inserted,
          exists: false,
          oldNext: itemAt(tree.rows, 0).next,
          oldLists: 0n,
          oldEscrow: ZERO,
          slot: tree.path(FULL),
          low: itemAt(tree.rows, 0),
          lowPath: tree.path(0),
        },
      ],
    });
    await expect(
      write.withWrite(absent, listWrite({ set: [ListId.block] })).prove(insert),
    ).rejects.toMatchObject({ code: "RING_BUILD_LIST_WRITE", causeCode: "RING_REGISTRY_FULL" });
    expect(insert.proveRing).not.toHaveBeenCalled();
  });

  it("proves a clear of an absent member over the low path Rust serves as its slot", async () => {
    const { tree, accounts } = await fullRegistry(memberOfIdentity(field("02".repeat(32))));
    const absent = memberOfIdentity(field("01".repeat(32)));
    const entry = { member: absent, mask: BLOCK, value: 0n, escrowKey: ZERO };
    const noop = client(accounts, {
      oldRoot: tree.root,
      newRoot: tree.root,
      oldNextIndex: FULL,
      newNextIndex: FULL,
      chainStart: ZERO,
      chainEnd: queueChain(ZERO, entry),
      writes: [
        {
          entry,
          exists: false,
          oldNext: itemAt(tree.rows, 0).next,
          oldLists: 0n,
          oldEscrow: ZERO,
          slot: tree.path(0),
          low: itemAt(tree.rows, 0),
          lowPath: tree.path(0),
        },
      ],
    });
    await new AuthorityListWrite({ ringProgramId: RING, authority: AUTHORITY })
      .withWrite(absent, listWrite({ clear: [ListId.block] }))
      .prove(noop);
    expect(noop.proveRing).toHaveBeenCalledOnce();
  });
});

describe("permissionless application", () => {
  it("applies an aged queue and reads nothing before it is due", async () => {
    const vector = application(1);
    const accounts = await chain(vector);
    const early = client(accounts, inputs(vector), QUEUED_SLOT + 149n);
    await expect(new RecordApplication(RING).prove(early)).resolves.toBeUndefined();
    expect(early.getRingApplyProofInputs).not.toHaveBeenCalled();
    const due = client(accounts, inputs(vector), QUEUED_SLOT + 150n);
    const proven = await new RecordApplication(RING).prove(due);
    const [registry] = await ringMemberRegistryPda(RING);
    const [queue] = await ringRecordQueuePda(RING);
    expect(proven?.instruction.data).toEqual(
      Uint8Array.of(41, ...PROOF, ...field(vector.new_root), ...u32le(vector.new_next_index)),
    );
    expect(proven?.instruction.accounts?.map(({ address, role }) => [address, role])).toEqual([
      [registry, 1],
      [queue, 1],
    ]);
    const request = due.proveRing.mock.calls[0]?.[0];
    expect(hex(request?.publicInputHash ?? new Uint8Array())).toBe(vector.statement_hash);
  });

  it("waits out the delay after the previous application", async () => {
    const vector = application(1);
    const accounts = await chain(vector, { nextApplySlot: QUEUED_SLOT + 200n });
    const reader = client(accounts, inputs(vector), QUEUED_SLOT + 150n);
    await expect(new RecordApplication(RING).prove(reader)).resolves.toBeUndefined();
    expect(reader.getRingApplyProofInputs).not.toHaveBeenCalled();
  });
});
