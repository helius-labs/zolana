import { getAddressDecoder } from "@solana/kit";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { initializePoseidon } from "../src/hasher/index.js";
import { ringConfigPda, ringMemberRegistryRootPda } from "../src/interface/pda/index.js";
import type { Bytes32 } from "../src/interface/types.js";
import type { CustomRingUpdateMembersProofRequest } from "../src/client/prover/types.js";
import { customRingUpdateMembersProofRequest } from "../src/client/prover/client.js";
import {
  buildRingListWriteTransaction,
  buildRingMemberUpdateTransaction,
  type RingListWriteClient,
  type RingMemberWrite,
} from "../src/ring/list-write.js";
import { updateRingMembersInstruction } from "../src/ring/instructions.js";
import { ListId, memberOfTag, type Member } from "../src/ring/policy.js";
import {
  MemberRegistryOverlay,
  memberRegistryRootFromProof,
  memberRegistryLeaf,
  updateMembersPublicInputHash,
} from "../src/ring/member-registry-tree.js";
import { ZERO_32, bigIntBytes } from "../src/transaction/internal.js";
import { registryFixture, memberRegistryRootData } from "./helpers/member-registry.js";
import { ownedAccount, ringProgramConfigData } from "./helpers/ring-accounts.js";
import { X25519Keypair } from "../src/keypair/x25519.js";
import { BLOCKHASH } from "./helpers/clients.js";
const filled = (byte: number) => new Uint8Array(32).fill(byte) as Bytes32;
const address = (byte: number) => getAddressDecoder().decode(filled(byte));
const RING = address(1),
  AUTHORITY = address(2),
  OTHER = address(3);
beforeAll(initializePoseidon);
async function fixture(records: Parameters<typeof registryFixture>[0] = []) {
  const registry = registryFixture(records),
    [config, bump] = await ringConfigPda(RING),
    [root, rootBump] = await ringMemberRegistryRootPda(RING);
  const prove = vi.fn(async (_request: CustomRingUpdateMembersProofRequest) => new Uint8Array(192));
  const read = vi.fn(async (request: Parameters<RingListWriteClient["getRingMemberRecord"]>[0]) =>
    registry.read(request.member),
  );
  const tip = vi.fn(async () => registry.tip);
  const client: RingListWriteClient = {
    getAccount: async (key) =>
      key === config
        ? ownedAccount(
            RING,
            ringProgramConfigData({
              authority: AUTHORITY,
              auditorPublicKey: X25519Keypair.fromBytes(filled(3)).publicKey().toBytes(),
              hasPolicy: false,
              bump,
            }),
          )
        : key === root
          ? ownedAccount(
              RING,
              memberRegistryRootData({
                root: registry.root,
                nextIndex: registry.tip.nextIndex,
                bump: rootBump,
              }),
            )
          : undefined,
    getLatestBlockhash: async () => BLOCKHASH,
    getRingMemberRecord: read,
    getRingMemberRegistryRoot: tip,
    proveCustomRingUpdateMembers: prove,
  };
  return {
    registry,
    client,
    prove,
    read,
    tip,
    write: (
      member: Member,
      listId: ListId,
      state: "active" | "cleared" = "active",
      payer = AUTHORITY,
    ) =>
      buildRingListWriteTransaction({ client, ringProgramId: RING, payer, member, listId, state }),
  };
}
describe("member list writes", () => {
  it("inserts a first member with a batch proof", async () => {
    const test = await fixture(),
      member = memberOfTag(filled(4));
    const result = await test.write(member, ListId.allow);
    expect(result.kind).toBe("transaction");
    expect(test.prove).toHaveBeenCalledTimes(1);
    const request = test.prove.mock.calls[0]![0];
    expect(request.newRoot).toEqual(registryFixture([{ member, lists: 1n }]).root);
    expect(request.items[0]).toMatchObject({
      oldLists: 0n,
      lists: 1n,
      index: 1n,
      update: { exists: false },
    });
  });
  it("returns unchanged without fetching an append path or proving", async () => {
    const member = memberOfTag(filled(4)),
      test = await fixture([{ member, lists: 1n }]);
    expect((await test.write(member, ListId.allow)).kind).toBe("unchanged");
    expect(test.prove).not.toHaveBeenCalled();
    expect(test.tip).not.toHaveBeenCalled();
  });
  it("rewrites a list bit in place and preserves other bits", async () => {
    const member = memberOfTag(filled(4)),
      test = await fixture([{ member, lists: 3n }]);
    await test.write(member, ListId.block, "cleared");
    const request = test.prove.mock.calls[0]![0];
    expect(request.newRoot).toEqual(registryFixture([{ member, lists: 1n }]).root);
    expect(request.items[0]).toMatchObject({
      oldLists: 3n,
      lists: 1n,
      index: 1n,
      update: { exists: true },
    });
  });
  it("refuses an unauthorized writer before reading or proving", async () => {
    const test = await fixture();
    await expect(
      test.write(memberOfTag(filled(4)), ListId.allow, "active", OTHER),
    ).rejects.toMatchObject({
      code: "RING_BUILD_LIST_WRITE",
      causeCode: "RING_LIST_WRITER_UNAUTHORIZED",
    });
    expect(test.read).not.toHaveBeenCalled();
    expect(test.prove).not.toHaveBeenCalled();
  });
  it("allows a member to write its recovery bit without a policy", async () => {
    const test = await fixture();
    await test.write(memberOfTag(filled(3)), ListId.recovery, "active", OTHER);
    expect(test.prove.mock.calls[0]![0].items[0]?.lists).toBe(16n);
  });
  it("refuses the authority writing another member's recovery bit", async () => {
    const test = await fixture();
    await expect(test.write(memberOfTag(filled(3)), ListId.recovery)).rejects.toBeDefined();
    expect(test.prove).not.toHaveBeenCalled();
  });
  it("merges writes to one member into one record", async () => {
    const test = await fixture(),
      member = memberOfTag(filled(4));
    await buildRingMemberUpdateTransaction({
      client: test.client,
      ringProgramId: RING,
      payer: AUTHORITY,
      signers: [AUTHORITY],
      writes: [
        { member, set: [ListId.allow], clear: [] },
        { member, set: [ListId.block], clear: [] },
      ],
    });
    expect(test.prove.mock.calls[0]![0].items).toHaveLength(1);
    expect(test.prove.mock.calls[0]![0].items[0]?.lists).toBe(3n);
  });
  it("refuses conflicting writes atomically", async () => {
    const test = await fixture(),
      member = memberOfTag(filled(4));
    await expect(
      buildRingMemberUpdateTransaction({
        client: test.client,
        ringProgramId: RING,
        payer: AUTHORITY,
        signers: [AUTHORITY],
        writes: [{ member, set: [ListId.allow], clear: [ListId.allow] }],
      }),
    ).rejects.toBeDefined();
    expect(test.read).not.toHaveBeenCalled();
    expect(test.prove).not.toHaveBeenCalled();
  });
  it("updates shared paths for two inserts in sorted order", async () => {
    const test = await fixture(),
      members = [memberOfTag(filled(6)), memberOfTag(filled(5))];
    await buildRingMemberUpdateTransaction({
      client: test.client,
      ringProgramId: RING,
      payer: AUTHORITY,
      signers: [AUTHORITY],
      writes: members.map((member) => ({ member, set: [ListId.allow], clear: [] })),
    });
    const request = test.prove.mock.calls[0]![0];
    expect(request.newRoot).toEqual(
      registryFixture(members.map((member) => ({ member, lists: 1n }))).root,
    );
    expect(request.items.map((item) => item.index)).toEqual([1n, 2n]);
    expect(request.items[1]?.update.lowMember).toEqual(request.items[0]?.member);
  });
  it("mixes rewrites and inserts under one root", async () => {
    const existing = memberOfTag(filled(7)),
      fresh = memberOfTag(filled(8)),
      test = await fixture([{ member: existing, lists: 2n }]);
    const writes: RingMemberWrite[] = [
      { member: existing, set: [ListId.allow], clear: [ListId.block] },
      { member: fresh, set: [ListId.allow], clear: [] },
    ];
    await buildRingMemberUpdateTransaction({
      client: test.client,
      ringProgramId: RING,
      payer: AUTHORITY,
      signers: [AUTHORITY],
      writes,
    });
    const request = test.prove.mock.calls[0]![0];
    expect(request.newRoot).toEqual(
      registryFixture([
        { member: existing, lists: 1n },
        { member: fresh, lists: 1n },
      ]).root,
    );
    expect(
      request.items.find((item) => Buffer.compare(item.member, existing) === 0)?.update.exists,
    ).toBe(true);
  });
  it("refuses a malformed member proof before proving", async () => {
    const test = await fixture();
    test.read.mockImplementation(async (request) => ({
      ...test.registry.read(request.member),
      low: null,
    }));
    await expect(test.write(memberOfTag(filled(4)), ListId.allow)).rejects.toBeDefined();
    expect(test.prove).not.toHaveBeenCalled();
  });
  it("refuses an unauthenticated append path before proving", async () => {
    const test = await fixture();
    test.tip.mockResolvedValue({
      ...test.registry.tip,
      appendPath: Array.from({ length: 20 }, () => ZERO_32),
    });
    await expect(test.write(memberOfTag(filled(4)), ListId.allow)).rejects.toBeDefined();
    expect(test.prove).not.toHaveBeenCalled();
  });
  it("rejects empty and oversized batches before reads", async () => {
    for (const count of [0, 17]) {
      const test = await fixture();
      await expect(
        buildRingMemberUpdateTransaction({
          client: test.client,
          ringProgramId: RING,
          payer: AUTHORITY,
          signers: [AUTHORITY],
          writes: Array.from({ length: count }, (_, i) => ({
            member: memberOfTag(bigIntBytes(BigInt(i + 1)) as Bytes32),
            set: [ListId.allow],
            clear: [],
          })),
        }),
      ).rejects.toBeDefined();
      expect(test.prove).not.toHaveBeenCalled();
      expect(test.read).not.toHaveBeenCalled();
    }
  });
  it("serializes tag 32, current-root index and member fields in Rust order", async () => {
    const test = await fixture(),
      member = memberOfTag(filled(4));
    await test.write(member, ListId.allow);
    const request = test.prove.mock.calls[0]![0],
      items = request.items;
    const instruction = await updateRingMembersInstruction({
      ringProgramId: RING,
      proof: new Uint8Array(192),
      oldRootIndex: 5,
      newRoot: request.newRoot,
      items,
      signers: [AUTHORITY],
    });
    expect(instruction.data?.[0]).toBe(32);
    expect(instruction.data?.[193]).toBe(5);
    expect(instruction.data?.[226]).toBe(1);
    expect(instruction.data?.slice(227, 259)).toEqual(member);
    expect(instruction.accounts?.map((meta) => meta.address)).toEqual([
      (await ringConfigPda(RING))[0],
      (await ringMemberRegistryRootPda(RING))[0],
      AUTHORITY,
    ]);
  });
  it("pads the prover batch to sixteen slots and binds its count", async () => {
    const test = await fixture();
    await test.write(memberOfTag(filled(4)), ListId.allow);
    const request = test.prove.mock.calls[0]![0],
      body = customRingUpdateMembersProofRequest(request);
    expect(body["itemCount"]).toBe(1);
    expect(body["items"]).toHaveLength(16);
    expect(request.publicInputHash).toEqual(
      updateMembersPublicInputHash(request.oldRoot, request.newRoot, request.items),
    );
    expect(() => customRingUpdateMembersProofRequest({ ...request, items: [] })).toThrow();
  });
  it("keeps an overlay's predecessor path authenticated", () => {
    const tree = registryFixture(),
      overlay = new MemberRegistryOverlay(tree.root, 1n, tree.tip.appendPath),
      read = tree.read(memberOfTag(filled(4)));
    if (read.low === null) throw new Error("no low");
    expect(
      memberRegistryRootFromProof({
        leaf: memberRegistryLeaf(read.low),
        index: 0n,
        proof: overlay.path(0n, read.low.path),
      }),
    ).toEqual(tree.root);
  });
});
