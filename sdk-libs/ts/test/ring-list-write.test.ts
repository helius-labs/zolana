import {
  AccountRole,
  getAddressDecoder,
  getProgramDerivedAddress,
  type Address,
} from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import type { MerkleProof, NonInclusionProof } from "../src/client/rpc.js";
import { initializePoseidon } from "../src/hasher/index.js";
import { SYSTEM_PROGRAM } from "../src/interface/instructions/index.js";
import { addressBytes } from "../src/interface/internal.js";
import { nullifierPdaAddress } from "../src/interface/pda/index.js";
import { SHIELDED_POOL_PROGRAM_ID } from "../src/interface/program.js";
import type { Bytes32, TransactProof } from "../src/interface/types.js";
import { ViewingKey } from "../src/keypair/viewing-key.js";
import { bigintToBytes, bytesToBigInt } from "../src/client/internal.js";
import {
  ringConfigAddress,
  ringPolicyConfigAddress,
  ringPolicyNamespaceAddress,
} from "../src/ring/config.js";
import {
  proveRingEntryTransition,
  ringEntryTransitionInputs,
  type RingEntryStateLeaf,
} from "../src/ring/entry-proof.js";
import {
  RING_ENTRY_MUTATION_COMPUTE_UNIT_LIMIT,
  createRingEntryInstruction,
  updateRingEntryInstruction,
} from "../src/ring/instructions.js";
import { buildRingListWriteTransaction } from "../src/ring/list-write.js";
import {
  ListId,
  RingListNamespace,
  buildRuleTable,
  encodeListEntry,
  memberOfTag,
  type ListEntry,
} from "../src/ring/policy.js";
import type { IndexedShieldedTransaction } from "../src/transaction/instructions/transact.js";

import { BLOCKHASH, transactionsPage } from "./helpers/clients.js";
import {
  ownSources,
  ownedAccount,
  policyConfigPda,
  ringPolicyConfigData,
  ringProgramConfigData,
} from "./helpers/ring-accounts.js";
import { filled as fill, treeAccount } from "./helpers/tree-account.js";

await initializePoseidon();

const filled = (byte: number): Bytes32 => fill(byte) as Bytes32;
const addressOf = (bytes: Uint8Array): Address => getAddressDecoder().decode(bytes);
const hexOf = (value: bigint): string => Buffer.from(bigintToBytes(value)).toString("hex");
const RECORDS_PDA = addressOf(filled(0x11));
const PAYER = addressOf(filled(0x01));
const ENTRIES_TREE = addressOf(filled(0x30));
const RING = addressOf(filled(0x10));
const ZERO_PROOF: TransactProof = {
  a: new Uint8Array(32) as Bytes32,
  b: new Uint8Array(128) as TransactProof["b"],
  c: new Uint8Array(32) as Bytes32,
};

const member = memberOfTag(filled(0xa1));
const v0Draft = {
  listId: ListId.allow,
  member,
  state: "active",
  version: 0n,
  contentHash: filled(0),
} as const;
const v0: ListEntry = { ...v0Draft, blinding: filled(0x21) };
const v1: ListEntry = { ...v0, version: 1n, blinding: filled(0x22) };
/** The Rust vectors hash under tree 3 from seed 8. */
const VECTOR_TREE_ID = 3;
const BLINDING_SEED = filled(0x08);

function absenceOf(target: Bytes32, tree = ENTRIES_TREE): NonInclusionProof {
  return {
    leaf: target,
    merkleContext: { treeType: 1, tree },
    path: Array.from({ length: 40 }, () => filled(0)),
    lowElement: filled(2),
    lowElementIndex: 9n,
    highElement: filled(3),
    highElementIndex: 10n,
    root: filled(7),
    rootSeq: 1n,
    rootIndex: 5,
  };
}

function inclusionOf(leaf: Bytes32, tree = ENTRIES_TREE): MerkleProof {
  return {
    leaf,
    merkleContext: { treeType: 1, tree },
    path: Array.from({ length: 32 }, () => filled(0)),
    leafIndex: 3n,
    root: filled(6),
    rootSeq: 1n,
    rootIndex: 4,
  };
}

const HEAD: RingEntryStateLeaf = {
  root: filled(6),
  rootIndex: 4,
  path: Array.from({ length: 32 }, () => filled(0)),
  leafIndex: 0n,
};

/** `custom-rings/sdk/tests/entry_proof_vectors.rs`. */
describe("entry transition inputs", () => {
  const owner = RingListNamespace.of(RECORDS_PDA, VECTOR_TREE_ID);
  const claim = () =>
    ringEntryTransitionInputs({
      namespace: RECORDS_PDA,
      entriesTreeId: VECTOR_TREE_ID,
      payer: PAYER,
      entry: v0Draft,
      state: HEAD,
      absence: absenceOf(owner.entryAddress(v0Draft)),
      blindingSeed: BLINDING_SEED,
    });

  it("hashes a claim like Rust `EntryWitness::prove`", () => {
    const address = owner.entryAddress(v0Draft);
    const { inputs, nullifier, entry } = claim();
    expect(hexOf(bytesToBigInt(entry.blinding))).toBe(
      "078e398422043456dc67a4c39f57ab507670ab3d1024746d47a2e93c7a46c344",
    );
    expect(nullifier).toEqual(address);
    expect(hexOf(inputs.externalDataHash)).toBe(
      "007d8570799cec47261326adb458082d7d3e2209c1fe09ee4203f1e79c040376",
    );
    expect(hexOf(inputs.privateTxHash)).toBe(
      "1f5af8e4fba46ce23dc7690ba20a2c900dee0e9226e080427ea4b370c13ea9b8",
    );
    expect(hexOf(inputs.publicInputHash)).toBe(
      "2600314d0e9cc38c907456b62b8ce775a9c4fcb76e237babd6edc1e731530241",
    );
    const [input] = inputs.inputs;
    expect(input?.circuit.domain).toBe(2n);
    expect(input?.circuit.asset).toBe(0n);
    expect(input?.nullifier).toBe(BigInt(`0x${Buffer.from(address).toString("hex")}`));
    expect(input?.statePathIndex).toBe(0n);
    expect(inputs.signerPublicKeyHashes).toHaveLength(2);
    expect(inputs.publishedOutputOwnerPublicKeyHashes).toEqual([inputs.signerPublicKeyHashes[1]]);
    expect(inputs.outputs[0]?.circuit.blinding).toBe(bytesToBigInt(entry.blinding));
    expect(inputs.inputFlags).toBe(1n);
    expect(inputs.ringProgramId).toBe(0n);
  });

  it("hashes a spend like Rust `EntryWitness::prove`", () => {
    const spent = claim().entry;
    const spentHashes = owner.entryHashes(spent);
    const { inputs, nullifier } = ringEntryTransitionInputs({
      namespace: RECORDS_PDA,
      entriesTreeId: VECTOR_TREE_ID,
      payer: PAYER,
      entry: { ...v0Draft, version: 1n },
      spent,
      state: { ...HEAD, leafIndex: 3n },
      absence: absenceOf(spentHashes.nullifier),
      blindingSeed: BLINDING_SEED,
    });
    expect(nullifier).toEqual(spentHashes.nullifier);
    expect(hexOf(inputs.privateTxHash)).toBe(
      "202e31e8682a29d7c0a061e836bc43b159ee93ddeacc12f155c46a69f2c89713",
    );
    expect(hexOf(inputs.publicInputHash)).toBe(
      "040d44e7358f23ab67b986eb83961dbd7dff30abb77c6759b80d0d7728ce01f4",
    );
    expect(inputs.inputs[0]?.circuit.domain).toBe(3n);
    expect(inputs.inputs[0]?.statePathIndex).toBe(3n);
    expect(inputs.outputs[0]?.circuit.blinding).toBe(
      0x018be3ee8af2454b58a964be7d94a0b752f31e5a85f4a0c80b4d25213d44b256n,
    );
  });
});

describe("entry transition proving", () => {
  function client(input: Readonly<{ tree?: Address; account?: boolean }> = {}) {
    const tree = input.tree ?? ENTRIES_TREE;
    const getMerkleProofs = vi.fn(async (_tree: Address, leaves: readonly Bytes32[]) => ({
      context: { blockTime: 1n, slot: 1n },
      proofs: leaves.map((leaf) => inclusionOf(leaf, tree)),
    }));
    const getNonInclusionProofs = vi.fn(async (_tree: Address, leaves: readonly Bytes32[]) => ({
      context: { blockTime: 1n, slot: 1n },
      proofs: leaves.map((leaf) => absenceOf(leaf, tree)),
    }));
    const getAccount = vi.fn(async () =>
      input.account === false
        ? undefined
        : ownedAccount(
            SHIELDED_POOL_PROGRAM_ID,
            treeAccount({ stateCursor: 4, written: 5, nullifierCursor: 6n }),
          ),
    );
    const proveTransferInputs = vi.fn(async () => ZERO_PROOF);
    return { getMerkleProofs, getNonInclusionProofs, getAccount, proveTransferInputs };
  }

  it("claims from the tree head without a state proof", async () => {
    const fake = client();
    const { entry, proof } = await proveRingEntryTransition({
      client: fake,
      ringProgramId: RING,
      entriesTree: ENTRIES_TREE,
      entriesTreeId: 0,
      payer: PAYER,
      entry: v0Draft,
    });
    const namespace = RingListNamespace.of(await ringPolicyNamespaceAddress(RING), 0);
    expect(entry).toMatchObject(v0Draft);
    expect(proof).toEqual({
      proof: ZERO_PROOF,
      utxoTreeRootIndex: 4,
      nullifierTreeRootIndex: 5,
      nullifier: namespace.entryHashes(v0).address,
      privateTxBlinding: expect.any(Uint8Array),
    });
    expect(fake.getMerkleProofs).not.toHaveBeenCalled();
    expect(fake.getAccount).toHaveBeenCalledWith(ENTRIES_TREE, undefined);
    expect(fake.getNonInclusionProofs).toHaveBeenCalledWith(
      ENTRIES_TREE,
      [namespace.entryHashes(v0).address],
      undefined,
      undefined,
    );
  });

  it("spends the live leaf with its inclusion proof", async () => {
    const fake = client();
    const { proof } = await proveRingEntryTransition({
      client: fake,
      ringProgramId: RING,
      entriesTree: ENTRIES_TREE,
      entriesTreeId: 0,
      payer: PAYER,
      entry: v1,
      spent: v0,
    });
    const namespace = RingListNamespace.of(await ringPolicyNamespaceAddress(RING), 0);
    expect(proof.nullifier).toEqual(namespace.entryHashes(v0).nullifier);
    expect(fake.getAccount).not.toHaveBeenCalled();
    expect(fake.getMerkleProofs).toHaveBeenCalledWith(
      ENTRIES_TREE,
      [namespace.entryHashes(v0).utxoHash],
      undefined,
      undefined,
    );
  });

  it("refuses a proof from another tree and a missing tree account", async () => {
    await expect(
      proveRingEntryTransition({
        client: client({ tree: addressOf(filled(0x31)) }),
        ringProgramId: RING,
        entriesTree: ENTRIES_TREE,
        entriesTreeId: 0,
        payer: PAYER,
        entry: v1,
        spent: v0,
      }),
    ).rejects.toMatchObject({ code: "RING_ENTRY_PROOF_INCOMPLETE" });
    const missing = client({ account: false });
    await expect(
      proveRingEntryTransition({
        client: missing,
        ringProgramId: RING,
        entriesTree: ENTRIES_TREE,
        entriesTreeId: 0,
        payer: PAYER,
        entry: v0Draft,
      }),
    ).rejects.toMatchObject({ code: "RING_ENTRIES_TREE_INVALID" });
    expect(missing.proveTransferInputs).not.toHaveBeenCalled();
  });
});

describe("entry instructions", () => {
  const proof = {
    proof: ZERO_PROOF,
    utxoTreeRootIndex: 0x0102,
    nullifierTreeRootIndex: 0x0304,
    nullifier: filled(9),
    privateTxBlinding: filled(0x11),
  };

  it("create entry lays out the claim and forwards the SPP accounts", async () => {
    const instruction = await createRingEntryInstruction({
      ringProgramId: RING,
      payer: PAYER,
      entriesTree: ENTRIES_TREE,
      entry: v0,
      proof,
    });
    expect(instruction.accounts?.map((meta) => [meta.address, meta.role])).toEqual([
      [await ringConfigAddress(RING), AccountRole.READONLY],
      [await ringPolicyConfigAddress(RING), AccountRole.READONLY],
      [PAYER, AccountRole.WRITABLE_SIGNER],
      [ENTRIES_TREE, AccountRole.WRITABLE],
      [ENTRIES_TREE, AccountRole.WRITABLE],
      [SHIELDED_POOL_PROGRAM_ID, AccountRole.READONLY],
      [SYSTEM_PROGRAM, AccountRole.READONLY],
      [await nullifierPdaAddress(ENTRIES_TREE, filled(9)), AccountRole.WRITABLE],
      [await ringPolicyNamespaceAddress(RING), AccountRole.READONLY],
    ]);
    expect([...(instruction.data ?? [])]).toEqual([
      8,
      ListId.allow,
      ...member,
      1,
      ...filled(0),
      ...v0.blinding,
      ...filled(0x11),
      0x04,
      0x03,
      0x02,
      0x01,
      ...new Uint8Array(192),
    ]);
  });

  it("update entry carries the spent version before the new fields", async () => {
    const instruction = await updateRingEntryInstruction({
      ringProgramId: RING,
      payer: PAYER,
      entriesTree: ENTRIES_TREE,
      entry: { ...v1, state: "cleared" },
      spent: v0,
      proof,
    });
    expect([...(instruction.data ?? [])].slice(0, 1 + 1 + 32 + 1 + 32 + 8 + 32 + 1)).toEqual([
      9,
      ListId.allow,
      ...member,
      1,
      ...filled(0),
      ...new Uint8Array(8),
      ...v0.blinding,
      2,
    ]);
    expect(instruction.data).toHaveLength(
      1 + 1 + 32 + 1 + 32 + 8 + 32 + 1 + 32 + 32 + 32 + 4 + 192,
    );
    expect(RING_ENTRY_MUTATION_COMPUTE_UNIT_LIMIT).toBe(1_400_000);
  });
});

describe("list writes", () => {
  const AUTHORITY = addressOf(filled(0x12));
  const CURATOR = addressOf(filled(0x20));
  const table = buildRuleTable({
    rules: [
      {
        subject: "outputOwner",
        source: { kind: "lists", present: [ListId.allow], absent: [ListId.block] },
        guard: { kind: "always" },
      },
      {
        subject: "sender",
        source: { kind: "lists", present: [], absent: [ListId.frozen] },
        guard: { kind: "always" },
      },
    ],
  });

  async function chain(
    input: Readonly<{ hasPolicy?: boolean; live?: readonly IndexedShieldedTransaction[] }> = {},
  ) {
    const [[configAddress, configBump], [policyAddress, policyBump], namespace, curatorNamespace] =
      await Promise.all([
        getProgramDerivedAddress({
          programAddress: RING,
          seeds: [new TextEncoder().encode("config")],
        }),
        policyConfigPda(RING),
        ringPolicyNamespaceAddress(RING),
        ringPolicyNamespaceAddress(CURATOR),
      ]);
    const sources = ownSources(table, namespace).map((slot) =>
      slot.listId === ListId.frozen ? { listId: slot.listId, namespace: curatorNamespace } : slot,
    );
    const accounts = new Map([
      [
        configAddress,
        ownedAccount(
          RING,
          ringProgramConfigData({
            authority: AUTHORITY,
            auditorPublicKey: ViewingKey.generate().publicKey().toBytes(),
            bump: configBump,
            hasPolicy: input.hasPolicy ?? true,
          }),
        ),
      ],
      [
        policyAddress,
        ownedAccount(
          RING,
          ringPolicyConfigData({ table, sources, entriesTree: ENTRIES_TREE, bump: policyBump }),
        ),
      ],
      [
        ENTRIES_TREE,
        ownedAccount(
          SHIELDED_POOL_PROGRAM_ID,
          treeAccount({ stateCursor: 4, written: 5, nullifierCursor: 6n }),
        ),
      ],
    ]);
    const live = input.live ?? [];
    const byNullifiers = vi.fn(async (request: { nullifiers: readonly Bytes32[] }) =>
      transactionsPage({
        transactions: live.filter((transaction) =>
          transaction.nullifiers.some((spent) =>
            request.nullifiers.some((asked) => Buffer.from(asked).equals(spent)),
          ),
        ),
        scannedThrough: new Uint8Array([1]),
      }),
    );
    return {
      namespace,
      client: {
        getAccount: vi.fn(async (account: Address) => accounts.get(account)),
        getLatestBlockhash: vi.fn(async () => BLOCKHASH),
        getEncryptedUtxosByTags: vi.fn(async () => {
          throw new Error("unused");
        }),
        getShieldedTransactionsByNullifiers: byNullifiers,
        getMerkleProofs: vi.fn(async (_tree: Address, leaves: readonly Bytes32[]) => ({
          context: { blockTime: 1n, slot: 1n },
          proofs: leaves.map((leaf) => inclusionOf(leaf)),
        })),
        getNonInclusionProofs: vi.fn(async (_tree: Address, leaves: readonly Bytes32[]) => ({
          context: { blockTime: 1n, slot: 1n },
          proofs: leaves.map((leaf) => absenceOf(leaf)),
        })),
        proveTransferInputs: vi.fn(async () => ZERO_PROOF),
      },
    };
  }

  function spender(
    namespace: Address,
    nullifier: Bytes32,
    entry: ListEntry,
  ): IndexedShieldedTransaction {
    const hashes = RingListNamespace.of(namespace, 0).entryHashes(entry);
    return {
      slot: 5n,
      txSignature: "claim" as IndexedShieldedTransaction["txSignature"],
      outputSlots: [
        {
          viewTag: filled(0),
          outputContext: { hash: hashes.utxoHash, tree: ENTRIES_TREE, leafIndex: 0n },
          payload: encodeListEntry(entry),
        },
      ],
      messages: [],
      nullifiers: [nullifier],
      proofless: false,
    };
  }

  it("claims a new entry for the authority at version zero", async () => {
    const { client } = await chain();
    const write = await buildRingListWriteTransaction({
      client,
      ringProgramId: RING,
      payer: AUTHORITY,
      listId: ListId.allow,
      member,
      state: "active",
    });
    expect(write.kind).toBe("transaction");
    if (write.kind !== "transaction") return;
    expect(write.change).toBe("claimed");
    expect(write.entry).toMatchObject(v0Draft);
    expect(Object.keys(write.transaction.signatures)).toEqual([AUTHORITY]);
    expect(client.proveTransferInputs).toHaveBeenCalledTimes(1);
    expect(client.getMerkleProofs).not.toHaveBeenCalled();
  });

  it("reports an entry already in the target state without a transaction", async () => {
    const { client, namespace } = await chain();
    const address = RingListNamespace.of(namespace, 0).entryHashes(v0).address;
    const seeded = await chain({ live: [spender(namespace, address, v0)] });
    const write = await buildRingListWriteTransaction({
      client: seeded.client,
      ringProgramId: RING,
      payer: AUTHORITY,
      listId: ListId.allow,
      member,
      state: "active",
    });
    expect(write).toMatchObject({ kind: "unchanged", entry: { entry: v0 } });
    expect(seeded.client.proveTransferInputs).not.toHaveBeenCalled();
    expect(client.proveTransferInputs).not.toHaveBeenCalled();
  });

  it("moves a live entry to the next version", async () => {
    const { namespace } = await chain();
    const address = RingListNamespace.of(namespace, 0).entryHashes(v0).address;
    const { client } = await chain({ live: [spender(namespace, address, v0)] });
    const write = await buildRingListWriteTransaction({
      client,
      ringProgramId: RING,
      payer: AUTHORITY,
      listId: ListId.allow,
      member,
      state: "cleared",
    });
    expect(write).toMatchObject({
      kind: "transaction",
      change: "moved",
      entry: { ...v0Draft, version: 1n, state: "cleared" },
    });
    expect(client.getMerkleProofs).toHaveBeenCalledTimes(1);
  });

  it("refuses a curator-served list and a foreign writer before any read", async () => {
    const cases = [
      { listId: ListId.frozen, payer: AUTHORITY, cause: "RING_LIST_SHARED" },
      { listId: ListId.allow, payer: PAYER, cause: "RING_LIST_WRITER_UNAUTHORIZED" },
      { listId: ListId.ringViewing, payer: AUTHORITY, cause: "RING_LIST_WRITER_UNAUTHORIZED" },
    ] as const;
    for (const { listId, payer, cause } of cases) {
      const { client } = await chain();
      await expect(
        buildRingListWriteTransaction({
          client,
          ringProgramId: RING,
          payer,
          listId,
          member,
          state: "active",
        }),
      ).rejects.toMatchObject({ code: "RING_BUILD_LIST_WRITE", causeCode: cause });
      expect(client.getShieldedTransactionsByNullifiers).not.toHaveBeenCalled();
      expect(client.proveTransferInputs).not.toHaveBeenCalled();
    }
  });

  it("lets a member write its own member list and refuses a ring without a policy", async () => {
    const { client } = await chain();
    const self = memberOfTag(addressBytes(PAYER));
    const write = await buildRingListWriteTransaction({
      client,
      ringProgramId: RING,
      payer: PAYER,
      listId: ListId.ringViewing,
      member: self,
      state: "active",
    });
    expect(write.kind).toBe("transaction");
    const audit = await chain({ hasPolicy: false });
    await expect(
      buildRingListWriteTransaction({
        client: audit.client,
        ringProgramId: RING,
        payer: AUTHORITY,
        listId: ListId.allow,
        member,
        state: "active",
      }),
    ).rejects.toMatchObject({
      code: "RING_BUILD_LIST_WRITE",
      causeCode: "RING_POLICY_CONFIG_NOT_FOUND",
    });
  });
});
