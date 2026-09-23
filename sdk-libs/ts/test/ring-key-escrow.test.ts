import { AccountRole, address, getAddressDecoder, type Address } from "@solana/kit";
import { beforeAll, describe, expect, it, vi } from "vitest";

import { ClientError } from "../src/client/error.js";
import type { MerkleProof, NonInclusionProof } from "../src/client/rpc.js";
import type { CustomRingDepositProofRequest } from "../src/client/prover/types.js";
import { hashBytes, initializePoseidon } from "../src/hasher/index.js";
import {
  nullifierPdaAddress,
  ringConfigPda,
  ringDepositAuditAddress,
  ringDepositAuditPda,
  ringKeyRegistryRootAddress,
  ringKeyRegistryRootPda,
  treeAddress,
} from "../src/interface/pda/index.js";
import { bigintToBytes } from "../src/client/internal.js";
import { DUMMY_DOMAIN, SHIELDED_POOL_PROGRAM_ID, UTXO_DOMAIN } from "../src/interface/program.js";
import { DepositAsset, type Bytes16, type Bytes31, type Bytes32 } from "../src/interface/types.js";
import { NullifierKey } from "../src/keypair/nullifier-key.js";
import { ShieldedAddress, ShieldedKeypair } from "../src/keypair/shielded.js";
import { ViewingKey } from "../src/keypair/viewing-key.js";
import { buildRingDepositTransaction } from "../src/ring/deposit.js";
import { sealRingDepositOpenings } from "../src/ring/deposit-audit.js";
import { ringDepositInstruction } from "../src/ring/deposit-instruction.js";
import { KEY_REGISTRY_EMPTY_ROOT } from "../src/ring/key-registry-tree.js";
import { openRingEscrowedKeys, ringEscrowedOwners } from "../src/ring/key-escrow.js";
import { ZERO_NULLIFIER_PK, memberOfTag, ringNamespaceOwnerHash } from "../src/ring/policy.js";
import {
  planPolicyTrees,
  provePolicyTrees,
  revocationPdaAddresses,
} from "../src/ring/policy-trees.js";
import { poseidon } from "../src/transaction/internal.js";

import { depositClient } from "./helpers/clients.js";
import { keyRegistryRootData, oneMemberRegistry } from "./helpers/key-registry.js";
import { ownedAccount, ringProgramConfigData } from "./helpers/ring-accounts.js";
import { treeAccount } from "./helpers/tree-account.js";

const RING = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
const TREE = treeAddress(0);
const filled = (byte: number): Bytes32 => new Uint8Array(32).fill(byte) as Bytes32;
const addressOf = (byte: number): Address => getAddressDecoder().decode(filled(byte));

beforeAll(initializePoseidon);

/** A ring whose registry holds `member` alone, its root at history slot 1. */
async function escrowedRing() {
  const auditor = ViewingKey.generate();
  const member = ShieldedKeypair.generate();
  const registry = oneMemberRegistry({
    member: memberOfTag(member.shieldedAddress().confidentialViewTag()),
    nullifierKey: member.nullifierKey(),
    auditor: auditor.publicKey(),
  });
  const [config, configBump] = await ringConfigPda(RING);
  const [root, rootBump] = await ringKeyRegistryRootPda(RING);
  const accounts = new Map([
    [
      config,
      ownedAccount(
        RING,
        ringProgramConfigData({
          authority: RING,
          auditorPublicKey: auditor.publicKey().toBytes(),
          bump: configBump,
          hasPolicy: true,
          keyEscrow: true,
        }),
      ),
    ],
    [
      root,
      ownedAccount(
        RING,
        keyRegistryRootData({
          root: registry.root,
          nextIndex: 2n,
          bump: rootBump,
          cursor: 1,
          history: [KEY_REGISTRY_EMPTY_ROOT],
        }),
      ),
    ],
  ]);
  const getRingKeyRegistryEntry = vi.fn(async (request: { member: Bytes32 }) => {
    if (Buffer.from(request.member).equals(registry.entry.member)) return registry.entry;
    throw new ClientError("CLIENT_KEY_REGISTRY_MEMBER_UNREGISTERED", {
      details: { method: "getRingKeyRegistryEntry" },
    });
  });
  return {
    auditor,
    member,
    registry,
    client: {
      getAccount: vi.fn(async (key: Address) => accounts.get(key)),
      getRingKeyRegistryEntry,
    },
  };
}

function ownerOf(keypair: ShieldedKeypair) {
  const shielded = keypair.shieldedAddress();
  return {
    ownerPkHash: shielded.signingPublicKey.ownerProofInputHash(),
    nullifierPk: shielded.nullifierPublicKey,
  };
}

describe("escrowed output keys", () => {
  it("pins the zero key to the nullifier key of the zero secret", () => {
    const zero = NullifierKey.fromSecret(new Uint8Array(31) as Bytes31);
    try {
      expect(zero.publicKey()).toEqual(ZERO_NULLIFIER_PK);
      expect(poseidon([new Uint8Array(32) as Bytes32])).toEqual(ZERO_NULLIFIER_PK);
    } finally {
      zero.destroy();
    }
  });

  it("passes skipped slots without an indexer read", async () => {
    const ring = await escrowedRing();
    const keys = await openRingEscrowedKeys({
      client: ring.client,
      ringProgramId: RING,
      owners: [undefined, undefined],
    });
    expect(keys).toEqual({ root: ring.registry.root, rootIndex: 1, keys: [undefined, undefined] });
    expect(ring.client.getRingKeyRegistryEntry).not.toHaveBeenCalled();
  });

  it("refuses the zero key for a registered or an unregistered owner", async () => {
    const ring = await escrowedRing();
    for (const keypair of [ring.member, ShieldedKeypair.generate()]) {
      await expect(
        openRingEscrowedKeys({
          client: ring.client,
          ringProgramId: RING,
          owners: [{ ownerPkHash: ownerOf(keypair).ownerPkHash, nullifierPk: ZERO_NULLIFIER_PK }],
        }),
      ).rejects.toMatchObject({ code: "RING_UNREGISTERED_OUTPUT_KEY" });
    }
  });

  // Mirrors Rust `only_the_namespace_owned_record_skips_its_key_opening`.
  it("skips only the namespace-owned record and padding", () => {
    const namespace = addressOf(0x21);
    const viewingPublicKey = ViewingKey.generate().publicKey();
    const record = ShieldedAddress.forPda({
      pda: filled(0x21),
      nullifierPublicKey: ZERO_NULLIFIER_PK,
      viewingPublicKey,
    });
    const member = ShieldedKeypair.generate();
    const zeroKey = {
      ownerPkHash: ownerOf(member).ownerPkHash,
      nullifierPk: ZERO_NULLIFIER_PK,
    };
    const opening = (domain: number, owner: { ownerPkHash: Bytes32; nullifierPk: Bytes32 }) => {
      const zero = new Uint8Array(32) as Bytes32;
      return {
        domain: bigintToBytes(BigInt(domain)) as Bytes32,
        treeId: zero,
        ...owner,
        asset: zero,
        amount: zero,
        blinding: zero,
        dataHash: zero,
        ringDataHash: zero,
        ringProgramId: zero,
      };
    };
    const owners = ringEscrowedOwners(
      [
        opening(UTXO_DOMAIN, {
          ownerPkHash: record.signingPublicKey.ownerProofInputHash(),
          nullifierPk: ZERO_NULLIFIER_PK,
        }),
        opening(UTXO_DOMAIN, zeroKey),
        opening(DUMMY_DOMAIN, zeroKey),
      ],
      ringNamespaceOwnerHash(namespace),
    );
    expect(owners).toEqual([undefined, zeroKey, undefined]);
  });

  it("opens a registered owner's key under the bound root once per owner", async () => {
    const ring = await escrowedRing();
    const owner = ownerOf(ring.member);
    const { root, rootIndex, keys } = await openRingEscrowedKeys({
      client: ring.client,
      ringProgramId: RING,
      owners: [owner, owner],
    });
    expect(root).toEqual(ring.registry.root);
    expect(rootIndex).toBe(1);
    expect(keys[0]).toEqual({
      next: ring.registry.entry.next,
      ctHash: hashBytes(ring.registry.entry.ciphertext),
      index: 1n,
      path: ring.registry.entry.proof,
    });
    expect(keys[1]).toBe(keys[0]);
    expect(ring.client.getRingKeyRegistryEntry).toHaveBeenCalledTimes(1);
    expect(ring.client.getRingKeyRegistryEntry).toHaveBeenCalledWith(
      expect.objectContaining({ expectedRoot: ring.registry.root, expectedNextIndex: 2n }),
      expect.anything(),
    );
  });

  it("refuses an unregistered owner and a registered owner under another key before proving", async () => {
    const ring = await escrowedRing();
    const stranger = ShieldedKeypair.generate();
    await expect(
      openRingEscrowedKeys({
        client: ring.client,
        ringProgramId: RING,
        owners: [ownerOf(ring.member), ownerOf(stranger)],
      }),
    ).rejects.toMatchObject({
      code: "RING_UNREGISTERED_OUTPUT_KEY",
      details: { owner: expect.any(String) },
    });
    const rotated = ShieldedKeypair.generate();
    await expect(
      openRingEscrowedKeys({
        client: ring.client,
        ringProgramId: RING,
        owners: [
          {
            ownerPkHash: ownerOf(ring.member).ownerPkHash,
            nullifierPk: rotated.shieldedAddress().nullifierPublicKey,
          },
        ],
      }),
    ).rejects.toMatchObject({ code: "RING_UNREGISTERED_OUTPUT_KEY" });
  });
});

describe("escrowed deposits", () => {
  function deposit(ciphertext: Uint8Array) {
    return {
      asset: DepositAsset.sol(),
      viewTag: filled(1),
      ownerUtxoHash: filled(2),
      amount: 1n,
      ringDataHash: new Uint8Array(32) as Bytes32,
      encrypted: {
        txViewingPublicKey: ViewingKey.generate().publicKey().toBytes(),
        salt: new Uint8Array(16) as Bytes16,
        ciphertext,
      },
    };
  }

  it("refuses a plain deposit and lists the registry root after the deposit audit", async () => {
    const auditor = ViewingKey.generate();
    const sealed = sealRingDepositOpenings(
      [{ ownerHash: filled(0), blinding: filled(0), recipientCiphertext: Uint8Array.of(1) }],
      auditor.publicKey(),
    );
    try {
      const input = {
        ringProgramId: RING,
        tree: TREE,
        depositor: RING,
        deposits: [deposit(sealed.payloads[0] ?? new Uint8Array())],
        keyRegistryRootIndex: 7,
      };
      await expect(ringDepositInstruction(input)).rejects.toMatchObject({
        code: "RING_DEPOSIT_AUDIT_REQUIRED",
      });
      const audited = await ringDepositInstruction({ ...input, proof: new Uint8Array(192) });
      expect(audited.data?.[193]).toBe(7);
      expect(audited.accounts?.slice(3, 5).map((meta) => [meta.address, meta.role])).toEqual([
        [await ringDepositAuditAddress(RING), AccountRole.READONLY],
        [await ringKeyRegistryRootAddress(RING), AccountRole.READONLY],
      ]);
    } finally {
      sealed.ephemeralSecret.fill(0);
      auditor.destroy();
    }
  });

  it("audits every deposit into an escrowed ring and proves the recipient's registered key, never the zero key", async () => {
    const ring = await escrowedRing();
    const [setting] = await ringDepositAuditPda(RING);
    const requests: CustomRingDepositProofRequest[] = [];
    const client = {
      ...depositClient({
        getAccount: async (key) => (key === setting ? undefined : ring.client.getAccount(key)),
      }),
      getRingKeyRegistryEntry: ring.client.getRingKeyRegistryEntry,
      proveCustomRingDeposit: vi.fn(async (request: CustomRingDepositProofRequest) => {
        requests.push({ ...request, keys: [...request.keys] });
        return new Uint8Array(192);
      }),
    };
    const transaction = await buildRingDepositTransaction({
      client,
      ringProgramId: RING,
      feePayer: addressOf(3),
      recipient: ring.member.shieldedAddress(),
      amount: 1n,
    });
    expect(transaction).toBeDefined();
    const [request] = requests;
    expect(request?.keyRegistryRoot).toEqual(ring.registry.root);
    expect(request?.ownerPkHashes[0]).toEqual(ownerOf(ring.member).ownerPkHash);
    expect(request?.nullifierPks[0]).toEqual(ownerOf(ring.member).nullifierPk);
    expect(request?.keys[0]).toMatchObject({ index: 1n, path: ring.registry.entry.proof });
    expect(request?.keys.slice(1).every((key) => key === undefined)).toBe(true);

    await expect(
      buildRingDepositTransaction({
        client,
        ringProgramId: RING,
        feePayer: addressOf(3),
        recipient: ShieldedKeypair.generate().shieldedAddress(),
        amount: 1n,
      }),
    ).rejects.toMatchObject({
      code: "RING_BUILD_DEPOSIT",
      causeCode: "RING_UNREGISTERED_OUTPUT_KEY",
    });
    const registered = ring.member.shieldedAddress();
    await expect(
      buildRingDepositTransaction({
        client,
        ringProgramId: RING,
        feePayer: addressOf(3),
        recipient: ShieldedAddress.fromPublicKeys(
          registered.signingPublicKey,
          ZERO_NULLIFIER_PK,
          registered.viewingPublicKey,
        ),
        amount: 1n,
      }),
    ).rejects.toMatchObject({
      code: "RING_BUILD_DEPOSIT",
      causeCode: "RING_UNREGISTERED_OUTPUT_KEY",
    });
    expect(client.proveCustomRingDeposit).toHaveBeenCalledTimes(1);
  });
});

describe("policy trees", () => {
  const ADDRESS = { tree: addressOf(0x40), treeId: 4 };
  const OTHER = { tree: addressOf(0x41), treeId: 5 };

  // Mirrors Rust `fact_trees_dedupe_and_bind_the_address_tree_first`.
  it("leads with the address tree when an absence or no fact reads it and dedupes the rest", () => {
    expect(planPolicyTrees(ADDRESS, [])).toEqual({ trees: [ADDRESS], factSlots: [] });
    expect(planPolicyTrees(ADDRESS, [OTHER, undefined, OTHER, ADDRESS])).toEqual({
      trees: [ADDRESS, OTHER],
      factSlots: [1, 0, 1, 0],
    });
    expect(planPolicyTrees(ADDRESS, [OTHER])).toEqual({ trees: [OTHER], factSlots: [0] });
    expect(planPolicyTrees(ADDRESS, [OTHER, ADDRESS])).toEqual({
      trees: [OTHER, ADDRESS],
      factSlots: [0, 1],
    });
    const six = Array.from({ length: 6 }, (_, index) => ({
      tree: addressOf(0x50 + index),
      treeId: 10 + index,
    }));
    expect(planPolicyTrees(ADDRESS, six.slice(0, 5)).trees).toHaveLength(5);
    expect(() => planPolicyTrees(ADDRESS, six)).toThrow(
      expect.objectContaining({ code: "RING_TOO_MANY_POLICY_TREES" }),
    );
    expect(() => planPolicyTrees(ADDRESS, [...six.slice(0, 4), undefined])).not.toThrow();
    expect(() => planPolicyTrees(ADDRESS, [...six.slice(0, 5), undefined])).toThrow(
      expect.objectContaining({ code: "RING_TOO_MANY_POLICY_TREES" }),
    );
  });

  it("proves each tree's facts in its own request and binds each slot's roots", async () => {
    const proof = (tree: Address, leaf: Bytes32, root: number) => ({
      leaf,
      merkleContext: { treeType: 0, tree },
      path: Array.from({ length: 32 }, () => filled(0)),
      leafIndex: 0n,
      root: filled(root),
      rootSeq: 0n,
      rootIndex: root,
    });
    const absence = (tree: Address, leaf: Bytes32, root: number) => ({
      leaf,
      merkleContext: { treeType: 1, tree },
      path: Array.from({ length: 40 }, () => filled(0)),
      lowElement: filled(0),
      lowElementIndex: 0n,
      highElement: filled(0xff),
      highElementIndex: 1n,
      root: filled(root),
      rootSeq: 0n,
      rootIndex: root,
    });
    const getMerkleProofs = vi.fn(async (tree: Address, leaves: readonly Bytes32[]) => ({
      context: { blockTime: 0n, slot: 0n },
      proofs: leaves.map((leaf): MerkleProof => proof(tree, leaf, tree === OTHER.tree ? 21 : 11)),
    }));
    const getNonInclusionProofs = vi.fn(async (tree: Address, leaves: readonly Bytes32[]) => ({
      context: { blockTime: 0n, slot: 0n },
      proofs: leaves.map((leaf): NonInclusionProof =>
        absence(tree, leaf, tree === OTHER.tree ? 22 : 12),
      ),
    }));
    const getAccount = vi.fn(async (tree: Address) =>
      tree === ADDRESS.tree
        ? ownedAccount(
            SHIELDED_POOL_PROGRAM_ID,
            treeAccount({
              stateCursor: 4,
              written: 5,
              nullifierCursor: 6n,
              treeId: ADDRESS.treeId,
            }),
          )
        : undefined,
    );
    const proven = await provePolicyTrees({
      client: { getAccount, getMerkleProofs, getNonInclusionProofs },
      addressTree: ADDRESS,
      facts: [
        { holder: OTHER, state: filled(1), absence: filled(2) },
        { absence: filled(3) },
        { holder: OTHER, state: filled(4), absence: filled(5) },
      ],
    });
    expect(proven.trees).toEqual([ADDRESS, OTHER]);
    expect(proven.factSlots).toEqual([1, 0, 1]);
    expect(getMerkleProofs.mock.calls.map(([tree, leaves]) => [tree, leaves])).toEqual([
      [OTHER.tree, [filled(1), filled(4)]],
    ]);
    expect(getNonInclusionProofs.mock.calls.map(([tree, leaves]) => [tree, leaves])).toEqual([
      [ADDRESS.tree, [filled(3)]],
      [OTHER.tree, [filled(2), filled(5)]],
    ]);
    // The address tree's utxo root comes from its head, no live fact sits in it.
    expect(getAccount).toHaveBeenCalledWith(ADDRESS.tree, undefined);
    expect(proven.slots[0]).toMatchObject({ id: 4, nullifierRoot: filled(12) });
    expect(proven.slots[1]).toEqual({ id: 5, utxoRoot: filled(21), nullifierRoot: filled(22) });
    expect(proven.contexts[1]).toEqual({ utxoTreeRootIndex: 21, nullifierTreeRootIndex: 22 });
  });

  it("derives each revocation PDA under its fact's tree and refuses an index past the trees", async () => {
    const targets = [filled(7), filled(8), ...Array.from({ length: 8 }, () => filled(0))];
    const trees = [ADDRESS.tree, OTHER.tree];
    expect(
      await revocationPdaAddresses({
        policyTrees: trees,
        targets,
        treeIndexes: [1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
      }),
    ).toEqual([
      await nullifierPdaAddress(OTHER.tree, filled(7)),
      await nullifierPdaAddress(ADDRESS.tree, filled(8)),
    ]);
    for (const treeIndexes of [
      [2, 0, 0, 0, 0, 0, 0, 0, 0, 0],
      [0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
    ]) {
      await expect(
        revocationPdaAddresses({ policyTrees: trees, targets, treeIndexes }),
      ).rejects.toMatchObject({ code: "RING_POLICY_SHAPE_UNSUPPORTED" });
    }
  });
});
