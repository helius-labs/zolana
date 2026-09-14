import {
  getAddressDecoder,
  getProgramDerivedAddress,
  generateKeyPairSigner,
  signTransactionWithSigners,
} from "@solana/kit";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { initializePoseidon } from "../src/hasher/index.js";
import { ClientError } from "../src/client/error.js";
import type { CustomRingRegisterProofRequest, TransferInputs } from "../src/client/prover/types.js";
import type { RingSpendRegistrationClient } from "../src/ring/register-spend.js";
import {
  buildRingSpendRegistrationTransaction,
  createRingSpendRegistrationSubmission,
  prepareRingSpendRegistration,
} from "../src/ring/register-spend.js";
import {
  ringConfigAddress,
  ringPolicyConfigAddress,
  ringPolicyNamespaceAddress,
  fetchRingConfigs,
} from "../src/ring/config.js";
import { ringHeadMapRootPda } from "../src/interface/pda/index.js";
import { Writer, addressBytes } from "../src/interface/internal.js";
import { SHIELDED_POOL_PROGRAM_ID } from "../src/interface/program.js";
import type { Bytes32, TransactProof } from "../src/interface/types.js";
import { ViewingKey } from "../src/keypair/viewing-key.js";
import {
  buildRuleTable,
  memberOfAsset,
  memberOfTag,
  ringNamespaceOwnerHash,
  RingListNamespace,
  spendCountersCommitment,
  zeroSpendCounters,
} from "../src/ring/policy.js";
import {
  HEAD_MAP_EMPTY_ROOT,
  HEAD_MAP_FIELD_MAX,
  headMapLeaf,
  headMapZeroBytes,
  verifyHeadMapInsert,
} from "../src/ring/head-map.js";
import { SOL_MINT } from "../src/transaction/asset.js";
import { hashChain, bigIntBytes } from "../src/transaction/internal.js";
import { BLOCKHASH } from "./helpers/clients.js";
import {
  ownSources,
  ownedAccount,
  ringPolicyConfigData,
  ringProgramConfigData,
} from "./helpers/ring-accounts.js";
import { treeAccount } from "./helpers/tree-account.js";

const field = (value: number): Bytes32 => {
  const bytes = new Uint8Array(32);
  bytes[31] = value;
  return bytes as Bytes32;
};
const address = (value: number) => getAddressDecoder().decode(field(value));
const RING = address(9),
  TREE = address(8),
  PAYER = address(7);
const PROOF: TransactProof = {
  a: field(0),
  b: new Uint8Array(128) as TransactProof["b"],
  c: field(0),
};
beforeAll(initializePoseidon);

async function fixture(payer = PAYER) {
  const namespace = await ringPolicyNamespaceAddress(RING);
  const config = await ringConfigAddress(RING),
    policy = await ringPolicyConfigAddress(RING);
  const [root, rootBump] = await ringHeadMapRootPda(RING);
  const [, configBump] = await getProgramDerivedAddress({
    programAddress: RING,
    seeds: [new TextEncoder().encode("config")],
  });
  const [, policyBump] = await getProgramDerivedAddress({
    programAddress: RING,
    seeds: [new TextEncoder().encode("policy")],
  });
  const auditor = ViewingKey.fromBytes(field(2));
  const table = buildRuleTable({
    rules: [],
    windowSlots: 100n,
    velocity: [{ asset: memberOfAsset(SOL_MINT), cap: 100n, cosignAbove: 0n }],
  });
  const member = memberOfTag(addressBytes(payer));
  const zeros = headMapZeroBytes();
  const head = {
    context: { slot: 1n, blockTime: 1n },
    root: HEAD_MAP_EMPTY_ROOT,
    nextIndex: 1n,
    member,
    lowMember: field(0),
    lowNext: HEAD_MAP_FIELD_MAX,
    lowNullifier: field(0),
    lowIndex: 0n,
    lowProof: zeros.slice(0, 40),
    newProof: [headMapLeaf(field(0), member, field(0)), ...zeros.slice(1, 40)],
  };
  let request: CustomRingRegisterProofRequest | undefined;
  const prove = vi.fn(async (input: CustomRingRegisterProofRequest) => {
    request = input;
    return new Uint8Array(128);
  });
  const spp = vi.fn(async (_input: TransferInputs) => PROOF);
  let slot = 700n;
  const client: RingSpendRegistrationClient = {
    getAccount: async (key) => {
      if (key === config)
        return ownedAccount(
          RING,
          ringProgramConfigData({
            authority: PAYER,
            auditorPublicKey: auditor.publicKey().toBytes(),
            bump: configBump,
            hasPolicy: true,
          }),
        );
      if (key === policy)
        return ownedAccount(
          RING,
          ringPolicyConfigData({
            table,
            sources: ownSources(table, namespace),
            entriesTree: TREE,
            bump: policyBump,
            namespaceOwnerHash: ringNamespaceOwnerHash(namespace),
          }),
        );
      if (key === root)
        return ownedAccount(
          RING,
          new Writer()
            .u8(8, "tag")
            .bytes(HEAD_MAP_EMPTY_ROOT)
            .u64(1n, "cursor")
            .u8(rootBump, "bump")
            .finish(),
        );
      if (key === TREE)
        return ownedAccount(
          SHIELDED_POOL_PROGRAM_ID,
          treeAccount({ stateCursor: 0, written: 1, nullifierCursor: 0n }),
        );
      return undefined;
    },
    getLatestBlockhash: async () => BLOCKHASH,
    getSlot: async () => slot,
    getRingHeadRegisterProof: async () => head,
    getRingHeadTransferProof: async () => {
      throw new ClientError("CLIENT_HEAD_MEMBER_UNREGISTERED", {
        details: { method: "getRingHeadTransferProof" },
      });
    },
    getMerkleProofs: async () => {
      throw new Error("registration must not request membership");
    },
    getNonInclusionProofs: async (tree, leaves) => ({
      context: { slot: 1n, blockTime: 1n },
      proofs: leaves.map((leaf) => ({
        leaf,
        merkleContext: { treeType: 1, tree },
        path: zeros.slice(0, 40),
        lowElement: field(0),
        lowElementIndex: 0n,
        highElement: HEAD_MAP_FIELD_MAX,
        highElementIndex: 1n,
        root: field(1),
        rootSeq: 1n,
        rootIndex: 0,
      })),
    }),
    proveTransferInputs: spp,
    proveCustomRingRegister: prove,
  };
  return {
    client,
    head,
    prove,
    spp,
    request: () => request,
    auditor,
    setSlot: (value: bigint) => {
      slot = value;
    },
  };
}

describe("compressed registration flow", () => {
  it("proves the address claim and a separate authenticated head insertion", async () => {
    const test = await fixture();
    const transaction = await buildRingSpendRegistrationTransaction({
      client: test.client,
      ringProgramId: RING,
      payer: PAYER,
    });
    expect(transaction.messageBytes.length).toBeGreaterThan(461);
    const request = test.request();
    if (request === undefined) throw new Error("registration proof missing");
    const config = await fetchRingConfigs(test.client, RING);
    if (!config.hasPolicy) throw new Error("policy missing");
    const spp = test.spp.mock.calls[0]?.[0];
    const output = spp?.outputs[0];
    if (output === undefined) throw new Error("registration output missing");
    const hashes = RingListNamespace.of(
      await ringPolicyNamespaceAddress(RING),
      config.policy.entriesTreeId,
    ).spendRecordHashes({
      member: test.head.member,
      version: 0n,
      window: 7n,
      countersCommitment: spendCountersCommitment(zeroSpendCounters()),
      blinding: bigIntBytes(output.circuit.blinding) as Bytes32,
    });
    expect(request.genesis).toEqual(hashes.nullifier);
    expect(request.headNewRoot).toEqual(
      verifyHeadMapInsert({
        root: test.head.root,
        appendIndex: test.head.nextIndex,
        member: test.head.member,
        genesis: request.genesis,
        lowMember: test.head.lowMember,
        lowNext: test.head.lowNext,
        lowNullifier: test.head.lowNullifier,
        lowIndex: test.head.lowIndex,
        lowProof: test.head.lowProof,
        newProof: test.head.newProof,
      }),
    );
    expect(request.publicInputHash).toEqual(
      hashChain([
        request.headOldRoot,
        request.headNewRoot,
        request.member,
        request.genesis,
        bigIntBytes(1n) as Bytes32,
      ]),
    );
    test.auditor.destroy();
  });

  it("rebuilds a known failed registration at the new window, never while its send is unknown", async () => {
    const payer = await generateKeyPairSigner();
    const test = await fixture(payer.address);
    const submission = await createRingSpendRegistrationSubmission({
      client: test.client,
      ringProgramId: RING,
      payer,
    });
    const send = vi.fn(async () => {});
    const sign = vi.fn(async (transaction: Parameters<typeof signTransactionWithSigners>[1]) =>
      signTransactionWithSigners([payer], transaction),
    );
    const first = test.request();
    const unknown = await submission.send({
      sign,
      send,
      status: async () => ({ kind: "unknown" }),
    });
    test.setSlot(800n);
    expect(
      await submission.send({ sign, send, status: async () => ({ kind: "unknown" }) }),
    ).toEqual(unknown);
    expect(test.prove).toHaveBeenCalledTimes(1);
    let statuses = 0;
    const result = await submission.send({
      sign,
      send,
      status: async () =>
        statuses++ === 0
          ? { kind: "failed", instructionIndex: 0, customCode: 8101 }
          : { kind: "confirmed", slot: 801n },
    });
    expect(result).toMatchObject({ kind: "confirmed", attempts: 2 });
    expect(send).toHaveBeenCalledTimes(2);
    expect(test.prove).toHaveBeenCalledTimes(2);
    expect(test.request()?.genesis).not.toEqual(first?.genesis);
    test.auditor.destroy();
  });

  it("rejects stale correlated head state before requesting either proof", async () => {
    const test = await fixture();
    const spp = vi.fn(test.client.proveTransferInputs);
    await expect(
      buildRingSpendRegistrationTransaction({
        client: {
          ...test.client,
          proveTransferInputs: spp,
          getRingHeadRegisterProof: async () => ({ ...test.head, nextIndex: 2n }),
        },
        ringProgramId: RING,
        payer: PAYER,
      }),
    ).rejects.toMatchObject({ code: "RING_HEAD_MAP_STALE" });
    expect(spp).not.toHaveBeenCalled();
    expect(test.prove).not.toHaveBeenCalled();
    test.auditor.destroy();
  });

  it("does not interpret indexer unavailability as unregistered", async () => {
    const test = await fixture();
    await expect(
      prepareRingSpendRegistration({
        client: {
          ...test.client,
          getRingHeadTransferProof: async () => {
            throw new ClientError("CLIENT_HEAD_MAP_OUT_OF_SYNC", {
              details: { method: "getRingHeadTransferProof" },
            });
          },
        },
        ringProgramId: RING,
        payer: PAYER,
      }),
    ).rejects.toMatchObject({ code: "CLIENT_HEAD_MAP_OUT_OF_SYNC" });
    expect(test.prove).not.toHaveBeenCalled();
    test.auditor.destroy();
  });
});
