import {
  getAddressDecoder,
  getProgramDerivedAddress,
  generateKeyPairSigner,
  signTransactionWithSigners,
} from "@solana/kit";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { initializePoseidon } from "../src/hasher/index.js";
import { ClientError } from "../src/client/error.js";
import type { TransferInputs } from "../src/client/prover/types.js";
import type { RingSpendRegistrationClient } from "../src/ring/register-spend.js";
import {
  buildRingSpendRegistrationTransaction,
  createRingSpendRegistrationSubmission,
  prepareRingSpendRegistration,
} from "../src/ring/register-spend.js";
import { ringPolicyNamespaceAddress, fetchRingConfigs } from "../src/ring/config.js";
import { ringConfigAddress, ringPolicyConfigAddress } from "../src/interface/pda/index.js";
import { addressBytes } from "../src/interface/internal.js";
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
import { KEY_REGISTRY_FIELD_MAX, keyRegistryZeroBytes } from "../src/ring/key-registry-tree.js";
import { SOL_MINT } from "../src/transaction/asset.js";
import { bigIntBytes } from "../src/transaction/internal.js";
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
  const zeros = keyRegistryZeroBytes();
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
            addressTree: TREE,
            bump: policyBump,
            namespaceOwnerHash: ringNamespaceOwnerHash(namespace),
          }),
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
    getRingSpendRecord: async () => ({ context: { slot: 1n, blockTime: 1n }, record: null }),
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
        highElement: KEY_REGISTRY_FIELD_MAX,
        highElementIndex: 1n,
        root: field(1),
        rootSeq: 1n,
        rootIndex: 0,
      })),
    }),
    proveTransferInputs: spp,
  };
  return {
    client,
    member,
    spp,
    auditor,
    setSlot: (value: bigint) => {
      slot = value;
    },
  };
}

function outputHash(spp: { mock: { calls: readonly (readonly [TransferInputs])[] } }, call = 0) {
  const output = spp.mock.calls[call]?.[0]?.outputs[0];
  if (output === undefined) throw new Error("registration output missing");
  return { hash: bigIntBytes(output.hash), blinding: bigIntBytes(output.circuit.blinding) };
}

describe("compressed registration flow", () => {
  it("proves the address claim for a genesis record in the pinned window", async () => {
    const test = await fixture();
    await buildRingSpendRegistrationTransaction({
      client: test.client,
      ringProgramId: RING,
      payer: PAYER,
    });
    const config = await fetchRingConfigs(test.client, RING);
    if (!config.hasPolicy) throw new Error("policy missing");
    const output = outputHash(test.spp);
    const hashes = RingListNamespace.of(
      await ringPolicyNamespaceAddress(RING),
      config.policy.addressTreeId,
    ).spendRecordHashes(
      {
        member: test.member,
        version: 0n,
        window: 7n,
        countersCommitment: spendCountersCommitment(zeroSpendCounters()),
        blinding: output.blinding as Bytes32,
      },
      config.policy.addressTreeId,
    );
    expect(output.hash).toEqual(hashes.utxoHash);
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
    const send = vi.fn(async () => undefined);
    const sign = vi.fn(async (transaction: Parameters<typeof signTransactionWithSigners>[1]) =>
      signTransactionWithSigners([payer], transaction),
    );
    const unknown = await submission.send({
      sign,
      send,
      status: async () => ({ kind: "unknown" }),
    });
    test.setSlot(800n);
    expect(
      await submission.send({ sign, send, status: async () => ({ kind: "unknown" }) }),
    ).toEqual(unknown);
    expect(test.spp).toHaveBeenCalledTimes(1);
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
    expect(test.spp).toHaveBeenCalledTimes(2);
    expect(outputHash(test.spp, 1).hash).not.toEqual(outputHash(test.spp, 0).hash);
    test.auditor.destroy();
  });

  it("surfaces an indexer failure instead of treating the member as unregistered", async () => {
    const test = await fixture();
    const failure = new ClientError("CLIENT_INDEXER", {
      details: { method: "getRingSpendRecord", retryable: true },
    });
    await expect(
      prepareRingSpendRegistration({
        client: {
          ...test.client,
          getRingSpendRecord: async () => {
            throw failure;
          },
        },
        ringProgramId: RING,
        payer: PAYER,
      }),
    ).rejects.toBe(failure);
    expect(test.spp).not.toHaveBeenCalled();
    test.auditor.destroy();
  });

  it("builds a registration only for an unregistered member", async () => {
    const test = await fixture();
    const prepared = await prepareRingSpendRegistration({
      client: test.client,
      ringProgramId: RING,
      payer: PAYER,
    });
    expect(prepared.kind).toBe("pending");
    expect(test.spp).toHaveBeenCalledTimes(1);
    test.auditor.destroy();
  });
});
