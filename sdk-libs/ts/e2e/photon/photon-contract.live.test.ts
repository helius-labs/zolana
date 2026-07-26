/// <reference types="node" />

/**
 * Gate 6 — same-revision live Photon contract.
 *
 * Boots `startLocalStack` Photon's binary (offset 800) and drives every
 * production indexer method through `@zolana/api` / `ZolanaIndexer`. The stack
 * reads `CARGO_TARGET_DIR` (else `<repo>/target`) for the same-revision
 * `debug/photon` and `deploy/*.so` that CI builds with `just build-photon` /
 * `just build-programs`. Assertions require the client's decoder to accept the
 * live payload and the wire fields the decoder depends on to arrive in the
 * types Photon actually emits (not a recorded fixture).
 *
 * Light's precedent is `js/stateless.js/tests/e2e/rpc-interop.test.ts`: live
 * Photon, production SDK client, field-level checks after real chain activity.
 */

import { ApiError, ZolanaApi } from "@zolana/api";
import { ClientError, createAndSendTransaction, createIndexerRpcConfig } from "@zolana/client";
import {
  GET_ENCRYPTED_UTXOS_BY_TAGS,
  GET_MERKLE_PROOFS,
  GET_NON_INCLUSION_PROOFS,
  GET_NULLIFIER_QUEUE_ELEMENTS,
  GET_SHIELDED_TRANSACTIONS_BY_TAGS,
  PAGE_LIMIT,
  hash,
  limit,
} from "@zolana/indexer-api";
import {
  getEncryptedUtxosByTagsMethod,
  getMerkleProofsMethod,
  getNonInclusionProofsMethod,
  getNullifierQueueElementsMethod,
  getShieldedTransactionsByTagsMethod,
} from "@zolana/indexer-api/methods";
import type { Address, Bytes32, Signature } from "@zolana/interface";
import { TREE_ACCOUNT_SIZE } from "@zolana/interface";
import { ShieldedKeypair } from "@zolana/keypair";
import { SOL_MINT } from "@zolana/transaction";
import { createTestWallet, startLocalStack, type LocalStack } from "@zolana/test-kit";
import {
  createE2eHarness,
  createProtocolConfigInstructions,
  createTestNativeSigner,
  createTreeInstructions,
  signTestTransaction,
  type E2eHarness,
} from "@zolana/test-kit/node";
import { createDeposit, deposit, ensureRegistered, syncWallet } from "@zolana/wallet";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const DEFAULT_OFFSET = 800;
const DEPOSIT_AMOUNT = 1_000_000_000n;
const DEPOSIT_COUNT = 3;
const REQUEST_ID = "test-account";

function bytes32(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

async function airdrop(url: URL, address: Address, lamports: bigint): Promise<Signature> {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "requestAirdrop",
      params: [address, Number(lamports)],
    }),
  });
  const envelope = (await response.json()) as { result?: Signature; error?: unknown };
  if (envelope.result === undefined) {
    throw new Error(`airdrop failed: ${JSON.stringify(envelope.error)}`);
  }
  return envelope.result;
}

async function confirm(
  rpc: E2eHarness["rpc"],
  signature: Signature,
  timeoutMs = 60_000,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await rpc.confirmTransaction(signature)) return;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(`transaction confirmation timed out: ${signature}`);
}

async function waitForAccount(
  rpc: E2eHarness["rpc"],
  address: Address,
  timeoutMs = 60_000,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if ((await rpc.getAccount(address)) !== undefined) return;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(`account did not appear: ${address}`);
}

async function syncUntil(
  input: Parameters<typeof syncWallet>[0],
  predicate: () => boolean,
  timeoutMs = 120_000,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    await syncWallet({
      ...input,
      config: { waitForIndexer: true, ...(input.config ?? {}) },
    });
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error("wallet sync predicate timed out");
}

interface JsonRpcEnvelope {
  readonly result?: unknown;
  readonly error?: Readonly<{ code?: unknown; message?: unknown }>;
}

/** POST the same path shape `@zolana/api` uses, return the parsed envelope. */
async function rawIndexerCall(
  indexerUrl: URL,
  method: string,
  params: Readonly<Record<string, unknown>>,
): Promise<{
  readonly status: number;
  readonly bodyText: string;
  readonly envelope: JsonRpcEnvelope;
}> {
  const url = new URL(indexerUrl.href);
  url.pathname = `${url.pathname.replace(/\/+$/u, "")}/${method}`;
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      id: REQUEST_ID,
      jsonrpc: "2.0",
      method,
      params,
    }),
  });
  const bodyText = await response.text();
  return {
    status: response.status,
    bodyText,
    envelope: JSON.parse(bodyText) as JsonRpcEnvelope,
  };
}

function asRecord(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} is not an object`);
  }
  return value as Record<string, unknown>;
}

/** Safe-range integers Photon emits as JSON numbers (C04 / Light UnsignedInteger). */
function expectWireNumber(value: unknown, path: string): number {
  expect(typeof value, `${path} must be a JSON number on the live wire`).toBe("number");
  expect(Number.isSafeInteger(value), `${path} must be a safe integer`).toBe(true);
  return value as number;
}

function expectWireContext(context: unknown): void {
  const record = asRecord(context, "context");
  expect(Object.keys(record).sort()).toEqual(["block_time"]);
  expectWireNumber(record["block_time"], "context.block_time");
}

describe("gate 6 live Photon contract", () => {
  const offset = Number(process.env["ZOLANA_PORT_OFFSET"] ?? String(DEFAULT_OFFSET));

  let stack: LocalStack;
  let harness: E2eHarness;
  let api: ZolanaApi;
  let tree: Address;
  let recipientTag: Bytes32;
  let leafHashes: Bytes32[];

  beforeAll(async () => {
    expect(offset).toBe(DEFAULT_OFFSET);
    stack = await startLocalStack({ portOffset: offset });
    const authoritySeed = bytes32(61);
    const payerSeed = bytes32(62);
    const treeSeed = bytes32(63);
    const recipientSeed = bytes32(64);

    const authority = createTestNativeSigner(authoritySeed);
    const payer = createTestNativeSigner(payerSeed);
    const treeSigner = createTestNativeSigner(treeSeed);
    const recipientSigner = createTestNativeSigner(recipientSeed);
    tree = treeSigner.address;

    const recipient = createTestWallet(recipientSeed);
    const recipientKeypair = ShieldedKeypair.fromEd25519(recipientSeed, 0);
    recipientTag = recipient.wallet.identity.confidentialViewTag();

    harness = createE2eHarness(stack, tree);
    api = new ZolanaApi({ url: stack.indexerUrl });

    for (const [address, lamports] of [
      [authority.address, 2_000_000_000n],
      [payer.address, 20_000_000_000n],
      [recipientSigner.address, 10_000_000_000n],
    ] as const) {
      await confirm(harness.rpc, await airdrop(stack.rpcUrl, address, lamports));
    }

    const configSig = await createAndSendTransaction({
      rpc: harness.rpc,
      feePayer: authority.address,
      instructions: [...createProtocolConfigInstructions({ authority: authority.address })],
      sign: (transaction) => signTestTransaction(transaction, [authority]),
    });
    await confirm(harness.rpc, configSig);

    const treeIxs = await createTreeInstructions(harness.rpc, {
      payer: payer.address,
      authority: authority.address,
      tree,
      accountSize: TREE_ACCOUNT_SIZE,
    });
    const treeSig = await createAndSendTransaction({
      rpc: harness.rpc,
      feePayer: payer.address,
      instructions: [...treeIxs],
      sign: (transaction) => signTestTransaction(transaction, [payer, treeSigner, authority]),
    });
    await confirm(harness.rpc, treeSig);
    await waitForAccount(harness.rpc, tree);

    const registration = await ensureRegistered({
      rpc: harness.rpc,
      funding: recipientSigner,
      keypair: recipientKeypair,
    });
    expect(registration).toBeTypeOf("string");
    await confirm(harness.rpc, registration as Signature);

    for (let index = 0; index < DEPOSIT_COUNT; index += 1) {
      const note = createDeposit({
        recipient: await recipient.authority.shieldedAddress(),
        asset: SOL_MINT,
        amount: DEPOSIT_AMOUNT + BigInt(index),
      });
      const depositSig = await deposit({
        rpc: harness.rpc,
        payer: recipientSigner,
        depositor: recipientSigner,
        tree,
        deposit: note,
      });
      await confirm(harness.rpc, depositSig);
    }

    await syncUntil(
      {
        wallet: recipient.wallet,
        authority: recipient.authority,
        indexer: harness.indexer,
        registryRpc: harness.rpc,
      },
      () =>
        recipient.wallet
          .utxos()
          .filter((entry) => !entry.spent && entry.outputContext.tree === tree).length >=
        DEPOSIT_COUNT,
    );

    leafHashes = recipient.wallet
      .utxos()
      .filter((entry) => !entry.spent && entry.outputContext.tree === tree)
      .map((entry) => entry.outputContext.hash);
    expect(leafHashes.length).toBeGreaterThanOrEqual(DEPOSIT_COUNT);
  }, 600_000);

  afterAll(async () => {
    if (harness !== undefined) {
      await harness.stop();
      return;
    }
    if (stack !== undefined) await stack.stop();
  });

  it("rejects empty tags with a JSON-RPC error the API layer classifies", async () => {
    const wire = await rawIndexerCall(stack.indexerUrl, GET_ENCRYPTED_UTXOS_BY_TAGS, {
      tags: [],
    });
    expect(wire.status).toBe(200);
    expect(wire.envelope.result).toBeUndefined();
    expect(typeof wire.envelope.error?.code).toBe("number");
    expect(typeof wire.envelope.error?.message).toBe("string");
    expect(String(wire.envelope.error?.message)).toMatch(/at least one tag/i);

    await expect(api.getEncryptedUtxosByTags({ tags: [] as never })).rejects.toBeInstanceOf(
      ApiError,
    );
    await expect(api.getEncryptedUtxosByTags({ tags: [] as never })).rejects.toMatchObject({
      code: "API_JSON_RPC",
    });
  });

  it("rejects a page limit above Photon's PAGE_LIMIT", async () => {
    const tag = hash(recipientTag);
    const wire = await rawIndexerCall(stack.indexerUrl, GET_ENCRYPTED_UTXOS_BY_TAGS, {
      tags: [tag],
      limit: Number(PAGE_LIMIT) + 1,
    });
    expect(wire.envelope.result).toBeUndefined();
    expect(typeof wire.envelope.error?.code).toBe("number");

    // Client-side `limit()` refuses before the wire; Photon's Limit type is the
    // same 1..=1000 bound the raw call above already exercised.
    expect(() => limit(PAGE_LIMIT + 1n)).toThrow();
  });

  it("rejects merkle proofs for an unknown tree", async () => {
    const unknownTree = "11111111111111111111111111111111" as Address;
    const leaf = hash(leafHashes[0]!);
    const wire = await rawIndexerCall(stack.indexerUrl, GET_MERKLE_PROOFS, {
      tree_account: unknownTree,
      leaves: [leaf],
    });
    expect(wire.envelope.result).toBeUndefined();
    expect(String(wire.envelope.error?.message)).toMatch(/invalid public key|validation/i);

    await expect(
      api.getMerkleProofs({ treeAccount: unknownTree, leaves: [leaf] }),
    ).rejects.toMatchObject({ code: "API_JSON_RPC" });
  });

  it("returns empty match lists with the decoded context shape", async () => {
    const stranger = hash(bytes32(200));
    const encrypted = await api.getEncryptedUtxosByTags({ tags: [stranger] });
    expect(typeof encrypted.context.blockTime).toBe("bigint");
    expect(encrypted.matches).toEqual([]);
    expect(encrypted.nextCursor).toBeUndefined();

    const shielded = await api.getShieldedTransactionsByTags({ tags: [stranger] });
    expect(typeof shielded.context.blockTime).toBe("bigint");
    expect(shielded.transactions).toEqual([]);
    expect(shielded.nextCursor).toBeUndefined();

    const queue = await api.getNullifierQueueElements({
      treeAccount: tree,
      limit: limit(10n),
    });
    expect(typeof queue.context.blockTime).toBe("bigint");
    expect(queue.elements).toEqual([]);

    const encryptedWire = await rawIndexerCall(
      stack.indexerUrl,
      GET_ENCRYPTED_UTXOS_BY_TAGS,
      getEncryptedUtxosByTagsMethod.encodeRequest({ tags: [stranger] }),
    );
    expect(encryptedWire.status).toBe(200);
    const encryptedResult = asRecord(encryptedWire.envelope.result, "encrypted empty result");
    expectWireContext(encryptedResult["context"]);
    expect(encryptedResult["matches"]).toEqual([]);
    expect(
      getEncryptedUtxosByTagsMethod.decodeResponse(encryptedWire.envelope.result),
    ).toMatchObject({ matches: [] });
  });

  it("decodes live encrypted UTXO matches including integer-domain fields", async () => {
    const tag = hash(recipientTag);
    const params = getEncryptedUtxosByTagsMethod.encodeRequest({
      tags: [tag],
      limit: limit(PAGE_LIMIT),
    });
    expect(params["limit"]).toBe(Number(PAGE_LIMIT));

    const wire = await rawIndexerCall(stack.indexerUrl, GET_ENCRYPTED_UTXOS_BY_TAGS, params);
    expect(wire.status).toBe(200);
    expect(wire.bodyText.length).toBeLessThan(10 * 1024 * 1024);

    const result = asRecord(wire.envelope.result, "encrypted result");
    expectWireContext(result["context"]);
    expect(Array.isArray(result["matches"])).toBe(true);
    expect((result["matches"] as unknown[]).length).toBeGreaterThanOrEqual(DEPOSIT_COUNT);

    const match = asRecord((result["matches"] as unknown[])[0], "matches[0]");
    expectWireNumber(match["slot"], "matches[0].slot");
    expect(typeof match["tx_signature"]).toBe("string");
    const outputSlot = asRecord(match["output_slot"], "matches[0].output_slot");
    expect(typeof outputSlot["view_tag"]).toBe("string");
    expect(typeof outputSlot["payload"]).toBe("string");
    const outputContext = asRecord(outputSlot["output_context"], "output_context");
    expect(typeof outputContext["hash"]).toBe("string");
    expect(outputContext["tree"]).toBe(tree);
    expectWireNumber(outputContext["leaf_index"], "output_context.leaf_index");

    const decoded = getEncryptedUtxosByTagsMethod.decodeResponse(wire.envelope.result);
    expect(decoded.matches.length).toBeGreaterThanOrEqual(DEPOSIT_COUNT);
    expect(typeof decoded.matches[0]?.slot).toBe("bigint");
    expect(typeof decoded.context.blockTime).toBe("bigint");

    const throughApi = await api.getEncryptedUtxosByTags({
      tags: [tag],
      limit: limit(PAGE_LIMIT),
    });
    expect(throughApi.matches.length).toBe(decoded.matches.length);

    const throughIndexer = await harness.indexer.getEncryptedUtxosByTags({
      tags: [recipientTag],
      limit: Number(PAGE_LIMIT),
    });
    expect(throughIndexer.matches.length).toBe(decoded.matches.length);
    expect(throughIndexer.matches[0]?.outputSlot.outputContext.tree).toBe(tree);
  });

  it("paginates encrypted UTXOs with limit and next_cursor", async () => {
    const tag = hash(recipientTag);
    const first = await api.getEncryptedUtxosByTags({ tags: [tag], limit: limit(1n) });
    expect(first.matches).toHaveLength(1);
    expect(first.nextCursor).toBeDefined();
    expect(typeof first.nextCursor).toBe("string");

    const firstWire = await rawIndexerCall(stack.indexerUrl, GET_ENCRYPTED_UTXOS_BY_TAGS, {
      tags: [tag],
      limit: 1,
    });
    const firstResult = asRecord(firstWire.envelope.result, "page 1");
    expect(typeof firstResult["next_cursor"]).toBe("string");

    const second = await api.getEncryptedUtxosByTags({
      tags: [tag],
      limit: limit(1n),
      cursor: first.nextCursor,
    });
    expect(second.matches).toHaveLength(1);
    expect(second.matches[0]?.txSignature).not.toBe(first.matches[0]?.txSignature);

    const omittedLimit = await api.getEncryptedUtxosByTags({ tags: [tag] });
    expect(omittedLimit.matches.length).toBeGreaterThanOrEqual(DEPOSIT_COUNT);
  });

  it("decodes live shielded transactions including proofless deposits", async () => {
    const tag = hash(recipientTag);
    const wire = await rawIndexerCall(
      stack.indexerUrl,
      GET_SHIELDED_TRANSACTIONS_BY_TAGS,
      getShieldedTransactionsByTagsMethod.encodeRequest({ tags: [tag], limit: limit(10n) }),
    );
    const result = asRecord(wire.envelope.result, "shielded result");
    expectWireContext(result["context"]);
    const transactions = result["transactions"] as unknown[];
    expect(transactions.length).toBeGreaterThanOrEqual(DEPOSIT_COUNT);

    const transaction = asRecord(transactions[0], "transactions[0]");
    expectWireNumber(transaction["slot"], "transactions[0].slot");
    expect(typeof transaction["tx_signature"]).toBe("string");
    expect(typeof transaction["proofless"]).toBe("boolean");
    expect(transaction["proofless"]).toBe(true);
    expect(Array.isArray(transaction["output_slots"])).toBe(true);
    expect(Array.isArray(transaction["messages"])).toBe(true);
    expect(Array.isArray(transaction["nullifiers"])).toBe(true);

    const decoded = getShieldedTransactionsByTagsMethod.decodeResponse(wire.envelope.result);
    expect(decoded.transactions.some((item) => item.proofless)).toBe(true);

    const throughIndexer = await harness.indexer.getShieldedTransactionsByTags({
      tags: [recipientTag],
      limit: 10,
    });
    expect(throughIndexer.transactions.length).toBeGreaterThanOrEqual(DEPOSIT_COUNT);
    expect(throughIndexer.transactions.every((item) => item.proofless)).toBe(true);
  });

  it("decodes live merkle proofs for deposited leaves", async () => {
    const leaves = leafHashes.slice(0, 2).map((leaf) => hash(leaf));
    const params = getMerkleProofsMethod.encodeRequest({ treeAccount: tree, leaves });
    expect(params).toEqual({ tree_account: tree, leaves });

    const wire = await rawIndexerCall(stack.indexerUrl, GET_MERKLE_PROOFS, params);
    const result = asRecord(wire.envelope.result, "merkle result");
    expectWireContext(result["context"]);
    const proofs = result["proofs"] as unknown[];
    expect(proofs).toHaveLength(leaves.length);

    const proof = asRecord(proofs[0], "proofs[0]");
    expect(typeof proof["leaf"]).toBe("string");
    expect(Array.isArray(proof["path"])).toBe(true);
    expectWireNumber(proof["leaf_index"], "proofs[0].leaf_index");
    expectWireNumber(proof["root_seq"], "proofs[0].root_seq");
    expectWireNumber(proof["root_index"], "proofs[0].root_index");
    const merkleContext = asRecord(proof["merkle_context"], "merkle_context");
    expectWireNumber(merkleContext["tree_type"], "merkle_context.tree_type");
    expect(merkleContext["tree"]).toBe(tree);

    const decoded = getMerkleProofsMethod.decodeResponse(wire.envelope.result);
    expect(decoded.proofs).toHaveLength(leaves.length);
    expect(typeof decoded.proofs[0]?.rootSeq).toBe("bigint");
    expect(typeof decoded.proofs[0]?.leafIndex).toBe("bigint");

    const throughIndexer = await harness.indexer.getMerkleProofs(
      tree,
      leafHashes.slice(0, 2),
      createIndexerRpcConfig(true),
    );
    expect(throughIndexer.proofs).toHaveLength(2);
    expect(throughIndexer.proofs[0]?.merkleContext.tree).toBe(tree);
  });

  it("decodes live non-inclusion proofs for an absent nullifier leaf", async () => {
    const absent = hash(bytes32(7));
    const params = getNonInclusionProofsMethod.encodeRequest({
      treeAccount: tree,
      leaves: [absent],
    });
    const wire = await rawIndexerCall(stack.indexerUrl, GET_NON_INCLUSION_PROOFS, params);
    const result = asRecord(wire.envelope.result, "non-inclusion result");
    expectWireContext(result["context"]);
    const proofs = result["proofs"] as unknown[];
    expect(proofs).toHaveLength(1);

    const proof = asRecord(proofs[0], "proofs[0]");
    expect(typeof proof["low_element"]).toBe("string");
    expect(typeof proof["high_element"]).toBe("string");
    expectWireNumber(proof["low_element_index"], "low_element_index");
    expectWireNumber(proof["high_element_index"], "high_element_index");
    expectWireNumber(proof["root_seq"], "root_seq");

    const decoded = getNonInclusionProofsMethod.decodeResponse(wire.envelope.result);
    expect(decoded.proofs).toHaveLength(1);
    expect(typeof decoded.proofs[0]?.rootSeq).toBe("bigint");

    const throughIndexer = await harness.indexer.getNonInclusionProofs(tree, [bytes32(7)]);
    expect(throughIndexer.proofs).toHaveLength(1);
  });

  it("decodes live nullifier queue responses", async () => {
    const params = getNullifierQueueElementsMethod.encodeRequest({
      treeAccount: tree,
      startSeq: 0n,
      limit: limit(10n),
    });
    expect(params["limit"]).toBe(10);
    expect(params["start_seq"]).toBe(0);

    const wire = await rawIndexerCall(stack.indexerUrl, GET_NULLIFIER_QUEUE_ELEMENTS, params);
    const result = asRecord(wire.envelope.result, "nullifier queue result");
    expectWireContext(result["context"]);
    expect(Array.isArray(result["elements"])).toBe(true);

    const decoded = getNullifierQueueElementsMethod.decodeResponse(wire.envelope.result);
    expect(decoded.elements).toEqual([]);

    const throughApi = await api.getNullifierQueueElements({
      treeAccount: tree,
      limit: limit(10n),
    });
    expect(throughApi.elements).toEqual([]);
  });

  it("surfaces a missing leaf as a client indexer error, not a silent empty proof", async () => {
    const missing = bytes32(99);
    await expect(harness.indexer.getMerkleProofs(tree, [missing])).rejects.toBeInstanceOf(
      ClientError,
    );
    await expect(harness.indexer.getMerkleProofs(tree, [missing])).rejects.toMatchObject({
      code: expect.stringMatching(/^CLIENT_/),
    });
  });
});
