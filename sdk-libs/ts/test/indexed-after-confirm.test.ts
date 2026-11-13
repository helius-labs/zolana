import { getBase58Decoder, signature } from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import { SprClient, atSlot, createIndexerPollConfig } from "../src/client/index.js";

const RPC_URL = "https://rpc.example.com/spr";
const SIGNATURE = signature(getBase58Decoder().decode(new Uint8Array(64).fill(7)));
const OTHER = signature(getBase58Decoder().decode(new Uint8Array(64).fill(8)));
const LANDED = 42;
const POLL = createIndexerPollConfig(5, 0n, 0n);

const event = {
  eventIndex: 0,
  transaction: {
    slot: LANDED,
    txSignature: SIGNATURE,
    eventIndex: 0,
    txViewingPk: null,
    salt: null,
    outputSlots: [],
    messages: [],
    nullifiers: [],
    proofless: false,
  },
};

function reply(id: unknown, result: unknown): Response {
  return Response.json({ jsonrpc: "2.0", id, result });
}

/**
 * An RPC that confirms every signature at slot 42, and an indexer two slots
 * behind it that catches up by `advance` slots per request.
 */
function laggingStack(advance = 1) {
  let indexerSlot = LANDED - 2;
  const indexerSlots: number[] = [];
  const fetch = vi.fn<typeof globalThis.fetch>(async (input, init) => {
    const body: unknown = JSON.parse(String(init?.body));
    if (typeof body !== "object" || body === null || !("id" in body) || !("method" in body)) {
      throw new Error("not a JSON-RPC request");
    }
    if (body.method === "getSignatureStatuses") {
      return reply(body.id, {
        context: { slot: LANDED },
        value: [{ slot: LANDED, confirmations: null, err: null, confirmationStatus: "confirmed" }],
      });
    }
    if (String(input).endsWith("/getShieldedTransactionsBySignature")) {
      const slot = indexerSlot;
      indexerSlots.push(slot);
      indexerSlot += advance;
      return reply(body.id, {
        context: { blockTime: 0, slot },
        transactions: slot >= LANDED ? [event] : [],
      });
    }
    throw new Error(`unexpected request ${String(input)}`);
  });
  const client = new SprClient({
    solanaRpcUrl: RPC_URL,
    proofDataSource: "client",
    fetch,
    indexerConfig: { poll: POLL },
  });
  return { client, indexerSlots };
}

describe("a signature lookup after confirmation", () => {
  it("waits for a lagging indexer to reach the slot the transaction landed in", async () => {
    const { client, indexerSlots } = laggingStack();
    await expect(client.confirmTransaction(SIGNATURE)).resolves.toBe(BigInt(LANDED));
    const response = await client.getShieldedTransactionsBySignature(SIGNATURE);
    expect(response.context.slot).toBe(BigInt(LANDED));
    expect(response.transactions).toHaveLength(1);
    expect(indexerSlots).toEqual([40, 41, 42]);
  });

  it("reads once for a signature the client did not confirm", async () => {
    const { client, indexerSlots } = laggingStack();
    await client.confirmTransaction(OTHER);
    const response = await client.getShieldedTransactionsBySignature(SIGNATURE);
    expect(response.transactions).toEqual([]);
    expect(indexerSlots).toEqual([40]);
  });

  it("keeps an explicit config as given", async () => {
    const { client, indexerSlots } = laggingStack();
    await client.confirmTransaction(SIGNATURE);
    const once = await client.getShieldedTransactionsBySignature(SIGNATURE, { poll: POLL });
    expect(once.transactions).toEqual([]);
    expect(indexerSlots).toEqual([40]);
    const waited = await client.getShieldedTransactionsBySignature(SIGNATURE, atSlot(42n, POLL));
    expect(waited.transactions).toHaveLength(1);
    expect(indexerSlots).toEqual([40, 41, 42]);
  });

  it("reports an indexer that never catches up", async () => {
    const { client, indexerSlots } = laggingStack(0);
    await client.confirmTransaction(SIGNATURE);
    await expect(client.getShieldedTransactionsBySignature(SIGNATURE)).rejects.toMatchObject({
      code: "CLIENT_INDEXER_NOT_CAUGHT_UP",
      details: { target: "42", latest: "40", attempts: 6 },
    });
    expect(indexerSlots).toEqual([40, 40, 40, 40, 40, 40]);
  });
});
