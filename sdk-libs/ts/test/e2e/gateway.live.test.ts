// The SDK against this checkout's prover, Photon and ring RPC behind the
// reference gateway (docs/gateway.md), the way a hosted deployment serves them.
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { address } from "@solana/kit";

import {
  SOL_MINT,
  buildDepositTransaction,
  buildTransferTransaction,
  buildWithdrawalTransaction,
  createZolanaClient,
} from "../../src/index.js";
import type { ZolanaClient } from "../../src/client/client.js";
import { RingRpc } from "../../src/ring/index.js";
import { startReferenceGateway, type ReferenceGateway } from "../reference-gateway.js";
import { fund, liveHarness, signSendAndConfirm, sync } from "./live-helpers.js";
import { freshActor, requiredEnv } from "./ring-live-helpers.js";

const API_KEY = globalThis.crypto.randomUUID();

describe("services behind a gateway", () => {
  let gateway: ReferenceGateway;
  let client: ZolanaClient;
  let ring: RingRpc;

  beforeAll(async () => {
    const harness = await liveHarness();
    gateway = await startReferenceGateway({
      origins: {
        prover: harness.proverUrl,
        photon: harness.indexerUrl,
        ringRpc: requiredEnv("RING_RPC_URL"),
      },
      apiKeys: [API_KEY],
    });
    const zolana = new URL("/v1/zolana", gateway.url);
    zolana.searchParams.set("api-key", API_KEY);
    client = await createZolanaClient({
      solanaRpcUrl: harness.rpcUrl,
      indexerUrl: zolana,
      proverUrl: zolana,
      tree: harness.tree,
      proofDataSource: "client",
      indexerConfig: { poll: { numRetries: 120, delayMs: 250n, maxDelayMs: 2_000n } },
    });
    ring = new RingRpc(new URL("/v1/zolana/ring", gateway.url), { apiKey: API_KEY });
  });

  afterAll(async () => {
    await gateway?.close();
  });

  const unitsSince = (from: number): number =>
    gateway.billed.slice(from).reduce((total, entry) => total + entry.units, 0);

  it("runs only the method a path names and bills nothing it refuses", async () => {
    const from = gateway.billed.length;
    expect(["local", "derived"]).toContain((await ring.health()).mode);
    expect(unitsSince(from)).toBe(1);

    const refused = gateway.billed.length;
    for (const [path, call] of [
      ["/v1/zolana/ring/health", { jsonrpc: "2.0", id: 1, method: "ringStatus" }],
      ["/v1/zolana/ring/health", [{ jsonrpc: "2.0", id: 1, method: "health" }]],
      ["/v1/zolana/getUserRecords", { jsonrpc: "2.0", id: 1, method: "getMerkleProofs" }],
    ] as const) {
      const url = new URL(path, gateway.url);
      url.searchParams.set("api-key", API_KEY);
      const response = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(call),
      });
      expect(response.status, path).toBe(400);
      expect(await response.json()).toMatchObject({ error: { code: -32601 } });
    }
    expect(gateway.billed.length - refused).toBe(3);
    expect(unitsSince(refused)).toBe(0);
  });

  it("bills a deposits page by the signatures it examines", async () => {
    const ringProgramId = address(requiredEnv("RING_PROGRAM_ID"));
    const from = gateway.billed.length;
    await ring.ringDeposits({ ringProgramId, limit: 200 });
    expect(unitsSince(from)).toBe(4);
    await ring.ringDeposits({ ringProgramId });
    expect(unitsSince(from)).toBe(5);
  });

  it("deposits, transfers and withdraws with every read and proof through the gateway", async () => {
    const owner = await freshActor(client);
    const recipient = await freshActor(client);
    await fund(client, owner);
    const from = gateway.billed.length;

    await signSendAndConfirm(
      client,
      await buildDepositTransaction({
        client,
        feePayer: owner.signer.address,
        recipient: owner.keypair.shieldedAddress(),
        amount: 30_000_000n,
      }),
      [owner.signer],
    );
    await sync(client, owner);
    expect(owner.wallet.balance(SOL_MINT).amount).toBe(30_000_000n);

    await signSendAndConfirm(
      client,
      await buildTransferTransaction({
        client,
        wallet: owner.wallet,
        keys: owner.keys,
        feePayer: owner.signer.address,
        recipient: recipient.keypair.shieldedAddress(),
        amount: 10_000_000n,
      }),
      [owner.signer],
    );
    await sync(client, recipient);
    expect(recipient.wallet.balance(SOL_MINT).amount).toBe(10_000_000n);

    await sync(client, owner);
    const before = await client.getBalance(recipient.signer.address);
    await signSendAndConfirm(
      client,
      await buildWithdrawalTransaction({
        client,
        wallet: owner.wallet,
        keys: owner.keys,
        feePayer: owner.signer.address,
        recipient: recipient.signer.address,
        amount: 5_000_000n,
      }),
      [owner.signer],
    );
    await sync(client, owner);
    expect(owner.wallet.balance(SOL_MINT).amount).toBe(15_000_000n);
    expect(await client.getBalance(recipient.signer.address)).toBe(before + 5_000_000n);

    const calls = gateway.billed.slice(from);
    const proofs = calls.filter((entry) => entry.route.path === "/v1/zolana/prove/{key}");
    // One input each, so both spends prove on S-tier keys.
    expect(proofs.map(({ status, units }) => ({ status, units }))).toEqual([
      { status: 200, units: 1 },
      { status: 200, units: 1 },
    ]);
    expect(calls.some((entry) => entry.route.origin === "photon" && entry.status === 200)).toBe(
      true,
    );
  }, 900_000);
});
