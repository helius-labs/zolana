import {
  address,
  assertIsTransactionWithBlockhashLifetime,
  getSignatureFromTransaction,
  lamports,
  sendTransactionWithoutConfirmingFactory,
  signTransactionWithSigners,
} from "@solana/kit";
import { describe, expect, it } from "vitest";

import { buildDepositTransaction, createZolanaClient } from "../../src/index.js";
import { wireDecoder } from "../../src/interface/decode.js";
import { actor } from "./live-helpers.js";

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`private recovery integration requires ${name}`);
  return value;
}

function client(fetch?: typeof globalThis.fetch) {
  return createZolanaClient({
    solanaRpcUrl: requiredEnv("ZOLANA_LOCALNET_URL"),
    indexerUrl: requiredEnv("ZOLANA_INDEXER_URL"),
    tree: address(requiredEnv("ZOLANA_TREE")),
    // Deposits and recovery need no proof, so this suite needs no running prover.
    proverUrl: "http://127.0.0.1:3001",
    indexerConfig: { poll: { numRetries: 300, delayMs: 100n, maxDelayMs: 100n } },
    ...(fetch === undefined ? {} : { fetch }),
  });
}

function method(init: RequestInit | undefined): string {
  const decode = wireDecoder((path) => new Error(`invalid integration request ${path}`));
  const request = decode.record(JSON.parse(String(init?.body)), "request");
  return decode.string(request["method"], "method");
}

describe("private recovery with a validator and Photon", { concurrent: false }, () => {
  it("recovers a broadcast whose response was lost, including while the RPC hangs", async () => {
    let sends = 0;
    const order: string[] = [];
    const dropSendResponse: typeof globalThis.fetch = async (url, init) => {
      const response = await globalThis.fetch(url, init);
      if (method(init) === "sendTransaction") {
        sends++;
        order.push("broadcast");
        if (!response.ok) return response;
        // Consume the genuine response before simulating its loss in transport.
        await response.text();
        throw new TypeError("send response lost after broadcast");
      }
      return response;
    };
    const sender = await client(dropSendResponse);
    const owner = await actor(sender, 201);
    const airdrop = await sender.solanaRpc
      .requestAirdrop(owner.signer.address, lamports(20_000_000_000n))
      .send();
    await sender.confirmTransaction(airdrop);
    const transaction = await buildDepositTransaction({
      client: sender,
      feePayer: owner.signer.address,
      recipient: owner.keypair.shieldedAddress(),
      amount: 1_000_000n,
    });
    const signed = await signTransactionWithSigners([owner.signer], transaction);
    assertIsTransactionWithBlockhashLifetime(signed);
    const checkpoint = {
      signature: getSignatureFromTransaction(signed),
      height: signed.lifetimeConstraint.lastValidBlockHeight,
    };
    order.push("checkpoint");
    await expect(
      sendTransactionWithoutConfirmingFactory({ rpc: sender.solanaRpc })(signed, {
        commitment: "confirmed",
      }),
    ).rejects.toThrow();

    // A fresh client has no in-memory confirmation state from the sender.
    const restarted = await client();
    await restarted.waitForPrivateTransaction(checkpoint.signature, checkpoint.height);
    const found = await restarted.getShieldedTransactionsBySignature(checkpoint.signature);
    expect(found.transactions.length).toBeGreaterThan(0);
    expect(
      found.transactions.every((event) => event.transaction.txSignature === checkpoint.signature),
    ).toBe(true);
    expect(sends).toBe(1);
    expect(order).toEqual(["checkpoint", "broadcast"]);

    let hungSignal: AbortSignal | null | undefined;
    const methods: string[] = [];
    const hangStatus: typeof globalThis.fetch = (url, init) => {
      const name = method(init);
      methods.push(name);
      if (name !== "getSignatureStatuses") return globalThis.fetch(url, init);
      hungSignal = init?.signal;
      return new Promise((_resolve, reject) => {
        init?.signal?.addEventListener(
          "abort",
          () => reject(new DOMException("aborted", "AbortError")),
          { once: true },
        );
      });
    };
    const withoutStatus = await client(hangStatus);
    await withoutStatus.waitForPrivateTransaction(
      checkpoint.signature,
      checkpoint.height,
      undefined,
      { timeoutMs: 2_000 },
    );
    expect(hungSignal?.aborted).toBe(true);
    expect(methods).not.toContain("sendTransaction");
    expect(sends).toBe(1);
  }, 60_000);

  it("requires Photon to process the slot where expiry was observed before allowing replacement", async () => {
    const fresh = await client();
    const owner = await actor(fresh, 202);
    const airdrop = await fresh.solanaRpc
      .requestAirdrop(owner.signer.address, lamports(20_000_000_000n))
      .send();
    await fresh.confirmTransaction(airdrop);
    const transaction = await buildDepositTransaction({
      client: fresh,
      feePayer: owner.signer.address,
      recipient: owner.keypair.shieldedAddress(),
      amount: 1_000_000n,
    });
    const signed = await signTransactionWithSigners([owner.signer], transaction);
    assertIsTransactionWithBlockhashLifetime(signed);
    const signature = getSignatureFromTransaction(signed);
    const height = signed.lifetimeConstraint.lastValidBlockHeight;
    // Retain an actual Photon response from before expiry to model a lagging
    // replica, without inventing either its slot or its transaction rows.
    let cached: Response | undefined;
    const methods: string[] = [];
    const staleIndexer: typeof globalThis.fetch = async (url, init) => {
      const name = method(init);
      methods.push(name);
      if (name === "getShieldedTransactionsBySignature" && cached !== undefined)
        return cached.clone();
      const response = await globalThis.fetch(url, init);
      if (name === "getShieldedTransactionsBySignature") cached = response.clone();
      return response;
    };
    const stale = await client(staleIndexer);
    const before = await stale.getShieldedTransactionsBySignature(signature);
    expect(before.transactions).toHaveLength(0);
    let bank = await fresh.solanaRpc.getEpochInfo({ commitment: "confirmed" }).send();
    const deadline = Date.now() + 90_000;
    while (bank.blockHeight <= height && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 100));
      bank = await fresh.solanaRpc.getEpochInfo({ commitment: "confirmed" }).send();
    }
    expect(bank.blockHeight).toBeGreaterThan(height);
    expect(before.context.slot).toBeLessThan(bank.absoluteSlot);
    await expect(
      stale.waitForPrivateTransaction(signature, height, {
        poll: { numRetries: 0, delayMs: 0n, maxDelayMs: 0n },
      }),
    ).rejects.toMatchObject({ code: "CLIENT_TRANSACTION_OUTCOME_UNKNOWN" });
    await expect(fresh.waitForPrivateTransaction(signature, height)).rejects.toMatchObject({
      code: "CLIENT_TRANSACTION_EXPIRED",
      details: { signature },
    });
    const after = await fresh.getShieldedTransactionsBySignature(signature);
    expect(after.transactions).toHaveLength(0);
    expect(after.context.slot).toBeGreaterThanOrEqual(bank.absoluteSlot);
    expect(methods).not.toContain("sendTransaction");
  }, 120_000);
});
