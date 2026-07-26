/// <reference types="node" />

import type { Rpc } from "@zolana/client";
import type { Address, Bytes32, Signature } from "@zolana/interface";
import { buildRegistrationTransaction } from "@zolana/wallet";
import { describe, expect, it } from "vitest";

import { createTestWallet, startLocalStack } from "../src/index.js";
import {
  createE2eHarness,
  createTestNativeSigner,
  enableMerging,
  submitSetMergingEnabled,
  userRecordAddress,
} from "../src/node/index.js";

const live = process.env["ZOLANA_TEST_LIVE"] === "1" ? describe : describe.skip;

function bytes32(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

live("user registry merge setup local lifecycle", () => {
  it("registers, rejects an unauthorized owner, enables idempotently, and cleans up", async () => {
    const stack = await startLocalStack({ portOffset: 500 });
    const harness = createE2eHarness(stack);
    const ownerSeed = bytes32(21);
    const owner = createTestNativeSigner(ownerSeed);
    const stranger = createTestNativeSigner(bytes32(22));
    const identity = createTestWallet(ownerSeed).wallet.identity;
    let registered = false;
    try {
      const airdrops = await Promise.all([
        airdrop(stack.rpcUrl, owner.address, 2_000_000_000n),
        airdrop(stack.rpcUrl, stranger.address, 1_000_000_000n),
      ]);
      await Promise.all(airdrops.map((signature) => waitForConfirmation(harness.rpc, signature)));
      const registration = await buildRegistrationTransaction({
        rpc: harness.rpc,
        owner: owner.address,
        address: identity,
      });
      if (registration === undefined) throw new Error("expected registration transaction");
      const record = userRecordAddress(owner.address);
      await expect(
        enableMerging({
          rpc: harness.rpc,
          owner: owner.address,
          signer: owner,
          registration,
        }),
      ).resolves.toMatchObject({ changed: true, userRecord: record.address });
      registered = true;

      await expect(
        submitSetMergingEnabled({
          rpc: harness.rpc,
          signer: stranger,
          userRecord: record.address,
          enabled: false,
        }),
      ).rejects.toMatchObject({ code: "TEST_KIT_RPC" });
      await expect(
        enableMerging({ rpc: harness.rpc, owner: owner.address, signer: owner }),
      ).resolves.toEqual({ changed: false, userRecord: record.address });
    } finally {
      if (registered) {
        const record = userRecordAddress(owner.address);
        await submitSetMergingEnabled({
          rpc: harness.rpc,
          signer: owner,
          userRecord: record.address,
          enabled: false,
        });
        expect((await harness.rpc.getAccount(record.address))?.data.at(-1)).toBe(0);
      }
      await harness.stop();
    }
    await expect(fetch(stack.rpcUrl)).rejects.toThrow();
  }, 180_000);
});

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

async function waitForConfirmation(rpc: Rpc, signature: Signature): Promise<void> {
  for (let attempt = 0; attempt < 50; attempt++) {
    if (await rpc.confirmTransaction(signature)) return;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error("airdrop confirmation timed out");
}
