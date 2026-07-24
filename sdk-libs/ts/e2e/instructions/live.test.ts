/// <reference types="node" />

import type { Rpc } from "@zolana/client";
import type { Address, Bytes32, Signature, Transaction } from "@zolana/interface";
import { startLocalStack } from "@zolana/test-kit";
import { fixtureJson } from "@zolana/test-kit/fixtures";
import { createE2eHarness, createTestNativeSigner } from "@zolana/test-kit/node";
import { describe, expect, it } from "vitest";

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

async function confirm(rpc: Rpc, signature: Signature, timeoutMs = 15_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await rpc.confirmTransaction(signature)) return;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(`transaction confirmation timed out: ${signature}`);
}

describe("P13 live raw instruction lifecycle", () => {
  it("rejects a wrong external signature against an isolated stack", async () => {
    const offset = Number(process.env["ZOLANA_PORT_OFFSET"] ?? "400");
    expect(offset).toBe(400);
    const stack = await startLocalStack({ portOffset: offset });
    const harness = createE2eHarness(stack);
    const seed = bytes32(81);
    const signer = createTestNativeSigner(seed);
    try {
      await confirm(harness.rpc, await airdrop(stack.rpcUrl, signer.address, 5_000_000_000n));
      const balanceBefore = await harness.rpc.getBalance(signer.address);
      const fixture = await fixtureJson<{
        readonly expected: {
          readonly railCases: readonly {
            readonly wire: { readonly unsignedMessageBytes: string };
          }[];
        };
      }>("workflows/instruction-transfer-v1");
      const message = fixture.expected.railCases[0]?.wire.unsignedMessageBytes;
      if (message === undefined) throw new Error("transfer fixture has no rail case");
      const unsigned: Transaction = {
        messageBytes: Uint8Array.from(
          message.match(/../gu)?.map((pair) => Number.parseInt(pair, 16)) ?? [],
        ),
        signatures: [undefined],
      };
      const signed = await signer.signNativeTransaction(unsigned);
      expect(signed.messageBytes).toEqual(unsigned.messageBytes);
      await expect(harness.rpc.sendTransaction(signed)).rejects.toMatchObject({
        code: "CLIENT_RPC_ENVELOPE",
      });
      expect(await harness.rpc.getBalance(signer.address)).toBe(balanceBefore);
    } finally {
      await harness.stop();
    }
    await expect(fetch(stack.rpcUrl)).rejects.toThrow();
  }, 240_000);
});
