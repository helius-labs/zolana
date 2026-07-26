/// <reference types="node" />

import type { Rpc } from "@zolana/client";
import type { Address, Bytes32, Signature } from "@zolana/interface";
import { syncWallet } from "@zolana/wallet";

export function bytes32(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

export async function airdrop(
  url: URL,
  address: Address,
  lamports: bigint,
): Promise<Signature> {
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

export async function confirm(
  rpc: Rpc,
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

export async function waitForAccount(
  rpc: Rpc,
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

export async function syncUntil(
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
