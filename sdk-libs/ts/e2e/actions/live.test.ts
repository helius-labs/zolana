/// <reference types="node" />

import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

import type { Rpc } from "@zolana/client";
import type { Address, Bytes32, Signature } from "@zolana/interface";
import { ShieldedKeypair } from "@zolana/keypair";
import { buildRegistrationTransaction, createAssociatedTokenAccount } from "@zolana/wallet";
import { createTestWallet, startLocalStack } from "@zolana/test-kit";
import {
  createE2eHarness,
  createTestNativeSigner,
  enableMerging,
  submitSetMergingEnabled,
  userRecordAddress,
} from "@zolana/test-kit/node";
import { describe, expect, it } from "vitest";

const execute = promisify(execFile);
const TOKEN_ADDRESS = /Creating token ([1-9A-HJ-NP-Za-km-z]{32,44})/;

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

async function waitForAccount(rpc: Rpc, address: Address, timeoutMs = 15_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if ((await rpc.getAccount(address)) !== undefined) return;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(`account did not appear: ${address}`);
}

async function createMint(rpcUrl: URL, feePayerSeed: Bytes32, feePayer: Address): Promise<Address> {
  const directory = await mkdtemp(path.join(os.tmpdir(), "zolana-p12-mint-"));
  try {
    const keypair = ShieldedKeypair.fromEd25519(feePayerSeed, 0);
    const publicKey = keypair.signingPublicKey().ed25519();
    const secret = [...feePayerSeed, ...publicKey];
    const keypairPath = path.join(directory, "payer.json");
    await writeFile(keypairPath, JSON.stringify(secret), { mode: 0o600 });
    const result = await execute("spl-token", [
      "create-token",
      "--url",
      rpcUrl.href,
      "--fee-payer",
      keypairPath,
      "--mint-authority",
      feePayer,
    ]);
    const match = TOKEN_ADDRESS.exec(result.stdout);
    if (match?.[1] === undefined) {
      throw new Error(`could not parse token address: ${result.stdout}`);
    }
    return match[1] as Address;
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

describe("P12 live action lifecycle", () => {
  it("uses a fresh isolated stack for registration, merge opt-in, and idempotent ATA submission", async () => {
    const offset = Number(process.env["ZOLANA_PORT_OFFSET"] ?? "300");
    expect(offset).toBe(300);
    const stack = await startLocalStack({ portOffset: offset });
    const harness = createE2eHarness(stack);
    const ownerSeed = bytes32(71);
    const owner = createTestNativeSigner(ownerSeed);
    const identity = createTestWallet(ownerSeed).wallet.identity;
    let mergingEnabled = false;
    try {
      await confirm(harness.rpc, await airdrop(stack.rpcUrl, owner.address, 5_000_000_000n));
      const registration = await buildRegistrationTransaction({
        rpc: harness.rpc,
        owner: owner.address,
        address: identity,
      });
      if (registration === undefined) throw new Error("expected registration transaction");
      const enabled = await enableMerging({
        rpc: harness.rpc,
        owner: owner.address,
        signer: owner,
        registration,
      });
      mergingEnabled = true;
      expect(enabled.changed).toBe(true);
      await expect(
        enableMerging({ rpc: harness.rpc, owner: owner.address, signer: owner }),
      ).resolves.toMatchObject({ changed: false });

      const mint = await createMint(stack.rpcUrl, ownerSeed, owner.address);
      const first = await createAssociatedTokenAccount({
        rpc: harness.rpc,
        payer: owner,
        owner: owner.address,
        mint,
      });
      await confirm(harness.rpc, first.signature);
      await waitForAccount(harness.rpc, first.address);
      const second = await createAssociatedTokenAccount({
        rpc: harness.rpc,
        payer: owner,
        owner: owner.address,
        mint,
      });
      await confirm(harness.rpc, second.signature);
      expect(second.address).toBe(first.address);
      expect(await harness.rpc.getAccount(first.address)).toBeDefined();
    } finally {
      if (mergingEnabled) {
        const record = await userRecordAddress(owner.address);
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
  }, 240_000);
});
