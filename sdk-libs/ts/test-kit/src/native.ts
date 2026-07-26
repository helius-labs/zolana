import type { Rpc, ZolanaClient } from "@zolana/client";
import type { Address, Instruction, RequestContext, Signature } from "@zolana/interface";
import type { TransactionSigner } from "@zolana/wallet";

import { TestKitError } from "./error.js";

/**
 * Send through the client and wait for the cluster to accept the result.
 *
 * `ZolanaClient.createAndSendTransaction` returns as soon as the transaction is
 * submitted, which is what an application wants. A setup step is different: the
 * accounts it creates are read by the very next step, so it has to land first.
 */
export async function sendAndConfirm(
  input: Readonly<{
    client: ZolanaClient;
    feePayer: TransactionSigner;
    instructions: readonly Instruction[];
    signers?: readonly TransactionSigner[];
    timeoutMs?: number;
  }>,
  context?: RequestContext,
): Promise<Signature> {
  const signature = await input.client.createAndSendTransaction(
    {
      instructions: input.instructions,
      feePayer: input.feePayer,
      ...(input.signers === undefined ? {} : { signers: input.signers }),
    },
    context,
  );
  await confirm(
    {
      rpc: input.client,
      signature,
      ...(input.timeoutMs === undefined ? {} : { timeoutMs: input.timeoutMs }),
    },
    context,
  );
  return signature;
}

export async function confirm(
  input: Readonly<{ rpc: Rpc; signature: Signature; timeoutMs?: number }>,
  context?: RequestContext,
): Promise<void> {
  const timeoutMs = input.timeoutMs ?? 30_000;
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await input.rpc.confirmTransaction(input.signature, context)) return;
    await delay(100);
  }
  throw new TestKitError("TEST_KIT_TIMEOUT", {
    details: { stage: "confirm", signature: input.signature, timeoutMs },
  });
}

/** Not on the `Rpc` interface, so the example asks the validator directly. */
export async function requestAirdrop(
  input: Readonly<{ rpcUrl: URL; address: Address; lamports: bigint }>,
): Promise<Signature> {
  return await rpcCall<Signature>(input.rpcUrl, "requestAirdrop", [
    input.address,
    Number(input.lamports),
  ]);
}

/** Not on the `Rpc` interface, so the example asks the validator directly. */
export async function minimumBalanceForRentExemption(
  input: Readonly<{ rpcUrl: URL; space: number }>,
): Promise<bigint> {
  return BigInt(
    await rpcCall<number>(input.rpcUrl, "getMinimumBalanceForRentExemption", [input.space]),
  );
}

async function rpcCall<T>(url: URL, method: string, params: readonly unknown[]): Promise<T> {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const envelope = (await response.json()) as { result?: T; error?: unknown };
  if (envelope.result === undefined) {
    throw new TestKitError("TEST_KIT_RPC", {
      details: { method, error: JSON.stringify(envelope.error) },
    });
  }
  return envelope.result;
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => {
    const timeout = setTimeout(resolve, milliseconds);
    timeout.unref();
  });
}
