import { ed25519 } from "@noble/curves/ed25519.js";
import {
  address,
  createKeyPairSignerFromBytes,
  lamports,
  type KeyPairSigner,
  type Signature,
} from "@solana/kit";
import { describe, expect, it } from "vitest";

import {
  LocalWalletAuthority,
  ShieldedKeypair,
  SOL_MINT,
  Wallet,
  createZolanaClient,
  deposit,
  registerIfAbsent,
  syncWallet,
  transfer,
  type Bytes32,
} from "../../src/index.js";

interface Actor {
  readonly signer: KeyPairSigner;
  readonly keypair: ShieldedKeypair;
  readonly wallet: Wallet;
  readonly authority: LocalWalletAuthority;
}

async function actor(seedByte: number, rail: "ed25519" | "p256" = "ed25519"): Promise<Actor> {
  const seed = new Uint8Array(32).fill(seedByte) as Bytes32;
  const publicKey = ed25519.getPublicKey(seed);
  const signer = await createKeyPairSignerFromBytes(Uint8Array.of(...seed, ...publicKey));
  const keypair =
    rail === "ed25519" ? ShieldedKeypair.fromEd25519(seed, 0) : ShieldedKeypair.generate();
  if (rail === "ed25519") {
    expect(keypair.shieldedAddress().solanaAddress()).toBe(signer.address);
  }
  return {
    signer,
    keypair,
    wallet: new Wallet({ identity: keypair.shieldedAddress() }),
    authority: new LocalWalletAuthority({
      solanaPublicKey: signer.address,
      keypair,
    }),
  };
}

async function waitForSignature(
  rpc: Awaited<ReturnType<typeof createZolanaClient>>["solanaRpc"],
  signature: Signature,
): Promise<void> {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    const { value } = await rpc
      .getSignatureStatuses([signature], { searchTransactionHistory: true })
      .send();
    const status = value[0];
    if (status?.err !== null && status?.err !== undefined) {
      throw new Error(`airdrop failed: ${JSON.stringify(status.err)}`);
    }
    if (status?.confirmationStatus === "confirmed" || status?.confirmationStatus === "finalized") {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`airdrop confirmation timed out: ${signature}`);
}

describe("live SDK private flow", () => {
  it("runs private transfers on both ownership rails", async () => {
    const rpcUrl = process.env["ZOLANA_LOCALNET_URL"];
    const indexerUrl = process.env["ZOLANA_INDEXER_URL"];
    const proverUrl = process.env["ZOLANA_PROVER_URL"];
    const configuredTree = process.env["ZOLANA_TREE"];
    if (!rpcUrl || !indexerUrl || !proverUrl || !configuredTree) {
      throw new Error("the live TypeScript test requires localnet service URLs and ZOLANA_TREE");
    }

    const client = await createZolanaClient({
      solanaRpcUrl: rpcUrl,
      indexerUrl,
      proverUrl,
      tree: address(configuredTree),
      indexerConfig: {
        waitForIndexer: true,
        poll: { numRetries: 90, delayMs: 250n, maxDelayMs: 2_000n },
      },
    });
    const alice = await actor(71);
    const bob = await actor(72);
    const carol = await actor(73, "p256");

    for (const owner of [alice.signer.address, bob.signer.address, carol.signer.address]) {
      const signature = await client.solanaRpc
        .requestAirdrop(owner, lamports(5_000_000_000n))
        .send();
      await waitForSignature(client.solanaRpc, signature);
    }

    await expect(
      registerIfAbsent({
        client,
        funding: alice.signer,
        keypair: alice.keypair,
      }),
    ).resolves.toMatchObject({ kind: "written" });
    await expect(
      registerIfAbsent({
        client,
        funding: carol.signer,
        keypair: carol.keypair,
      }),
    ).resolves.toMatchObject({ kind: "written" });
    await expect(
      registerIfAbsent({
        client,
        funding: bob.signer,
        keypair: bob.keypair,
      }),
    ).resolves.toMatchObject({ kind: "written" });

    await deposit({
      client,
      feePayer: alice.signer,
      recipient: alice.keypair.shieldedAddress(),
      amount: 100_000_000n,
    });
    await syncWallet({
      client,
      wallet: alice.wallet,
      authority: alice.authority,
      config: { waitForIndexer: true },
    });
    expect(alice.wallet.balance(SOL_MINT).amount).toBe(100_000_000n);

    await transfer({
      client,
      wallet: alice.wallet,
      authority: alice.authority,
      feePayer: alice.signer,
      recipient: bob.signer.address,
      amount: 40_000_000n,
    });
    await syncWallet({
      client,
      wallet: bob.wallet,
      authority: bob.authority,
      config: { waitForIndexer: true },
    });
    expect(bob.wallet.balance(SOL_MINT).amount).toBe(40_000_000n);

    await deposit({
      client,
      feePayer: carol.signer,
      recipient: carol.keypair.shieldedAddress(),
      amount: 60_000_000n,
    });
    await syncWallet({
      client,
      wallet: carol.wallet,
      authority: carol.authority,
      config: { waitForIndexer: true },
    });
    expect(carol.wallet.balance(SOL_MINT).amount).toBe(60_000_000n);

    await transfer({
      client,
      wallet: carol.wallet,
      authority: carol.authority,
      feePayer: carol.signer,
      recipient: bob.signer.address,
      amount: 30_000_000n,
    });
    await syncWallet({
      client,
      wallet: bob.wallet,
      authority: bob.authority,
      config: { waitForIndexer: true },
    });
    expect(bob.wallet.balance(SOL_MINT).amount).toBe(70_000_000n);
  }, 300_000);
});
