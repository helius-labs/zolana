import { readFile } from "node:fs/promises";

import { ed25519 } from "@noble/curves/ed25519.js";
import {
  address,
  createKeyPairSignerFromBytes,
  getSignatureFromTransaction,
  lamports,
  sendTransactionWithoutConfirmingFactory,
  signTransactionWithSigners,
  type Address,
  type KeyPairSigner,
  type Signature,
  type Transaction,
  type TransactionModifyingSigner,
  type TransactionPartialSigner,
} from "@solana/kit";

import {
  LocalWalletAuthority,
  ShieldedKeypair,
  SigningKey,
  Wallet,
  createZolanaClient,
  syncWallet,
  type Bytes32,
} from "../../src/index.js";
import type { ZolanaClient } from "../../src/client/client.js";
import type { IndexedShieldedTransaction } from "../../src/transaction/instructions/transact.js";
import type { SyncWalletConfig } from "../../src/wallet/sync.js";

export interface Actor {
  readonly signer: KeyPairSigner;
  readonly keypair: ShieldedKeypair;
  readonly wallet: Wallet;
  readonly authority: LocalWalletAuthority;
}

export interface LiveHarness {
  readonly client: ZolanaClient;
  readonly rpcUrl: string;
  readonly indexerUrl: string;
  readonly proverUrl: string;
  readonly tree: Address;
  readonly mint: Address;
  readonly testTokenAccount: Address;
  readonly token2022Mint: Address;
  readonly testToken2022Account: Address;
  readonly testAuthority: KeyPairSigner;
}

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`the live TypeScript test requires ${name}`);
  return value;
}

export async function actor(
  seedByte: number,
  rail: "ed25519" | "p256" = "ed25519",
): Promise<Actor> {
  const seed = new Uint8Array(32).fill(seedByte) as Bytes32;
  const publicKey = ed25519.getPublicKey(seed);
  const signer = await createKeyPairSignerFromBytes(Uint8Array.of(...seed, ...publicKey));
  const keypair =
    rail === "ed25519"
      ? ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(seed))
      : ShieldedKeypair.generate("p256");
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

async function signerFromWalletFile(path: string): Promise<KeyPairSigner> {
  const parsed = JSON.parse(await readFile(path, "utf8")) as {
    funding_secret_hex?: unknown;
  };
  if (typeof parsed.funding_secret_hex !== "string") {
    throw new Error("test authority wallet has no funding secret");
  }
  const seed = Uint8Array.from(Buffer.from(parsed.funding_secret_hex, "hex"));
  if (seed.length !== 32) throw new Error("test authority funding secret must be 32 bytes");
  return createKeyPairSignerFromBytes(Uint8Array.of(...seed, ...ed25519.getPublicKey(seed)));
}

export async function liveHarness(): Promise<LiveHarness> {
  const rpcUrl = requiredEnv("ZOLANA_LOCALNET_URL");
  const indexerUrl = requiredEnv("ZOLANA_INDEXER_URL");
  const proverUrl = requiredEnv("ZOLANA_PROVER_URL");
  const tree = address(requiredEnv("ZOLANA_TREE"));
  const mint = address(requiredEnv("ZOLANA_TEST_MINT"));
  const testTokenAccount = address(requiredEnv("ZOLANA_TEST_TOKEN_ACCOUNT"));
  const token2022Mint = address(requiredEnv("ZOLANA_TEST_TOKEN_2022_MINT"));
  const testToken2022Account = address(requiredEnv("ZOLANA_TEST_TOKEN_2022_ACCOUNT"));
  const testAuthority = await signerFromWalletFile(requiredEnv("ZOLANA_TEST_AUTHORITY_WALLET"));
  const client = await createZolanaClient({
    solanaRpcUrl: rpcUrl,
    indexerUrl,
    proverUrl,
    tree,
    indexerConfig: {
      poll: { numRetries: 120, delayMs: 250n, maxDelayMs: 2_000n },
    },
  });
  return {
    client,
    rpcUrl,
    indexerUrl,
    proverUrl,
    tree,
    mint,
    testTokenAccount,
    token2022Mint,
    testToken2022Account,
    testAuthority,
  };
}

export async function waitForSignature(
  rpc: ZolanaClient["solanaRpc"],
  signature: Signature,
): Promise<void> {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    const { value } = await rpc
      .getSignatureStatuses([signature], { searchTransactionHistory: true })
      .send({ abortSignal: AbortSignal.timeout(5_000) });
    const status = value[0];
    if (status?.err !== null && status?.err !== undefined) {
      throw new Error(`transaction failed: ${JSON.stringify(status.err)}`);
    }
    if (status?.confirmationStatus === "confirmed" || status?.confirmationStatus === "finalized") {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`transaction confirmation timed out: ${signature}`);
}

export async function signSendAndConfirm(
  client: ZolanaClient,
  transaction: Transaction,
  signers: readonly (TransactionModifyingSigner | TransactionPartialSigner)[],
): Promise<Signature> {
  const signed = await signTransactionWithSigners(signers, transaction);
  const signature = getSignatureFromTransaction(signed);
  await sendTransactionWithoutConfirmingFactory({ rpc: client.solanaRpc })(signed, {
    commitment: client.commitment,
  });
  await waitForSignature(client.solanaRpc, signature);
  return signature;
}

export async function fund(client: ZolanaClient, ...actors: readonly Actor[]): Promise<void> {
  for (const owner of actors) {
    const signature = await client.solanaRpc
      .requestAirdrop(owner.signer.address, lamports(5_000_000_000n))
      .send();
    await waitForSignature(client.solanaRpc, signature);
  }
}

/**
 * Chain slot to require the indexer to have reached. A freshness requirement is a
 * per-operation decision, so it is read at call time rather than baked into the
 * client's config.
 */
export async function currentSlot(client: ZolanaClient): Promise<bigint> {
  return BigInt(await client.solanaRpc.getSlot().send());
}

export async function sync(
  client: ZolanaClient,
  owner: Actor,
  config: SyncWalletConfig = {},
): Promise<void> {
  await syncWallet({
    client,
    wallet: owner.wallet,
    authority: owner.authority,
    config: { requireSlot: await currentSlot(client), ...config },
  });
}

export async function indexedTransaction(
  client: ZolanaClient,
  signature: Signature,
): Promise<IndexedShieldedTransaction> {
  const response = await client.getShieldedTransactionsBySignature(
    signature,
    { ...client.indexerConfig, requireSlot: await currentSlot(client) },
    { timeoutMs: 30_000 },
  );
  const transaction = response.transactions[0]?.transaction;
  if (transaction !== undefined) return transaction;
  throw new Error(`Photon did not return ${signature}`);
}

export async function tokenBalance(client: ZolanaClient, tokenAccount: Address): Promise<bigint> {
  const response = await client.solanaRpc.getTokenAccountBalance(tokenAccount).send();
  return BigInt(response.value.amount);
}

export function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

export function historyKey(
  value: Readonly<{ id: Readonly<{ signature: Signature; slot: bigint; index: bigint }> }>,
): string {
  return `${value.id.signature}:${value.id.slot.toString()}:${value.id.index.toString()}`;
}
