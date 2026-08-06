import { readFile } from "node:fs/promises";

import {
  airdropFactory,
  address,
  appendTransactionMessageInstructions,
  assertIsTransactionWithBlockhashLifetime,
  getAddressEncoder,
  getProgramDerivedAddress,
  getSignatureFromTransaction,
  createSolanaRpc,
  createSolanaRpcSubscriptions,
  createTransactionMessage,
  lamports,
  pipe,
  sendAndConfirmTransactionFactory,
  setTransactionMessageFeePayerSigner,
  setTransactionMessageLifetimeUsingBlockhash,
  signTransactionMessageWithSigners,
  type Address,
  type Instruction,
  type Signature,
  type TransactionSigner,
} from "@solana/kit";
import {
  SHIELDED_POOL_PROGRAM_ID,
  SPL_TOKEN_PROGRAM_ID,
  ShieldedKeypair,
  createZolanaClient,
  initializePoseidon,
  type Bytes32,
} from "@zolana/sdk";

// The SDK's localnet default; the airdrop is a localnet-only operation and
// targets the same validator the bare client connects to.
const LOCALNET_RPC_URL = "http://127.0.0.1:8899";

const SENDER_LAMPORTS = 2_000_000_000n;
const FIRST_SPL_ASSET_ID = 2n;
const encoder = new TextEncoder();
const addressEncoder = getAddressEncoder();

export interface SplExampleSetup {
  readonly assetId: bigint;
  readonly mint: Address;
  readonly sourceTokenAccount: Address;
  readonly recipientTokenAccount: Address;
  readonly splTokenInterface: Address;
  readonly splInterfacePda: Address;
  readonly tokenProgram: Address;
}

export interface ExampleSetup {
  /**
   * The funded sender. The example derives both its Solana signer and its
   * shielded address from this one keypair, as the Rust example does.
   */
  readonly sender: ShieldedKeypair;
  readonly recipient: ShieldedKeypair;
  readonly spl: SplExampleSetup;
}

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`the TypeScript SDK example requires ${name}`);
  return value;
}

function subscriptionsUrl(rpcUrl: string): string {
  const url = new URL(rpcUrl);
  if (url.port !== "") {
    url.port = String(Number(url.port) + 1);
  }
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  return url.href;
}

async function senderKeypair(): Promise<ShieldedKeypair> {
  const wallet = JSON.parse(
    await readFile(requiredEnv("ZOLANA_TEST_AUTHORITY_WALLET"), "utf8"),
  ) as {
    funding_secret_hex?: unknown;
  };
  if (typeof wallet.funding_secret_hex !== "string") {
    throw new Error("the TypeScript SDK example authority has no funding secret");
  }
  const seed = Uint8Array.from(Buffer.from(wallet.funding_secret_hex, "hex")) as Bytes32;
  if (seed.length !== 32) {
    throw new Error("the TypeScript SDK example authority seed must be 32 bytes");
  }
  try {
    return ShieldedKeypair.fromEd25519(seed, 0);
  } finally {
    seed.fill(0);
  }
}

function recipientKeypair(): ShieldedKeypair {
  const seed = crypto.getRandomValues(new Uint8Array(32)) as Bytes32;
  try {
    return ShieldedKeypair.fromEd25519(seed, 0);
  } finally {
    seed.fill(0);
  }
}

/**
 * Sign and send instructions as the given fee payer, then wait for the
 * transaction to confirm.
 *
 * The SDK returns instructions and leaves signing and sending to the
 * application, so a Kit app owns this step. It lives here rather than in the
 * example so the example stays about the shielded-pool calls.
 */
export function sendAndConfirmFactory(
  client: Awaited<ReturnType<typeof createZolanaClient>>,
  feePayer: TransactionSigner,
): (instructions: readonly Instruction[]) => Promise<Signature> {
  const sendAndConfirmTransaction = sendAndConfirmTransactionFactory({
    rpc: client.solanaRpc,
    rpcSubscriptions: client.solanaRpcSubscriptions,
  });

  return async function sendAndConfirm(instructions: readonly Instruction[]): Promise<Signature> {
    const { value: lifetime } = await client.solanaRpc.getLatestBlockhash().send();
    const signed = await signTransactionMessageWithSigners(
      pipe(
        createTransactionMessage({ version: 0 }),
        (message) => setTransactionMessageFeePayerSigner(feePayer, message),
        (message) => setTransactionMessageLifetimeUsingBlockhash(lifetime, message),
        (message) => appendTransactionMessageInstructions(instructions, message),
      ),
    );
    assertIsTransactionWithBlockhashLifetime(signed);
    await sendAndConfirmTransaction(signed, { commitment: "confirmed" });
    return getSignatureFromTransaction(signed);
  };
}

export async function setup(): Promise<ExampleSetup> {
  await initializePoseidon();

  const sender = await senderKeypair();
  const mint = address(requiredEnv("ZOLANA_TEST_MINT"));
  const [splInterfacePda] = await getProgramDerivedAddress({
    programAddress: SHIELDED_POOL_PROGRAM_ID,
    seeds: [encoder.encode("spl_asset_vault"), addressEncoder.encode(mint)],
  });

  const airdrop = airdropFactory({
    rpc: createSolanaRpc(LOCALNET_RPC_URL),
    rpcSubscriptions: createSolanaRpcSubscriptions(subscriptionsUrl(LOCALNET_RPC_URL)),
  });
  await airdrop({
    commitment: "confirmed",
    recipientAddress: sender.toSolanaSigner().address,
    lamports: lamports(SENDER_LAMPORTS),
  });
  const tokenAccount = address(requiredEnv("ZOLANA_TEST_TOKEN_ACCOUNT"));

  return Object.freeze({
    sender,
    recipient: recipientKeypair(),
    spl: Object.freeze({
      assetId: FIRST_SPL_ASSET_ID,
      mint,
      sourceTokenAccount: tokenAccount,
      recipientTokenAccount: tokenAccount,
      splTokenInterface: splInterfacePda,
      splInterfacePda,
      tokenProgram: SPL_TOKEN_PROGRAM_ID,
    }),
  });
}
