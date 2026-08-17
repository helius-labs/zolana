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
  sendTransactionWithoutConfirmingFactory,
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
  SigningKey,
  createZolanaClient,
  initializePoseidon,
  type Bytes32,
  type ZolanaClientConfig,
} from "@heliuslabs/zolana";

// The SDK's localnet default; the airdrop is a localnet-only operation and
// targets the same validator the client connects to.
const DEFAULT_LOCALNET_RPC_URL = "http://127.0.0.1:8899";

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
  /**
   * Empty on a default localnet, so the example client stays zero-config. The
   * `just` live recipes shift every service port by `ZOLANA_PORT_OFFSET` and
   * export the resulting URLs; those must reach the client or it polls dead
   * default ports until the test times out.
   */
  readonly clientConfig: ZolanaClientConfig;
}

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`the TypeScript SDK example requires ${name}`);
  return value;
}

function clientConfigFromEnv(): ZolanaClientConfig {
  const solanaRpcUrl = process.env["ZOLANA_LOCALNET_URL"];
  const indexerUrl = process.env["ZOLANA_INDEXER_URL"];
  const proverUrl = process.env["ZOLANA_PROVER_URL"];
  return Object.freeze({
    ...(solanaRpcUrl === undefined ? {} : { solanaRpcUrl }),
    ...(indexerUrl === undefined ? {} : { indexerUrl }),
    ...(proverUrl === undefined ? {} : { proverUrl }),
  });
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
    return ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(seed));
  } finally {
    seed.fill(0);
  }
}

function recipientKeypair(): ShieldedKeypair {
  const seed = crypto.getRandomValues(new Uint8Array(32)) as Bytes32;
  try {
    return ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(seed));
  } finally {
    seed.fill(0);
  }
}

export interface ConfirmedTransaction {
  readonly signature: Signature;
  /** Slot the transaction landed in; drives the indexer freshness gates. */
  readonly slot: bigint;
}

/**
 * Sign and send instructions as the given fee payer, then wait for the
 * transaction to confirm.
 *
 * The SDK returns instructions and leaves signing and sending to the
 * application, so a Kit app owns this step. It lives here rather than in the
 * example so the example stays about the shielded-pool calls. The SDK's
 * `confirmTransaction` is the confirmation, and the status response that
 * confirms also carries the landed slot, so no request is issued twice.
 */
export function sendAndConfirmFactory(
  client: Awaited<ReturnType<typeof createZolanaClient>>,
  feePayer: TransactionSigner,
): (instructions: readonly Instruction[]) => Promise<ConfirmedTransaction> {
  const sendTransaction = sendTransactionWithoutConfirmingFactory({ rpc: client.solanaRpc });

  return async function sendAndConfirm(
    instructions: readonly Instruction[],
  ): Promise<ConfirmedTransaction> {
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
    await sendTransaction(signed, { commitment: "confirmed" });
    const signature = getSignatureFromTransaction(signed);
    const slot = await client.confirmTransaction(signature);
    return { signature, slot };
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

  const clientConfig = clientConfigFromEnv();
  const rpcUrl =
    typeof clientConfig.solanaRpcUrl === "string"
      ? clientConfig.solanaRpcUrl
      : DEFAULT_LOCALNET_RPC_URL;
  const airdrop = airdropFactory({
    rpc: createSolanaRpc(rpcUrl),
    rpcSubscriptions: createSolanaRpcSubscriptions(subscriptionsUrl(rpcUrl)),
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
    clientConfig,
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
