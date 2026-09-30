import { readFileSync } from "node:fs";

import { SOL_MINT, type ZolanaClientConfig } from "@heliuslabs/zolana";
import { atSlot, type ZolanaClient } from "@heliuslabs/zolana/client";
import {
  encodeTransactInstructionData,
  transactCpiAccounts,
  type TransactInstructionData,
} from "@heliuslabs/zolana/interface";
import {
  P256_PUBLIC_KEY_LENGTH,
  ShieldedKeypair,
  SigningKey,
  bytes32,
  bytes64,
  type ViewingKey,
} from "@heliuslabs/zolana/keypair";
import {
  LocalShieldedKeys,
  ProgramOwner,
  Wallet,
  decodeConfidential,
  decodeOutputData,
  decryptTransactions,
  toProgramWalletUtxo,
  type AssetRegistry,
  type IndexedShieldedTransaction,
  type ProgramWalletUtxo,
} from "@heliuslabs/zolana/transaction";
import {
  AccountRole,
  address,
  airdropFactory,
  appendTransactionMessageInstructions,
  assertIsTransactionWithBlockhashLifetime,
  createSolanaRpc,
  createSolanaRpcSubscriptions,
  createTransactionMessage,
  getAddressEncoder,
  getSignatureFromTransaction,
  lamports,
  pipe,
  sendTransactionWithoutConfirmingFactory,
  setTransactionMessageConfig,
  setTransactionMessageFeePayerSigner,
  setTransactionMessageLifetimeUsingBlockhash,
  signTransactionMessageWithSigners,
  type AccountMeta,
  type AccountSignerMeta,
  type Address,
  type Instruction,
  type TransactionSigner,
} from "@solana/kit";

import type {
  CompressedGroth16Proof,
  DataUtxo,
  EscrowTerms,
  ProgramProof,
  ProgramTransaction,
} from "./wasm.js";
import type { Timings } from "./timings.js";
import { wasm } from "./wasm.js";

export const ESCROW_OUTPUT_SLOT = 1;

const ESCROW_TAG = 0;
const WITHDRAW_TAG = 1;
const ESCROW_AUTHORITY_SEED = "escrow_authority";
const DEFAULT_LOCALNET_RPC_URL = "http://127.0.0.1:8899";
const TRANSACT_COMPUTE_UNIT_LIMIT = 1_400_000;
const LOADED_ACCOUNTS_DATA_SIZE_LIMIT = 64 * 1024 * 1024;
const PROVING_KEYS = new URL("../../../target/zk/timelock-escrow-program/", import.meta.url);
const addressEncoder = getAddressEncoder();

function concat(...parts: readonly Uint8Array[]): Uint8Array {
  const bytes = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  parts.reduce((offset, part) => {
    bytes.set(part, offset);
    return offset + part.length;
  }, 0);
  return bytes;
}

function u64le(value: bigint): Uint8Array {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, value, true);
  return bytes;
}

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`the timelock escrow TypeScript test requires ${name}`);
  return value;
}

export function escrowProgramId(): Address {
  return address(requiredEnv("TIMELOCK_ESCROW_PROGRAM_ID"));
}

export function clientConfig(): ZolanaClientConfig {
  const solanaRpcUrl = process.env["ZOLANA_LOCALNET_URL"];
  const indexerUrl = process.env["ZOLANA_INDEXER_URL"];
  const proverUrl = process.env["ZOLANA_PROVER_URL"];
  return Object.freeze({
    ...(solanaRpcUrl === undefined ? {} : { solanaRpcUrl }),
    ...(indexerUrl === undefined ? {} : { indexerUrl }),
    ...(proverUrl === undefined ? {} : { proverUrl }),
  });
}

export function randomKeypair(): ShieldedKeypair {
  const seed = bytes32(crypto.getRandomValues(new Uint8Array(32)));
  try {
    return ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(seed));
  } finally {
    seed.fill(0);
  }
}

export async function airdrop(
  config: ZolanaClientConfig,
  recipient: Address,
  amount: bigint,
): Promise<void> {
  const rpcUrl =
    typeof config.solanaRpcUrl === "string" ? config.solanaRpcUrl : DEFAULT_LOCALNET_RPC_URL;
  const subscriptions = new URL(rpcUrl);
  subscriptions.port = String(Number(subscriptions.port) + 1);
  subscriptions.protocol = subscriptions.protocol === "https:" ? "wss:" : "ws:";
  await airdropFactory({
    rpc: createSolanaRpc(rpcUrl),
    rpcSubscriptions: createSolanaRpcSubscriptions(subscriptions.href),
  })({ commitment: "confirmed", recipientAddress: recipient, lamports: lamports(amount) });
}

export function sendAndConfirmFactory(
  client: ZolanaClient,
  feePayer: TransactionSigner,
): (instructions: readonly Instruction[]) => Promise<bigint> {
  const sendTransaction = sendTransactionWithoutConfirmingFactory({ rpc: client.solanaRpc });
  return async (instructions) => {
    const { value: lifetime } = await client.solanaRpc.getLatestBlockhash().send();
    const signed = await signTransactionMessageWithSigners(
      pipe(
        createTransactionMessage({ version: 1 }),
        (message) => setTransactionMessageFeePayerSigner(feePayer, message),
        (message) => setTransactionMessageLifetimeUsingBlockhash(lifetime, message),
        (message) =>
          setTransactionMessageConfig(
            {
              computeUnitLimit: TRANSACT_COMPUTE_UNIT_LIMIT,
              loadedAccountsDataSizeLimit: LOADED_ACCOUNTS_DATA_SIZE_LIMIT,
            },
            message,
          ),
        (message) => appendTransactionMessageInstructions(instructions, message),
      ),
    );
    assertIsTransactionWithBlockhashLifetime(signed);
    await sendTransaction(signed, { commitment: "confirmed" });
    return client.confirmTransaction(getSignatureFromTransaction(signed));
  };
}

export function escrowAuthority(programId: Address, creator: Address): Promise<ProgramOwner> {
  return ProgramOwner.find([ESCROW_AUTHORITY_SEED, addressEncoder.encode(creator)], programId);
}

export async function creatorTransactions(
  client: ZolanaClient,
  creator: ShieldedKeypair,
  authority: ProgramOwner,
  slot: bigint,
): Promise<readonly IndexedShieldedTransaction[]> {
  const response = await client.getShieldedTransactionsByTags(
    { tags: [creator.shieldedAddress().confidentialViewTag(), authority.ownerTag()], limit: 50 },
    atSlot(slot),
  );
  return response.transactions;
}

export async function spendableSol(
  client: ZolanaClient,
  creator: ShieldedKeypair,
  transactions: readonly IndexedShieldedTransaction[],
  assets: AssetRegistry,
): Promise<readonly ProgramWalletUtxo[]> {
  const wallet = new Wallet({ identity: creator.shieldedAddress(), registry: assets });
  const keys = LocalShieldedKeys.fromKeypair(creator);
  try {
    await decryptTransactions({ wallet, keys, transactions });
  } finally {
    keys.destroy();
  }
  return wallet
    .utxos()
    .filter((utxo) => !utxo.spent && utxo.utxo.asset === SOL_MINT)
    .map((utxo) =>
      toProgramWalletUtxo(utxo, {
        nullifierPublicKey: creator.nullifierPublicKey(),
        treeId: client.treeId,
        assets,
      }),
    );
}

export function escrowUtxos(
  timings: Timings,
  viewingKey: ViewingKey,
  transactions: readonly IndexedShieldedTransaction[],
  authority: ProgramOwner,
  assets: AssetRegistry,
  treeId: number,
): readonly DataUtxo<EscrowTerms>[] {
  const ownerTag = hex(authority.ownerTag());
  const owner = authority.publicKey().toBytes();
  const nullifierPubkey = ProgramOwner.nullifierPublicKey();
  const nullifierKey = ProgramOwner.nullifierKey();
  const spent = new Set(transactions.flatMap((tx) => tx.nullifiers.map(hex)));
  const escrows = new Map<string, DataUtxo<EscrowTerms>>();
  try {
    for (const tx of transactions) {
      const { txViewingPublicKey, salt } = tx;
      if (txViewingPublicKey === undefined || salt === undefined) continue;
      tx.outputSlots.forEach((slot, slotIndex) => {
        if (hex(slot.viewTag) !== ownerTag) return;
        const body = decodeOutputData(slot.payload).body;
        const plaintext = decodeConfidential(
          viewingKey.decryptUtxo(
            body.slice(P256_PUBLIC_KEY_LENGTH),
            txViewingPublicKey,
            salt,
            slotIndex,
          ),
        );
        const utxoHash = slot.outputContext.hash;
        const candidate = {
          utxo: {
            owner,
            asset: { asset: assets.resolve(plaintext.assetId), assetId: plaintext.assetId },
            amount: plaintext.amount,
            blinding: plaintext.blinding,
            data: { records: [...plaintext.data.records()] },
          },
          nullifierPubkey,
          utxoHash,
          nullifier: nullifierKey.nullifier(utxoHash, plaintext.blinding),
          treeId,
          leafIndex: slot.outputContext.leafIndex,
        };
        const escrow = timings.measure("escrowTermsDataUtxo", () =>
          wasm.escrowTermsDataUtxo(candidate),
        );
        if (!spent.has(hex(escrow.utxo.nullifier))) escrows.set(hex(utxoHash), escrow);
      });
    }
  } finally {
    nullifierKey.destroy();
  }
  return [...escrows.values()];
}

export function prove(
  timings: Timings,
  circuit: "escrow" | "withdraw",
  transaction: ProgramTransaction,
): ProgramProof {
  const key = timings.measure(`${circuit} read proving key`, () =>
    readFileSync(new URL(`${circuit}.pk`, PROVING_KEYS)),
  );
  const prover = timings.measure(`${circuit} prover fromKey`, () =>
    circuit === "escrow" ? wasm.EscrowProver.fromKey(key) : wasm.WithdrawProver.fromKey(key),
  );
  try {
    return timings.measure(`${circuit} prove`, () => prover.prove(transaction.proofInputs));
  } finally {
    prover.free();
  }
}

interface ProgramTransactInput {
  readonly programId: Address;
  readonly client: ZolanaClient;
  readonly creator: TransactionSigner;
  readonly authority: ProgramOwner;
  readonly proof: CompressedGroth16Proof;
  readonly transact: TransactInstructionData;
}

function signer(
  account: TransactionSigner,
  role: AccountRole.READONLY_SIGNER | AccountRole.WRITABLE_SIGNER,
): AccountSignerMeta {
  return { address: account.address, role, signer: account };
}

function proofBytes(proof: CompressedGroth16Proof): Uint8Array {
  return concat(bytes32(proof.a), bytes64(proof.b), bytes32(proof.c));
}

async function programTransact(
  input: ProgramTransactInput,
  tag: number,
  args: Uint8Array,
  accounts: readonly AccountMeta[],
): Promise<Instruction> {
  const sppAccounts = await transactCpiAccounts({
    payer: input.creator,
    inputTree: input.client.tree,
    outputTree: input.client.tree,
    data: input.transact,
    signerPdas: [input.authority.pda],
  });
  return {
    programAddress: input.programId,
    accounts: [...accounts, ...sppAccounts],
    data: concat(Uint8Array.of(tag), args, encodeTransactInstructionData(input.transact)),
  };
}

export function escrowInstruction(input: ProgramTransactInput): Promise<Instruction> {
  return programTransact(input, ESCROW_TAG, proofBytes(input.proof), [
    signer(input.creator, AccountRole.READONLY_SIGNER),
  ]);
}

export function withdrawInstruction(
  input: ProgramTransactInput & Readonly<{ unlock: bigint }>,
): Promise<Instruction> {
  return programTransact(
    input,
    WITHDRAW_TAG,
    concat(proofBytes(input.proof), u64le(input.unlock)),
    [
      signer(input.creator, AccountRole.WRITABLE_SIGNER),
      signer(input.creator, AccountRole.READONLY_SIGNER),
    ],
  );
}
