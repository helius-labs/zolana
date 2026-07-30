import type { TransactionSigner } from "@solana/kit";

import { buildUnsignedTransaction } from "../client/kit.js";
import type { ZolanaClient } from "../client/client.js";
import { SPL_TOKEN_PROGRAM_ID } from "../interface/program.js";
import { checkedTransactionSize } from "../interface/transaction-size.js";
import {
  type Address,
  type Bytes32,
  type AssetDeposit,
  type DepositAsset,
  type Instruction,
  type RequestContext,
  type Signature,
  type Transaction,
} from "../interface/types.js";
import { associatedTokenAddress } from "../interface/pda/index.js";
import { depositInstruction } from "../interface/instructions/index.js";
import { randomBlinding } from "../keypair/bytes.js";
import type { ShieldedAddress } from "../keypair/shielded.js";
import { ownerUtxoHash } from "../transaction/utxo.js";
import { SOL_MINT } from "../transaction/wallet/asset.js";

import { WalletError, wrapWalletError } from "./error.js";

export interface DepositParams {
  readonly recipient: ShieldedAddress;
  readonly asset: Address;
  readonly amount: bigint;
  readonly splTokenAccount?: Address;
  readonly splTokenProgram?: Address | null;
  readonly memo?: Uint8Array;
}

export interface DepositActionParams {
  readonly client: Pick<
    ZolanaClient,
    "tree" | "signAndSendInstructions" | "confirmPrivateTransaction"
  >;
  readonly feePayer: TransactionSigner;
  readonly depositor?: TransactionSigner;
  readonly tree?: Address;
  readonly recipient: ShieldedAddress;
  readonly asset?: Address;
  readonly amount: bigint;
  readonly splTokenAccount?: Address;
  readonly splTokenProgram?: Address | null;
  readonly memo?: Uint8Array;
  readonly waitForIndexer?: boolean;
}

export interface SubmittedDeposit {
  readonly signature: Signature;
  readonly utxoHash: Bytes32;
}

export class Deposit {
  readonly data: Omit<AssetDeposit, "asset">;
  readonly utxoHash: Bytes32;
  readonly asset: Address;
  readonly settlement: DepositAsset;

  constructor(
    input: Readonly<{
      data: Omit<AssetDeposit, "asset">;
      utxoHash: Bytes32;
      asset: Address;
      settlement: DepositAsset;
    }>,
  ) {
    this.data = Object.freeze({
      ...input.data,
      viewTag: new Uint8Array(input.data.viewTag) as Bytes32,
      owner: new Uint8Array(input.data.owner) as Bytes32,
      blinding: new Uint8Array(input.data.blinding) as Bytes32,
      ...(input.data.memo === undefined ? {} : { memo: new Uint8Array(input.data.memo) }),
    });
    this.utxoHash = new Uint8Array(input.utxoHash) as Bytes32;
    this.asset = input.asset;
    this.settlement = input.settlement;
  }

  instruction(tree: Address, depositor: Address): Promise<Instruction> {
    return depositInstruction({
      tree,
      depositor,
      deposits: [{ ...this.data, asset: this.settlement }],
    });
  }

  viewTag(): Bytes32 {
    return new Uint8Array(this.data.viewTag) as Bytes32;
  }
}

export async function createDeposit(params: DepositParams): Promise<Deposit> {
  try {
    if (params.amount <= 0n || params.amount > 0xffff_ffff_ffff_ffffn) {
      throw new WalletError("WALLET_INVALID_AMOUNT", {
        details: { amount: params.amount.toString() },
      });
    }
    const owner = params.recipient.ownerHash();
    const blinding = randomBlinding();
    const data: Omit<AssetDeposit, "asset"> = {
      viewTag: params.recipient.viewingPublicKey.x(),
      owner,
      blinding,
      amount: params.amount,
      ...(params.memo === undefined ? {} : { memo: new Uint8Array(params.memo) }),
    };
    // A SOL deposit needs no token accounts, so one supplied alongside it is
    // ignored rather than rejected.
    let settlement: DepositAsset = { kind: "sol" };
    if (params.asset !== SOL_MINT) {
      if (params.splTokenAccount === undefined) {
        throw new WalletError("WALLET_MISSING_SPL_TOKEN_ACCOUNT", {
          details: { mint: params.asset },
        });
      }
      settlement = {
        kind: "spl",
        accounts: {
          mint: params.asset,
          userToken: params.splTokenAccount,
          tokenProgram: params.splTokenProgram ?? SPL_TOKEN_PROGRAM_ID,
        },
      };
    }
    return new Deposit({
      data,
      utxoHash: ownerUtxoHash({
        owner,
        asset: params.asset,
        amount: params.amount,
        blinding,
      }),
      asset: params.asset,
      settlement,
    });
  } catch (cause) {
    throw wrapWalletError("WALLET_CREATE_DEPOSIT", cause);
  }
}

/**
 * Build, sign, and send a deposit. The depositor signs alongside the payer only
 * when they are different accounts; the funding account must authorize the
 * lamport or token transfer either way.
 */
export async function submitDeposit(
  input: Readonly<{
    client: Pick<ZolanaClient, "signAndSendInstructions">;
    payer: TransactionSigner;
    tree: Address;
    depositor: TransactionSigner;
    deposit: Deposit;
  }>,
  context?: RequestContext,
): Promise<Signature> {
  try {
    return await input.client.signAndSendInstructions(
      {
        feePayer: input.payer,
        instructions: [await input.deposit.instruction(input.tree, input.depositor.address)],
        ...(input.depositor.address === input.payer.address
          ? {}
          : { additionalSigners: [input.depositor] }),
      },
      context,
    );
  } catch (cause) {
    throw wrapWalletError("WALLET_DEPOSIT", cause);
  }
}

export async function deposit(
  input: DepositActionParams,
  context?: RequestContext,
): Promise<SubmittedDeposit> {
  const depositor = input.depositor ?? input.feePayer;
  const asset = input.asset ?? SOL_MINT;
  const splTokenAccount =
    asset === SOL_MINT
      ? undefined
      : (input.splTokenAccount ??
        (await associatedTokenAddress(depositor.address, asset, input.splTokenProgram)));
  const created = await createDeposit({
    recipient: input.recipient,
    asset,
    amount: input.amount,
    ...(splTokenAccount === undefined ? {} : { splTokenAccount }),
    ...(input.splTokenProgram === undefined ? {} : { splTokenProgram: input.splTokenProgram }),
    ...(input.memo === undefined ? {} : { memo: input.memo }),
  });
  const signature = await submitDeposit(
    {
      client: input.client,
      payer: input.feePayer,
      tree: input.tree ?? input.client.tree,
      depositor,
      deposit: created,
    },
    context,
  );
  if (input.waitForIndexer !== false) {
    await input.client.confirmPrivateTransaction(signature, context);
  }
  return Object.freeze({ signature, utxoHash: new Uint8Array(created.utxoHash) as Bytes32 });
}

export async function buildDepositTransaction(
  input: Readonly<{
    client: Pick<ZolanaClient, "getLatestBlockhash">;
    payer: Address;
    tree: Address;
    depositor: Address;
    deposit: Deposit;
  }>,
  context?: RequestContext,
): Promise<Transaction> {
  try {
    const lifetime = await input.client.getLatestBlockhash(context);
    return checkedTransactionSize(
      buildUnsignedTransaction({
        feePayer: input.payer,
        lifetime,
        instructions: [await input.deposit.instruction(input.tree, input.depositor)],
      }),
    );
  } catch (cause) {
    throw wrapWalletError("WALLET_BUILD_DEPOSIT", cause);
  }
}
