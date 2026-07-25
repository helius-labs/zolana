import type { Rpc } from "@zolana/client";
import {
  SPL_TOKEN_PROGRAM_ID,
  type Address,
  type Bytes31,
  type Bytes32,
  type DepositInstructionData,
  type Instruction,
  type RequestContext,
  type Signature,
  type Transaction,
} from "@zolana/interface";
import { splAssetRegistryAddress, splAssetVaultAddress } from "@zolana/interface/pda";
import { depositInstruction } from "@zolana/interface/instructions";
import { randomBlinding, type ShieldedAddress } from "@zolana/keypair";
import { SOL_MINT, ownerUtxoHash } from "@zolana/transaction";

import { WalletError, wrapWalletError } from "./error.js";
import { compileTransaction } from "./internal.js";
import type { TransactionSigner } from "./submit.js";

export interface DepositSplAccounts {
  readonly userToken: Address;
  readonly splTokenInterface: Address;
  readonly registry: Address;
  readonly tokenProgram: Address;
}

export interface DepositParams {
  readonly recipient: ShieldedAddress;
  readonly asset: Address;
  readonly amount: bigint;
  readonly splTokenAccount?: Address;
  readonly memo?: Uint8Array;
}

export class Deposit {
  readonly data: DepositInstructionData;
  readonly utxoHash: Bytes32;
  readonly asset: Address;
  readonly spl?: DepositSplAccounts;

  constructor(
    input: Readonly<{
      data: DepositInstructionData;
      utxoHash: Bytes32;
      asset: Address;
      spl?: DepositSplAccounts;
    }>,
  ) {
    this.data = Object.freeze({
      ...input.data,
      viewTag: new Uint8Array(input.data.viewTag) as Bytes32,
      owner: new Uint8Array(input.data.owner) as Bytes32,
      blinding: new Uint8Array(input.data.blinding) as Bytes31,
      ...(input.data.memo === undefined ? {} : { memo: new Uint8Array(input.data.memo) }),
    });
    this.utxoHash = new Uint8Array(input.utxoHash) as Bytes32;
    this.asset = input.asset;
    if (input.spl !== undefined) this.spl = Object.freeze({ ...input.spl });
  }

  instruction(tree: Address, depositor: Address): Instruction {
    return depositInstruction({
      tree,
      depositor,
      data: this.data,
      ...(this.spl === undefined ? {} : { spl: this.spl }),
    });
  }

  viewTag(): Bytes32 {
    return new Uint8Array(this.data.viewTag) as Bytes32;
  }
}

export function createDeposit(params: DepositParams): Deposit {
  try {
    if (params.amount < 0n || params.amount > 0xffff_ffff_ffff_ffffn) {
      throw new WalletError("WALLET_INVALID_AMOUNT", {
        details: { amount: params.amount.toString() },
      });
    }
    const owner = params.recipient.ownerHash();
    const blinding = randomBlinding();
    const data: DepositInstructionData = {
      // Every output is tagged by its owner pubkey, so discovery keys on the
      // recipient's signing key, not its viewing key.
      viewTag: params.recipient.confidentialViewTag(),
      owner,
      blinding,
      amount: params.amount,
      ...(params.memo === undefined ? {} : { memo: new Uint8Array(params.memo) }),
    };
    // A SOL deposit needs no token accounts, so one supplied alongside it is
    // ignored rather than rejected.
    let spl: DepositSplAccounts | undefined;
    if (params.asset !== SOL_MINT) {
      if (params.splTokenAccount === undefined) {
        throw new WalletError("WALLET_MISSING_SPL_TOKEN_ACCOUNT", {
          details: { mint: params.asset },
        });
      }
      spl = {
        userToken: params.splTokenAccount,
        splTokenInterface: splAssetVaultAddress(params.asset),
        registry: splAssetRegistryAddress(params.asset),
        tokenProgram: SPL_TOKEN_PROGRAM_ID,
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
      ...(spl === undefined ? {} : { spl }),
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
export async function deposit(
  input: Readonly<{
    rpc: Rpc;
    payer: TransactionSigner;
    tree: Address;
    depositor: TransactionSigner;
    deposit: Deposit;
  }>,
  context?: RequestContext,
): Promise<Signature> {
  try {
    const unsigned = await buildDepositTransaction(
      {
        rpc: input.rpc,
        payer: input.payer.address,
        tree: input.tree,
        depositor: input.depositor.address,
        deposit: input.deposit,
      },
      context,
    );
    let signed = await input.payer.signNativeTransaction(unsigned);
    if (input.depositor.address !== input.payer.address) {
      signed = await input.depositor.signNativeTransaction(signed);
    }
    return await input.rpc.sendTransaction(signed, context);
  } catch (cause) {
    throw wrapWalletError("WALLET_DEPOSIT", cause);
  }
}

export async function buildDepositTransaction(
  input: Readonly<{
    rpc: Rpc;
    payer: Address;
    tree: Address;
    depositor: Address;
    deposit: Deposit;
  }>,
  context?: RequestContext,
): Promise<Transaction> {
  try {
    const latest = await input.rpc.getLatestBlockhash(context);
    return compileTransaction({
      feePayer: input.payer,
      recentBlockhash: latest.blockhash,
      instructions: [input.deposit.instruction(input.tree, input.depositor)],
    });
  } catch (cause) {
    throw wrapWalletError("WALLET_BUILD_DEPOSIT", cause);
  }
}
