import type { ZolanaClient } from "../client/client.js";
import { SPL_TOKEN_PROGRAM_ID } from "../interface/program.js";
import {
  type Address,
  type Bytes32,
  type RequestContext,
  type TransactWithdrawal,
} from "../interface/types.js";
import { associatedTokenAddress, splAssetVaultPda } from "../interface/pda/index.js";
import { ShieldedAddress } from "../keypair/shielded.js";
import { SOL_MINT } from "../transaction/wallet/asset.js";
import type { Wallet, WalletUtxo } from "../transaction/wallet/state.js";

import { WalletError, wrapWalletError } from "./error.js";
import { equalBytes } from "./internal.js";
import { resolveRegisteredAddress } from "./registry.js";

interface UnsignedSpendInput {
  readonly entry: WalletUtxo;
}

type PrivateAction =
  | Readonly<{
      kind: "transfer";
      recipient: ShieldedAddress;
      asset: Address;
      amount: bigint;
    }>
  | Readonly<{
      kind: "withdrawal";
      asset: Address;
      amount: bigint;
      target:
        | Readonly<{ kind: "sol"; recipient: Address }>
        | Readonly<{
            kind: "spl";
            userTokenAccount: Address;
            splTokenInterface: Address;
            vaultBump: number;
          }>;
    }>
  | Readonly<{
      kind: "split";
      asset: Address;
      numOutputs: number;
      perOutputAmount: bigint;
    }>;

export class UnsignedPrivateTransaction {
  readonly #payer: Address;
  readonly #tree: Address;
  readonly #inputs: readonly UnsignedSpendInput[];
  readonly #action: PrivateAction;
  readonly #withdrawal?: TransactWithdrawal;
  readonly #summary: string;

  constructor(
    input: Readonly<{
      payer: Address;
      tree: Address;
      inputs: readonly UnsignedSpendInput[];
      action: PrivateAction;
      withdrawal?: TransactWithdrawal;
      summary: string;
    }>,
  ) {
    this.#payer = input.payer;
    this.#tree = input.tree;
    this.#inputs = Object.freeze([...input.inputs]);
    this.#action = input.action;
    if (input.withdrawal !== undefined) this.#withdrawal = input.withdrawal;
    this.#summary = input.summary;
  }

  payer(): Address {
    return this.#payer;
  }

  tree(): Address {
    return this.#tree;
  }

  inputCount(): number {
    return this.#inputs.length;
  }

  _inputs(): readonly UnsignedSpendInput[] {
    return this.#inputs;
  }

  _action(): PrivateAction {
    return this.#action;
  }

  _withdrawal(): TransactWithdrawal | undefined {
    return this.#withdrawal;
  }

  _summary(): string {
    return this.#summary;
  }
}

export interface TransferParams {
  readonly client?: Pick<ZolanaClient, "getAccount">;
  readonly wallet: Wallet;
  readonly payer: Address;
  readonly recipient: TransferDestination;
  readonly asset: Address;
  readonly amount: bigint;
}

export type TransferDestination = Address | ShieldedAddress;

export interface WithdrawalParams {
  readonly wallet: Wallet;
  readonly payer: Address;
  readonly recipient: Address;
  readonly asset: Address;
  readonly amount: bigint;
}

export type TransferRecipient =
  | Readonly<{
      kind: "shielded";
      address: ShieldedAddress;
      viewTag: Bytes32;
    }>
  | Readonly<{
      kind: "registered";
      owner: Address;
      address: ShieldedAddress;
      viewTag: Bytes32;
    }>;

export interface CreatedTransfer {
  readonly transaction: UnsignedPrivateTransaction;
  readonly recipient: TransferRecipient;
}

export interface CreatedWithdrawal {
  readonly transaction: UnsignedPrivateTransaction;
  readonly withdrawal: TransactWithdrawal;
}

export interface SplitParams {
  readonly wallet: Wallet;
  readonly payer: Address;
  readonly asset: Address;
  readonly parts: number;
  readonly input?: Bytes32;
}

export interface CreatedSplit {
  readonly transaction: UnsignedPrivateTransaction;
  readonly numOutputs: number;
  readonly perOutputAmount: bigint;
}

/** Rust takes a `u64`, so only a value outside that range is refused. */
function u64Amount(amount: bigint): void {
  if (amount < 0n || amount > 0xffff_ffff_ffff_ffffn) {
    throw new WalletError("WALLET_INVALID_AMOUNT", {
      details: { amount: amount.toString() },
    });
  }
}

function plain(entry: WalletUtxo): boolean {
  return (
    entry.utxo.zoneProgramId === undefined &&
    entry.zoneDataHash === undefined &&
    entry.dataHash === undefined &&
    entry.utxo.data.isEmpty()
  );
}

function spendTree(
  wallet: Wallet,
  asset: Address,
  eligible: (entry: WalletUtxo) => boolean,
): Address {
  const trees = new Set(
    wallet
      .utxos()
      .filter((entry) => !entry.spent && entry.utxo.asset === asset && eligible(entry))
      .map((entry) => entry.outputContext.tree),
  );
  const first = trees.values().next();
  if (first.done) {
    throw new WalletError("WALLET_INSUFFICIENT_BALANCE", {
      details: { requested: "1", available: "0" },
    });
  }
  if (trees.size !== 1) {
    throw new WalletError("WALLET_MULTIPLE_INPUT_TREES", {
      details: { asset, treeCount: trees.size },
    });
  }
  return first.value;
}

function selectInputs(
  wallet: Wallet,
  tree: Address,
  asset: Address,
  amount: bigint,
  eligible: (entry: WalletUtxo) => boolean,
): readonly UnsignedSpendInput[] {
  const selected: UnsignedSpendInput[] = [];
  let available = 0n;
  for (const entry of wallet.utxos()) {
    if (
      entry.spent ||
      entry.utxo.asset !== asset ||
      entry.outputContext.tree !== tree ||
      !eligible(entry)
    ) {
      continue;
    }
    selected.push({ entry });
    available += entry.utxo.amount;
    // Rust sums into a `u64`, so a running total past that ceiling is a
    // rejection there rather than a wider number.
    if (available > 0xffff_ffff_ffff_ffffn) {
      throw new WalletError("WALLET_SELECTED_BALANCE_OVERFLOW", {
        details: { available: available.toString() },
      });
    }
    if (available >= amount) return Object.freeze(selected);
  }
  throw new WalletError("WALLET_INSUFFICIENT_BALANCE", {
    details: { requested: amount.toString(), available: available.toString() },
  });
}

async function withdrawal(
  recipient: Address,
  asset: Address,
): Promise<
  Readonly<{
    target: Extract<PrivateAction, { kind: "withdrawal" }>["target"];
    accounts: TransactWithdrawal;
  }>
> {
  if (asset === SOL_MINT) {
    return {
      target: { kind: "sol", recipient },
      accounts: { kind: "sol", recipient },
    };
  }
  const [userTokenAccount, [splTokenInterface, vaultBump]] = await Promise.all([
    associatedTokenAddress(recipient, asset),
    splAssetVaultPda(asset),
  ]);
  return {
    target: { kind: "spl", userTokenAccount, splTokenInterface, vaultBump },
    accounts: {
      kind: "spl",
      mint: asset,
      splTokenInterface,
      userTokenAccount,
      tokenProgram: SPL_TOKEN_PROGRAM_ID,
    },
  };
}

export async function createWithdrawal(params: WithdrawalParams): Promise<CreatedWithdrawal> {
  u64Amount(params.amount);
  if (params.amount === 0n) {
    throw new WalletError("WALLET_INVALID_AMOUNT", { details: { amount: "0" } });
  }
  const tree = spendTree(params.wallet, params.asset, plain);
  const inputs = selectInputs(params.wallet, tree, params.asset, params.amount, plain);
  const resolved = await withdrawal(params.recipient, params.asset);
  return Object.freeze({
    transaction: new UnsignedPrivateTransaction({
      payer: params.payer,
      tree,
      inputs,
      action: {
        kind: "withdrawal",
        asset: params.asset,
        amount: params.amount,
        target: resolved.target,
      },
      withdrawal: resolved.accounts,
      summary: `private transaction withdrawal of ${String(params.amount)} to ${params.recipient}`,
    }),
    withdrawal: resolved.accounts,
  });
}

export async function createTransfer(
  params: TransferParams,
  context?: RequestContext,
): Promise<CreatedTransfer> {
  u64Amount(params.amount);
  try {
    const recipient = params.recipient;
    if (recipient instanceof ShieldedAddress) {
      const tree = spendTree(params.wallet, params.asset, plain);
      const inputs = selectInputs(params.wallet, tree, params.asset, params.amount, plain);
      return Object.freeze({
        transaction: new UnsignedPrivateTransaction({
          payer: params.payer,
          tree,
          inputs,
          action: {
            kind: "transfer",
            recipient,
            asset: params.asset,
            amount: params.amount,
          },
          summary: `private transaction transfer of ${String(params.amount)} to a shielded address`,
        }),
        recipient: {
          kind: "shielded" as const,
          address: recipient,
          viewTag: recipient.confidentialViewTag(),
        },
      });
    }
    if (params.client === undefined) {
      throw new WalletError("WALLET_RECIPIENT_CLIENT_REQUIRED");
    }
    const registered = await resolveRegisteredAddress(
      { rpc: params.client, owner: recipient },
      context,
    );
    if (registered === undefined) {
      throw new WalletError("WALLET_RECIPIENT_NOT_REGISTERED", {
        details: { recipient },
      });
    }
    const tree = spendTree(params.wallet, params.asset, plain);
    const inputs = selectInputs(params.wallet, tree, params.asset, params.amount, plain);
    return Object.freeze({
      transaction: new UnsignedPrivateTransaction({
        payer: params.payer,
        tree,
        inputs,
        action: {
          kind: "transfer",
          recipient: registered.address,
          asset: params.asset,
          amount: params.amount,
        },
        summary: `private transaction transfer of ${String(params.amount)} to ${recipient}`,
      }),
      recipient: { kind: "registered" as const, ...registered },
    });
  } catch (cause) {
    throw wrapWalletError("WALLET_CREATE_TRANSFER", cause);
  }
}

export function createSplit(params: SplitParams): CreatedSplit {
  if (!Number.isInteger(params.parts) || params.parts < 2 || params.parts > 8) {
    throw new WalletError("WALLET_SPLIT_INVALID_PART_COUNT", {
      details: { parts: params.parts },
    });
  }
  const entries = params.wallet
    .utxos()
    .filter((entry) => !entry.spent && entry.utxo.asset === params.asset);
  const named = params.input
    ? entries.find((entry) => equalBytes(entry.outputContext.hash, params.input as Bytes32))
    : undefined;
  if (params.input !== undefined && named === undefined) {
    throw new WalletError("WALLET_INPUT_UTXO_UNAVAILABLE");
  }
  const tree = named ? named.outputContext.tree : spendTree(params.wallet, params.asset, plain);
  const candidates = entries.filter((entry) => entry.outputContext.tree === tree && plain(entry));
  const selected =
    named ??
    [...candidates]
      .filter((entry) => entry.utxo.amount % BigInt(params.parts) === 0n)
      .sort((left, right) =>
        left.utxo.amount > right.utxo.amount ? -1 : left.utxo.amount < right.utxo.amount ? 1 : 0,
      )[0];
  if (selected === undefined) {
    const largest = [...candidates].sort((left, right) =>
      left.utxo.amount > right.utxo.amount ? -1 : 1,
    )[0];
    if (largest !== undefined) {
      throw new WalletError("WALLET_SPLIT_NOT_DIVISIBLE", {
        details: { amount: largest.utxo.amount.toString(), parts: params.parts },
      });
    }
    throw new WalletError("WALLET_INSUFFICIENT_BALANCE");
  }
  const hash = selected.outputContext.hash;
  if (selected.utxo.zoneProgramId !== undefined) {
    throw new WalletError("WALLET_SPLIT_INPUT_ZONE_MISMATCH", { details: { hash } });
  }
  if (!plain(selected)) throw new WalletError("WALLET_SPLIT_INPUT_HAS_DATA", { details: { hash } });
  if (selected.utxo.amount % BigInt(params.parts) !== 0n) {
    throw new WalletError("WALLET_SPLIT_NOT_DIVISIBLE", {
      details: { amount: selected.utxo.amount.toString(), parts: params.parts },
    });
  }
  const perOutputAmount = selected.utxo.amount / BigInt(params.parts);
  return Object.freeze({
    transaction: new UnsignedPrivateTransaction({
      payer: params.payer,
      tree,
      inputs: [{ entry: selected }],
      action: {
        kind: "split",
        asset: params.asset,
        numOutputs: params.parts,
        perOutputAmount,
      },
      summary: `private transaction split into ${String(params.parts)} utxos of ${String(perOutputAmount)}`,
    }),
    numOutputs: params.parts,
    perOutputAmount,
  });
}
