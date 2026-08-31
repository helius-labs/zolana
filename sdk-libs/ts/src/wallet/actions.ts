import type { ChainReader } from "../client/ports.js";
import {
  type Address,
  type Bytes32,
  type RequestContext,
  TransactWithdrawal,
} from "../interface/types.js";
import { ShieldedAddress } from "../keypair/shielded.js";
import { WithdrawalTarget } from "../transaction/instructions/transact.js";
import { hex, type Wallet, type WalletUtxo } from "../transaction/wallet/state.js";

import { reservedNoteKeys, unreserved } from "../flows/reserve.js";
import { resolveWithdrawalSettlement } from "../flows/settlement.js";
import {
  MAX_SPEND_INPUTS,
  isPlainUtxo,
  selectNotes,
  type SpendPolicy,
  type SpendSelectionErrors,
} from "../flows/select.js";
import { WalletError, wrapWalletError } from "./error.js";
import { equalBytes, reserveWalletEntries } from "./internal.js";
import { resolveRegisteredAddress } from "./registry.js";

export { resolveWithdrawalSettlement as resolveWithdrawal };

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
      target: WithdrawalTarget;
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
  readonly #reservationId?: string;

  constructor(
    input: Readonly<{
      payer: Address;
      tree: Address;
      inputs: readonly UnsignedSpendInput[];
      action: PrivateAction;
      withdrawal?: TransactWithdrawal;
      summary: string;
      reservationId?: string;
    }>,
  ) {
    this.#payer = input.payer;
    this.#tree = input.tree;
    this.#inputs = Object.freeze([...input.inputs]);
    this.#action = input.action;
    if (input.withdrawal !== undefined) this.#withdrawal = input.withdrawal;
    this.#summary = input.summary;
    if (input.reservationId !== undefined) this.#reservationId = input.reservationId;
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

  /** @internal */
  _inputs(): readonly UnsignedSpendInput[] {
    return this.#inputs;
  }

  /** @internal */
  _action(): PrivateAction {
    return this.#action;
  }

  /** @internal */
  _withdrawal(): TransactWithdrawal | undefined {
    return this.#withdrawal;
  }

  /** @internal */
  _summary(): string {
    return this.#summary;
  }

  /** @internal */
  _reservationId(): string | undefined {
    return this.#reservationId;
  }
}

export interface TransferParams {
  readonly client?: Pick<ChainReader, "getAccount">;
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
  readonly splTokenProgram?: Address | null;
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

const walletSelectionErrors: SpendSelectionErrors = {
  insufficient: ({ requested, available }) =>
    new WalletError("WALLET_INSUFFICIENT_BALANCE", {
      details: { requested: requested.toString(), available: available.toString() },
    }),
  tooManyInputs: ({ eligible, max }) =>
    new WalletError("WALLET_TOO_MANY_INPUTS", { details: { got: eligible, max } }),
  overflow: ({ available }) =>
    new WalletError("WALLET_SELECTED_BALANCE_OVERFLOW", {
      details: { available: available.toString() },
    }),
  multipleTrees: ({ asset, treeCount }) =>
    new WalletError("WALLET_MULTIPLE_INPUT_TREES", { details: { asset, treeCount } }),
};

function defaultSpendPolicy(): SpendPolicy {
  return {
    eligible: isPlainUtxo,
    ordering: "largestFirst",
    maxInputs: MAX_SPEND_INPUTS,
    tree: { kind: "inferSingle" },
    errors: walletSelectionErrors,
  };
}

function spendTree(wallet: Wallet, asset: Address): Address {
  const trees = new Set(
    wallet
      .utxos()
      .filter((entry) => !entry.spent && entry.utxo.asset === asset && isPlainUtxo(entry))
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

function selectSpendInputs(
  wallet: Wallet,
  asset: Address,
  amount: bigint,
): Readonly<{ tree: Address; inputs: readonly UnsignedSpendInput[]; reservationId: string }> {
  const reserved = reservedNoteKeys(wallet);
  const base = defaultSpendPolicy();
  const selection = selectNotes({
    wallet,
    asset,
    target: { kind: "cover", amount },
    policy: { ...base, eligible: (entry) => base.eligible(entry) && unreserved(reserved)(entry) },
  });
  const reservation = reserveWalletEntries(wallet, selection.entries);
  return {
    tree: selection.tree,
    inputs: Object.freeze(selection.entries.map((entry) => ({ entry }))),
    reservationId: reservation.id,
  };
}

export async function createWithdrawal(params: WithdrawalParams): Promise<CreatedWithdrawal> {
  u64Amount(params.amount);
  if (params.amount === 0n) {
    throw new WalletError("WALLET_INVALID_AMOUNT", { details: { amount: "0" } });
  }
  const resolved = await resolveWithdrawalSettlement(
    params.recipient,
    params.asset,
    params.splTokenProgram,
  );
  const { tree, inputs, reservationId } = selectSpendInputs(
    params.wallet,
    params.asset,
    params.amount,
  );
  return Object.freeze({
    transaction: new UnsignedPrivateTransaction({
      payer: params.payer,
      tree,
      inputs,
      reservationId,
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
      const { tree, inputs, reservationId } = selectSpendInputs(
        params.wallet,
        params.asset,
        params.amount,
      );
      return Object.freeze({
        transaction: new UnsignedPrivateTransaction({
          payer: params.payer,
          tree,
          inputs,
          reservationId,
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
    const { tree, inputs, reservationId } = selectSpendInputs(
      params.wallet,
      params.asset,
      params.amount,
    );
    return Object.freeze({
      transaction: new UnsignedPrivateTransaction({
        payer: params.payer,
        tree,
        inputs,
        reservationId,
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
  const tree = named ? named.outputContext.tree : spendTree(params.wallet, params.asset);
  const reserved = reservedNoteKeys(params.wallet);
  const candidates = entries.filter(
    (entry) =>
      entry.outputContext.tree === tree && isPlainUtxo(entry) && unreserved(reserved)(entry),
  );
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
  const hash = hex(selected.outputContext.hash);
  if (selected.utxo.ringProgramId !== undefined) {
    throw new WalletError("WALLET_SPLIT_INPUT_RING_MISMATCH", { details: { hash } });
  }
  if (!isPlainUtxo(selected)) {
    throw new WalletError("WALLET_SPLIT_INPUT_HAS_DATA", { details: { hash } });
  }
  if (selected.utxo.amount % BigInt(params.parts) !== 0n) {
    throw new WalletError("WALLET_SPLIT_NOT_DIVISIBLE", {
      details: { amount: selected.utxo.amount.toString(), parts: params.parts },
    });
  }
  const perOutputAmount = selected.utxo.amount / BigInt(params.parts);
  const reservation = reserveWalletEntries(params.wallet, [selected]);
  return Object.freeze({
    transaction: new UnsignedPrivateTransaction({
      payer: params.payer,
      tree,
      inputs: [{ entry: selected }],
      reservationId: reservation.id,
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
