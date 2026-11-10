import { SPP_SUPPORTED_SHAPES } from "../interface/shape.js";
import type { Address } from "../interface/types.js";
import {
  isDefaultRingSpendable,
  type Wallet,
  type WalletUtxo,
} from "../transaction/wallet/state.js";

const U64_MAX = 0xffff_ffff_ffff_ffffn;

/**
 * @internal Notes a wallet spend selects at most, Rust `MAX_SPEND_INPUTS`. Selection
 * pads with random dummies, so the cheapest shape holding this many notes still
 * fits one transaction with two encrypted outputs, inputs from every allowed
 * tree, an owner signer other than the payer and an SPL withdrawal; the next
 * wider shape does not. A wider balance merges first.
 */
export const MAX_SPEND_INPUTS = 40;

/**
 * @internal UTXOs a spend with `outputs` outputs selects at most: the widest
 * shape holding that many outputs, capped at `MAX_SPEND_INPUTS`. A transfer with
 * two payments and change proves on 4-output keys, which take at most 24 UTXOs.
 */
export function maxSpendInputs(outputs: number): number {
  const widest = SPP_SUPPORTED_SHAPES.filter((shape) => shape.outputs >= outputs).reduce(
    (max, shape) => Math.max(max, shape.inputs),
    0,
  );
  return Math.min(MAX_SPEND_INPUTS, widest);
}

/**
 * @internal Rust `WalletUtxo::is_plain`: default-ring spendable with no
 * attached data, the only UTXOs a split or a merge takes, since their spend
 * input drops the committed data hashes. A transfer or withdrawal takes any
 * `isDefaultRingSpendable` UTXO.
 */
export function isPlainUtxo(entry: WalletUtxo): boolean {
  return isDefaultRingSpendable(entry) && entry.dataHash === undefined && entry.utxo.data.isEmpty();
}

/** @internal */
export interface SpendSelectionErrors {
  insufficient(input: Readonly<{ asset: Address; requested: bigint; available: bigint }>): Error;
  tooManyInputs(input: Readonly<{ eligible: number; max: number }>): Error;
  overflow(input: Readonly<{ available: bigint }>): Error;
  multipleTrees?(input: Readonly<{ asset: Address; treeCount: number }>): Error;
  tooFewUtxos?(input: Readonly<{ eligible: number; minimum: number }>): Error;
}

/** @internal */
export interface SpendPolicy {
  readonly eligible: (entry: WalletUtxo) => boolean;
  readonly ordering: "largestFirst" | "smallestFirst";
  readonly maxInputs: number;
  /** Ring proofs range-check individual outputs, not the wallet's unspent total. */
  readonly allowWideBalance?: true;
  /**
   * `infer` takes the trees the selected UTXOs happen to sit in, up to
   * `maxTrees` of them. A rail that publishes one input tree passes
   * `maxTrees: 1`. `fullest` takes only the eligible UTXOs of the tree that
   * holds the most of them, the lowest tree id on a tie, as Rust
   * `select_merge` does.
   */
  readonly tree:
    | Readonly<{ kind: "fixed"; tree: Address }>
    | Readonly<{ kind: "infer"; maxTrees: number }>
    | Readonly<{ kind: "fullest" }>;
  readonly errors: SpendSelectionErrors;
}

/** @internal */
export type SpendTarget =
  | Readonly<{ kind: "cover"; amount: bigint }>
  | Readonly<{ kind: "consolidate"; minInputs: number }>;

/** @internal */
export interface SelectedSpendInputs {
  /** Grouped by tree: each tree owns one contiguous run. */
  readonly entries: readonly WalletUtxo[];
  /** The entries' trees, in the order the entries first sit in them. */
  readonly trees: readonly Address[];
  /** The whole eligible balance. */
  readonly total: bigint;
}

/** @internal */
export function selectUtxos(
  input: Readonly<{
    wallet: Wallet;
    asset: Address;
    target: SpendTarget;
    policy: SpendPolicy;
  }>,
): SelectedSpendInputs {
  const policy = input.policy;
  const eligible = input.wallet
    .utxos()
    .filter(
      (entry) =>
        !entry.spent &&
        entry.utxo.asset === input.asset &&
        entry.utxo.amount > 0n &&
        policy.eligible(entry) &&
        (policy.tree.kind !== "fixed" || entry.outputContext.tree === policy.tree.tree),
    );
  const candidates = policy.tree.kind === "fullest" ? fullestTree(eligible) : eligible;
  if (policy.tree.kind !== "fixed" && candidates.length === 0) {
    throw policy.errors.insufficient({ asset: input.asset, requested: 1n, available: 0n });
  }
  const sorted = [...candidates].sort((left, right) => {
    const ascending =
      left.utxo.amount < right.utxo.amount ? -1 : left.utxo.amount > right.utxo.amount ? 1 : 0;
    return policy.ordering === "largestFirst" ? -ascending : ascending;
  });
  let total = 0n;
  for (const entry of sorted) {
    total += entry.utxo.amount;
    if (policy.allowWideBalance !== true && total > U64_MAX)
      throw policy.errors.overflow({ available: total });
  }

  if (input.target.kind === "consolidate") {
    const entries = sorted.slice(0, policy.maxInputs);
    if (entries.length < input.target.minInputs) {
      throw requiredError(
        policy.errors.tooFewUtxos,
        "tooFewUtxos",
      )({
        eligible: entries.length,
        minimum: input.target.minInputs,
      });
    }
    return grouped(entries, input.asset, policy, total);
  }

  const amount = input.target.amount;
  const entries: WalletUtxo[] = [];
  let available = 0n;
  for (const entry of sorted.slice(0, policy.maxInputs)) {
    entries.push(entry);
    available += entry.utxo.amount;
    if (available >= amount) break;
  }
  if (available < amount) {
    if (total >= amount) {
      throw policy.errors.tooManyInputs({ eligible: sorted.length, max: policy.maxInputs });
    }
    throw policy.errors.insufficient({ asset: input.asset, requested: amount, available: total });
  }
  return grouped(entries, input.asset, policy, total);
}

/** The entries of the tree holding the most of them; the lowest tree id wins a tie. */
function fullestTree(entries: readonly WalletUtxo[]): readonly WalletUtxo[] {
  const trees = new Map<number, WalletUtxo[]>();
  for (const entry of entries) {
    const run = trees.get(entry.outputContext.treeId);
    if (run === undefined) trees.set(entry.outputContext.treeId, [entry]);
    else run.push(entry);
  }
  let fullest: Readonly<{ treeId: number; entries: readonly WalletUtxo[] }> | undefined;
  for (const [treeId, run] of trees) {
    if (
      fullest === undefined ||
      run.length > fullest.entries.length ||
      (run.length === fullest.entries.length && treeId < fullest.treeId)
    ) {
      fullest = { treeId, entries: run };
    }
  }
  return fullest?.entries ?? [];
}

/**
 * The selected entries are reordered into per-tree runs, keeping the amount
 * order inside each. A policy that infers the trees refuses more trees than
 * its `maxTrees`.
 */
function grouped(
  entries: readonly WalletUtxo[],
  asset: Address,
  policy: SpendPolicy,
  total: bigint,
): SelectedSpendInputs {
  const trees: Address[] = [];
  for (const entry of entries) {
    if (!trees.includes(entry.outputContext.tree)) trees.push(entry.outputContext.tree);
  }
  if (policy.tree.kind === "infer" && trees.length > policy.tree.maxTrees) {
    throw requiredError(
      policy.errors.multipleTrees,
      "multipleTrees",
    )({
      asset,
      treeCount: trees.length,
    });
  }
  return Object.freeze({
    entries: Object.freeze(
      trees.flatMap((tree) => entries.filter((entry) => entry.outputContext.tree === tree)),
    ),
    trees: Object.freeze(trees),
    total,
  });
}

function requiredError<T>(
  handler: ((input: T) => Error) | undefined,
  name: string,
): (input: T) => Error {
  if (handler === undefined) {
    throw new Error(`the selection policy names no ${name} error`);
  }
  return handler;
}
