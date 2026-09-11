import { SPP_SUPPORTED_SHAPES } from "../interface/shape.js";
import type { Address } from "../interface/types.js";
import type { Wallet, WalletUtxo } from "../transaction/wallet/state.js";

const U64_MAX = 0xffff_ffff_ffff_ffffn;

/** @internal The cover cap, matches Rust `select_bounded_inputs`. */
export const MAX_SPEND_INPUTS = Math.max(...SPP_SUPPORTED_SHAPES.map((shape) => shape.inputs));

/** @internal Rust `is_plain_utxo`, a UTXO the default rail can always prove. */
export function isPlainUtxo(entry: WalletUtxo): boolean {
  return (
    entry.utxo.ringProgramId === undefined &&
    entry.ringDataHash === undefined &&
    entry.dataHash === undefined &&
    entry.utxo.data.isEmpty()
  );
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
  /**
   * `infer` takes the trees the selected UTXOs happen to sit in, up to
   * `maxTrees` of them. A rail that publishes one input tree passes
   * `maxTrees: 1`.
   */
  readonly tree:
    | Readonly<{ kind: "fixed"; tree: Address }>
    | Readonly<{ kind: "infer"; maxTrees: number }>;
  readonly errors: SpendSelectionErrors;
}

/** @internal */
export type SpendTarget =
  | Readonly<{ kind: "cover"; amount: bigint }>
  | Readonly<{ kind: "consolidate"; minInputs: number }>;

/** @internal */
export interface SelectedSpendInputs {
  /** Grouped by tree: each tree owns one contiguous run, as a proof requires. */
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
  const candidates = input.wallet
    .utxos()
    .filter(
      (entry) =>
        !entry.spent &&
        entry.utxo.asset === input.asset &&
        policy.eligible(entry) &&
        (policy.tree.kind !== "fixed" || entry.outputContext.tree === policy.tree.tree),
    );
  if (policy.tree.kind === "infer" && candidates.length === 0) {
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
    if (total > U64_MAX) throw policy.errors.overflow({ available: total });
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

/**
 * A proof gives each input tree one contiguous run of inputs, so the selected
 * entries are reordered into per-tree runs, keeping the amount order inside
 * each. A policy that infers the trees refuses more runs than it admits.
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
