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
  readonly tree: Readonly<{ kind: "fixed"; tree: Address }> | Readonly<{ kind: "inferSingle" }>;
  readonly errors: SpendSelectionErrors;
}

/** @internal */
export type SpendTarget =
  | Readonly<{ kind: "cover"; amount: bigint }>
  | Readonly<{ kind: "consolidate"; minInputs: number }>;

/** @internal */
export interface SelectedSpendInputs {
  readonly entries: readonly WalletUtxo[];
  /** Every entry's tree. */
  readonly tree: Address;
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
  const tree = resolveTree(input.asset, policy, candidates);
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
    return Object.freeze({ entries: Object.freeze(entries), tree, total });
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
  return Object.freeze({ entries: Object.freeze(entries), tree, total });
}

function resolveTree(
  asset: Address,
  policy: SpendPolicy,
  candidates: readonly WalletUtxo[],
): Address {
  if (policy.tree.kind === "fixed") return policy.tree.tree;
  const trees = new Set(candidates.map((entry) => entry.outputContext.tree));
  const first = trees.values().next();
  if (first.done) {
    throw policy.errors.insufficient({ asset, requested: 1n, available: 0n });
  }
  if (trees.size !== 1) {
    throw requiredError(
      policy.errors.multipleTrees,
      "multipleTrees",
    )({
      asset,
      treeCount: trees.size,
    });
  }
  return first.value;
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
