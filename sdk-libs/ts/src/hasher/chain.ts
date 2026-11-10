/**
 * The Poseidon hash chains Rust builds public inputs from, written once over
 * any field representation. Each layer supplies its own `hash`, so a rejected
 * input surfaces in that layer's error taxonomy.
 */

/** A field element as a `bigint` or as 32 big-endian bytes. */
export type FieldElement = bigint | Uint8Array;

/** How one layer represents and hashes a field element. */
export interface ChainField<T extends FieldElement> {
  /** A fresh zero element, the value of an empty chain. */
  readonly zero: () => T;
  readonly isZero: (value: T) => boolean;
  readonly hash: (inputs: readonly T[]) => T;
}

/** `Poseidon(...Poseidon(Poseidon(v0, v1), v2)..., vn)`. Mirrors Rust `create_hash_chain_from_slice`. */
export function foldHashChain<T extends FieldElement>(
  values: readonly T[],
  field: ChainField<T>,
): T {
  const [first, ...remaining] = values;
  if (first === undefined) return field.zero();
  let result = first;
  for (const value of remaining) result = field.hash([result, value]);
  return result;
}

/**
 * Folds three elements per Poseidon call, a short last group padded with zeros.
 * The fold carries no length tag, so it is injective only over the
 * fixed-length public-input chains of one circuit.
 */
export function foldHashChain4<T extends FieldElement>(
  values: readonly T[],
  field: ChainField<T>,
): T {
  const [first, ...remaining] = values;
  if (first === undefined) return field.zero();
  let result = first;
  for (let index = 0; index < remaining.length; index += 3) {
    result = field.hash([
      result,
      remaining[index] ?? field.zero(),
      remaining[index + 1] ?? field.zero(),
      remaining[index + 2] ?? field.zero(),
    ]);
  }
  return result;
}

/** `Poseidon(v0, Poseidon(v1, ...Poseidon(vn-1, vn)))`. */
export function foldRightHashChain<T extends FieldElement>(
  values: readonly T[],
  field: ChainField<T>,
): T {
  const last = values.at(-1);
  if (last === undefined) return field.zero();
  let result = last;
  for (let index = values.length - 2; index >= 0; index -= 1) {
    result = field.hash([values[index] as T, result]);
  }
  return result;
}

/**
 * Folds three elements per Poseidon call from the right: the chain starts at
 * the last element and every group of up to three preceding elements, in
 * order, folds as `Poseidon(g0, g1, g2, h)`. The short group is the leftmost
 * one and its elements stay left-aligned, so an all-zero suffix folds to a
 * value that depends on its length alone and SPP can seed the fold from that
 * constant. Mirrors Rust `create_right_hash_chain_4_from_slice`; the
 * cached-commitment chain uses it.
 */
export function foldRightHashChain4<T extends FieldElement>(
  values: readonly T[],
  field: ChainField<T>,
): T {
  const last = values.at(-1);
  if (last === undefined) return field.zero();
  let result = last;
  for (let end = values.length - 1; end > 0;) {
    const start = Math.max(end - 3, 0);
    const group = values.slice(start, end);
    while (group.length < 3) group.push(field.zero());
    result = field.hash([...group, result]);
    end = start;
  }
  return result;
}

/**
 * Folds `Poseidon(h, v)` over the nonzero entries in order, starting from the
 * first nonzero entry; a chain with no nonzero entry is zero. Zero entries are
 * skipped, so padding positions do not change the result. Mirrors Rust
 * `create_nonzero_hash_chain_from_slice`.
 */
export function foldNonZeroHashChain<T extends FieldElement>(
  values: readonly T[],
  field: ChainField<T>,
): T {
  let result = field.zero();
  for (const value of values) {
    if (field.isZero(value)) continue;
    result = field.isZero(result) ? value : field.hash([result, value]);
  }
  return result;
}
