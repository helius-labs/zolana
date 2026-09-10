/** Spend more than N-1 equal notes, retaining half a note for withdrawal. */
export function sweepAmounts(
  shieldAmount: bigint,
  notes: number,
): Readonly<{ transfer: bigint; withdrawal: bigint }> {
  if (
    !Number.isSafeInteger(notes) ||
    notes < 1 ||
    notes > 5 ||
    shieldAmount <= 0n ||
    shieldAmount % BigInt(notes) !== 0n
  ) {
    throw new Error("The sweep requires 1–5 equal notes and a divisible positive shield amount");
  }
  const withdrawal = shieldAmount / BigInt(notes) / 2n;
  if (withdrawal === 0n)
    throw new Error("Each benchmark note must contain at least two base units");
  return { transfer: shieldAmount - withdrawal, withdrawal };
}
