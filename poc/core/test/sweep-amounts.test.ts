import { beforeAll, expect, it } from "vitest";
// Exercise the SDK's actual selector, including its largest-first policy.
import {
  selectUtxos,
  isPlainUtxo,
  MAX_SPEND_INPUTS,
} from "../../../sdk-libs/ts/src/flows/select.js";
import {
  initializePoseidon,
  ShieldedKeypair,
  Wallet,
  Utxo,
  Data,
  SOL_MINT,
  type Bytes32,
} from "../../../sdk-libs/ts/src/index.js";
import { address } from "@solana/kit";
import { sweepAmounts } from "../src/sweep-amounts.js";

beforeAll(initializePoseidon);
const tree = address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");
function bytes(value: number): Bytes32 {
  const data = new Uint8Array(32).fill(value);
  if (data.length !== 32) throw new Error("expected 32 bytes");
  return data as Bytes32;
}
it.each([1, 2, 3, 4, 5])(
  "requires all %i equal notes and retains enough for withdrawal",
  (notes) => {
    const shieldAmount = 12_000_000n;
    const amounts = sweepAmounts(shieldAmount, notes);
    const keypair = ShieldedKeypair.generate();
    const wallet = new Wallet({ identity: keypair.shieldedAddress() });
    wallet._replace({
      utxos: Array.from({ length: notes }, (_, i) => ({
        utxo: new Utxo({
          owner: keypair.signingPublicKey(),
          asset: SOL_MINT,
          amount: shieldAmount / BigInt(notes),
          blinding: bytes(i + 1),
          data: new Data(),
        }),
        outputContext: { hash: bytes(i + 1), tree, leafIndex: BigInt(i) },
        nullifier: bytes(i + 100),
        spent: false,
      })),
      transactions: [],
      nullifiers: new Set(),
    });
    const fail = () => new Error("unexpected selection failure");
    const selection = selectUtxos({
      wallet,
      asset: SOL_MINT,
      target: { kind: "cover", amount: amounts.transfer },
      policy: {
        eligible: isPlainUtxo,
        ordering: "largestFirst",
        maxInputs: MAX_SPEND_INPUTS,
        tree: { kind: "inferSingle" },
        errors: { insufficient: fail, tooManyInputs: fail, overflow: fail, multipleTrees: fail },
      },
    });
    expect(selection.entries).toHaveLength(notes);
    expect(selection.total - amounts.transfer).toBe(amounts.withdrawal);
    expect(amounts.withdrawal).toBeGreaterThan(0n);
  },
);
it("rejects invalid or indivisible sweep amounts", () => {
  for (const [amount, notes] of [
    [0n, 1],
    [1n, 1],
    [12n, 0],
    [12n, 6],
    [12n, 1.5],
    [13n, 5],
  ] as const) {
    expect(() => sweepAmounts(amount, notes)).toThrow();
  }
});
