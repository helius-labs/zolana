import { address, type Address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import type { Bytes32 } from "../src/interface/index.js";
import { ShieldedKeypair } from "../src/keypair/index.js";
import { Data, Utxo, Wallet } from "../src/transaction/index.js";
import { AssetRegistry } from "../src/transaction/asset.js";
import {
  MAX_SPEND_INPUTS,
  isPlainUtxo,
  selectNotes,
  type SpendPolicy,
  type SpendSelectionErrors,
} from "../src/flows/select.js";

const TREE = address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");
const OTHER_TREE = address("8qbHbw2BbbTHBW1sbeqakYXV9q2RZ1R6MUi6nEZa6wJk");
const MINT = address("So11111111111111111111111111111111111111112");

function filled(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

const errors: SpendSelectionErrors = {
  insufficient: ({ requested, available }) =>
    new Error(`insufficient ${String(requested)} ${String(available)}`),
  tooManyInputs: ({ eligible, max }) => new Error(`tooMany ${String(eligible)} ${String(max)}`),
  overflow: () => new Error("overflow"),
  multipleTrees: ({ treeCount }) => new Error(`trees ${String(treeCount)}`),
  tooFewNotes: ({ eligible, minimum }) =>
    new Error(`tooFew ${String(eligible)} ${String(minimum)}`),
};

function policy(overrides: Partial<SpendPolicy> = {}): SpendPolicy {
  return {
    eligible: isPlainUtxo,
    ordering: "largestFirst",
    maxInputs: MAX_SPEND_INPUTS,
    tree: { kind: "inferSingle" },
    errors,
    ...overrides,
  };
}

function walletWith(notes: readonly (readonly [bigint, Address?])[]): Wallet {
  const keypair = ShieldedKeypair.generate();
  const wallet = new Wallet({ identity: keypair.shieldedAddress(), registry: new AssetRegistry() });
  wallet._replace({
    utxos: notes.map(([amount, tree], index) => ({
      utxo: new Utxo({
        owner: keypair.signingPublicKey(),
        asset: MINT,
        amount,
        blinding: filled(index + 1),
        data: new Data(),
      }),
      outputContext: { hash: filled(index + 1), tree: tree ?? TREE, leafIndex: BigInt(index) },
      nullifier: filled(index + 100),
      spent: false,
    })),
    transactions: [],
    nullifiers: new Set(),
  });
  return wallet;
}

describe("note selection", () => {
  it("covers with the fewest notes under largest-first ordering", () => {
    const wallet = walletWith([[5n], [5n], [5n], [5n], [5n], [5n], [100n]]);
    const selection = selectNotes({
      wallet,
      asset: MINT,
      target: { kind: "cover", amount: 100n },
      policy: policy(),
    });
    expect(selection.entries.map((entry) => entry.utxo.amount)).toEqual([100n]);
    expect(selection.total).toBe(130n);
  });

  it("consolidates the smallest notes first up to the cap", () => {
    const wallet = walletWith([[9n], [1n], [5n], [3n]]);
    const selection = selectNotes({
      wallet,
      asset: MINT,
      target: { kind: "consolidate", minInputs: 2 },
      policy: policy({ ordering: "smallestFirst", maxInputs: 3 }),
    });
    expect(selection.entries.map((entry) => entry.utxo.amount)).toEqual([1n, 3n, 5n]);
  });

  it("distinguishes a fragmented balance from a poor one", () => {
    const fragmented = walletWith([[5n], [5n], [5n], [5n], [5n], [5n]]);
    expect(() =>
      selectNotes({
        wallet: fragmented,
        asset: MINT,
        target: { kind: "cover", amount: 30n },
        policy: policy(),
      }),
    ).toThrow("tooMany 6 5");
    expect(() =>
      selectNotes({
        wallet: fragmented,
        asset: MINT,
        target: { kind: "cover", amount: 31n },
        policy: policy(),
      }),
    ).toThrow("insufficient 31 30");
  });

  it("filters to a fixed tree and infers a single one otherwise", () => {
    const wallet = walletWith([[50n, OTHER_TREE], [20n]]);
    const selection = selectNotes({
      wallet,
      asset: MINT,
      target: { kind: "cover", amount: 20n },
      policy: policy({ tree: { kind: "fixed", tree: TREE } }),
    });
    expect(selection.entries.map((entry) => entry.utxo.amount)).toEqual([20n]);
    expect(selection.tree).toBe(TREE);
    expect(() =>
      selectNotes({
        wallet,
        asset: MINT,
        target: { kind: "cover", amount: 20n },
        policy: policy(),
      }),
    ).toThrow("trees 2");
  });

  it("reports an empty eligible set as an insufficient one-lamport cover", () => {
    const wallet = walletWith([]);
    expect(() =>
      selectNotes({
        wallet,
        asset: MINT,
        target: { kind: "cover", amount: 1n },
        policy: policy(),
      }),
    ).toThrow("insufficient 1 0");
  });

  it("refuses an eligible balance past the u64 ceiling", () => {
    const wallet = walletWith([[0xffff_ffff_ffff_ffffn], [1n]]);
    expect(() =>
      selectNotes({
        wallet,
        asset: MINT,
        target: { kind: "cover", amount: 1n },
        policy: policy(),
      }),
    ).toThrow("overflow");
  });

  it("refuses a consolidation below the minimum note count", () => {
    const wallet = walletWith([[9n]]);
    expect(() =>
      selectNotes({
        wallet,
        asset: MINT,
        target: { kind: "consolidate", minInputs: 2 },
        policy: policy({ ordering: "smallestFirst" }),
      }),
    ).toThrow("tooFew 1 2");
  });
});
