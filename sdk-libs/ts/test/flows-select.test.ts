import { address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import type { Bytes32 } from "../src/interface/index.js";
import { ShieldedKeypair } from "../src/keypair/index.js";
import { Data, Utxo, Wallet } from "../src/transaction/index.js";
import { treeAddress } from "../src/interface/pda/index.js";
import { isDefaultRingSpendable } from "../src/transaction/wallet/state.js";
import { AssetRegistry } from "../src/transaction/asset.js";
import {
  MAX_SPEND_INPUTS,
  isPlainUtxo,
  selectUtxos,
  type SpendPolicy,
  type SpendSelectionErrors,
} from "../src/flows/select.js";
import { MAX_INPUT_TREES } from "../src/interface/tree-slot.js";

const TREE = treeAddress(0);
const OTHER_TREE = treeAddress(1);
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
  tooFewUtxos: ({ eligible, minimum }) =>
    new Error(`tooFew ${String(eligible)} ${String(minimum)}`),
};

function policy(overrides: Partial<SpendPolicy> = {}): SpendPolicy {
  return {
    eligible: isPlainUtxo,
    ordering: "largestFirst",
    maxInputs: MAX_SPEND_INPUTS,
    tree: { kind: "infer", maxTrees: MAX_INPUT_TREES },
    errors,
    ...overrides,
  };
}

/** `[amount, treeId]` per UTXO, tree 0 when the id is left out. */
function walletWith(utxos: readonly (readonly [bigint, number?])[]): Wallet {
  const keypair = ShieldedKeypair.generate();
  const wallet = new Wallet({ identity: keypair.shieldedAddress(), registry: new AssetRegistry() });
  wallet._replace({
    utxos: utxos.map(([amount, treeId = 0], index) => ({
      utxo: new Utxo({
        owner: keypair.signingPublicKey(),
        asset: MINT,
        amount,
        blinding: filled(index + 1),
        data: new Data(),
      }),
      outputContext: {
        hash: filled(index + 1),
        tree: treeAddress(treeId),
        treeId,
        leafIndex: BigInt(index),
      },
      nullifier: filled(index + 100),
      spent: false,
    })),
    transactions: [],
    nullifiers: new Set(),
  });
  return wallet;
}

describe("UTXO selection", () => {
  it("covers with the fewest UTXOs under largest-first ordering", () => {
    const wallet = walletWith([[5n], [5n], [5n], [5n], [5n], [5n], [100n]]);
    const selection = selectUtxos({
      wallet,
      asset: MINT,
      target: { kind: "cover", amount: 100n },
      policy: policy(),
    });
    expect(selection.entries.map((entry) => entry.utxo.amount)).toEqual([100n]);
    expect(selection.total).toBe(130n);
  });

  it("consolidates the smallest UTXOs first up to the cap", () => {
    const wallet = walletWith([[9n], [1n], [5n], [3n]]);
    const selection = selectUtxos({
      wallet,
      asset: MINT,
      target: { kind: "consolidate", minInputs: 2 },
      policy: policy({ ordering: "smallestFirst", maxInputs: 3 }),
    });
    expect(selection.entries.map((entry) => entry.utxo.amount)).toEqual([1n, 3n, 5n]);
  });

  it("never selects a zero-amount UTXO", () => {
    const wallet = walletWith([[0n], [0n], [5n], [3n]]);
    const selection = selectUtxos({
      wallet,
      asset: MINT,
      target: { kind: "consolidate", minInputs: 2 },
      policy: policy({ ordering: "smallestFirst", maxInputs: 3 }),
    });
    expect(selection.entries.map((entry) => entry.utxo.amount)).toEqual([3n, 5n]);
  });

  it("distinguishes a fragmented balance from a poor one", () => {
    const count = MAX_SPEND_INPUTS + 1;
    const fragmented = walletWith(Array.from({ length: count }, () => [5n] as const));
    const total = 5n * BigInt(count);
    expect(MAX_SPEND_INPUTS).toBe(40);
    expect(() =>
      selectUtxos({
        wallet: fragmented,
        asset: MINT,
        target: { kind: "cover", amount: total },
        policy: policy(),
      }),
    ).toThrow(`tooMany ${String(count)} ${String(MAX_SPEND_INPUTS)}`);
    expect(() =>
      selectUtxos({
        wallet: fragmented,
        asset: MINT,
        target: { kind: "cover", amount: total + 1n },
        policy: policy(),
      }),
    ).toThrow(`insufficient ${String(total + 1n)} ${String(total)}`);
  });

  it("filters to a fixed tree", () => {
    const wallet = walletWith([[50n, 1], [20n]]);
    const selection = selectUtxos({
      wallet,
      asset: MINT,
      target: { kind: "cover", amount: 20n },
      policy: policy({ tree: { kind: "fixed", tree: TREE } }),
    });
    expect(selection.entries.map((entry) => entry.utxo.amount)).toEqual([20n]);
    expect(selection.trees).toEqual([TREE]);
  });

  it("takes only the tree it spends from when eligible funds straddle trees", () => {
    const wallet = walletWith([[50n, 1], [20n]]);
    const selection = selectUtxos({
      wallet,
      asset: MINT,
      target: { kind: "cover", amount: 20n },
      policy: policy(),
    });
    expect(selection.trees).toEqual([OTHER_TREE]);
  });

  it("groups a spend across trees and refuses more trees than the policy admits", () => {
    const wallet = walletWith([[50n, 1], [20n], [5n, 1]]);
    const selection = selectUtxos({
      wallet,
      asset: MINT,
      target: { kind: "cover", amount: 75n },
      policy: policy(),
    });
    // Largest-first picks 50, 20 and 5; each tree then owns a contiguous run.
    expect(selection.trees).toEqual([OTHER_TREE, TREE]);
    expect(selection.entries.map((entry) => [entry.utxo.amount, entry.outputContext.tree])).toEqual(
      [
        [50n, OTHER_TREE],
        [5n, OTHER_TREE],
        [20n, TREE],
      ],
    );
    expect(() =>
      selectUtxos({
        wallet,
        asset: MINT,
        target: { kind: "cover", amount: 75n },
        policy: policy({ tree: { kind: "infer", maxTrees: 1 } }),
      }),
    ).toThrow("trees 2");
  });

  it("reports an empty eligible set as an insufficient one-lamport cover", () => {
    const wallet = walletWith([]);
    expect(() =>
      selectUtxos({
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
      selectUtxos({
        wallet,
        asset: MINT,
        target: { kind: "cover", amount: 1n },
        policy: policy(),
      }),
    ).toThrow("overflow");
  });

  it("refuses a consolidation below the minimum UTXO count", () => {
    const wallet = walletWith([[9n]]);
    expect(() =>
      selectUtxos({
        wallet,
        asset: MINT,
        target: { kind: "consolidate", minInputs: 2 },
        policy: policy({ ordering: "smallestFirst" }),
      }),
    ).toThrow("tooFew 1 2");
  });

  it("merges the tree holding the most UTXOs, smallest first, the lowest id on a tie", () => {
    const merge = (wallet: Wallet) =>
      selectUtxos({
        wallet,
        asset: MINT,
        target: { kind: "consolidate", minInputs: 2 },
        policy: policy({ ordering: "smallestFirst", tree: { kind: "fullest" } }),
      });
    // Tree 0 holds the two smallest UTXOs, tree 1 holds three.
    const fuller = merge(walletWith([[1n], [2n], [9n, 1], [7n, 1], [8n, 1]]));
    expect(fuller.trees).toEqual([OTHER_TREE]);
    expect(fuller.entries.map((entry) => entry.utxo.amount)).toEqual([7n, 8n, 9n]);
    expect(fuller.total).toBe(24n);

    const tie = merge(walletWith([[9n, 1], [8n, 1], [5n], [6n]]));
    expect(tie.trees).toEqual([TREE]);
    expect(tie.entries.map((entry) => entry.utxo.amount)).toEqual([5n, 6n]);
  });

  it("refuses a merge when no tree holds two eligible UTXOs", () => {
    expect(() =>
      selectUtxos({
        wallet: walletWith([[1n], [2n, 1]]),
        asset: MINT,
        target: { kind: "consolidate", minInputs: 2 },
        policy: policy({ ordering: "smallestFirst", tree: { kind: "fullest" } }),
      }),
    ).toThrow("tooFew 1 2");
  });
});

describe("spend eligibility", () => {
  const keypair = ShieldedKeypair.generate();
  const entry = (
    input: Readonly<{ data?: Data; dataHash?: Bytes32; ringDataHash?: Bytes32; ring?: boolean }>,
  ) => ({
    utxo: new Utxo({
      owner: keypair.signingPublicKey(),
      asset: MINT,
      amount: 1n,
      blinding: filled(1),
      data: input.data ?? new Data(),
      ...(input.ring === true ? { ringProgramId: MINT } : {}),
    }),
    outputContext: { hash: filled(1), tree: TREE, treeId: 0, leafIndex: 0n },
    nullifier: filled(2),
    ...(input.dataHash === undefined ? {} : { dataHash: input.dataHash }),
    ...(input.ringDataHash === undefined ? {} : { ringDataHash: input.ringDataHash }),
    spent: false,
  });

  it("spends a data-carrying UTXO on the default ring but never splits or merges it", () => {
    const withData = entry({
      data: new Data([{ kind: "utxoData", bytes: Uint8Array.of(1) }]),
      dataHash: filled(3),
    });
    expect(isDefaultRingSpendable(withData)).toBe(true);
    expect(isPlainUtxo(withData)).toBe(false);
    expect(isDefaultRingSpendable(entry({}))).toBe(true);
    expect(isPlainUtxo(entry({}))).toBe(true);
  });

  it("keeps ring-bound UTXOs off the default ring", () => {
    for (const ringBound of [entry({ ring: true }), entry({ ringDataHash: filled(4) })]) {
      expect(isDefaultRingSpendable(ringBound)).toBe(false);
      expect(isPlainUtxo(ringBound)).toBe(false);
    }
  });
});
