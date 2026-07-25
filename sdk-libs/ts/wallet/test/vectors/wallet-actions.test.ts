import type { Address, Bytes32 } from "@zolana/interface";
import { ShieldedKeypair } from "@zolana/keypair";
import { AssetRegistry, Data, SOL_MINT, Utxo, Wallet } from "@zolana/transaction";
import { describe, expect, it } from "vitest";

import fixture from "../../../vectors/wallet-actions-v1.json" with { type: "json" };
import { createSplit, createWithdrawal } from "../../src/index.js";

type WalletId = keyof typeof fixture.wallets;

interface Note {
  readonly amount: string;
  readonly tree: string;
  readonly kind: string;
}

// Rust `ClientError` variants and the wallet codes they must become. Rust has no
// wallet error type, so the port names each rejection itself; this table is the
// translation, and an unmapped variant fails rather than passing quietly.
const REJECTIONS: Readonly<Record<string, string>> = {
  AmbiguousTree: "WALLET_MULTIPLE_INPUT_TREES",
  InputUtxoUnavailable: "WALLET_INPUT_UTXO_UNAVAILABLE",
  InsufficientBalance: "WALLET_INSUFFICIENT_BALANCE",
  SelectedBalanceOverflow: "WALLET_SELECTED_BALANCE_OVERFLOW",
  SplitInputHasData: "WALLET_SPLIT_INPUT_HAS_DATA",
  SplitInputZoneMismatch: "WALLET_SPLIT_INPUT_ZONE_MISMATCH",
  SplitNotDivisible: "WALLET_SPLIT_NOT_DIVISIBLE",
  "Transaction(SplitInvalidPartCount": "WALLET_SPLIT_INVALID_PART_COUNT",
};

const PAYER = "11111111111111111111111111111111" as Address;
const RECIPIENT = "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi" as Address;

function filled(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

// Rust `Debug` renders the payload as `Variant { hash: [..] }`, and the payload
// repeats what the case already states, so only the variant is translated.
function expectedCode(error: string): string {
  const head = error.split(" ")[0] ?? error;
  const code = REJECTIONS[head] ?? REJECTIONS[head.split("(")[0] ?? head];
  if (code === undefined) {
    throw new Error(`no wallet error code is mapped for Rust ${error}`);
  }
  return code;
}

function tree(name: string): Address {
  const address = (fixture.trees as Readonly<Record<string, string>>)[name];
  if (address === undefined) {
    throw new Error(`the fixture has no tree named ${name}`);
  }
  return address as Address;
}

function buildWallet(id: WalletId): Wallet {
  const notes = fixture.wallets[id] as readonly Note[];
  const keypair = ShieldedKeypair.generate();
  const wallet = new Wallet({
    identity: keypair.shieldedAddress(),
    registry: new AssetRegistry([]),
  });
  wallet._replace({
    utxos: notes.map((note, index) => {
      const blinding = new Uint8Array(31);
      blinding[30] = index + 1;
      return {
        utxo: new Utxo({
          owner: keypair.signingPublicKey(),
          asset: SOL_MINT,
          amount: BigInt(note.amount),
          blinding,
          data: new Data(),
          ...(note.kind === "zoneBound" ? { zoneProgramId: fixture.zoneProgram as Address } : {}),
        }),
        outputContext: {
          hash: filled(index + 1),
          tree: tree(note.tree),
          leafIndex: BigInt(index),
        },
        nullifier: filled(index + 20),
        ...(note.kind === "withData" ? { dataHash: filled(3) } : {}),
        spent: false,
      };
    }),
    transactions: [],
    nullifiers: new Set(),
  });
  return wallet;
}

type Outcome =
  | { readonly arm: "ok"; readonly value: Readonly<Record<string, string>> }
  | { readonly arm: "err"; readonly error: string };

function observe(outcome: Outcome, act: () => Readonly<Record<string, string>>): unknown {
  if (outcome.arm === "ok") {
    return { arm: "ok", value: act() };
  }
  try {
    act();
  } catch (cause) {
    return { arm: "err", code: (cause as { code?: unknown }).code };
  }
  throw new Error(`expected ${outcome.error} but the call succeeded`);
}

function expected(outcome: Outcome): unknown {
  return outcome.arm === "ok"
    ? { arm: "ok", value: outcome.value }
    : { arm: "err", code: expectedCode(outcome.error) };
}

describe("withdrawal input selection against the Rust wallet", () => {
  // `create_withdrawal` has no amount guard and `select_inputs` stops at the
  // first note that covers the request, so zero is an amount Rust builds and the
  // note count is where that loop stopped.
  for (const [position, entry] of fixture.withdrawals.entries()) {
    const outcome = entry.outcome as Outcome;
    it(`case ${String(position)}: ${entry.wallet} withdrawing ${entry.amount}`, () => {
      const wallet = buildWallet(entry.wallet as WalletId);
      expect(
        observe(outcome, () => {
          const created = createWithdrawal({
            wallet,
            payer: PAYER,
            recipient: RECIPIENT,
            asset: SOL_MINT,
            amount: BigInt(entry.amount),
          });
          return { inputCount: created.transaction.inputCount().toString() };
        }),
      ).toEqual(expected(outcome));
    });
  }
});

describe("split selection against the Rust wallet", () => {
  for (const [position, entry] of fixture.splits.entries()) {
    const outcome = entry.outcome as Outcome;
    const named = entry.input === null ? "auto-selected" : `note ${entry.input}`;
    it(`case ${String(position)}: ${entry.wallet} into ${entry.parts} from ${named}`, () => {
      const wallet = buildWallet(entry.wallet as WalletId);
      expect(
        observe(outcome, () => {
          const created = createSplit({
            wallet,
            payer: PAYER,
            asset: SOL_MINT,
            parts: Number(entry.parts),
            ...(entry.input === null ? {} : { input: filled(Number(entry.input) + 1) }),
          });
          return {
            numOutputs: created.numOutputs.toString(),
            perOutputAmount: created.perOutputAmount.toString(),
            inputCount: created.transaction.inputCount().toString(),
          };
        }),
      ).toEqual(expected(outcome));
    });
  }
});
