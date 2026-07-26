import type { Rpc, SignedPrivateTransaction, ZolanaClient } from "@zolana/client";
import type { Address, Bytes32, Transaction } from "@zolana/interface";
import { ShieldedKeypair } from "@zolana/keypair";
import { AssetRegistry, OutputData, SOL_MINT, Utxo, Wallet } from "@zolana/transaction";
import { describe, expect, it } from "vitest";

import fixture from "../../../vectors/wallet-actions-v1.json" with { type: "json" };
import {
  LocalWalletAuthority,
  createMerge,
  createSplit,
  createWithdrawal,
  signPrivateTransaction,
} from "../../src/index.js";

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
  InputUtxoTreeMismatch: "WALLET_INPUT_UTXO_TREE_MISMATCH",
  InputUtxoUnavailable: "WALLET_INPUT_UTXO_UNAVAILABLE",
  InsufficientBalance: "WALLET_INSUFFICIENT_BALANCE",
  SelectedBalanceOverflow: "WALLET_SELECTED_BALANCE_OVERFLOW",
  SplitInputHasData: "WALLET_SPLIT_INPUT_HAS_DATA",
  SplitInputZoneMismatch: "WALLET_SPLIT_INPUT_ZONE_MISMATCH",
  SplitNotDivisible: "WALLET_SPLIT_NOT_DIVISIBLE",
  UnsignedInputUnavailable: "WALLET_UNSIGNED_INPUT_UNAVAILABLE",
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
  return buildWalletWithKey(id, ShieldedKeypair.generate());
}

function buildWalletWithKey(id: WalletId, keypair: ShieldedKeypair): Wallet {
  const notes = fixture.wallets[id] as readonly Note[];
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
          data: new OutputData(),
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

function railKeypair(rail: string, seed: number): ShieldedKeypair {
  return rail === "p256"
    ? ShieldedKeypair.generate()
    : ShieldedKeypair.fromEd25519(filled(seed), 0);
}

/**
 * A wallet whose identity is `authority`'s shielded address holding one plain
 * note owned by `noteOwner`, so the two rails can be set independently. Only the
 * rails are load-bearing, so the port builds its own keys rather than replaying
 * the generator's bytes.
 */
function railWallet(authority: ShieldedKeypair, noteOwner: ShieldedKeypair): Wallet {
  const wallet = new Wallet({
    identity: authority.shieldedAddress(),
    registry: new AssetRegistry([]),
  });
  wallet._replace({
    utxos: [
      {
        utxo: new Utxo({
          owner: noteOwner.signingPublicKey(),
          asset: SOL_MINT,
          amount: 10n,
          blinding: new Uint8Array(31).fill(1),
          data: new OutputData(),
        }),
        outputContext: { hash: filled(1), tree: tree("primary"), leafIndex: 0n },
        nullifier: filled(20),
        spent: false,
      },
    ],
    transactions: [],
    nullifiers: new Set(),
  });
  return wallet;
}

/**
 * Drive the wallet through `signPrivateTransaction` and hand back the shielded
 * transaction the client was asked to submit, which carries the field Rust
 * records: whether `apply_p256_signature` attached a signature.
 */
async function signCapturing(
  wallet: Wallet,
  keypair: ShieldedKeypair,
): Promise<SignedPrivateTransaction> {
  let captured: SignedPrivateTransaction | undefined;
  const native: Transaction = { messageBytes: Uint8Array.of(1), signatures: [undefined] };
  const client = {
    rpc: {
      getLatestBlockhash: () => Promise.resolve({ blockhash: PAYER, lastValidBlockHeight: 1n }),
    } as unknown as Rpc,
    finishSubmissionUnsigned: (input: Readonly<{ signed: SignedPrivateTransaction }>) => {
      captured = input.signed;
      return Promise.resolve(native);
    },
  } as unknown as ZolanaClient;
  await signPrivateTransaction({
    transaction: createWithdrawal({
      wallet,
      payer: PAYER,
      recipient: RECIPIENT,
      asset: SOL_MINT,
      amount: 5n,
    }).transaction,
    wallet,
    authority: new LocalWalletAuthority({ solanaPublicKey: PAYER, keypair }),
    client,
    feePayer: { address: PAYER, signNativeTransaction: (value) => Promise.resolve(value) },
  });
  if (captured === undefined) throw new Error("the client was never asked to submit");
  return captured;
}

describe("signing rail selection against the Rust wallet", () => {
  // `apply_p256_signature` reads the rail off the authority's own shielded
  // address and never off the notes. Same-key and mixed-rail cases both follow
  // that rule now that construction no longer refuses a foreign-owned input.
  for (const entry of fixture.rails.filter((candidate) => candidate.sameKey)) {
    const outcome = entry.outcome as Outcome;
    it(`a ${entry.authorityRail} authority spending its own notes`, async () => {
      const authority = railKeypair(entry.authorityRail, 61);
      expect(authority.shieldedAddress().signingPublicKey.signatureType()).toBe(
        entry.authorityRail,
      );
      const wallet = railWallet(authority, authority);
      expect(
        await observeAsync(outcome, async () => {
          const signed = await signCapturing(wallet, authority);
          return { p256Signature: signed.transaction.p256Signature() !== undefined };
        }),
      ).toEqual(expected(outcome));
    });
  }

  // Rust signs or declines purely on the authority's rail, including when the
  // notes are owned on the other rail. TypeScript used to refuse those at
  // `ConfidentialTransfer` construction; with that guard removed, the mixed
  // cases are driven the same way as the same-key ones.
  for (const entry of fixture.rails.filter((candidate) => !candidate.sameKey)) {
    const outcome = entry.outcome as Outcome;
    it(`a ${entry.authorityRail} authority spending ${entry.noteRail} notes`, async () => {
      const authority = railKeypair(entry.authorityRail, 61);
      const noteOwner = railKeypair(entry.noteRail, 62);
      expect(noteOwner.signingPublicKey().signatureType()).toBe(entry.noteRail);
      expect(
        await observeAsync(outcome, async () => {
          const signed = await signCapturing(railWallet(authority, noteOwner), authority);
          return { p256Signature: signed.transaction.p256Signature() !== undefined };
        }),
      ).toEqual(expected(outcome));
    });
  }
});

describe("unsigned input substitution against the Rust wallet", () => {
  // `validate_unsigned_inputs` compares the whole `Utxo` alongside the four
  // context fields, so every substitution but `none` is refused. A re-check
  // narrowed to the commitment, nullifier, asset, amount, and blinding would let
  // the owner, zone program, and note payload cases through.
  for (const entry of fixture.substitutions) {
    const outcome = entry.outcome as Outcome;
    it(`substituting ${entry.substitution}`, async () => {
      const keypair = ShieldedKeypair.fromEd25519(filled(63), 0);
      const wallet = railWallet(keypair, keypair);
      const original = wallet.utxos()[0];
      if (original === undefined) throw new Error("the wallet holds no note");
      const observed = await observeAsync(outcome, async () => {
        const transaction = createWithdrawal({
          wallet,
          payer: PAYER,
          recipient: RECIPIENT,
          asset: SOL_MINT,
          amount: 5n,
        }).transaction;
        wallet._replace({
          utxos: [substituted(original, entry.substitution)],
          transactions: [],
          nullifiers: new Set(),
        });
        const client = {
          rpc: {
            getLatestBlockhash: () =>
              Promise.resolve({ blockhash: PAYER, lastValidBlockHeight: 1n }),
          } as unknown as Rpc,
          finishSubmissionUnsigned: () =>
            Promise.resolve({ messageBytes: Uint8Array.of(1), signatures: [undefined] }),
        } as unknown as ZolanaClient;
        await signPrivateTransaction({
          transaction,
          wallet,
          authority: new LocalWalletAuthority({ solanaPublicKey: PAYER, keypair }),
          client,
          feePayer: { address: PAYER, signNativeTransaction: (value) => Promise.resolve(value) },
        });
        return {};
      });
      expect(observed).toEqual(expected(outcome));
    });
  }
});

type WalletEntry = ReturnType<Wallet["utxos"]>[number];

function substituted(entry: WalletEntry, substitution: string): WalletEntry {
  const utxo = (overrides: Partial<ConstructorParameters<typeof Utxo>[0]>): WalletEntry => ({
    ...entry,
    utxo: new Utxo({
      owner: entry.utxo.owner,
      asset: entry.utxo.asset,
      amount: entry.utxo.amount,
      blinding: entry.utxo.blinding,
      data: entry.utxo.data,
      ...overrides,
    }),
  });
  switch (substitution) {
    case "none":
      return entry;
    case "spent":
      return { ...entry, spent: true };
    case "tree":
      return { ...entry, outputContext: { ...entry.outputContext, tree: tree("secondary") } };
    case "commitment":
      return { ...entry, outputContext: { ...entry.outputContext, hash: filled(99) } };
    case "nullifier":
      return { ...entry, nullifier: filled(99) };
    case "dataHash":
      return { ...entry, dataHash: filled(99) };
    case "zoneDataHash":
      return { ...entry, zoneDataHash: filled(99) };
    case "utxo.owner":
      return utxo({ owner: ShieldedKeypair.fromEd25519(filled(64), 0).signingPublicKey() });
    case "utxo.asset":
      return utxo({ asset: tree("secondary") });
    case "utxo.amount":
      return utxo({ amount: entry.utxo.amount + 1n });
    case "utxo.blinding":
      return utxo({ blinding: new Uint8Array(31).fill(9) });
    case "utxo.zoneProgramId":
      return utxo({ zoneProgramId: fixture.zoneProgram as Address });
    default:
      throw new Error(`no substitution named ${substitution}`);
  }
}

async function observeAsync(
  outcome: Outcome,
  act: () => Promise<Readonly<Record<string, unknown>>>,
): Promise<unknown> {
  if (outcome.arm === "ok") {
    return { arm: "ok", value: await act() };
  }
  try {
    await act();
  } catch (cause) {
    return { arm: "err", code: (cause as { causeCode?: unknown; code?: unknown }).code };
  }
  throw new Error(`expected ${outcome.error} but the call succeeded`);
}

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

describe("merge tree selection against the Rust wallet", () => {
  // Optional `tree` disambiguates a rollover; omitting it keeps the historical
  // AmbiguousTree refusal. A mixed-tree explicit hash names both trees.
  for (const [position, entry] of fixture.merges.entries()) {
    const outcome = entry.outcome as Outcome;
    const treeLabel = entry.tree === null ? "inferred" : entry.tree;
    const inputsLabel =
      entry.inputs === null ? "auto-sweep" : `notes [${entry.inputs.join(", ")}]`;
    it(`case ${String(position)}: ${entry.wallet} on ${treeLabel} via ${inputsLabel}`, () => {
      const keypair = ShieldedKeypair.generate();
      const wallet = buildWalletWithKey(entry.wallet as WalletId, keypair);
      expect(
        observe(outcome, () => {
          const created = createMerge({
            wallet,
            keypair,
            asset: SOL_MINT,
            ...(entry.tree === null ? {} : { tree: tree(entry.tree) }),
            ...(entry.inputs === null
              ? {}
              : { inputs: entry.inputs.map((index) => filled(Number(index) + 1)) }),
          });
          return {
            numInputs: created.numInputs.toString(),
            mergedAmount: created.mergedAmount.toString(),
            tree: created.tree,
          };
        }),
      ).toEqual(expected(outcome));
    });
  }
});
