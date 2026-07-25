import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { SPL_TOKEN_PROGRAM_ID, type Address } from "@zolana/interface";
import { splAssetRegistryAddress, splAssetVaultAddress } from "@zolana/interface/pda";
import { ShieldedKeypair } from "@zolana/keypair";
import { AssetRegistry, ConfidentialTransfer, SOL_MINT, Wallet } from "@zolana/transaction";
import * as transaction from "@zolana/transaction";
import { describe, expect, it } from "vitest";

import * as actions from "../../src/actions/index.js";
import * as wallet from "../../src/index.js";
import * as walletAuthority from "../../src/wallet-authority.js";
import { fromBase58, hex, walletFixture } from "../helpers/fixtures.js";

const names: Record<string, string> = {
  build_deposit_transaction: "buildDepositTransaction",
  build_private_transaction: "buildPrivateTransaction",
  create_associated_token_account: "createAssociatedTokenAccount",
  create_deposit: "createDeposit",
  create_merge: "createMerge",
  create_split: "createSplit",
  create_transfer: "createTransfer",
  create_withdrawal: "createWithdrawal",
  deposit: "deposit",
  sign_private_transaction: "signPrivateTransaction",
  submit_merge_transaction: "submitMergeTransaction",
  Deposit: "Deposit",
  UnsignedPrivateTransaction: "UnsignedPrivateTransaction",
};

/**
 * `actions/mod.rs` re-exports these as values. Rust structs used only as
 * parameter or result shapes (`DepositParams`, `CreatedTransfer`, ...) become
 * TypeScript types and vanish at runtime, so the typecheck below covers them.
 */
const rustValueExports = Object.keys(names);

/**
 * The `_sync` adapters Rust re-exports alongside each async action have no
 * counterpart on purpose: they exist to serve blocking Rust callers, and the
 * TypeScript actions are already the single promise-returning form.
 *
 * TypeScript-only value exports, each with the reason Rust needs no counterpart.
 * `TransactionSigner` is type-only and so is absent from this runtime list.
 */
const dispositions: Record<string, string> = {
  MergeMaterial: "Rust callers reach actions::submit::MergeMaterial through the public submodule",
};

/** Erased at runtime, so the typecheck is the only place a drop shows up. */
export type RustTypeExports = Readonly<{
  CreatedMerge: actions.CreatedMerge;
  CreatedSplit: actions.CreatedSplit;
  CreatedTransfer: actions.CreatedTransfer;
  CreatedWithdrawal: actions.CreatedWithdrawal;
  DepositParams: actions.DepositParams;
  MergeParams: actions.MergeParams;
  ResolvedAddress: actions.ResolvedAddress;
  SplitParams: actions.SplitParams;
  SubmitMergeTransaction: actions.SubmitMergeTransaction;
  SubmittedMerge: actions.SubmittedMerge;
  TransferParams: actions.TransferParams;
  TransferRecipient: actions.TransferRecipient;
  WithdrawalParams: actions.WithdrawalParams;
}>;

describe("wallet export vectors", () => {
  it("exports every frozen action name and nothing undocumented", async () => {
    const fixture = await walletFixture<{ expected: { exports: string[] } }>("mod");
    // The fixture allowlist is a subset of the module, so it can only be
    // checked for containment; the exact set is pinned against Rust below.
    for (const rustName of fixture.expected.exports) {
      expect(rustValueExports).toContain(rustName);
    }
    for (const rustName of rustValueExports) {
      const typescriptName = names[rustName] as keyof typeof actions;
      expect(actions[typescriptName], rustName).toBeDefined();
      expect(wallet[typescriptName as keyof typeof wallet]).toBe(actions[typescriptName]);
    }
    expect(Object.keys(actions).sort()).toEqual(
      [...Object.values(names), ...Object.keys(dispositions)].sort(),
    );
  });

  it("pins the SOL and SPL routing boundary the frozen fixture records", async () => {
    const fixture = await walletFixture<{
      expected: { routing: { solAssetBytes: string; splRequiresSettlementAccounts: boolean } };
    }>("mod");
    expect(hex(fromBase58(SOL_MINT))).toBe(fixture.expected.routing.solAssetBytes);
    const recipient = ShieldedKeypair.generate().shieldedAddress();
    expect(actions.createDeposit({ recipient, asset: SOL_MINT, amount: 1n }).spl).toBeUndefined();
    const mint = "So11111111111111111111111111111111111111112" as Address;
    const userToken = "32ZsJ2yJjwuoBiWE5xnZjG9tKmK3CubbmEzgkQLyQzgD" as Address;
    const spl = actions.createDeposit({
      recipient,
      asset: mint,
      amount: 1n,
      splTokenAccount: userToken,
    }).spl;
    expect(fixture.expected.routing.splRequiresSettlementAccounts).toBe(true);
    expect(spl).toEqual({
      userToken,
      splTokenInterface: splAssetVaultAddress(mint),
      registry: splAssetRegistryAddress(mint),
      tokenProgram: SPL_TOKEN_PROGRAM_ID,
    });
    expect(() => actions.createDeposit({ recipient, asset: mint, amount: 1n })).toThrow(
      expect.objectContaining({ code: "WALLET_MISSING_SPL_TOKEN_ACCOUNT" }),
    );
  });

  it("preserves the root flow surface and nested wallet error cause", async () => {
    const fixture = await walletFixture<{
      expected: { flow: string[]; nestedErrors: { transaction: { code: string } } };
    }>("lib");
    const flow = fixture.expected.flow.map((name) =>
      name === "send_transaction" || name === "confirm_private_transaction"
        ? "client"
        : (names[name] ?? (name === "sync_wallet" ? "syncWallet" : name)),
    );
    expect(flow).toEqual([
      "syncWallet",
      "createTransfer",
      "signPrivateTransaction",
      "client",
      "client",
    ]);
    const empty = new Wallet({
      identity: (await import("@zolana/keypair")).ShieldedKeypair.generate().shieldedAddress(),
      registry: new AssetRegistry(),
    });
    expect(() =>
      wallet.createWithdrawal({
        wallet: empty,
        payer: "11111111111111111111111111111111" as Address,
        recipient: "11111111111111111111111111111111" as Address,
        asset: SOL_MINT,
        amount: 1n,
      }),
    ).toThrow(expect.objectContaining({ code: "WALLET_INSUFFICIENT_BALANCE" }));
    let transactionCode = "";
    try {
      new ConfidentialTransfer(empty.identity, [], "11111111111111111111111111111111" as Address);
    } catch (error) {
      transactionCode = (error as { code?: string }).code ?? "";
    }
    expect(transactionCode.replace("TRANSACTION_", "").replaceAll("_", "").toLowerCase()).toBe(
      fixture.expected.nestedErrors.transaction.code.toLowerCase(),
    );
  });
});

/**
 * The Rust name sets below are read out of the crate source at test time rather
 * than transcribed here. A transcribed list passes whether or not it still
 * matches Rust, which is how a missing export can sit behind a green test; a
 * parsed one fails when the crate adds or drops a name.
 */
async function rustReExports(file: string): Promise<readonly string[]> {
  const source = await readFile(new URL(`../../../../wallet/src/${file}`, import.meta.url), "utf8");
  // A `#[doc(hidden)]` re-export is not part of the documented surface, so the
  // port owes it no counterpart.
  const documented = source.replaceAll(/#\[doc\(hidden\)\]\s*pub use [^;]*;/gu, "");
  const grouped = [...documented.matchAll(/pub use [\w:]+::\{([^}]*)\}\s*;/gu)].flatMap((match) =>
    (match[1] ?? "").split(",").map((entry) => entry.trim()),
  );
  const single = [...documented.matchAll(/pub use [\w:]+::(\w+)\s*;/gu)].map(
    (match) => match[1] ?? "",
  );
  const names = [...grouped, ...single].filter((entry) => entry.length > 0);
  if (names.length === 0) {
    throw new Error(`no pub use names parsed from wallet/src/${file}`);
  }
  return names;
}

/** Names in a TypeScript export clause, with the `type` marker dropped. */
function clauseNames(source: string, from: string): readonly string[] {
  const pattern = new RegExp(String.raw`export\s*\{([^}]*)\}\s*from\s*"${from}"`, "gu");
  return [...source.matchAll(pattern)].flatMap((match) =>
    (match[1] ?? "")
      .split(",")
      .map((entry) => entry.replace(/\btype\b/u, "").trim())
      .filter((entry) => entry.length > 0),
  );
}

describe("wallet-authority re-export parity (W06)", () => {
  it("re-exports the Rust names from @zolana/transaction and declares nothing", async () => {
    const source = await readFile(
      new URL("../../src/wallet-authority.ts", import.meta.url),
      "utf8",
    );
    const names = clauseNames(source, String.raw`@zolana/transaction`);
    expect(
      names,
      "wallet-authority.ts must be one @zolana/transaction re-export clause",
    ).not.toHaveLength(0);
    expect([...names].sort()).toStrictEqual(
      [...(await rustReExports("wallet_authority.rs"))].sort(),
    );
    expect(source).not.toMatch(/\b(class|function|const|interface)\b/);
  });

  it("binds the one runtime name to the transaction package's own class", () => {
    expect(Object.keys(walletAuthority)).toStrictEqual(["LocalWalletAuthority"]);
    expect(walletAuthority.LocalWalletAuthority).toBe(transaction.LocalWalletAuthority);
    expect(wallet.LocalWalletAuthority).toBe(transaction.LocalWalletAuthority);
  });
});

/**
 * Rust splits blocking and async into `f` / `f_async` (or `f_sync` / `f`) pairs
 * and TypeScript has one promise-returning function per pair, so the suffix
 * comes off before the snake-to-camel rewrite and both Rust names land on the
 * same TypeScript name.
 */
function typescriptName(rustName: string): string {
  if (/^[A-Z]/u.test(rustName)) {
    return rustName;
  }
  const base = rustName.replace(/_(sync|async)$/u, "");
  return base.replaceAll(/_(\w)/gu, (_match, letter: string) => letter.toUpperCase());
}

/**
 * Rust root names the TypeScript root does not publish under the mechanical
 * name, each with the reason it needs no counterpart.
 */
const ABSENT_RUST_ROOT_EXPORTS: Readonly<Record<string, string>> = {
  syncWalletWithConfig:
    "syncWallet takes the same config as an optional argument, so Rust's separate with_config entry point collapses into it",
};

/**
 * Names the TypeScript root publishes that `lib.rs` does not. Each is either
 * reachable through a Rust module path or a deliberate widening; a name may not
 * appear here without a reason recorded next to it.
 */
const DISPOSITIONED_TS_ONLY_EXPORTS: Readonly<Record<string, string>> = {
  MergeMaterial:
    "class in TS, struct in Rust; reachable as zolana_wallet::actions::submit::MergeMaterial",
  TransactionSigner: "the custody callback shape; Rust passes a &dyn WalletAuthority instead",
  deposit: "reachable as zolana_wallet::actions::deposit",
  registerIfAbsent: "reachable as zolana_wallet::user_registry::register_if_absent",
  fetchUserRecord:
    "widening: Rust keeps the unchecked fetch private and publishes only the _checked forms",
  backfillAssetRegistry:
    "widening: Rust keeps refresh_registry_from_chain private inside wallet_sync",
  senderViewingPublicKey:
    "free function over UserRecord; Rust has it as UserRecord::sender_viewing_pubkey",
  DepositSplAccounts: "the SPL account bundle Rust nests inside Deposit rather than naming",
  CounterpartyCounter: "per-counterparty tag counters; Rust keeps them inside the wallet state",
  ViewingKeyCounters: "the same counters keyed by viewing key",
  StrictRegistration: "the registration outcome Rust returns as a tuple",
  SyncDelegateEntry: "a user-record field Rust reads through UserRecord",
  UserRecord: "re-exported from the registry interface crate in Rust",
  WalletError: "TS-only error class; Rust returns ClientError from the same call sites",
  WalletErrorCode: "the code union's member type",
  WALLET_ERROR_CODES: "the closed code union backing WalletError",
};

async function rootExportSets(): Promise<
  Readonly<{ rust: readonly string[]; published: readonly string[] }>
> {
  const source = await readFile(new URL("../../src/index.ts", import.meta.url), "utf8");
  const published = [...source.matchAll(/from\s*"\.\/([\w-]+)\.js"/gu)].flatMap((match) =>
    clauseNames(source, String.raw`\./${match[1] ?? ""}\.js`),
  );
  const rust = [...new Set((await rustReExports("lib.rs")).map(typescriptName))];
  return { rust, published: [...new Set(published)] };
}

describe("root export set (W09)", () => {
  // Both directions are exact rather than "contains", so a disposition that
  // stops being true fails here instead of quietly covering for a real gap.
  it("publishes every documented Rust root name except the recorded ones", async () => {
    const { rust, published } = await rootExportSets();
    expect(rust.length).toBeGreaterThan(50);
    const absent = rust.filter((name) => !published.includes(name)).sort();
    expect(absent).toStrictEqual(Object.keys(ABSENT_RUST_ROOT_EXPORTS).sort());
  });

  it("publishes nothing beyond Rust except the recorded ones", async () => {
    const { rust, published } = await rootExportSets();
    const extra = published.filter((name) => !rust.includes(name)).sort();
    expect(extra).toStrictEqual(Object.keys(DISPOSITIONED_TS_ONLY_EXPORTS).sort());
  });

  it("binds every runtime root name to the module that owns it", () => {
    for (const [rustName, typescriptSpelling] of Object.entries(names)) {
      expect(wallet, rustName).toHaveProperty(typescriptSpelling);
    }
  });

  it("keeps WALLET_ERROR_CODES closed over every code the package raises", async () => {
    const directory = fileURLToPath(new URL("../../src", import.meta.url));
    const files = (await readdir(directory, { recursive: true })).filter((entry) =>
      entry.endsWith(".ts"),
    );
    const raised = new Set<string>();
    for (const file of files) {
      const source = await readFile(path.join(directory, file), "utf8");
      if (file === "error.ts") continue;
      for (const match of source.matchAll(/"(WALLET_[A-Z0-9_]+)"/g)) raised.add(match[1]);
    }
    expect([...raised].sort()).toStrictEqual([...wallet.WALLET_ERROR_CODES].sort());
  });

  it("lifts the wrapped client or transaction code to causeCode", () => {
    const empty = new Wallet({
      identity: ShieldedKeypair.generate().shieldedAddress(),
      registry: new AssetRegistry(),
    });
    let raised: unknown;
    try {
      wallet.createSplit({
        wallet: empty,
        authority: null as never,
        asset: SOL_MINT,
        amounts: [1n],
      });
    } catch (error) {
      raised = error;
    }
    expect(raised).toBeInstanceOf(Error);
    expect((raised as { code?: string }).code).toMatch(/^WALLET_/);
  });

  it("collapses the Rust sync/async pairs onto one promise-returning export", () => {
    for (const name of [
      "buildDepositTransaction",
      "buildPrivateTransaction",
      "buildRegistrationTransaction",
      "createTransfer",
      "fetchUserRecordOptionalChecked",
      "isWalletRegistered",
      "recipientConfidentialViewTag",
      "signPrivateTransaction",
      "syncWallet",
      "tryResolveRegisteredAddress",
    ]) {
      expect(wallet, name).toHaveProperty(name);
      expect(wallet).not.toHaveProperty(`${name}Sync`);
      expect(wallet).not.toHaveProperty(`${name}Async`);
    }
  });
});
