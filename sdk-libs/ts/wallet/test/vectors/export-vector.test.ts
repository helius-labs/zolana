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
 * `sdk-libs/wallet/src/wallet_authority.rs` is a single `pub use` of ten names
 * from `zolana_transaction`. The TypeScript module must be the same ten names
 * bound to the same `@zolana/transaction` declarations, not local copies. Nine
 * are types and vanish at runtime, so the name set is read from the source
 * export clause; `npm run typecheck` compiles that clause and would reject a
 * name `@zolana/transaction` does not declare.
 */
const RUST_AUTHORITY_REEXPORTS = [
  "AnonymousRecipientSlot",
  "ApprovalRequest",
  "EncryptedEnvelope",
  "EncryptedSplit",
  "EncryptedTransfer",
  "LocalWalletAuthority",
  "P256Signature",
  "SyncWalletAuthority",
  "WalletAuthority",
  "WalletSyncMaterial",
];

describe("wallet-authority re-export parity (W06)", () => {
  it("re-exports the ten Rust names from @zolana/transaction and declares nothing", async () => {
    const source = await readFile(
      new URL("../../src/wallet-authority.ts", import.meta.url),
      "utf8",
    );
    const clause = /export\s*\{([^}]*)\}\s*from\s*"@zolana\/transaction";/.exec(source);
    expect(clause, "wallet-authority.ts must be one re-export clause").not.toBeNull();
    const names = (clause?.[1] ?? "")
      .split(",")
      .map((entry) => entry.replace(/\btype\b/, "").trim())
      .filter((entry) => entry.length > 0);
    expect([...names].sort()).toStrictEqual([...RUST_AUTHORITY_REEXPORTS].sort());
    expect(source).not.toMatch(/\b(class|function|const|interface)\b/);
  });

  it("binds the one runtime name to the transaction package's own class", () => {
    expect(Object.keys(walletAuthority)).toStrictEqual(["LocalWalletAuthority"]);
    expect(walletAuthority.LocalWalletAuthority).toBe(transaction.LocalWalletAuthority);
    expect(wallet.LocalWalletAuthority).toBe(transaction.LocalWalletAuthority);
  });
});

/**
 * Every runtime name `sdk-libs/wallet/src/lib.rs` re-exports, mapped to its
 * TypeScript name. Rust splits blocking and async into `f` / `f_async` (or
 * `f_sync` / `f`) pairs; TypeScript has one promise-returning function per
 * pair, so both Rust names collapse onto one entry here.
 */
const RUST_ROOT_RUNTIME_EXPORTS: Readonly<Record<string, string>> = {
  build_deposit_transaction: "buildDepositTransaction",
  build_private_transaction: "buildPrivateTransaction",
  build_registration_transaction: "buildRegistrationTransaction",
  create_associated_token_account: "createAssociatedTokenAccount",
  create_deposit: "createDeposit",
  create_merge: "createMerge",
  create_split: "createSplit",
  create_transfer: "createTransfer",
  create_withdrawal: "createWithdrawal",
  decode_user_record_account: "decodeUserRecordAccount",
  ensure_registered: "ensureRegistered",
  fetch_user_record_checked: "fetchUserRecordChecked",
  fetch_user_record_optional_checked: "fetchUserRecordOptionalChecked",
  get_private_token_balances: "getPrivateTokenBalances",
  get_private_transactions: "getPrivateTransactions",
  is_wallet_registered: "isWalletRegistered",
  recipient_confidential_view_tag: "recipientConfidentialViewTag",
  resolve_registered_address: "resolveRegisteredAddress",
  resolved_address_from_record: "resolvedAddressFromRecord",
  sign_private_transaction: "signPrivateTransaction",
  submit_merge_transaction: "submitMergeTransaction",
  sync_wallet: "syncWallet",
  try_resolve_registered_address: "tryResolveRegisteredAddress",
  validate_registered_keypair: "validateRegisteredKeypair",
  Deposit: "Deposit",
  LocalWalletAuthority: "LocalWalletAuthority",
  UnsignedPrivateTransaction: "UnsignedPrivateTransaction",
};

/**
 * Runtime names the TypeScript root publishes that `lib.rs` does not. Each is
 * either reachable through a Rust module path or a deliberate divergence; a
 * name may not appear here without a reason recorded next to it.
 */
const DISPOSITIONED_TS_ONLY_EXPORTS: Readonly<Record<string, string>> = {
  MergeMaterial:
    "class in TS, struct in Rust; reachable as zolana_wallet::actions::submit::MergeMaterial",
  deposit: "reachable as zolana_wallet::actions::deposit",
  registerIfAbsent: "reachable as zolana_wallet::user_registry::register_if_absent",
  fetchUserRecord:
    "widening: Rust keeps the unchecked fetch private and publishes only the _checked forms",
  backfillAssetRegistry:
    "widening: Rust keeps refresh_registry_from_chain private inside wallet_sync",
  senderViewingPublicKey:
    "free function over UserRecord; Rust has it as UserRecord::sender_viewing_pubkey",
  WalletError: "TS-only error class; Rust returns ClientError from the same call sites",
  WALLET_ERROR_CODES: "the closed code union backing WalletError",
};

describe("root export set (W09)", () => {
  it("publishes every Rust root runtime name and nothing undispositioned", () => {
    const actual = Object.keys(wallet).sort();
    const expected = [
      ...Object.values(RUST_ROOT_RUNTIME_EXPORTS),
      ...Object.keys(DISPOSITIONED_TS_ONLY_EXPORTS),
    ].sort();
    expect(actual).toStrictEqual(expected);
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
