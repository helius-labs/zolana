import { SPL_TOKEN_PROGRAM_ID, type Address } from "@zolana/interface";
import { splAssetRegistryAddress, splAssetVaultAddress } from "@zolana/interface/pda";
import { ShieldedKeypair } from "@zolana/keypair";
import { AssetRegistry, ConfidentialTransfer, SOL_MINT, Wallet } from "@zolana/transaction";
import { describe, expect, it } from "vitest";

import * as actions from "../../src/actions/index.js";
import * as wallet from "../../src/index.js";
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
