import type { Address } from "@zolana/interface";
import { AssetRegistry, ConfidentialTransfer, SOL_MINT, Wallet } from "@zolana/transaction";
import { describe, expect, it } from "vitest";

import * as actions from "../../src/actions/index.js";
import * as wallet from "../../src/index.js";
import { walletFixture } from "../helpers/fixtures.js";

const names: Record<string, string> = {
  create_associated_token_account: "createAssociatedTokenAccount",
  create_deposit: "createDeposit",
  create_merge: "createMerge",
  create_split: "createSplit",
  create_transfer: "createTransfer",
  create_withdrawal: "createWithdrawal",
  build_private_transaction: "buildPrivateTransaction",
  sign_private_transaction: "signPrivateTransaction",
  submit_merge_transaction: "submitMergeTransaction",
};

describe("wallet export vectors", () => {
  it("maps every frozen action export to the exact TypeScript allowlist", async () => {
    const fixture = await walletFixture<{ expected: { exports: string[] } }>("mod");
    for (const rustName of fixture.expected.exports) {
      const typescriptName = names[rustName];
      expect(typescriptName).toBeDefined();
      expect(typeof actions[typescriptName as keyof typeof actions]).toBe("function");
      expect(wallet[typescriptName as keyof typeof wallet]).toBe(
        actions[typescriptName as keyof typeof actions],
      );
    }
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
