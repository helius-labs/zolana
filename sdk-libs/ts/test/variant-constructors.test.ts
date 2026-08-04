import { address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import { DepositAsset, TransactWithdrawal } from "../src/interface/index.js";
import { WithdrawalTarget } from "../src/transaction/index.js";

const MINT = address("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");
const VAULT = address("8qbHbw2BbbTHBW1sbeqakYXV9q2RZ1R6MUi6nEZa6wJk");
const USER = address("CktRuQ2mttgRGZx9JmVJw9KVvHBFWZbS6KMbP9Wm9F8");
const TOKEN_PROGRAM = address("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");

describe("typed discriminated-union constructors", () => {
  it("constructs and freezes both deposit asset variants", () => {
    const sol = DepositAsset.sol();
    const accounts = { mint: MINT, sourceTokenAccount: USER, tokenProgram: TOKEN_PROGRAM };
    const spl = DepositAsset.spl(accounts);

    expect(sol).toEqual({ kind: "sol" });
    expect(spl).toEqual({ kind: "spl", accounts });
    expect(Object.isFrozen(sol)).toBe(true);
    expect(Object.isFrozen(spl)).toBe(true);
    expect(Object.isFrozen(spl.accounts)).toBe(true);
    expect(spl.accounts).not.toBe(accounts);
  });

  it("constructs and freezes every withdrawal settlement variant", () => {
    const sol = TransactWithdrawal.sol({ recipient: USER });
    const spl = TransactWithdrawal.spl({
      mint: MINT,
      splTokenInterface: VAULT,
      recipientTokenAccount: USER,
      tokenProgram: TOKEN_PROGRAM,
    });

    expect(sol).toEqual({ kind: "sol", recipient: USER });
    expect(spl).toEqual({
      kind: "spl",
      mint: MINT,
      splTokenInterface: VAULT,
      recipientTokenAccount: USER,
      tokenProgram: TOKEN_PROGRAM,
    });
    expect([sol, spl].every(Object.isFrozen)).toBe(true);
  });

  it("constructs and freezes both withdrawal target variants", () => {
    const sol = WithdrawalTarget.sol({ recipient: USER });
    const spl = WithdrawalTarget.spl({
      recipientTokenAccount: USER,
      splTokenInterface: VAULT,
    });

    expect(sol).toEqual({ kind: "sol", recipient: USER });
    expect(spl).toEqual({
      kind: "spl",
      recipientTokenAccount: USER,
      splTokenInterface: VAULT,
    });
    expect(Object.isFrozen(sol)).toBe(true);
    expect(Object.isFrozen(spl)).toBe(true);
  });

  it("exports every constructor from its supported package entry point", async () => {
    const [rawInterface, transaction] = await Promise.all([
      import("../src/interface/index.js"),
      import("../src/transaction/index.js"),
    ]);

    expect(rawInterface.DepositAsset.sol).toBeTypeOf("function");
    expect(rawInterface.DepositAsset.spl).toBeTypeOf("function");
    expect(rawInterface.TransactWithdrawal.sol).toBeTypeOf("function");
    expect(rawInterface.TransactWithdrawal.spl).toBeTypeOf("function");
    expect(transaction.WithdrawalTarget.sol).toBeTypeOf("function");
    expect(transaction.WithdrawalTarget.spl).toBeTypeOf("function");
  });

  it("returns exact typed variants with readonly raw fields", () => {
    const compileTimeOnly = (): void => {
      const depositSol: Extract<DepositAsset, { kind: "sol" }> = DepositAsset.sol();
      const depositSpl: Extract<DepositAsset, { kind: "spl" }> = DepositAsset.spl({
        mint: MINT,
        sourceTokenAccount: USER,
        tokenProgram: TOKEN_PROGRAM,
      });
      const settlementSol: Extract<TransactWithdrawal, { kind: "sol" }> = TransactWithdrawal.sol({
        recipient: USER,
      });
      const settlementSpl: Extract<TransactWithdrawal, { kind: "spl" }> = TransactWithdrawal.spl({
        mint: MINT,
        splTokenInterface: VAULT,
        recipientTokenAccount: USER,
        tokenProgram: TOKEN_PROGRAM,
      });
      const withdrawalSol: Extract<WithdrawalTarget, { kind: "sol" }> = WithdrawalTarget.sol({
        recipient: USER,
      });
      const withdrawalSpl: Extract<WithdrawalTarget, { kind: "spl" }> = WithdrawalTarget.spl({
        recipientTokenAccount: USER,
        splTokenInterface: VAULT,
      });

      // @ts-expect-error Constructor results expose readonly discriminants.
      depositSol.kind = "sol";
      // @ts-expect-error SPL deposits require their exact raw account set.
      DepositAsset.spl({ mint: MINT, sourceTokenAccount: USER });
      // @ts-expect-error SPL withdrawals require their exact account set.
      TransactWithdrawal.spl({ mint: MINT, splTokenInterface: VAULT });
      TransactWithdrawal.spl({
        mint: MINT,
        splTokenInterface: VAULT,
        // @ts-expect-error A withdrawal settles to a user token account, not a sender.
        sender: USER,
        recipientTokenAccount: USER,
        tokenProgram: TOKEN_PROGRAM,
      });
      // @ts-expect-error SPL withdrawal targets require a recipient token account.
      WithdrawalTarget.spl({ splTokenInterface: VAULT });

      void [depositSol, depositSpl, settlementSol, settlementSpl, withdrawalSol, withdrawalSpl];
    };

    expect(compileTimeOnly).toBeTypeOf("function");
  });
});
