import { AccountRole, address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import { initializePoseidon } from "../src/hasher/index.js";
import { SOL_INTERFACE, ringTransactAccounts } from "../src/interface/index.js";
import { ShieldedKeypair } from "../src/keypair/index.js";
import { AssetRegistry, ConfidentialTransfer, SOL_MINT } from "../src/transaction/index.js";

const PAYER = address("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");

describe("ConfidentialTransfer.newDeposit", () => {
  it("spends only dummies of its tree and funds the outputs from the deposit leg", async () => {
    await initializePoseidon();
    const funder = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate().shieldedAddress();
    const transfer = ConfidentialTransfer.newDeposit(funder.shieldedAddress(), 7, PAYER);
    transfer.deposit(SOL_MINT, 5n, { kind: "sol", funder: PAYER });
    transfer.send(recipient, SOL_MINT, 5n);

    const proof = transfer.sign(funder, new AssetRegistry());
    expect(proof.inputUtxos.every((input) => input.isDummy() && input.treeId === 7)).toBe(true);
    expect(proof.outputTreeId).toBe(7);
    expect(proof.firstNullifier()).toEqual(proof.inputUtxos[0]?.nullifier());
    expect(proof.outputs[0]?.amount).toBe(5n);
    expect(proof.externalData.interfaceTransfers).toEqual([
      { kind: "sol", isDeposit: true, amount: 5n, userSolAccount: PAYER },
    ]);
  });

  it("refuses a recipient past the deposit and a source of another asset", () => {
    const funder = ShieldedKeypair.generate();
    const transfer = ConfidentialTransfer.newDeposit(funder.shieldedAddress(), 0, PAYER);
    expect(() => transfer.deposit(PAYER, 1n, { kind: "sol", funder: PAYER })).toThrow(
      "TRANSACTION_DEPOSIT_ASSET_MISMATCH",
    );
    transfer.deposit(SOL_MINT, 5n, { kind: "sol", funder: PAYER });
    transfer.send(ShieldedKeypair.generate().shieldedAddress(), SOL_MINT, 6n);
    expect(() => transfer.prepare()).toThrow("TRANSACTION_INSUFFICIENT_BALANCE");
  });

  it("lists each deposit leg's group with its funder signing, ahead of the withdrawal", async () => {
    const mint = address("So11111111111111111111111111111111111111112");
    const vault = address("2RJD1KnDRGEkvuFfAGrJ7PD28LRE9LRDjZznDywagzmr");
    const source = address("2VDW9dFE1ZXz4zWAbaBDQFynNVdRpQ73HyfSHMzBSL6Z");
    const tokenProgram = address("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
    const recipient = address("8qbHbw2BbbTHBW1sbeqakYXV9q2RZ1R6MUi6nEZa6wJk");
    const accounts = await ringTransactAccounts({
      payer: PAYER,
      inputTrees: [vault],
      outputTree: vault,
      ringAuth: source,
      inputs: [],
      treeContexts: [{ utxoTreeRootIndex: 0, nullifierTreeRootIndex: 0 }],
      deposits: [
        { kind: "sol", funder: PAYER },
        {
          kind: "spl",
          mint,
          splTokenInterface: vault,
          funder: PAYER,
          sourceTokenAccount: source,
          tokenProgram,
        },
      ],
      withdrawal: { kind: "sol", recipient },
    });
    expect(accounts.slice(6).map((meta) => [meta.address, meta.role])).toEqual([
      [SOL_INTERFACE, AccountRole.WRITABLE],
      [PAYER, AccountRole.WRITABLE_SIGNER],
      [mint, AccountRole.READONLY],
      [vault, AccountRole.WRITABLE],
      [PAYER, AccountRole.READONLY_SIGNER],
      [source, AccountRole.WRITABLE],
      [tokenProgram, AccountRole.READONLY],
      [SOL_INTERFACE, AccountRole.WRITABLE],
      [recipient, AccountRole.WRITABLE],
    ]);
  });
});
