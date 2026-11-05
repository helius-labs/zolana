import { address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import { prepareTransfer } from "../src/client/prover/assembly.js";
import { decodeIndexedInputs } from "../src/client/prover/indexed.js";
import { initializePoseidon } from "../src/hasher/index.js";
import { ShieldedKeypair } from "../src/keypair/index.js";
import { AssetRegistry, ConfidentialTransfer, SOL_MINT } from "../src/transaction/index.js";

const PAYER = address("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");

describe("ConfidentialTransfer.newDeposit", () => {
  it("spends only dummies of its tree, funds the outputs from the deposit leg and opens that tree on the indexed route", async () => {
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
    const request = decodeIndexedInputs(prepareTransfer(proof).inputs);
    expect(request.trees.map((tree) => tree.id)).toEqual([7]);
  });

  it("refuses a recipient past the deposit and a source of another asset", async () => {
    await initializePoseidon();
    const funder = ShieldedKeypair.generate();
    const transfer = ConfidentialTransfer.newDeposit(funder.shieldedAddress(), 0, PAYER);
    expect(() => transfer.deposit(PAYER, 1n, { kind: "sol", funder: PAYER })).toThrow(
      "TRANSACTION_DEPOSIT_ASSET_MISMATCH",
    );
    transfer.deposit(SOL_MINT, 5n, { kind: "sol", funder: PAYER });
    transfer.send(ShieldedKeypair.generate().shieldedAddress(), SOL_MINT, 6n);
    expect(() => transfer.prepare()).toThrow("TRANSACTION_INSUFFICIENT_BALANCE");
  });
});
