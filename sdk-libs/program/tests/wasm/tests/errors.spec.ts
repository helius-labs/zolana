import { expect, test } from "./harness";
import { fixture, keyUrl } from "./fixtures";

test("every failure rejects with a named error and leaves the module proving", async ({
  harness,
}) => {
  const escrow = fixture("escrow");
  const withdraw = fixture("withdraw");
  const result = await harness.page.evaluate(
    async ({ escrow, withdraw, urls }) => {
      const api = window.zkProgram;
      const overdraft = structuredClone(escrow.inputs) as { private: { amount: number } };
      overdraft.private.amount = 5000;
      const tooManyTokens = structuredClone(escrow.inputs) as {
        private: { tokenUtxosAssetA: unknown[] };
      };
      const [firstToken] = tooManyTokens.private.tokenUtxosAssetA;
      tooManyTokens.private.tokenUtxosAssetA = new Array(6).fill(firstToken);
      const noTokens = structuredClone(escrow.inputs) as {
        private: { tokenUtxosAssetA: unknown[] };
      };
      noTokens.private.tokenUtxosAssetA = [];
      const { transaction } = await api.transaction(
        "escrow",
        escrow.inputs,
        escrow.sender,
        escrow.payer,
      );
      const withdrawTransaction = (
        await api.transaction("withdraw", withdraw.inputs, withdraw.sender, withdraw.payer)
      ).transaction;
      const attempts = {
        malformedInputs: await api.attempt("transaction", "escrow", { private: {} }, escrow.sender, escrow.payer),
        overdraft: await api.attempt("transaction", "escrow", overdraft, escrow.sender, escrow.payer),
        tooManyTokens: await api.attempt("transaction", "escrow", tooManyTokens, escrow.sender, escrow.payer),
        noTokens: await api.attempt("transaction", "escrow", noTokens, escrow.sender, escrow.payer),
        shortSender: await api.attempt("transaction", "escrow", escrow.inputs, escrow.sender.slice(1), escrow.payer),
        truncatedProofInputs: await api.attempt("prove", "escrow", "arkworks", urls.escrowKey, transaction.proofInputs.slice(0, -1)),
        otherCircuitProofInputs: await api.attempt("prove", "escrow", "arkworks", urls.escrowKey, withdrawTransaction.proofInputs),
        withdrawKey: await api.attempt("prove", "escrow", "arkworks", urls.withdrawKey, transaction.proofInputs),
        withdrawZkey: await api.attempt("prove", "escrow", "zkey", urls.withdrawZkey, transaction.proofInputs),
      };
      const proof = await api.prove("escrow", "arkworks", urls.escrowKey, transaction.proofInputs);
      return {
        names: Object.fromEntries(
          Object.entries(attempts).map(([attempt, outcome]) => [
            attempt,
            "error" in outcome ? outcome.error.name : "succeeded",
          ]),
        ),
        overdraftMessage: "error" in attempts.overdraft ? attempts.overdraft.error.message : "",
        overdraftLocation: "error" in attempts.overdraft ? attempts.overdraft.error.location : "",
        tooManyTokensMessage:
          "error" in attempts.tooManyTokens ? attempts.tooManyTokens.error.message : "",
        stillVerifies: await api.verify(escrow.verifyingKey, proof),
      };
    },
    {
      escrow,
      withdraw,
      urls: {
        escrowKey: keyUrl("escrow", "arkworks"),
        withdrawKey: keyUrl("withdraw", "arkworks"),
        withdrawZkey: keyUrl("withdraw", "zkey"),
      },
    },
  );

  expect(result).toEqual({
    names: {
      malformedInputs: "ClientError.InvalidArgument",
      overdraft: "CircuitError.RuleBroken",
      tooManyTokens: "CircuitError.TooManyItems",
      noTokens: "CircuitError.TooFewItems",
      shortSender: "ClientError.SenderLength",
      truncatedProofInputs: "ProverError.InvalidProofInputs",
      otherCircuitProofInputs: "ProverError.ProofInputsForAnotherCircuit",
      withdrawKey: "ProverError.KeysForAnotherCircuit",
      withdrawZkey: "ProverError.KeysForAnotherCircuit",
    },
    overdraftMessage: "the transfer exceeds the balance",
    overdraftLocation: expect.stringMatching(/program\/src\/escrow\.rs:\d+:\d+$/),
    tooManyTokensMessage: "token_utxos_asset_a takes at most 5 items, 6 given",
    stillVerifies: true,
  });
});
