import { beforeEach, expect, it, vi } from "vitest";
import {
  blockhash,
  compileTransaction,
  createTransactionMessage,
  generateKeyPairSigner,
  setTransactionMessageFeePayer,
  setTransactionMessageLifetimeUsingBlockhash,
  signature,
} from "@solana/kit";
import {
  buildDepositTransaction,
  buildSplitTransaction,
  buildTransferTransaction,
  buildWithdrawalTransaction,
  createZolanaClient,
  ShieldedKeypair,
  Wallet,
  Utxo,
  Data,
  SOL_MINT,
  KeypairWalletAuthority,
  type Bytes32,
} from "@heliuslabs/zolana";
import { runFlow, proverMeasurementSink, type FlowContext } from "../src/flow.js";
import { signSendAndConfirm } from "../src/submit.js";

vi.mock("@heliuslabs/zolana", async (original) => ({
  ...(await original<typeof import("@heliuslabs/zolana")>()),
  buildDepositTransaction: vi.fn(),
  buildSplitTransaction: vi.fn(),
  buildTransferTransaction: vi.fn(),
  buildWithdrawalTransaction: vi.fn(),
  syncWallet: vi.fn(),
}));
vi.mock("../src/submit.js", () => ({ signSendAndConfirm: vi.fn() }));
beforeEach(() => vi.clearAllMocks());
async function context(): Promise<FlowContext> {
  const client = await createZolanaClient();
  const signer = await generateKeyPairSigner();
  const keypair = ShieldedKeypair.generate();
  const wallet = new Wallet({ identity: keypair.shieldedAddress() });
  const bytes = new Uint8Array(32);
  if (bytes.length !== 32) throw new Error("expected 32 bytes");
  const value = bytes as Bytes32;
  vi.spyOn(wallet, "utxos").mockReturnValue([
    {
      utxo: new Utxo({
        owner: keypair.signingPublicKey(),
        asset: SOL_MINT,
        amount: 12_000_000n,
        blinding: value,
        data: new Data(),
      }),
      outputContext: { hash: value, tree: client.tree, leafIndex: 0n },
      nullifier: value,
      spent: false,
    },
  ]);
  const transaction = compileTransaction(
    setTransactionMessageLifetimeUsingBlockhash(
      { blockhash: blockhash("11111111111111111111111111111111"), lastValidBlockHeight: 1n },
      setTransactionMessageFeePayer(signer.address, createTransactionMessage({ version: 0 })),
    ),
  );
  for (const build of [
    buildDepositTransaction,
    buildSplitTransaction,
    buildTransferTransaction,
    buildWithdrawalTransaction,
  ])
    vi.mocked(build).mockResolvedValue(transaction);
  vi.mocked(signSendAndConfirm).mockResolvedValue({
    signature: signature("1".repeat(64)),
    slot: 1n,
  });
  return {
    client,
    signer,
    wallet,
    authority: new KeypairWalletAuthority({ keypair, solanaPublicKey: signer.address }),
    shieldedAddress: keypair.shieldedAddress(),
    transferRecipient: signer.address,
    withdrawalRecipient: signer.address,
    shieldAmount: 12_000_000n,
    prover: "wasm",
  };
}
it("labels the transfer with its observed shape, excluding later withdrawal shapes", async () => {
  const ctx = await context();
  const transaction = await buildTransferTransaction({
    ...ctx,
    feePayer: ctx.signer.address,
    recipient: ctx.transferRecipient,
    amount: 1n,
  });
  vi.mocked(buildTransferTransaction).mockImplementation(async () => {
    proverMeasurementSink({ step: "proof-request", ms: 0, shape: "2x3" });
    return transaction;
  });
  vi.mocked(buildWithdrawalTransaction).mockImplementation(async () => {
    proverMeasurementSink({ step: "proof-request", ms: 0, shape: "1x1" });
    return transaction;
  });
  const result = await runFlow(ctx, { notes: 1, reuseExistingNotes: true });
  expect(result.ok).toBe(true);
  expect(result.shape).toBe("2x3");
  expect(buildTransferTransaction).toHaveBeenLastCalledWith(
    expect.objectContaining({ amount: 6_000_000n }),
  );
  expect(buildWithdrawalTransaction).toHaveBeenCalledWith(
    expect.objectContaining({ amount: 6_000_000n }),
  );
});
it("refuses a mismatched note distribution before proving or submitting a transfer", async () => {
  const ctx = await context();
  const result = await runFlow(ctx, { notes: 2, reuseExistingNotes: true });
  expect(result.ok).toBe(false);
  expect(result.error).toContain("Expected 2 equal plain SOL notes");
  expect(result.shape).toContain("transfer not proved");
  expect(buildTransferTransaction).not.toHaveBeenCalled();
  expect(buildWithdrawalTransaction).not.toHaveBeenCalled();
  expect(signSendAndConfirm).toHaveBeenCalledTimes(1); // Only the split preceded the validation.
});
