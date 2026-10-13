import { address, type Address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import type { AuthorizedPrivateTransaction } from "../src/client/client.js";
import { LocalKeys } from "../src/client/keys.js";
import { privateTransactionClient } from "./helpers/clients.js";
import type { Bytes32 } from "../src/interface/index.js";
import { ShieldedKeypair, SigningKey } from "../src/keypair/index.js";
import {
  Data,
  SOL_MINT,
  Utxo,
  Wallet,
  approveIntent,
  intentHash,
  type ApprovalHandler,
} from "../src/transaction/index.js";
import {
  MAX_TRANSFER_PAYMENTS,
  checkIntentApproval,
  checkPreparedTransfer,
  checkTransactData,
  type TransactionIntent,
} from "../src/transaction/wallet/intent.js";
import { treeAddress } from "../src/interface/pda/index.js";
import { AssetRegistry } from "../src/transaction/asset.js";
import { buildTransferTransaction } from "../src/wallet/transactions.js";

const TREE = treeAddress(0);
const RING = address("9EwHno8C1T1vVGjasGnDH1GubiEu8qbgLX9qDjBshFhz");
const USDC = address("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");

function filled(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

function fixedKeypair(seed: number): ShieldedKeypair {
  return ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(filled(seed)));
}

function hex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

const mismatch = (field: string) => new Error(`mismatch ${field}`);

describe("intent hash", () => {
  it("matches the pinned vectors", () => {
    const transfer: TransactionIntent = {
      kind: "transfer",
      asset: SOL_MINT,
      amount: 25n,
      recipient: fixedKeypair(42).shieldedAddress(),
    };
    const ring: TransactionIntent = {
      kind: "ringTransfer",
      ringProgramId: RING,
      asset: USDC,
      amount: 1_000_000n,
      recipient: fixedKeypair(7).shieldedAddress(),
      boundary: "entry",
      defaultFunding: 1_500_000n,
    };
    expect(hex(intentHash(transfer))).toBe(
      "725cd3a4932e9d4960b573320196c76e8780a03e2e3479d382fee231e6f9a911",
    );
    expect(hex(intentHash(ring))).toBe(
      "ab073f7e3ee709822d2d857dab795914db0b5f898bd0620c717d2ba893e978e8",
    );
    const multi: TransactionIntent = {
      kind: "multiTransfer",
      asset: SOL_MINT,
      payments: [
        { recipient: fixedKeypair(42).shieldedAddress(), amount: 25n },
        { recipient: fixedKeypair(7).shieldedAddress(), amount: 3n },
      ],
    };
    // Recomputed outside the SDK from the layout: domain, tag 10, asset, count, then each
    // recipient and little-endian u64 amount.
    expect(hex(intentHash(multi))).toBe(
      "22e41ecb02ddc419ce5906ff03a1591524c61ecdaf0f738da5ce62053c893d2f",
    );
  });

  it("binds each payment's recipient, amount and position", () => {
    const first = { recipient: fixedKeypair(42).shieldedAddress(), amount: 25n };
    const second = { recipient: fixedKeypair(7).shieldedAddress(), amount: 3n };
    const base: TransactionIntent = {
      kind: "multiTransfer",
      asset: SOL_MINT,
      payments: [first, second],
    };
    const hashes = [
      base,
      { ...base, payments: [second, first] },
      { ...base, payments: [first, { ...second, amount: 4n }] },
      { ...base, payments: [first, { ...second, recipient: fixedKeypair(8).shieldedAddress() }] },
      { ...base, payments: [first, second, second] },
      { ...base, asset: USDC },
    ].map((intent) => hex(intentHash(intent)));
    expect(new Set(hashes).size).toBe(hashes.length);
  });

  it("refuses a multi-transfer intent outside its payment range or shape", () => {
    const payment = { recipient: fixedKeypair(42).shieldedAddress(), amount: 1n };
    const refused = (intent: unknown, field: string) =>
      expect(() => Reflect.apply(intentHash, undefined, [intent])).toThrowError(
        expect.objectContaining({ code: "TRANSACTION_DESERIALIZE", details: { field } }),
      );
    const intent = (payments: readonly unknown[]) => ({
      kind: "multiTransfer",
      asset: SOL_MINT,
      payments,
    });
    // One payment is a `transfer`; two encodings of one approval would alias.
    refused(intent([payment]), "intent.payments");
    refused(
      intent(Array.from({ length: MAX_TRANSFER_PAYMENTS + 1 }, () => payment)),
      "intent.payments",
    );
    refused(intent([payment, { ...payment, amount: 0n }]), "intent.amount");
    refused(intent([payment, { ...payment, memo: "x" }]), "intent.shape");
    refused({ ...intent([payment, payment]), amount: 2n }, "intent.shape");
    expect(MAX_TRANSFER_PAYMENTS).toBe(15);
    expect(() => intentHash(intent([payment, payment]) as TransactionIntent)).not.toThrow();
  });

  it("changes when any field changes", () => {
    const base: TransactionIntent = {
      kind: "withdrawal",
      asset: SOL_MINT,
      amount: 10n,
      recipient: TREE,
    };
    expect(hex(intentHash({ ...base, amount: 11n }))).not.toBe(hex(intentHash(base)));
    expect(hex(intentHash({ ...base, recipient: RING }))).not.toBe(hex(intentHash(base)));
  });

  it("accepts its own approval and refuses a tampered one", () => {
    const intent: TransactionIntent = {
      kind: "merge",
      asset: SOL_MINT,
      numInputs: 3,
      mergedAmount: 60n,
    };
    const approval = approveIntent(intent);
    expect(() => checkIntentApproval(approval, intent, mismatch)).not.toThrow();
    const tampered = new Uint8Array(approval.intentHash) as Bytes32;
    tampered[0] = tampered[0]! ^ 1;
    expect(() => checkIntentApproval({ intentHash: tampered }, intent, mismatch)).toThrowError(
      "mismatch intentHash",
    );
    expect(() =>
      Reflect.apply(checkIntentApproval, undefined, [undefined, intent, mismatch]),
    ).toThrowError("mismatch intentHash");
  });
});

describe("prepared and data checks", () => {
  function preparedWith(
    overrides: Partial<{
      outputs: readonly unknown[];
      senderOutputCount: number;
      interfaceTransfers: readonly unknown[];
      inputs: readonly unknown[];
    }>,
  ) {
    return {
      outputs: [],
      senderOutputCount: 0,
      interfaceTransfers: [],
      inputs: [],
      ...overrides,
    };
  }

  function recipientOutput(
    recipient: ShieldedKeypair,
    amount: bigint,
    ringProgramId?: Address,
  ): unknown {
    return {
      ownerAddress: recipient.shieldedAddress(),
      asset: SOL_MINT,
      amount,
      ...(ringProgramId === undefined ? {} : { ringProgramId }),
      isDummy: () => false,
    };
  }

  it("refuses a recipient output amount the intent does not cover", () => {
    const recipient = fixedKeypair(42);
    const intent: TransactionIntent = {
      kind: "transfer",
      asset: SOL_MINT,
      amount: 25n,
      recipient: recipient.shieldedAddress(),
    };
    const good = preparedWith({ outputs: [recipientOutput(recipient, 25n)] });
    expect(() =>
      Reflect.apply(checkPreparedTransfer, undefined, [good, intent, mismatch]),
    ).not.toThrow();
    const inflated = preparedWith({ outputs: [recipientOutput(recipient, 26n)] });
    expect(() =>
      Reflect.apply(checkPreparedTransfer, undefined, [inflated, intent, mismatch]),
    ).toThrowError("mismatch amount");
    const stranger = preparedWith({ outputs: [recipientOutput(fixedKeypair(7), 25n)] });
    expect(() =>
      Reflect.apply(checkPreparedTransfer, undefined, [stranger, intent, mismatch]),
    ).toThrowError("mismatch recipient");
  });

  it("checks a multi-transfer's outputs one for one, in order", () => {
    const first = fixedKeypair(42);
    const second = fixedKeypair(7);
    const intent: TransactionIntent = {
      kind: "multiTransfer",
      asset: SOL_MINT,
      payments: [
        { recipient: first.shieldedAddress(), amount: 25n },
        { recipient: second.shieldedAddress(), amount: 3n },
      ],
    };
    const check = (prepared: unknown) =>
      Reflect.apply(checkPreparedTransfer, undefined, [prepared, intent, mismatch]);
    const good = [recipientOutput(first, 25n), recipientOutput(second, 3n)];
    expect(() => check(preparedWith({ outputs: good }))).not.toThrow();
    expect(() =>
      check(preparedWith({ outputs: [recipientOutput(second, 3n), recipientOutput(first, 25n)] })),
    ).toThrowError("mismatch recipient");
    expect(() =>
      check(preparedWith({ outputs: [recipientOutput(first, 25n), recipientOutput(second, 4n)] })),
    ).toThrowError("mismatch amount");
    expect(() => check(preparedWith({ outputs: [recipientOutput(first, 28n)] }))).toThrowError(
      "mismatch payments",
    );
    expect(() =>
      check(preparedWith({ outputs: [...good, recipientOutput(fixedKeypair(8), 1n)] })),
    ).toThrowError("mismatch payments");
    expect(() =>
      check(
        preparedWith({ outputs: [recipientOutput(first, 25n), recipientOutput(second, 3n, RING)] }),
      ),
    ).toThrowError("mismatch ringProgramId");
    expect(() =>
      check(preparedWith({ outputs: good, interfaceTransfers: [{ kind: "sol" }] })),
    ).toThrowError("mismatch settlements");
  });

  it("refuses ring outputs that cross the approved boundary", () => {
    const recipient = fixedKeypair(42);
    const intent: TransactionIntent = {
      kind: "ringTransfer",
      ringProgramId: RING,
      asset: SOL_MINT,
      amount: 25n,
      recipient: recipient.shieldedAddress(),
      boundary: "exit",
      defaultFunding: 0n,
    };
    const ringBound = preparedWith({ outputs: [recipientOutput(recipient, 25n, RING)] });
    expect(() =>
      Reflect.apply(checkPreparedTransfer, undefined, [ringBound, intent, mismatch]),
    ).toThrowError("mismatch ringProgramId");
    const exit = preparedWith({ outputs: [recipientOutput(recipient, 25n)] });
    expect(() =>
      Reflect.apply(checkPreparedTransfer, undefined, [exit, intent, mismatch]),
    ).not.toThrow();
  });

  it("binds an spl settlement to the approved token account", () => {
    const intent: TransactionIntent = {
      kind: "withdrawal",
      asset: USDC,
      amount: 25n,
      recipient: TREE,
    };
    const settlement = (tokenAccount: Address) =>
      preparedWith({
        interfaceTransfers: [
          { kind: "spl", mint: USDC, isDeposit: false, amount: 25n, tokenAccount },
        ],
      });
    expect(() =>
      Reflect.apply(checkPreparedTransfer, undefined, [settlement(TREE), intent, mismatch]),
    ).not.toThrow();
    expect(() =>
      Reflect.apply(checkPreparedTransfer, undefined, [settlement(RING), intent, mismatch]),
    ).toThrowError("mismatch recipient");
  });

  it("refuses settlements a transfer intent never approved", () => {
    const data = {
      interfaceTransfers: [{ kind: "solWithdrawal", amount: 25n }],
    };
    const intent: TransactionIntent = {
      kind: "transfer",
      asset: SOL_MINT,
      amount: 25n,
      recipient: fixedKeypair(42).shieldedAddress(),
    };
    expect(() =>
      Reflect.apply(checkTransactData, undefined, [data, intent, mismatch]),
    ).toThrowError("mismatch settlements");
    const withdrawal: TransactionIntent = {
      kind: "withdrawal",
      asset: SOL_MINT,
      amount: 25n,
      recipient: TREE,
    };
    expect(() =>
      Reflect.apply(checkTransactData, undefined, [data, withdrawal, mismatch]),
    ).not.toThrow();
    const drifted = {
      interfaceTransfers: [{ kind: "solWithdrawal", amount: 26n }],
    };
    expect(() =>
      Reflect.apply(checkTransactData, undefined, [drifted, withdrawal, mismatch]),
    ).toThrowError("mismatch amount");
  });
});

describe("approval binding", () => {
  it("refuses an approval minted for a different intent", async () => {
    const keypair = fixedKeypair(42);
    const wallet = new Wallet({
      identity: keypair.shieldedAddress(),
      registry: new AssetRegistry([]),
    });
    wallet._replace({
      utxos: [
        {
          utxo: new Utxo({
            owner: keypair.signingPublicKey(),
            asset: SOL_MINT,
            amount: 100n,
            blinding: filled(1),
            data: new Data(),
          }),
          outputContext: { hash: filled(1), tree: TREE, leafIndex: 0n },
          nullifier: filled(20),
          spent: false,
        },
      ],
      transactions: [],
      nullifiers: new Set(),
    });
    const keys = LocalKeys.fromKeypair(keypair, {
      prove: () => Promise.reject(new Error("prove must not be called")),
      proveMerge: () => Promise.reject(new Error("proveMerge must not be called")),
    });
    const stale: ApprovalHandler = (request) => {
      if (request.intent.kind !== "transfer") throw new Error("expected transfer");
      return Promise.resolve(approveIntent({ ...request.intent, amount: 1n }));
    };
    const client = privateTransactionClient({
      getAccount: async () => undefined,
      assembleAuthorizedPrivateTransaction: async (_input: {
        authorized: AuthorizedPrivateTransaction;
      }) => {
        throw new Error("must not assemble");
      },
    });
    await expect(
      buildTransferTransaction({
        client,
        wallet,
        keys,
        approve: stale,
        feePayer: keypair.shieldedAddress().solanaAddress(),
        recipient: ShieldedKeypair.generate().shieldedAddress(),
        amount: 25n,
      }),
    ).rejects.toMatchObject({
      code: "WALLET_BUILD_TRANSFER",
      causeCode: "WALLET_INTENT_MISMATCH",
    });
  });
});
