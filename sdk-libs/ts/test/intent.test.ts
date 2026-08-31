import { address, type Address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import type { AuthorizedPrivateTransaction } from "../src/client/client.js";
import type { PrivateTransactionClient } from "../src/wallet/index.js";
import type { Bytes32, TransactInstructionData } from "../src/interface/index.js";
import { ShieldedKeypair, SigningKey } from "../src/keypair/index.js";
import {
  Data,
  KeypairWalletAuthority,
  SOL_MINT,
  Utxo,
  Wallet,
  approveIntent,
  intentHash,
  type ApprovalRequest,
  type IntentApproval,
} from "../src/transaction/index.js";
import {
  checkIntentApproval,
  checkPreparedTransfer,
  checkTransactData,
  type TransactionIntent,
} from "../src/transaction/wallet/intent.js";
import type { PreparedTransfer } from "../src/transaction/instructions/transact.js";
import { AssetRegistry } from "../src/transaction/asset.js";
import { buildTransferTransaction } from "../src/wallet/transactions.js";

const TREE = address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");
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
      checkIntentApproval(undefined as unknown as IntentApproval, intent, mismatch),
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
  ): PreparedTransfer {
    return {
      outputs: [],
      senderOutputCount: 0,
      interfaceTransfers: [],
      inputs: [],
      ...overrides,
    } as unknown as PreparedTransfer;
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
    expect(() => checkPreparedTransfer(good, intent, mismatch)).not.toThrow();
    const inflated = preparedWith({ outputs: [recipientOutput(recipient, 26n)] });
    expect(() => checkPreparedTransfer(inflated, intent, mismatch)).toThrowError("mismatch amount");
    const stranger = preparedWith({ outputs: [recipientOutput(fixedKeypair(7), 25n)] });
    expect(() => checkPreparedTransfer(stranger, intent, mismatch)).toThrowError(
      "mismatch recipient",
    );
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
    expect(() => checkPreparedTransfer(ringBound, intent, mismatch)).toThrowError(
      "mismatch ringProgramId",
    );
    const exit = preparedWith({ outputs: [recipientOutput(recipient, 25n)] });
    expect(() => checkPreparedTransfer(exit, intent, mismatch)).not.toThrow();
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
    expect(() => checkPreparedTransfer(settlement(TREE), intent, mismatch)).not.toThrow();
    expect(() => checkPreparedTransfer(settlement(RING), intent, mismatch)).toThrowError(
      "mismatch recipient",
    );
  });

  it("refuses settlements a transfer intent never approved", () => {
    const data = {
      interfaceTransfers: [{ kind: "solWithdrawal", amount: 25n }],
    } as unknown as TransactInstructionData;
    const intent: TransactionIntent = {
      kind: "transfer",
      asset: SOL_MINT,
      amount: 25n,
      recipient: fixedKeypair(42).shieldedAddress(),
    };
    expect(() => checkTransactData(data, intent, mismatch)).toThrowError("mismatch settlements");
    const withdrawal: TransactionIntent = {
      kind: "withdrawal",
      asset: SOL_MINT,
      amount: 25n,
      recipient: TREE,
    };
    expect(() => checkTransactData(data, withdrawal, mismatch)).not.toThrow();
    const drifted = {
      interfaceTransfers: [{ kind: "solWithdrawal", amount: 26n }],
    } as unknown as TransactInstructionData;
    expect(() => checkTransactData(drifted, withdrawal, mismatch)).toThrowError("mismatch amount");
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
    const authority = new KeypairWalletAuthority({
      solanaPublicKey: keypair.shieldedAddress().solanaAddress(),
      keypair,
    });
    const stale = new Proxy(authority, {
      get(target, property) {
        if (property === "requestUserApproval") {
          return async (request: ApprovalRequest): Promise<IntentApproval> =>
            approveIntent({ ...request.intent, amount: 1n } as TransactionIntent);
        }
        const value = Reflect.get(target, property);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
    const client = {
      getAccount: async () => undefined,
      assembleAuthorizedPrivateTransaction: async (_input: {
        authorized: AuthorizedPrivateTransaction;
      }) => {
        throw new Error("must not assemble");
      },
    } as PrivateTransactionClient;
    await expect(
      buildTransferTransaction({
        client,
        wallet,
        authority: stale,
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
