import {
  address,
  assertIsFullySignedTransaction,
  generateKeyPairSigner,
  signTransactionWithSigners,
  type Address,
  type Blockhash,
} from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import { LocalKeys } from "../src/client/keys.js";
import {
  authorizedPrivateTransactionMaterial,
  type AuthorizedPrivateTransaction,
  type ProofService,
} from "../src/client/ports.js";
import type { DepositClient, PrivateTransactionClient } from "../src/wallet/index.js";
import { SPL_TOKEN_2022_PROGRAM_ID, type Bytes32 } from "../src/interface/index.js";
import {
  NullifierKey,
  ShieldedKeypair,
  SigningKey,
  type ViewingKey,
} from "../src/keypair/index.js";
import {
  Data,
  LocalShieldedKeys,
  SOL_MINT,
  Utxo,
  Wallet,
  decryptToBalances,
  type ShieldedKeys,
} from "../src/transaction/index.js";
import { AssetRegistry } from "../src/transaction/asset.js";
import {
  createSplit,
  createTransfer,
  createWithdrawal,
  resolveWithdrawal,
} from "../src/wallet/actions.js";
import { associatedTokenAddress, splInterfaceWithBump } from "../src/interface/pda/index.js";
import {
  buildRingEntryTransaction,
  buildRingTransferTransaction,
  selectRingInputs,
} from "../src/ring/transfer.js";
import { buildDepositTransaction, createDeposit } from "../src/wallet/deposit.js";
import { depositClient, privateTransactionClient, ringTransferClient } from "./helpers/clients.js";
import { emptyTransaction } from "./helpers/transactions.js";
import { approveIntent, type ApprovalRequest } from "../src/transaction/wallet/intent.js";
import { withdrawalSetupInstructions } from "../src/flows/settlement.js";
import { buildMergeTransaction, createMerge, type MergeClient } from "../src/wallet/merge.js";
import { authorizePrivateTransaction } from "../src/wallet/private-transaction.js";
import {
  buildSplitTransaction,
  buildTransferTransaction,
  buildWithdrawalTransaction,
} from "../src/wallet/transactions.js";

const TREE = address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");
const PAYER = address("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");
const RECIPIENT = address("8qbHbw2BbbTHBW1sbeqakYXV9q2RZ1R6MUi6nEZa6wJk");
const SPL_MINT = address("So11111111111111111111111111111111111111112");
const RING = address("9EwHno8C1T1vVGjasGnDH1GubiEu8qbgLX9qDjBshFhz");
const BLOCKHASH = "11111111111111111111111111111111" as Blockhash;
const TRANSACTION = emptyTransaction(PAYER);

function filled(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

function spendingKeypair(): ShieldedKeypair {
  return ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(filled(42)));
}

/** Unit tests never reach the prover; the keys still need one to exist. */
function stubProofs(): ProofService {
  return {
    prove: vi.fn(async () => {
      throw new Error("prove must not be called");
    }),
    proveMerge: vi.fn(async () => {
      throw new Error("proveMerge must not be called");
    }),
  };
}

function localKeys(keypair: ShieldedKeypair): LocalKeys {
  return LocalKeys.fromKeypair(keypair, stubProofs());
}

/** Records every approval a build asks for and grants it. */
function recordingApproval(): Readonly<{
  approve: (request: ApprovalRequest) => Promise<ReturnType<typeof approveIntent>>;
  requests: ApprovalRequest[];
}> {
  const requests: ApprovalRequest[] = [];
  return {
    approve: (request) => {
      requests.push(request);
      return Promise.resolve(approveIntent(request.intent));
    },
    requests,
  };
}

/** Every per-transaction key a build mints, so a test can check they were wiped. */
function captureTransactionKeys(keys: LocalKeys): ViewingKey[] {
  const minted: ViewingKey[] = [];
  const mint = keys.transactionKeys.bind(keys);
  vi.spyOn(keys, "transactionKeys").mockImplementation(async (requests) => {
    const result = await mint(requests);
    minted.push(...result);
    return result;
  });
  return minted;
}

function fundedWallet(
  keypair: ShieldedKeypair,
  amounts: readonly bigint[],
  options: Readonly<{ asset?: Address; ringProgramId?: Address }> = {},
): Wallet {
  const asset = options.asset ?? SOL_MINT;
  const wallet = new Wallet({
    identity: keypair.shieldedAddress(),
    registry: new AssetRegistry(asset === SOL_MINT ? [] : [[2n, asset]]),
  });
  wallet._replace({
    utxos: amounts.map((amount, index) => ({
      utxo: new Utxo({
        owner: keypair.signingPublicKey(),
        asset,
        amount,
        blinding: new Uint8Array(32).fill(index + 1) as Bytes32,
        data: new Data(),
        ...(options.ringProgramId === undefined ? {} : { ringProgramId: options.ringProgramId }),
      }),
      outputContext: {
        hash: filled(index + 1),
        tree: TREE,
        leafIndex: BigInt(index),
      },
      nullifier: filled(index + 20),
      spent: false,
    })),
    transactions: [],
    nullifiers: new Set(),
  });
  return wallet;
}

function latestBlockhashClient(feeTree = TREE): DepositClient {
  return depositClient({
    tree: feeTree,
    getLatestBlockhash: vi.fn(async () => ({
      blockhash: BLOCKHASH,
      lastValidBlockHeight: 1n,
    })),
  });
}

function capturePrivateBuild(): Readonly<{
  client: PrivateTransactionClient;
  assemble: ReturnType<typeof vi.fn>;
}> {
  const assemble = vi.fn(
    async (_input: Readonly<{ authorized: AuthorizedPrivateTransaction }>) => TRANSACTION,
  );
  return {
    client: privateTransactionClient({
      getAccount: vi.fn(async () => undefined),
      assembleAuthorizedPrivateTransaction: assemble,
    }),
    assemble,
  };
}

describe("private transaction construction", () => {
  it("rejects zero-value public actions before building them", async () => {
    const keypair = ShieldedKeypair.generate();
    await expect(
      buildDepositTransaction({
        client: latestBlockhashClient(),
        feePayer: PAYER,
        recipient: keypair.shieldedAddress(),
        amount: 0n,
      }),
    ).rejects.toMatchObject({
      code: "WALLET_BUILD_DEPOSIT",
      causeCode: "WALLET_CREATE_DEPOSIT",
      causeCodes: ["WALLET_CREATE_DEPOSIT", "WALLET_INVALID_AMOUNT"],
    });
    await expect(
      createWithdrawal({
        wallet: fundedWallet(keypair, [100n]),
        payer: PAYER,
        recipient: RECIPIENT,
        asset: SOL_MINT,
        amount: 0n,
      }),
    ).rejects.toMatchObject({ code: "WALLET_INVALID_AMOUNT" });
  });

  it("covers a withdrawal with the largest UTXOs first", async () => {
    const keypair = ShieldedKeypair.generate();
    const created = await createWithdrawal({
      wallet: fundedWallet(keypair, [20n, 40n, 80n]),
      payer: PAYER,
      recipient: RECIPIENT,
      asset: SOL_MINT,
      amount: 50n,
    });
    expect(created.transaction.inputCount()).toBe(1);
    expect(created.transaction.tree()).toBe(TREE);
  });

  it("refuses a default-rail cover wider than the shape cap", async () => {
    const keypair = ShieldedKeypair.generate();
    await expect(
      createWithdrawal({
        wallet: fundedWallet(keypair, [10n, 10n, 10n, 10n, 10n, 10n]),
        payer: PAYER,
        recipient: RECIPIENT,
        asset: SOL_MINT,
        amount: 60n,
      }),
    ).rejects.toMatchObject({
      code: "WALLET_TOO_MANY_INPUTS",
      details: { got: 6, max: 5 },
    });
  });

  it("reports the full spendable balance when a cover falls short", async () => {
    const keypair = ShieldedKeypair.generate();
    await expect(
      createWithdrawal({
        wallet: fundedWallet(keypair, [10n, 15n]),
        payer: PAYER,
        recipient: RECIPIENT,
        asset: SOL_MINT,
        amount: 60n,
      }),
    ).rejects.toMatchObject({
      code: "WALLET_INSUFFICIENT_BALANCE",
      details: { requested: "60", available: "25" },
    });
  });

  it("rejects an Ed25519 spend whose fee payer is not its owner", async () => {
    const keypair = ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(filled(7)));
    const wallet = fundedWallet(keypair, [100n]);
    const created = await createWithdrawal({
      wallet,
      payer: PAYER,
      recipient: RECIPIENT,
      asset: SOL_MINT,
      amount: 50n,
    });

    await expect(
      authorizePrivateTransaction(
        created.transaction,
        wallet,
        LocalShieldedKeys.fromKeypair(keypair),
      ),
    ).rejects.toMatchObject({ code: "TRANSACTION_ED25519_PAYER_MISMATCH" });
  });

  it("does not spend ring-bound UTXOs through a default-ring action", async () => {
    const keypair = ShieldedKeypair.generate();
    await expect(
      createWithdrawal({
        wallet: fundedWallet(keypair, [100n], { ringProgramId: RING }),
        payer: PAYER,
        recipient: RECIPIENT,
        asset: SOL_MINT,
        amount: 50n,
      }),
    ).rejects.toMatchObject({ code: "WALLET_INSUFFICIENT_BALANCE" });
  });

  it("refuses to turn an unregistered private recipient into a public withdrawal", async () => {
    const keypair = ShieldedKeypair.generate();
    const getAccount = vi.fn(async () => undefined);
    await expect(
      createTransfer({
        client: { getAccount },
        wallet: fundedWallet(keypair, [100n]),
        payer: PAYER,
        recipient: RECIPIENT,
        asset: SOL_MINT,
        amount: 10n,
      }),
    ).rejects.toMatchObject({
      code: "WALLET_CREATE_TRANSFER",
      causeCode: "WALLET_RECIPIENT_NOT_REGISTERED",
    });
    expect(getAccount).toHaveBeenCalledOnce();
  });

  it("accepts an already-resolved shielded recipient without an RPC read", async () => {
    const sender = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate().shieldedAddress();
    const created = await createTransfer({
      wallet: fundedWallet(sender, [100n]),
      payer: PAYER,
      recipient,
      asset: SOL_MINT,
      amount: 10n,
    });
    expect(created.recipient).toMatchObject({
      kind: "shielded",
      address: recipient,
    });
  });

  it("keeps split and merge conservation in their internal intent models", async () => {
    const keypair = ShieldedKeypair.generate();
    const wallet = fundedWallet(keypair, [20n, 30n, 100n]);
    const split = createSplit({
      wallet,
      payer: PAYER,
      asset: SOL_MINT,
      parts: 2,
      input: wallet.utxos()[2]!.outputContext.hash,
    });
    const merge = await createMerge({
      wallet,
      keys: LocalShieldedKeys.fromKeypair(keypair),
      asset: SOL_MINT,
    });
    expect(split).toMatchObject({ numOutputs: 2, perOutputAmount: 50n });
    expect(merge).toMatchObject({ numInputs: 2, mergedAmount: 50n });
  });
});

describe("keys at the wallet boundary", () => {
  it("refuses a merge whose key holder answers the derivation batch short", async () => {
    const keypair = ShieldedKeypair.generate();
    const wallet = fundedWallet(keypair, [20n, 30n]);
    const local = LocalShieldedKeys.fromKeypair(keypair);
    const short: ShieldedKeys = {
      address: () => local.address(),
      viewingPublicKeys: () => local.viewingPublicKeys(),
      decrypt: (requests) => local.decrypt(requests),
      derive: async (requests) => (await local.derive(requests)).slice(1),
      transactionKeys: (requests) => local.transactionKeys(requests),
    };
    await expect(createMerge({ wallet, keys: short, asset: SOL_MINT })).rejects.toMatchObject({
      code: "WALLET_KEYS_BATCH_MISMATCH",
    });
    // The refused merge holds nothing.
    expect(wallet._reservationEntries()).toHaveLength(0);
  });

  it("treats the fee payer as the Solana account of a P256 owner", async () => {
    // A P256 identity has no Solana key of its own; the account that registered
    // it and signs for it is the fee payer, so approval and the registry record
    // both go by that account.
    const keypair = ShieldedKeypair.generate("p256");
    const wallet = fundedWallet(keypair, [20n, 30n]);
    const { approve, requests } = recordingApproval();
    const never = (member: string) => (): never => {
      throw new Error(`${member} must not be called`);
    };
    const client: MergeClient = {
      tree: TREE,
      getAccount: vi.fn(async () => undefined),
      proveMerge: never("proveMerge"),
      assembleAuthorizedMergeTransaction: never("assembleAuthorizedMergeTransaction"),
      getInputMerkleProofs: never("getInputMerkleProofs"),
      getNonInclusionProofs: never("getNonInclusionProofs"),
    };

    await expect(
      buildMergeTransaction({ client, wallet, keys: localKeys(keypair), approve, feePayer: PAYER }),
    ).rejects.toMatchObject({
      code: "WALLET_BUILD_MERGE",
      causeCode: "WALLET_USER_REGISTRY_RECORD_NOT_FOUND",
    });
    expect(requests.map((request) => request.solanaPublicKey)).toEqual([PAYER]);
    expect(wallet._reservationEntries()).toHaveLength(0);
  });

  it("refuses keys without a prover before copying any secret", () => {
    const keypair = ShieldedKeypair.generate();
    const minted: NullifierKey[] = [];
    const nullifier = keypair.nullifierKey.bind(keypair);
    vi.spyOn(keypair, "nullifierKey").mockImplementation(() => {
      const key = nullifier();
      minted.push(key);
      return key;
    });
    expect(() =>
      Reflect.apply(LocalKeys.fromKeypair, LocalKeys, [keypair, { prove: "later" }]),
    ).toThrowError(expect.objectContaining({ code: "CLIENT_INVALID_CONFIG" }));
    expect(minted).toHaveLength(0);
  });
});

describe("unsigned public transaction builders", () => {
  it("builds a normal unsigned deposit that consumers sign with Kit", async () => {
    const signer = await generateKeyPairSigner();
    const transaction = await buildDepositTransaction({
      client: latestBlockhashClient(),
      feePayer: signer.address,
      recipient: ShieldedKeypair.generate().shieldedAddress(),
      amount: 42n,
    });

    expect(() => assertIsFullySignedTransaction(transaction)).toThrow();
    const signed = await signTransactionWithSigners([signer], transaction);
    expect(() => assertIsFullySignedTransaction(signed)).not.toThrow();
  });

  it("tags a deposit with the recipient confidential view tag", async () => {
    const recipient = ShieldedKeypair.generate().shieldedAddress();
    const deposit = await createDeposit({
      recipient,
      asset: SOL_MINT,
      amount: 42n,
    });
    expect(deposit.viewTag()).toEqual(recipient.confidentialViewTag());
  });

  it("threads Token-2022 through an SPL deposit", async () => {
    const deposit = await createDeposit({
      recipient: ShieldedKeypair.generate().shieldedAddress(),
      asset: SPL_MINT,
      amount: 42n,
      splTokenAccount: RECIPIENT,
      splTokenProgram: SPL_TOKEN_2022_PROGRAM_ID,
    });
    const instruction = await deposit.instruction(TREE, PAYER);
    expect(
      instruction.accounts?.some((account) => account.address === SPL_TOKEN_2022_PROGRAM_ID),
    ).toBe(true);
  });

  it("includes idempotent Token-2022 ATA setup in a withdrawal build", async () => {
    const keypair = spendingKeypair();
    const payer = keypair.shieldedAddress().solanaAddress();
    const wallet = fundedWallet(keypair, [100n], { asset: SPL_MINT });
    const { client, assemble } = capturePrivateBuild();

    await buildWithdrawalTransaction({
      client,
      wallet,
      keys: localKeys(keypair),
      feePayer: payer,
      recipient: RECIPIENT,
      asset: SPL_MINT,
      amount: 25n,
      splTokenProgram: SPL_TOKEN_2022_PROGRAM_ID,
    });

    const request = assemble.mock.calls[0]?.[0];
    if (request === undefined) throw new Error("assembly request was not captured");
    const material = authorizedPrivateTransactionMaterial(request.authorized);
    if (material === undefined) throw new Error("authorization was not minted");
    expect(material.setupInstructions).toHaveLength(1);
    expect(
      material.setupInstructions[0]?.accounts?.some(
        (account) => account.address === SPL_TOKEN_2022_PROGRAM_ID,
      ),
    ).toBe(true);
    expect(material.withdrawal).toMatchObject({
      kind: "spl",
      tokenProgram: SPL_TOKEN_2022_PROGRAM_ID,
    });
  });

  it("refuses a fee payer other than the UTXO owner", async () => {
    const keypair = spendingKeypair();
    const wallet = fundedWallet(keypair, [100n]);
    const { client } = capturePrivateBuild();

    await expect(
      buildTransferTransaction({
        client,
        wallet,
        keys: localKeys(keypair),
        feePayer: RECIPIENT,
        recipient: ShieldedKeypair.generate().shieldedAddress(),
        amount: 25n,
      }),
    ).rejects.toMatchObject({
      code: "WALLET_BUILD_TRANSFER",
      causeCode: "TRANSACTION_ED25519_PAYER_MISMATCH",
    });
  });

  it("hands the build's request context to the key holder", async () => {
    // A remote holder stops its round trip when the caller's signal fires;
    // that only works if the build passes the context it was given on.
    const keypair = spendingKeypair();
    const wallet = fundedWallet(keypair, [20n, 30n, 100n]);
    const local = LocalShieldedKeys.fromKeypair(keypair);
    const seen: unknown[] = [];
    const keys: ShieldedKeys = {
      address: () => local.address(),
      viewingPublicKeys: () => local.viewingPublicKeys(),
      decrypt: (requests) => local.decrypt(requests),
      derive: (requests, context) => {
        seen.push(context);
        return local.derive(requests);
      },
      transactionKeys: (requests, context) => {
        seen.push(context);
        return local.transactionKeys(requests);
      },
    };
    const context = { signal: new AbortController().signal, timeoutMs: 1_000 };
    const { client } = capturePrivateBuild();

    await buildTransferTransaction(
      {
        client,
        wallet,
        keys: { ...keys, ...stubProofs() },
        feePayer: keypair.shieldedAddress().solanaAddress(),
        recipient: ShieldedKeypair.generate().shieldedAddress(),
        amount: 25n,
      },
      context,
    );
    await createMerge({ wallet, keys, asset: SOL_MINT }, context);

    expect(seen).toHaveLength(2);
    expect(seen.every((entry) => entry === context)).toBe(true);
  });

  it("does not mutate spend state and holds the UTXOs after a build", async () => {
    const keypair = spendingKeypair();
    const payer = keypair.shieldedAddress().solanaAddress();
    const wallet = fundedWallet(keypair, [100n]);
    const { client, assemble } = capturePrivateBuild();
    const input = {
      client,
      wallet,
      keys: localKeys(keypair),
      feePayer: payer,
      recipient: ShieldedKeypair.generate().shieldedAddress(),
      amount: 25n,
    } as const;

    await buildTransferTransaction(input);
    await expect(buildTransferTransaction(input)).rejects.toMatchObject({
      code: "WALLET_BUILD_TRANSFER",
      causeCodes: ["WALLET_CREATE_TRANSFER", "WALLET_INSUFFICIENT_BALANCE"],
    });

    expect(assemble).toHaveBeenCalledTimes(1);
    expect(wallet.balance(SOL_MINT).amount).toBe(100n);
    expect(wallet.utxos()[0]?.spent).toBe(false);
  });

  it("applies split defaults without mutating the wallet", async () => {
    const keypair = spendingKeypair();
    const payer = keypair.shieldedAddress().solanaAddress();
    const wallet = fundedWallet(keypair, [100n]);
    const { client, assemble } = capturePrivateBuild();

    await buildSplitTransaction({
      client,
      wallet,
      keys: localKeys(keypair),
      feePayer: payer,
    });

    const authorized = (assemble.mock.calls[0]![0] as { authorized: AuthorizedPrivateTransaction })
      .authorized;
    const material = authorizedPrivateTransactionMaterial(authorized);
    if (material === undefined) throw new Error("authorization was not minted");
    expect(material.proofInputs.outputs.filter((output) => output.amount > 0n)).toHaveLength(2);
    expect(wallet.balance(SOL_MINT).amount).toBe(100n);
  });
});

describe("resolveWithdrawal", () => {
  it("uses one idempotent ATA setup policy for every withdrawal rail", async () => {
    await expect(
      withdrawalSetupInstructions({ payer: PAYER, recipient: RECIPIENT, asset: SOL_MINT }),
    ).resolves.toEqual([]);
    const setup = await withdrawalSetupInstructions({
      payer: PAYER,
      recipient: RECIPIENT,
      asset: SPL_MINT,
      splTokenProgram: SPL_TOKEN_2022_PROGRAM_ID,
    });
    expect(setup).toHaveLength(1);
    expect(
      setup[0]?.accounts?.some((account) => account.address === SPL_TOKEN_2022_PROGRAM_ID),
    ).toBe(true);
  });

  it("derives one SPL settlement, shared by the proof side and the accounts side", async () => {
    const resolved = await resolveWithdrawal(RECIPIENT, SPL_MINT, SPL_TOKEN_2022_PROGRAM_ID);
    if (resolved.target.kind !== "spl" || resolved.accounts.kind !== "spl") {
      throw new Error("an SPL mint resolves to SPL settlement");
    }
    expect(resolved.accounts.recipientTokenAccount).toBe(resolved.target.recipientTokenAccount);
    expect(resolved.accounts.splTokenInterface).toBe(resolved.target.splTokenInterface);
    expect(resolved.accounts.mint).toBe(SPL_MINT);
    expect(resolved.accounts.tokenProgram).toBe(SPL_TOKEN_2022_PROGRAM_ID);
    expect(resolved.target.recipientTokenAccount).toBe(
      await associatedTokenAddress(RECIPIENT, SPL_MINT, SPL_TOKEN_2022_PROGRAM_ID),
    );
    const [splTokenInterface, splInterfaceBump] = await splInterfaceWithBump(SPL_MINT);
    expect(resolved.target.splTokenInterface).toBe(splTokenInterface);
    expect(resolved.target.splInterfaceBump).toBe(splInterfaceBump);
  });

  it("settles SOL through the recipient account itself", async () => {
    const resolved = await resolveWithdrawal(RECIPIENT, SOL_MINT);
    if (resolved.target.kind !== "sol" || resolved.accounts.kind !== "sol") {
      throw new Error("SOL resolves to SOL settlement");
    }
    expect(resolved.target.recipient).toBe(RECIPIENT);
    expect(resolved.accounts.recipient).toBe(RECIPIENT);
  });
});

describe("wallet balances split", () => {
  function mixedWallet(keypair: ShieldedKeypair): Wallet {
    const wallet = fundedWallet(keypair, [10n]);
    const entry = (index: number, amount: bigint, ringProgramId?: Address) => ({
      utxo: new Utxo({
        owner: keypair.signingPublicKey(),
        asset: SOL_MINT,
        amount,
        blinding: filled(index + 1),
        data: new Data(),
        ...(ringProgramId === undefined ? {} : { ringProgramId }),
      }),
      outputContext: { hash: filled(index + 1), tree: TREE, leafIndex: BigInt(index) },
      nullifier: filled(index + 20),
      spent: false,
    });
    wallet._replace({
      utxos: [entry(0, 10n), entry(1, 40n, RING), entry(2, 60n, RECIPIENT)],
      transactions: [],
      nullifiers: new Set(),
    });
    return wallet;
  }

  it("keeps ring-bound UTXOs out of the spendable view like Rust `balances`", () => {
    const wallet = mixedWallet(spendingKeypair());
    const spendable = wallet.balances(true);
    expect(spendable.map((balance) => balance.amount)).toEqual([10n]);
    expect(wallet.balance(SOL_MINT).amount).toBe(10n);
  });

  it("groups ring-bound UTXOs by ring in address order", () => {
    const wallet = mixedWallet(spendingKeypair());
    const rings = wallet.ringBalances(true);
    const expected = [[RING, 40n] as const, [RECIPIENT, 60n] as const].sort(([left], [right]) =>
      left < right ? -1 : 1,
    );
    expect(rings.map((ring) => [ring.ringProgramId, ring.assets[0]?.amount])).toEqual(expected);
  });
});

describe("AssetRegistry register", () => {
  it("inserts once, skips the exact pair, and raises on a conflicting binding", () => {
    const registry = new AssetRegistry();
    expect(registry.register(2n, SPL_MINT)).toBe(true);
    expect(registry.register(2n, SPL_MINT)).toBe(false);
    expect(() => registry.register(2n, RECIPIENT)).toThrow("TRANSACTION_DUPLICATE_ASSET_ID");
    expect(() => registry.register(3n, SPL_MINT)).toThrow("TRANSACTION_DUPLICATE_MINT");
  });
});

function ringUtxoWallet(
  keypair: ShieldedKeypair,
  utxos: readonly (readonly [bigint, Address | undefined, Address?])[],
): Wallet {
  const wallet = fundedWallet(keypair, []);
  wallet._replace({
    utxos: utxos.map(([amount, ringProgramId, tree], index) => ({
      utxo: new Utxo({
        owner: keypair.signingPublicKey(),
        asset: SOL_MINT,
        amount,
        blinding: filled(index + 1),
        data: new Data(),
        ...(ringProgramId === undefined ? {} : { ringProgramId }),
      }),
      outputContext: { hash: filled(index + 1), tree: tree ?? TREE, leafIndex: BigInt(index) },
      nullifier: filled(index + 20),
      spent: false,
    })),
    transactions: [],
    nullifiers: new Set(),
  });
  return wallet;
}

describe("selectRingInputs", () => {
  it("refuses a zero amount", () => {
    const wallet = ringUtxoWallet(spendingKeypair(), [[10n, RING]]);
    expect(() => selectRingInputs(wallet, RING, SOL_MINT, 0n, "ring", TREE)).toThrow(
      "RING_ZERO_AMOUNT",
    );
  });

  it("keeps default UTXOs out of ring funding unless the entry opts in", () => {
    const wallet = ringUtxoWallet(spendingKeypair(), [
      [10n, undefined],
      [10n, RING],
    ]);
    expect(() => selectRingInputs(wallet, RING, SOL_MINT, 15n, "ring", TREE)).toThrow(
      "RING_INSUFFICIENT_BALANCE",
    );
    const selected = selectRingInputs(wallet, RING, SOL_MINT, 15n, "ring-or-default", TREE);
    expect(selected).toHaveLength(2);
  });

  it("funds a default-only entry even when a ring UTXO covers", () => {
    const wallet = ringUtxoWallet(spendingKeypair(), [
      [100n, RING],
      [25n, undefined],
    ]);
    const selected = selectRingInputs(wallet, RING, SOL_MINT, 25n, "default", TREE);
    expect(selected).toHaveLength(1);
    expect(selected[0]?.utxo.ringProgramId).toBeUndefined();
    expect(() => selectRingInputs(wallet, RING, SOL_MINT, 30n, "default", TREE)).toThrow(
      "RING_INSUFFICIENT_BALANCE",
    );
  });

  it("never offers a UTXO outside the requested tree", () => {
    const wallet = ringUtxoWallet(spendingKeypair(), [
      [50n, RING, RECIPIENT],
      [20n, RING],
    ]);
    const selected = selectRingInputs(wallet, RING, SOL_MINT, 20n, "ring", TREE);
    expect(selected).toHaveLength(1);
    expect(selected[0]?.utxo.amount).toBe(20n);
    expect(() => selectRingInputs(wallet, RING, SOL_MINT, 30n, "ring", TREE)).toThrow(
      "RING_INSUFFICIENT_BALANCE",
    );
  });

  it("covers a fragmented balance with the largest UTXO", () => {
    const wallet = ringUtxoWallet(spendingKeypair(), [
      ...Array.from({ length: 6 }, () => [5n, RING] as const),
      [100n, RING],
    ]);
    const selected = selectRingInputs(wallet, RING, SOL_MINT, 100n, "ring", TREE);
    expect(selected).toHaveLength(1);
    expect(selected[0]?.utxo.amount).toBe(100n);
  });

  it("refuses a cover wider than the input cap", () => {
    const wallet = ringUtxoWallet(
      spendingKeypair(),
      Array.from({ length: 6 }, () => [5n, RING] as const),
    );
    expect(() => selectRingInputs(wallet, RING, SOL_MINT, 30n, "ring", TREE)).toThrow(
      "RING_TOO_MANY_INPUTS",
    );
  });

  it("never offers another ring's UTXOs under either mode", () => {
    const wallet = ringUtxoWallet(spendingKeypair(), [
      [50n, RECIPIENT],
      [20n, undefined],
    ]);
    const selected = selectRingInputs(wallet, RING, SOL_MINT, 20n, "ring-or-default", TREE);
    expect(selected).toHaveLength(1);
    expect(selected[0]?.utxo.ringProgramId).toBeUndefined();
    expect(() => selectRingInputs(wallet, RING, SOL_MINT, 30n, "ring-or-default", TREE)).toThrow(
      "RING_INSUFFICIENT_BALANCE",
    );
  });
});

describe("ring approval summary", () => {
  it("approves the exact amount moved into the ring", async () => {
    const keypair = spendingKeypair();
    const wallet = ringUtxoWallet(keypair, [[40n, undefined]]);
    const { approve, requests } = recordingApproval();

    await expect(
      buildRingEntryTransaction({
        client: ringTransferClient({ tree: TREE }),
        ringProgramId: RING,
        wallet,
        keys: localKeys(keypair),
        approve,
        feePayer: keypair.shieldedAddress().solanaAddress(),
        amount: 25n,
        lookupTable: RECIPIENT,
      }),
    ).rejects.toMatchObject({ code: "RING_BUILD_ENTRY" });
    expect(requests.map((request) => request.summary)).toEqual([
      `ring entry of 25 SOL into ring ${RING}`,
    ]);
    expect(requests[0]?.intent).toMatchObject({ kind: "ringEntry", amount: 25n });
  });

  async function capturedSummary(
    utxos: readonly (readonly [bigint, Address | undefined])[],
    amount: bigint,
    inputs: "ring" | "ring-or-default" | "default",
  ): Promise<string> {
    const keypair = spendingKeypair();
    const wallet = ringUtxoWallet(keypair, utxos);
    const { approve, requests } = recordingApproval();
    await expect(
      buildRingTransferTransaction({
        client: ringTransferClient({ tree: TREE }),
        ringProgramId: RING,
        wallet,
        keys: localKeys(keypair),
        approve,
        feePayer: keypair.shieldedAddress().solanaAddress(),
        recipient: ShieldedKeypair.generate().shieldedAddress(),
        amount,
        inputs,
        lookupTable: RECIPIENT,
      }),
    ).rejects.toMatchObject({ code: "RING_BUILD_TRANSFER" });
    const summary = requests[0]?.summary;
    if (summary === undefined) throw new Error("approval not requested");
    return summary;
  }

  it("names the whole default UTXO crossing into the ring, change included", async () => {
    const summary = await capturedSummary([[40n, undefined]], 25n, "default");
    expect(summary).toContain("ring entry of 25 SOL");
    expect(summary).toContain("moves 40 SOL of default UTXOs into the ring");
  });

  it("counts only the default share of mixed funding", async () => {
    const summary = await capturedSummary(
      [
        [30n, undefined],
        [10n, RING],
      ],
      35n,
      "ring-or-default",
    );
    expect(summary).toContain("ring entry of 35 SOL");
    expect(summary).toContain("moves 30 SOL of default UTXOs into the ring");
  });

  it("stays a transfer with no crossing clause on ring-only funding", async () => {
    const summary = await capturedSummary([[40n, RING]], 25n, "ring");
    expect(summary).toContain("ring transfer of 25 SOL");
    expect(summary).not.toContain("default UTXOs");
  });
});

describe("key lifecycle", () => {
  it("wipes the per-transaction key once the build succeeds and never lends the nullifier key", async () => {
    const keypair = spendingKeypair();
    const payer = keypair.shieldedAddress().solanaAddress();
    const wallet = fundedWallet(keypair, [100n]);
    const { client, assemble } = capturePrivateBuild();
    const keys = localKeys(keypair);
    const minted = captureTransactionKeys(keys);

    await buildTransferTransaction({
      client,
      wallet,
      keys,
      feePayer: payer,
      recipient: ShieldedKeypair.generate().shieldedAddress(),
      amount: 25n,
    });

    const authorized = (assemble.mock.calls[0]![0] as { authorized: AuthorizedPrivateTransaction })
      .authorized;
    const material = authorizedPrivateTransactionMaterial(authorized);
    if (material === undefined) throw new Error("authorization was not minted");
    // Proof inputs carry the nullifier public key and the nullifier, never the secret.
    const real = material.proofInputs.inputUtxos.filter((proofInput) => !proofInput.isDummy());
    expect(real).toHaveLength(1);
    for (const proofInput of real) {
      expect(Object.keys(proofInput)).not.toContain("nullifierKey");
      expect(proofInput.nullifierPublicKey).toEqual(keypair.nullifierPublicKey());
    }
    expect(minted).toHaveLength(1);
    expect(() => minted[0]?.publicKey()).toThrow("KEYPAIR_INVALID_SECRET_KEY");
  });

  it("wipes the per-transaction key and releases the inputs when approval fails", async () => {
    const keypair = spendingKeypair();
    const payer = keypair.shieldedAddress().solanaAddress();
    const wallet = fundedWallet(keypair, [100n]);
    const { client, assemble } = capturePrivateBuild();
    const keys = localKeys(keypair);
    const minted = captureTransactionKeys(keys);
    const input = {
      client,
      wallet,
      keys,
      feePayer: payer,
      recipient: ShieldedKeypair.generate().shieldedAddress(),
      amount: 25n,
    } as const;

    await expect(
      buildTransferTransaction({ ...input, approve: () => Promise.reject(new Error("refused")) }),
    ).rejects.toMatchObject({ code: "WALLET_BUILD_TRANSFER" });
    expect(assemble).not.toHaveBeenCalled();
    expect(minted).toHaveLength(1);
    expect(() => minted[0]?.publicKey()).toThrow("KEYPAIR_INVALID_SECRET_KEY");
    // The refused build holds nothing: the same UTXO funds the next one.
    await buildTransferTransaction(input);
    expect(assemble).toHaveBeenCalledTimes(1);
  });

  it("decryptToBalances wipes its minted keys", async () => {
    const keypair = ShieldedKeypair.generate();
    const mintedViewing: ReturnType<ShieldedKeypair["viewingKey"]>[] = [];
    const mintedNullifier: NullifierKey[] = [];
    const viewing = keypair.viewingKey.bind(keypair);
    const nullifier = keypair.nullifierKey.bind(keypair);
    vi.spyOn(keypair, "viewingKey").mockImplementation(() => {
      const key = viewing();
      mintedViewing.push(key);
      return key;
    });
    vi.spyOn(keypair, "nullifierKey").mockImplementation(() => {
      const key = nullifier();
      mintedNullifier.push(key);
      return key;
    });

    await decryptToBalances({ keypair, registry: new AssetRegistry(), transactions: [] });

    expect(mintedViewing).toHaveLength(1);
    expect(mintedNullifier).toHaveLength(1);
    expect(() => mintedViewing[0]?.publicKey()).toThrow("KEYPAIR_INVALID_SECRET_KEY");
    expect(() => mintedNullifier[0]?.publicKey()).toThrow("KEYPAIR_INVALID_SECRET_KEY");
  });
});
