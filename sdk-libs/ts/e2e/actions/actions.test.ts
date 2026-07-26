import { ZolanaClient } from "@zolana/client";
import { ProverClient, type SpendProof } from "@zolana/client/prover";
import type { Address, Bytes31, Bytes32, Signature, Transaction } from "@zolana/interface";
import { ShieldedKeypair, SigningKey, NullifierKey, ViewingKey } from "@zolana/keypair";
import {
  AssetRegistry,
  Data,
  deriveBlinding,
  ownerUtxoHash,
  SOL_MINT,
  Wallet,
} from "@zolana/transaction";
import {
  EncryptedScheme,
  encodeOutputData,
  encodeProofless,
} from "@zolana/transaction/serialization";
import {
  buildDepositTransaction,
  buildPrivateTransaction,
  createAssociatedTokenAccount,
  createDeposit,
  createMerge,
  createSplit,
  createTransfer,
  createWithdrawal,
  getPrivateTokenBalances,
  getPrivateTransactions,
  LocalWalletAuthority,
  MergeMaterial,
  signPrivateTransaction,
  submitMergeTransaction,
  syncWallet,
  type TransactionSigner,
  type WalletAuthority,
} from "@zolana/wallet";
import { fixtureJson } from "@zolana/test-kit/fixtures";
import {
  createTestNativeSigner,
  TestIndexer,
  TestRpc,
  walletDepositData,
} from "@zolana/test-kit/node";
import { describe, expect, it, vi } from "vitest";

import {
  clientDouble,
  depositSignature,
  fixtureIndexer,
  indexerDouble,
  rpcDouble,
} from "../support/doubles.js";

const TREE = "3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3" as Address;
const REGISTRY_PROGRAM = "EXM6UUA56UJySzRDCx4dKwN6Xdcrkq3kmizqgZwgwNEc" as Address;
const SIGNATURE = "1".repeat(64) as Signature;

interface ActionFixture {
  readonly id: string;
  readonly inputs: Readonly<Record<string, unknown>>;
  readonly expected: Readonly<Record<string, unknown>>;
}

interface SplitFixture extends ActionFixture {
  readonly inputs: {
    readonly signingSecretBytes: string;
    readonly viewingSeedBytes: string;
    readonly blindingSeedBytes: string;
    readonly walletAmounts: readonly string[];
    readonly parts: string;
    readonly payerBytes: string;
  };
  readonly expected: {
    readonly creation: {
      readonly inputCount: string;
      readonly outputCount: string;
      readonly perOutputAmount: string;
      readonly selectedInputHashBytes: string;
      readonly treeBytes: string;
    };
    readonly stateTransition: {
      readonly conservedAmount: string;
      readonly realOutputAmounts: readonly string[];
      readonly repeatedSyncAddsHistory: string;
      readonly repeatedSyncAddsUtxos: string;
    };
    readonly tamperEvidence: { readonly code: string };
  };
}

interface MergeFixture extends ActionFixture {
  readonly inputs: {
    readonly signingSecretBytes: string;
    readonly viewingSeedBytes: string;
    readonly blindingSeedBytes: string;
    readonly walletAmounts: readonly string[];
    readonly tree: Address;
    readonly enabledRecord: {
      readonly owner: Address;
      readonly pda: Address;
      readonly accountDataBytes: string;
      readonly mergingEnabled: boolean;
    };
  };
  readonly expected: {
    readonly creation: {
      readonly mergedAmount: string;
      readonly realInputCount: string;
      readonly selectedAmounts: readonly string[];
    };
    readonly material: {
      readonly signingPubkeyBytes: string;
      readonly viewingPubkeyBytes: string;
      readonly nullifierPubkeyBytes: string;
    };
    readonly proof: {
      readonly outputHashBytes: string;
    };
    readonly submission: {
      readonly submittedSignature: Signature;
      readonly submittedOutputHashBytes: string;
    };
    readonly stateTransition: {
      readonly mergedOutputAmount: string;
      readonly repeatedSyncAddsHistory: string;
      readonly repeatedSyncAddsUtxos: string;
    };
    readonly typedErrors: readonly Readonly<{ code: string }>[];
  };
}

interface AtaFixture extends ActionFixture {
  readonly inputs: {
    readonly blockhashBytes: string;
    readonly mint: Address;
    readonly owner: Address;
    readonly payerSecretBytes: string;
  };
  readonly expected: {
    readonly address: Address;
    readonly firstCreate: {
      readonly instruction: { readonly dataBytes: string };
      readonly transaction: {
        readonly messageBytes: string;
        readonly signatures: readonly Signature[];
      };
    };
    readonly idempotentRepeat: {
      readonly balanceDelta: string;
      readonly instructionMessageUnchanged: boolean;
    };
    readonly submissionCount: string;
    readonly typedError: { readonly code: string; readonly details: string };
  };
}

function hexBytes(value: string): Uint8Array {
  return Uint8Array.from(value.match(/../g)?.map((pair) => Number.parseInt(pair, 16)) ?? []);
}

function hex(value: Uint8Array): string {
  return [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function base58(value: Uint8Array): string {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const digits = [0];
  for (const byte of value) {
    let carry = byte;
    for (let index = 0; index < digits.length; index++) {
      const next = (digits[index] ?? 0) * 256 + carry;
      digits[index] = next % 58;
      carry = Math.floor(next / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  let prefix = "";
  for (let index = 0; index < value.length - 1 && value[index] === 0; index++) prefix += "1";
  return (
    prefix +
    digits
      .reverse()
      .map((digit) => alphabet[digit])
      .join("")
  );
}

function seededKeypair(signingSecret: string, viewingSeed: string): ShieldedKeypair {
  const signing = SigningKey.fromBytes(hexBytes(signingSecret) as Bytes32);
  return ShieldedKeypair.fromKeys(
    signing,
    NullifierKey.fromSigningKey(signing),
    ViewingKey.fromSeed(hexBytes(viewingSeed) as Bytes32, 0),
  );
}

function fixtureSigner(seed: string): TransactionSigner {
  return createTestNativeSigner(hexBytes(seed) as Bytes32);
}

function spendProof(
  input: import("@zolana/transaction").ProofInputUtxo,
  index: number,
): SpendProof {
  return {
    state: {
      leaf: input.hash(),
      merkleContext: { treeType: 1, tree: TREE },
      path: Array.from({ length: 32 }, () => new Uint8Array(32) as Bytes32),
      leafIndex: BigInt(index),
      root: new Uint8Array(32) as Bytes32,
      rootSeq: 1n,
      rootIndex: 40 + index,
    },
    nullifier: {
      leaf: input.nullifier(),
      merkleContext: { treeType: 1, tree: TREE },
      path: Array.from({ length: 40 }, () => new Uint8Array(32) as Bytes32),
      lowElement: new Uint8Array(32) as Bytes32,
      lowElementIndex: BigInt(index),
      highElement: new Uint8Array(32).fill(1) as Bytes32,
      highElementIndex: BigInt(index + 1),
      root: new Uint8Array(32) as Bytes32,
      rootSeq: 1n,
      rootIndex: 50 + index,
    },
  };
}

function proofResponse(fixture: Readonly<{ cBytes: string; bBytes: string }>): Response {
  const g1 = [`0x${fixture.cBytes.slice(0, 64)}`, `0x${fixture.cBytes.slice(64)}`];
  return Response.json({
    proof: {
      ar: g1,
      bs: [
        [`0x${fixture.bBytes.slice(0, 64)}`, `0x${fixture.bBytes.slice(64, 128)}`],
        [`0x${fixture.bBytes.slice(128, 192)}`, `0x${fixture.bBytes.slice(192)}`],
      ],
      krs: g1,
      proof_commitment: g1,
      proof_commitment_pok: g1,
    },
  });
}

async function walletFromDeposits(
  keypair: ShieldedKeypair,
  amounts: readonly bigint[],
  blindingSeed: string,
  asset: Address = SOL_MINT,
): Promise<
  Readonly<{ wallet: Wallet; authority: LocalWalletAuthority; deposits: readonly Bytes32[] }>
> {
  const wallet = new Wallet({
    identity: keypair.shieldedAddress(),
    registry: new AssetRegistry(asset === SOL_MINT ? [] : [[2n, asset]]),
  });
  const authority = new LocalWalletAuthority({
    solanaPublicKey: TREE,
    keypair,
  });
  const indexer = new TestIndexer();
  const seed = hexBytes(blindingSeed) as Bytes31;
  const deposits = amounts.map((amount, position) => {
    const data = walletDepositData({
      amount,
      recipient: keypair.shieldedAddress(),
      blindingSeed: seed,
      position,
    });
    const hash = ownerUtxoHash({
      owner: data.owner,
      asset,
      amount,
      blinding: data.blinding,
    });
    indexer.record({
      signature: depositSignature(BigInt(position)),
      outputs: [
        {
          viewTag: data.viewTag,
          utxoHash: hash,
          tree: TREE,
          leafIndex: BigInt(position),
          data: encodeOutputData(
            EncryptedScheme.proofless,
            encodeProofless({
              owner: data.owner,
              blinding: data.blinding,
              asset,
              amount,
              ...(data.memo === undefined ? {} : { memo: data.memo }),
            }),
            "plaintext",
          ),
        },
      ],
      nullifiers: [],
      proofless: true,
    });
    return hash;
  });
  await syncWallet({ wallet, authority, indexer: fixtureIndexer(indexer) });
  return Object.freeze({ wallet, authority, deposits: Object.freeze(deposits) });
}

describe("P12 action workflows", () => {
  it("routes SOL and SPL deposit construction through the production API", async () => {
    const fixture = await fixtureJson<ActionFixture>("workflows/deposit-v1");
    const keypair = ShieldedKeypair.generate();
    const rpc = new TestRpc();
    const payer = TREE;
    const sol = createDeposit({
      recipient: keypair.shieldedAddress(),
      asset: SOL_MINT,
      amount: 42n,
    });
    const mint = base58(new Uint8Array(32).fill(19)) as Address;
    const spl = createDeposit({
      recipient: keypair.shieldedAddress(),
      asset: mint,
      amount: 9n,
      splTokenAccount: payer,
    });
    const solMessage = await buildDepositTransaction({
      rpc,
      payer,
      tree: TREE,
      depositor: payer,
      deposit: sol,
    });
    const splMessage = await buildDepositTransaction({
      rpc,
      payer,
      tree: TREE,
      depositor: payer,
      deposit: spl,
    });

    expect(fixture.id).toBe("fx-workflow-instruction-deposit-v1");
    expect(sol.spl).toBeUndefined();
    expect(spl.spl).toMatchObject({ userToken: payer });
    expect(solMessage.signatures).toEqual([undefined]);
    expect(splMessage.messageBytes.length).toBeGreaterThan(solMessage.messageBytes.length);
  });

  it("routes registered and unregistered SOL and SPL transfers", async () => {
    const fixture = await fixtureJson<MergeFixture>("workflows/action-merge-v1");
    const keypair = seededKeypair(
      fixture.inputs.signingSecretBytes,
      fixture.inputs.viewingSeedBytes,
    );
    const { wallet } = await walletFromDeposits(
      keypair,
      [80n, 80n],
      fixture.inputs.blindingSeedBytes,
    );
    const rpc = new TestRpc();
    rpc.setAccount(fixture.inputs.enabledRecord.pda, {
      owner: REGISTRY_PROGRAM,
      data: hexBytes(fixture.inputs.enabledRecord.accountDataBytes),
      lamports: 1n,
    });
    const registeredSol = await createTransfer({
      rpc,
      wallet,
      payer: fixture.inputs.enabledRecord.owner,
      recipient: fixture.inputs.enabledRecord.owner,
      asset: SOL_MINT,
      amount: 10n,
    });
    const unregisteredSol = await createTransfer({
      rpc,
      wallet,
      payer: fixture.inputs.enabledRecord.owner,
      recipient: TREE,
      asset: SOL_MINT,
      amount: 10n,
    });
    const mint = base58(new Uint8Array(32).fill(41)) as Address;
    const splState = await walletFromDeposits(
      keypair,
      [80n],
      fixture.inputs.blindingSeedBytes,
      mint,
    );
    const registeredSpl = await createTransfer({
      rpc,
      wallet: splState.wallet,
      payer: fixture.inputs.enabledRecord.owner,
      recipient: fixture.inputs.enabledRecord.owner,
      asset: mint,
      amount: 10n,
    });
    const unregisteredSpl = await createTransfer({
      rpc,
      wallet: splState.wallet,
      payer: fixture.inputs.enabledRecord.owner,
      recipient: TREE,
      asset: mint,
      amount: 10n,
    });

    expect(registeredSol.recipient.kind).toBe("registered");
    expect(registeredSpl.recipient.kind).toBe("registered");
    expect(unregisteredSol.recipient).toEqual({
      kind: "publicWithdrawal",
      recipient: TREE,
      withdrawal: { kind: "sol", recipient: TREE },
    });
    expect(unregisteredSpl.recipient.kind).toBe("publicWithdrawal");
    if (unregisteredSpl.recipient.kind !== "publicWithdrawal") {
      throw new Error("expected an unregistered SPL withdrawal");
    }
    expect(unregisteredSpl.recipient.withdrawal.kind).toBe("spl");
  });

  it("creates SOL and SPL withdrawals and preserves external signer bytes", async () => {
    const fixture = await fixtureJson<MergeFixture>("workflows/action-merge-v1");
    const keypair = seededKeypair(
      fixture.inputs.signingSecretBytes,
      fixture.inputs.viewingSeedBytes,
    );
    const { wallet, authority } = await walletFromDeposits(
      keypair,
      [80n],
      fixture.inputs.blindingSeedBytes,
    );
    const sol = createWithdrawal({
      wallet,
      payer: fixture.inputs.enabledRecord.owner,
      recipient: TREE,
      asset: SOL_MINT,
      amount: 20n,
    });
    const mint = base58(new Uint8Array(32).fill(42)) as Address;
    const splState = await walletFromDeposits(
      keypair,
      [80n],
      fixture.inputs.blindingSeedBytes,
      mint,
    );
    const spl = createWithdrawal({
      wallet: splState.wallet,
      payer: fixture.inputs.enabledRecord.owner,
      recipient: TREE,
      asset: mint,
      amount: 20n,
    });
    const native: Transaction = {
      messageBytes: hexBytes(
        (
          await fixtureJson<{ expected: { legacyMessages: { limitOnlyBytes: string } } }>(
            "client/rpc-indexer-v1",
          )
        ).expected.legacyMessages.limitOnlyBytes,
      ),
      signatures: [undefined],
    };
    const client = clientDouble({
      rpc: new TestRpc(),
      finishSubmissionUnsigned: () => Promise.resolve(native),
    });
    const unsigned = await buildPrivateTransaction({
      transaction: sol.transaction,
      wallet,
      authority,
      client,
      feePayer: fixture.inputs.enabledRecord.owner,
    });
    const signed = await signPrivateTransaction({
      transaction: sol.transaction,
      wallet,
      authority,
      client,
      feePayer: {
        address: fixture.inputs.enabledRecord.owner,
        signNativeTransaction: (transaction) =>
          Promise.resolve({ ...transaction, signatures: [SIGNATURE] }),
      },
    });

    expect(sol.withdrawal).toEqual({ kind: "sol", recipient: TREE });
    expect(spl.withdrawal.kind).toBe("spl");
    expect(signed.messageBytes).toEqual(unsigned.messageBytes);
    expect(signed.signatures).toEqual([SIGNATURE]);
  });

  it("matches the split fixture and rejects a spent input without mutation", async () => {
    const fixture = await fixtureJson<SplitFixture>("workflows/action-split-v1");
    const keypair = seededKeypair(
      fixture.inputs.signingSecretBytes,
      fixture.inputs.viewingSeedBytes,
    );
    const state = await walletFromDeposits(
      keypair,
      fixture.inputs.walletAmounts.map(BigInt),
      fixture.inputs.blindingSeedBytes,
    );
    const payer = base58(hexBytes(fixture.inputs.payerBytes)) as Address;
    const created = createSplit({
      wallet: state.wallet,
      payer,
      asset: SOL_MINT,
      parts: Number(fixture.inputs.parts),
    });
    const before = state.wallet.utxos();
    const first = state.wallet
      .utxos()
      .find(
        (entry) =>
          hex(entry.outputContext.hash) === fixture.expected.creation.selectedInputHashBytes,
      );
    if (first === undefined) throw new Error("fixture split input was not synchronized");
    const tampered = () =>
      createSplit({
        wallet: state.wallet,
        payer,
        asset: SOL_MINT,
        parts: Number(fixture.inputs.parts),
        input: new Uint8Array(32).fill(255) as Bytes32,
      });

    expect(created.transaction.inputCount()).toBe(Number(fixture.expected.creation.inputCount));
    expect(created.numOutputs).toBe(Number(fixture.expected.creation.outputCount));
    expect(created.perOutputAmount).toBe(BigInt(fixture.expected.creation.perOutputAmount));
    expect(created.transaction.tree()).toBe(TREE);
    expect(tampered).toThrow(expect.objectContaining({ code: "WALLET_INPUT_UTXO_UNAVAILABLE" }));
    expect(state.wallet.utxos()).toHaveLength(before.length);
    expect(created.perOutputAmount * BigInt(created.numOutputs)).toBe(
      BigInt(fixture.expected.stateTransition.conservedAmount),
    );
  });

  it("creates and submits a merge through the production pipeline", async () => {
    const [fixture, proofFixture] = await Promise.all([
      fixtureJson<MergeFixture>("workflows/action-merge-v1"),
      fixtureJson<{
        expected: { bsb22: { uncompressed: { bBytes: string; cBytes: string } } };
      }>("client/proof-validity-v1"),
    ]);
    const keypair = seededKeypair(
      fixture.inputs.signingSecretBytes,
      fixture.inputs.viewingSeedBytes,
    );
    const state = await walletFromDeposits(
      keypair,
      fixture.inputs.walletAmounts.map(BigInt),
      fixture.inputs.blindingSeedBytes,
    );
    const created = createMerge({ wallet: state.wallet, keypair, asset: SOL_MINT });
    const material = MergeMaterial.fromKeypair(keypair);
    const rpc = new TestRpc();
    rpc.setAccount(fixture.inputs.enabledRecord.pda, {
      owner: REGISTRY_PROGRAM,
      data: hexBytes(fixture.inputs.enabledRecord.accountDataBytes),
      lamports: 1n,
    });
    const indexer = rpcDouble({
      getInputMerkleProofs: () =>
        Promise.resolve(
          created.prepared.inputs
            .filter((input) => !input.isDummy())
            .map((input, index) => spendProof(input, index)),
        ),
    });
    const proverFetch = vi.fn(() =>
      Promise.resolve(proofResponse(proofFixture.expected.bsb22.uncompressed)),
    );
    const mergeClient = new ZolanaClient({
      rpc,
      indexer: fixtureIndexer(new TestIndexer()),
      prover: new ProverClient({ url: "https://prover.example.test", fetch: proverFetch }),
      tree: TREE,
    });
    const submitted = await submitMergeTransaction({
      rpc: mergeClient,
      indexer,
      owner: fixture.inputs.enabledRecord.owner,
      payer: {
        address: fixture.inputs.enabledRecord.owner,
        signNativeTransaction: (transaction) =>
          Promise.resolve({ ...transaction, signatures: [SIGNATURE] }),
      },
      material,
      tree: TREE,
      prepared: created.prepared,
    });

    expect(created.numInputs).toBe(Number(fixture.expected.creation.realInputCount));
    expect(created.mergedAmount).toBe(BigInt(fixture.expected.creation.mergedAmount));
    expect(
      created.prepared.inputs.filter((input) => !input.isDummy()).map((input) => input.utxo.amount),
    ).toEqual(fixture.expected.creation.selectedAmounts.map(BigInt));
    expect(hex(material.signingPublicKey.toBytes())).toBe(
      fixture.expected.material.signingPubkeyBytes,
    );
    expect(hex(material.viewingPublicKey.toBytes())).toBe(
      fixture.expected.material.viewingPubkeyBytes,
    );
    expect(hex(material.nullifierKey.publicKey())).toBe(
      fixture.expected.material.nullifierPubkeyBytes,
    );
    expect(submitted.signature).toBe(fixture.expected.submission.submittedSignature);
    expect(submitted.outputHash).toEqual(created.prepared.output.hash());
    expect(proverFetch).toHaveBeenCalledOnce();
  });

  it("submits the exact idempotent ATA message twice and nests RPC errors", async () => {
    const fixture = await fixtureJson<AtaFixture>("workflows/action-ata-idempotent-v1");
    const rpc = new TestRpc();
    // `TestRpc` pins its default blockhash as a string literal type.
    const blockhash = base58(
      hexBytes(fixture.inputs.blockhashBytes),
    ) as typeof rpc.blockhash.blockhash;
    rpc.blockhash = { blockhash, lastValidBlockHeight: 1n };
    const signer = fixtureSigner(fixture.inputs.payerSecretBytes);
    const first = await createAssociatedTokenAccount({
      rpc,
      payer: signer,
      owner: fixture.inputs.owner,
      mint: fixture.inputs.mint,
    });
    const second = await createAssociatedTokenAccount({
      rpc,
      payer: signer,
      owner: fixture.inputs.owner,
      mint: fixture.inputs.mint,
    });

    expect(first.address).toBe(fixture.expected.address);
    expect(second.address).toBe(first.address);
    expect(rpc.sent).toHaveLength(Number(fixture.expected.submissionCount));
    expect(hex(rpc.sent[0]?.messageBytes ?? new Uint8Array())).toBe(
      fixture.expected.firstCreate.transaction.messageBytes,
    );
    expect(rpc.sent[1]?.messageBytes).toEqual(rpc.sent[0]?.messageBytes);
    expect(fixture.expected.idempotentRepeat.balanceDelta).toBe("0");
    expect(fixture.expected.idempotentRepeat.instructionMessageUnchanged).toBe(true);

    class RejectingRpc extends TestRpc {
      override sendTransaction(): Promise<Signature> {
        return Promise.reject(new Error("fixture submission rejected"));
      }
    }
    const rejected = createAssociatedTokenAccount({
      rpc: new RejectingRpc(),
      payer: signer,
      owner: fixture.inputs.owner,
      mint: fixture.inputs.mint,
    });
    await expect(rejected).rejects.toMatchObject({
      code: "WALLET_CREATE_ASSOCIATED_TOKEN_ACCOUNT",
      cause: expect.objectContaining({ message: "fixture submission rejected" }),
    });
  });

  it("approves any request the local authority is handed and builds rotation", async () => {
    const fixture = await fixtureJson<MergeFixture>("workflows/action-merge-v1");
    const keypair = seededKeypair(
      fixture.inputs.signingSecretBytes,
      fixture.inputs.viewingSeedBytes,
    );
    const owner = fixture.inputs.enabledRecord.owner;
    const authority: WalletAuthority = new LocalWalletAuthority({
      solanaPublicKey: owner,
      keypair,
    });
    await expect(
      authority.requestUserApproval({
        solanaPublicKey: owner,
        summary: "approve private transfer",
      }),
    ).resolves.toBeUndefined();
    // `LocalWalletAuthority` carries no interactive approval: Rust takes the
    // trait default, which approves without inspecting the request.
    await expect(
      authority.requestUserApproval({ solanaPublicKey: TREE, summary: "another identity" }),
    ).resolves.toBeUndefined();

    const rpc = new TestRpc();
    rpc.setAccount(fixture.inputs.enabledRecord.pda, {
      owner: REGISTRY_PROGRAM,
      data: hexBytes(fixture.inputs.enabledRecord.accountDataBytes),
      lamports: 1n,
    });
    const rotated = ShieldedKeypair.generate().shieldedAddress();
    const { buildRegistrationTransaction } = await import("@zolana/wallet");
    const transaction = await buildRegistrationTransaction({ rpc, owner, address: rotated });
    expect(transaction).toBeDefined();
    expect(transaction?.messageBytes).toContain(5);
  });

  it("covers P256, EdDSA, mixed ownership, balances, history, lag, abort, timeout, and retry", async () => {
    const fixture = await fixtureJson<MergeFixture>("workflows/action-merge-v1");
    const [authorityFixture, syncFixture, submitFixture, transactionFixture] = await Promise.all([
      fixtureJson<{
        id: string;
        inputs: { messageHashBytes: string; signingSecretBytes: string; viewingSeedBytes: string };
        expected: { p256Signature: { rBytes: string; sBytes: string } };
      }>("wallet/wallet_authority"),
      fixtureJson<{
        id: string;
        expected: { indexerOutcomes: { timeout: { code: string }; abort: { code: string } } };
      }>("wallet/wallet_sync"),
      fixtureJson<{
        id: string;
        inputs: { signingSecretBytes: string; viewingSeedBytes: string };
        expected: {
          material: {
            signingPubkeyBytes: string;
            viewingPubkeyBytes: string;
            nullifierPubkeyBytes: string;
          };
        };
      }>("wallet/submit"),
      fixtureJson<{
        id: string;
        expected: { merge: { mergedAmount: string; selectedAmounts: readonly string[] } };
      }>("wallet/transaction"),
    ]);
    const p256 = seededKeypair(fixture.inputs.signingSecretBytes, fixture.inputs.viewingSeedBytes);
    const eddsa = ShieldedKeypair.fromEd25519(new Uint8Array(32).fill(7) as Bytes32, 0);
    expect(p256.signingPublicKey().signatureType()).toBe("p256");
    expect(eddsa.signingPublicKey().signatureType()).toBe("ed25519");
    const state = await walletFromDeposits(p256, [20n, 60n], fixture.inputs.blindingSeedBytes);
    expect(getPrivateTokenBalances(state.wallet)).toEqual([
      { assetId: 1n, mint: SOL_MINT, amount: 80n, utxos: [] },
    ]);
    expect(getPrivateTransactions(state.wallet)).toHaveLength(2);
    const authorityKeypair = seededKeypair(
      authorityFixture.inputs.signingSecretBytes,
      authorityFixture.inputs.viewingSeedBytes,
    );
    const authoritySignature = authorityKeypair.signP256(
      hexBytes(authorityFixture.inputs.messageHashBytes) as Bytes32,
    );
    expect(hex(authoritySignature.r)).toBe(authorityFixture.expected.p256Signature.rBytes);
    expect(hex(authoritySignature.s)).toBe(authorityFixture.expected.p256Signature.sBytes);
    const submitMaterial = MergeMaterial.fromKeypair(
      seededKeypair(submitFixture.inputs.signingSecretBytes, submitFixture.inputs.viewingSeedBytes),
    );
    expect(hex(submitMaterial.signingPublicKey.toBytes())).toBe(
      submitFixture.expected.material.signingPubkeyBytes,
    );
    expect(BigInt(transactionFixture.expected.merge.mergedAmount)).toBe(
      BigInt(fixture.expected.creation.mergedAmount),
    );
    expect(transactionFixture.expected.merge.selectedAmounts).toEqual(
      fixture.expected.creation.selectedAmounts,
    );
    expect([authorityFixture.id, syncFixture.id, submitFixture.id, transactionFixture.id]).toEqual([
      "fx-p00-wallet-authority-v1",
      "fx-p00-wallet-sync-v1",
      "fx-p00-wallet-submit-v1",
      "fx-p00-wallet-transaction-v1",
    ]);

    const beforeUtxos = state.wallet.utxos().length;
    const beforeHistory = state.wallet.privateTransactions().length;
    const emptyIndexer = indexerDouble({
      getShieldedTransactionsByTags: () =>
        Promise.resolve({ context: { blockTime: 2n }, transactions: [] }),
      getEncryptedUtxosByTags: () => Promise.resolve({ context: { blockTime: 2n }, matches: [] }),
    });
    await syncWallet({ wallet: state.wallet, authority: state.authority, indexer: emptyIndexer });
    expect(state.wallet.utxos()).toHaveLength(beforeUtxos);
    expect(state.wallet.privateTransactions()).toHaveLength(beforeHistory);

    let attempts = 0;
    const retryingIndexer = indexerDouble({
      getShieldedTransactionsByTags: () => {
        attempts++;
        if (attempts === 1) {
          return Promise.reject(new Error(syncFixture.expected.indexerOutcomes.timeout.code));
        }
        return Promise.resolve({ context: { blockTime: 3n }, transactions: [] });
      },
      getEncryptedUtxosByTags: () => Promise.resolve({ context: { blockTime: 3n }, matches: [] }),
    });
    await expect(
      syncWallet({ wallet: state.wallet, authority: state.authority, indexer: retryingIndexer }),
    ).rejects.toMatchObject({ code: "WALLET_SYNC", cause: expect.any(Error) });
    await syncWallet({
      wallet: state.wallet,
      authority: state.authority,
      indexer: retryingIndexer,
    });
    expect(attempts).toBeGreaterThan(1);

    const controller = new AbortController();
    controller.abort();
    const abortingIndexer = indexerDouble({
      getShieldedTransactionsByTags: (_request, _config, context) =>
        context?.signal?.aborted === true
          ? Promise.reject(new Error(syncFixture.expected.indexerOutcomes.abort.code))
          : Promise.resolve({ context: { blockTime: 4n }, transactions: [] }),
      getEncryptedUtxosByTags: () => Promise.resolve({ context: { blockTime: 4n }, matches: [] }),
    });
    const aborted = syncWallet(
      { wallet: state.wallet, authority: state.authority, indexer: abortingIndexer },
      { signal: controller.signal },
    );
    await expect(aborted).rejects.toMatchObject({
      code: "WALLET_SYNC",
      cause: expect.objectContaining({
        message: syncFixture.expected.indexerOutcomes.abort.code,
      }),
    });
    const timedOut = new TestRpc().getLatestBlockhash({ timeoutMs: 0 });
    await expect(timedOut).rejects.toMatchObject({ code: "TEST_KIT_TIMEOUT" });
  });
});
