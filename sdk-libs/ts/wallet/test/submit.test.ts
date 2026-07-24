import type { Rpc } from "@zolana/client";
import type { Address, Bytes32, Signature, Transaction } from "@zolana/interface";
import { NullifierKey, ShieldedKeypair, SigningKey, ViewingKey } from "@zolana/keypair";
import { AssetRegistry, Data, SOL_MINT, Utxo, Wallet } from "@zolana/transaction";
import { describe, expect, it } from "vitest";

import {
  MergeMaterial,
  createMerge,
  submitMergeTransaction,
  type TransactionSigner,
} from "../src/index.js";
import { internalUserRecordPda } from "../src/registry.js";
import { base58, fromBase58, hex, hexBytes, walletFixture } from "./helpers/fixtures.js";

const REGISTRY_PROGRAM = "EXM6UUA56UJySzRDCx4dKwN6Xdcrkq3kmizqgZwgwNEc" as Address;
const TREE = base58(new Uint8Array(32).fill(39)) as Address;
const OWNER = base58(new Uint8Array(32).fill(37)) as Address;
const SIGNATURE = "1".repeat(64) as Signature;

interface SubmitFixture {
  readonly inputs: { signingSecretBytes: string; viewingSeedBytes: string };
  readonly expected: {
    material: {
      signingPubkeyBytes: string;
      viewingPubkeyBytes: string;
      nullifierPubkeyBytes: string;
    };
    pipeline: string[];
    errors: { code: string }[];
  };
}

function keypair(fixture: SubmitFixture): ShieldedKeypair {
  const signing = SigningKey.fromBytes(hexBytes(fixture.inputs.signingSecretBytes) as Bytes32);
  return ShieldedKeypair.fromKeys(
    signing,
    NullifierKey.fromSigningKey(signing),
    ViewingKey.fromSeed(hexBytes(fixture.inputs.viewingSeedBytes) as Bytes32, 0),
  );
}

function record(
  owner: Address,
  bump: number,
  material: MergeMaterial,
  enabled: boolean,
): Uint8Array {
  return Uint8Array.from([
    1,
    ...fromBase58(owner),
    bump,
    1,
    ...material.signingPublicKey.p256().toBytes(),
    ...material.nullifierKey.publicKey(),
    ...material.viewingPublicKey.toBytes(),
    0,
    0,
    0,
    0,
    0,
    enabled ? 1 : 0,
  ]);
}

function prepared(localKeypair: ShieldedKeypair) {
  const wallet = new Wallet({
    identity: localKeypair.shieldedAddress(),
    registry: new AssetRegistry(),
  });
  wallet._replace({
    utxos: [5n, 7n].map((amount, index) => {
      const utxo = new Utxo({
        owner: localKeypair.signingPublicKey(),
        asset: SOL_MINT,
        amount,
        blinding: new Uint8Array(31).fill(index + 1) as import("@zolana/interface").Bytes31,
        data: new Data(),
      });
      return {
        utxo,
        outputContext: {
          hash: utxo.hash(localKeypair.nullifierKey().publicKey()),
          tree: TREE,
          leafIndex: BigInt(index),
        },
        nullifier: localKeypair.nullifier(
          utxo.hash(localKeypair.nullifierKey().publicKey()),
          utxo.blinding,
        ),
        spent: false,
      };
    }),
    transactions: [],
    nullifiers: new Set(),
  });
  return createMerge({ wallet, keypair: localKeypair, asset: SOL_MINT }).prepared;
}

describe("merge submission", () => {
  it("matches frozen material and executes the submission pipeline in order", async () => {
    const fixture = await walletFixture<SubmitFixture>("submit");
    const localKeypair = keypair(fixture);
    const material = MergeMaterial.fromKeypair(localKeypair);
    expect(hex(material.signingPublicKey.toBytes())).toBe(
      fixture.expected.material.signingPubkeyBytes,
    );
    expect(hex(material.viewingPublicKey.toBytes())).toBe(
      fixture.expected.material.viewingPubkeyBytes,
    );
    expect(hex(material.nullifierKey.publicKey())).toBe(
      fixture.expected.material.nullifierPubkeyBytes,
    );
    const pda = await internalUserRecordPda(OWNER);
    const calls: string[] = [];
    let accountReads = 0;
    const unsupported = (): Promise<never> => Promise.reject(new Error("unexpected RPC call"));
    const indexer = {
      getInputMerkleProofs: () => {
        calls.push("fetchSpendProofs");
        return Promise.resolve([]);
      },
    } as unknown as Rpc;
    const native: Transaction = { messageBytes: Uint8Array.of(1), signatures: [undefined] };
    const rpc = {
      tree: TREE,
      getAccount: () => {
        if (accountReads++ === 0) calls.push("validateRegistry");
        return Promise.resolve({
          owner: REGISTRY_PROGRAM,
          data: record(OWNER, pda.bump, material, true),
          lamports: 1n,
        });
      },
      getMultipleAccounts: unsupported,
      getBalance: unsupported,
      getLatestBlockhash: () =>
        Promise.resolve({
          blockhash: base58(new Uint8Array(32).fill(3)),
          lastValidBlockHeight: 1n,
        }),
      sendTransaction: () => {
        calls.push("submit");
        return Promise.resolve(SIGNATURE);
      },
      confirmTransaction: unsupported,
      transactOutputViewTags: unsupported,
      getMerkleProofs: unsupported,
      getNonInclusionProofs: unsupported,
      getInputMerkleProofs: unsupported,
      proveMerge: async (input: { indexer: Pick<Rpc, "getInputMerkleProofs"> }) => {
        await input.indexer.getInputMerkleProofs([], undefined, undefined);
        calls.push("proveMerge");
        return {
          data: {} as never,
          outputHash: new Uint8Array(32).fill(8) as Bytes32,
        };
      },
      finishMergeSubmissionUnsigned: () => {
        calls.push("buildMergeTransact");
        return native;
      },
    } as unknown as Rpc;
    const payer: TransactionSigner = {
      address: OWNER,
      signNativeTransaction: (transaction) =>
        Promise.resolve({ ...transaction, signatures: [SIGNATURE] }),
    };
    const submitted = await submitMergeTransaction({
      rpc,
      indexer,
      owner: OWNER,
      payer,
      material,
      tree: TREE,
      proverUrl: "http://127.0.0.1:3001",
      prepared: prepared(localKeypair),
    });
    expect(submitted.signature).toBe(SIGNATURE);
    expect(calls).toEqual(fixture.expected.pipeline);
  });

  it("rejects a registry record without merge opt-in before proving", async () => {
    const fixture = await walletFixture<SubmitFixture>("submit");
    const localKeypair = keypair(fixture);
    const material = MergeMaterial.fromKeypair(localKeypair);
    const pda = await internalUserRecordPda(OWNER);
    const rpc = {
      getAccount: () =>
        Promise.resolve({
          owner: REGISTRY_PROGRAM,
          data: record(OWNER, pda.bump, material, false),
          lamports: 1n,
        }),
    } as unknown as Rpc;
    const rejection = submitMergeTransaction({
      rpc,
      indexer: rpc,
      owner: OWNER,
      payer: {
        address: OWNER,
        signNativeTransaction: (transaction) => Promise.resolve(transaction),
      },
      material,
      tree: TREE,
      proverUrl: "http://127.0.0.1:3001",
      prepared: prepared(localKeypair),
    });
    await expect(rejection).rejects.toEqual(
      expect.objectContaining({
        code: "WALLET_MERGE_DISABLED",
        details: { owner: OWNER },
      }),
    );
    await rejection.catch((error: unknown) => {
      const code = (error as { code: string }).code;
      expect(code.replace("WALLET_", "").replaceAll("_", "").toLowerCase()).toBe(
        fixture.expected.errors[0]?.code.toLowerCase(),
      );
    });

    const mismatchRpc = {
      tree: base58(new Uint8Array(32).fill(38)) as Address,
      getAccount: () =>
        Promise.resolve({
          owner: REGISTRY_PROGRAM,
          data: record(OWNER, pda.bump, material, true),
          lamports: 1n,
        }),
      proveMerge: () => Promise.reject(new Error("proof must not run")),
      finishMergeSubmissionUnsigned: () => {
        throw new Error("build must not run");
      },
    } as unknown as Rpc;
    const mismatch = submitMergeTransaction({
      rpc: mismatchRpc,
      indexer: mismatchRpc,
      owner: OWNER,
      payer: {
        address: OWNER,
        signNativeTransaction: (transaction) => Promise.resolve(transaction),
      },
      material,
      tree: TREE,
      proverUrl: "http://127.0.0.1:3001",
      prepared: prepared(localKeypair),
    });
    await expect(mismatch).rejects.toEqual(
      expect.objectContaining({ code: "WALLET_MERGE_TREE_MISMATCH" }),
    );
    await mismatch.catch((error: unknown) => {
      const code = (error as { code: string }).code;
      expect(code.replace("WALLET_", "").replaceAll("_", "").toLowerCase()).toBe(
        fixture.expected.errors[1]?.code.toLowerCase(),
      );
    });
  });
});
