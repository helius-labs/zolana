import { type Rpc, ZolanaClient, ZolanaIndexer } from "@zolana/client";
import { ProverClient, type SpendProof } from "@zolana/client/prover";
import type { Address, Bytes32, Signature } from "@zolana/interface";
import { NullifierKey, ShieldedKeypair, SigningKey, ViewingKey } from "@zolana/keypair";
import {
  AssetRegistry,
  Data,
  type ProofInputUtxo,
  SOL_MINT,
  Utxo,
  Wallet,
} from "@zolana/transaction";
import { describe, expect, it, vi } from "vitest";

import proofFixture from "../../fixtures/client/proof-validity-v1.json" with { type: "json" };
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

function spendProof(input: ProofInputUtxo, index: number): SpendProof {
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

function proofResponse(): Response {
  const c = proofFixture.expected.bsb22.uncompressed.cBytes;
  const b = proofFixture.expected.bsb22.uncompressed.bBytes;
  const g1 = [`0x${c.slice(0, 64)}`, `0x${c.slice(64)}`];
  return Response.json({
    proof: {
      ar: g1,
      bs: [
        [`0x${b.slice(0, 64)}`, `0x${b.slice(64, 128)}`],
        [`0x${b.slice(128, 192)}`, `0x${b.slice(192)}`],
      ],
      krs: g1,
      proof_commitment: g1,
      proof_commitment_pok: g1,
    },
  });
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
    const pda = internalUserRecordPda(OWNER);
    const calls: string[] = [];
    let accountReads = 0;
    const unsupported = (): Promise<never> => Promise.reject(new Error("unexpected RPC call"));
    const merge = prepared(localKeypair);
    const indexer = {
      getInputMerkleProofs: () => {
        calls.push("fetchSpendProofs");
        return Promise.resolve(
          merge.inputs
            .filter((input) => !input.isDummy())
            .map((input, index) => spendProof(input, index)),
        );
      },
    } as unknown as Rpc;
    const rpc = {
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
      getLatestBlockhash: () => {
        calls.push("buildMergeTransact");
        return Promise.resolve({
          blockhash: base58(new Uint8Array(32).fill(3)),
          lastValidBlockHeight: 1n,
        });
      },
      sendTransaction: () => {
        calls.push("submit");
        return Promise.resolve(SIGNATURE);
      },
      confirmTransaction: unsupported,
      transactOutputViewTags: unsupported,
      getMerkleProofs: unsupported,
      getNonInclusionProofs: unsupported,
      getInputMerkleProofs: unsupported,
    } as Rpc;
    const proverFetch = vi.fn(() => {
      calls.push("proveMerge");
      return Promise.resolve(proofResponse());
    });
    const client = new ZolanaClient({
      rpc,
      indexer: Object.create(ZolanaIndexer.prototype) as ZolanaIndexer,
      prover: new ProverClient({ url: "https://prover.example.test", fetch: proverFetch }),
      tree: TREE,
    });
    const payer: TransactionSigner = {
      address: OWNER,
      signNativeTransaction: (transaction) =>
        Promise.resolve({ ...transaction, signatures: [SIGNATURE] }),
    };
    const submitted = await submitMergeTransaction({
      rpc: client,
      indexer,
      owner: OWNER,
      payer,
      material,
      tree: TREE,
      prepared: merge,
    });
    expect(submitted.signature).toBe(SIGNATURE);
    expect(calls).toEqual(fixture.expected.pipeline);
  });

  it("rejects a registry record without merge opt-in before proving", async () => {
    const fixture = await walletFixture<SubmitFixture>("submit");
    const localKeypair = keypair(fixture);
    const material = MergeMaterial.fromKeypair(localKeypair);
    const pda = internalUserRecordPda(OWNER);
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
