import { type Rpc, ZolanaClient, ZolanaIndexer } from "@zolana/client";
import { ProverClient } from "@zolana/client/prover";
import type { Address, Bytes32, Bytes33 } from "@zolana/interface";
import { ShieldedKeypair } from "@zolana/keypair";
import {
  AssetRegistry,
  Data,
  type SppProofInputUtxo,
  SOL_MINT,
  Utxo,
  Wallet,
} from "@zolana/transaction";
import { describe, expect, it, vi } from "vitest";

import fixture from "../../../vectors/wallet-submit-v1.json" with { type: "json" };
import { MergeMaterial, createMerge, submitMergeTransaction } from "../../src/index.js";
import { internalUserRecordPda } from "../../src/registry.js";
import { fromBase58, hexBytes } from "../helpers/fixtures.js";

const REGISTRY_PROGRAM = "EXM6UUA56UJySzRDCx4dKwN6Xdcrkq3kmizqgZwgwNEc" as Address;

// Rust `ClientError` variants and the wallet codes they must become. Rust has no
// wallet error type, so the port names each rejection itself.
const REJECTIONS: Readonly<Record<string, string>> = {
  MergeSigningKeyMismatch: "WALLET_MERGE_SIGNING_KEY_MISMATCH",
  MergeNullifierKeyMismatch: "WALLET_MERGE_NULLIFIER_KEY_MISMATCH",
  MergeViewingKeyMismatch: "WALLET_MERGE_VIEWING_KEY_MISMATCH",
  MergeTreeMismatch: "WALLET_MERGE_TREE_MISMATCH",
};

function expectedCode(error: string): string {
  const code = REJECTIONS[error];
  if (code === undefined) throw new Error(`no wallet code mapped for Rust ${error}`);
  return code;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function keypair(): ShieldedKeypair {
  return ShieldedKeypair.fromEd25519(hexBytes(fixture.inputs.signingSeedHex) as Bytes32, 0);
}

function encodeRecord(input: {
  readonly owner: Address;
  readonly bump: number;
  readonly material: MergeMaterial;
  readonly enabled: boolean;
  readonly ownerP256?: Bytes33;
  readonly nullifierPublicKey?: Bytes32;
  readonly viewingPublicKey?: Bytes33;
}): Uint8Array {
  const ownerBytes = fromBase58(input.owner);
  const nullifier = input.nullifierPublicKey ?? input.material.nullifierKey.publicKey();
  const viewing = input.viewingPublicKey ?? input.material.viewingPublicKey.toBytes();
  return Uint8Array.from([
    1,
    ...ownerBytes,
    input.bump,
    ...(input.ownerP256 === undefined ? [0] : [1, ...input.ownerP256]),
    ...nullifier,
    ...viewing,
    0,
    0,
    0,
    0,
    0,
    input.enabled ? 1 : 0,
  ]);
}

function prepared(localKeypair: ShieldedKeypair, tree: Address) {
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
          tree,
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
  return createMerge({ wallet, keypair: localKeypair, asset: SOL_MINT, tree }).prepared;
}

function spendProof(
  input: SppProofInputUtxo,
  index: number,
  stateTree: Address,
  nullifierTree: Address,
) {
  return {
    state: {
      leaf: input.hash(),
      merkleContext: { treeType: 1, tree: stateTree },
      path: Array.from({ length: 32 }, () => new Uint8Array(32) as Bytes32),
      leafIndex: BigInt(index),
      root: new Uint8Array(32) as Bytes32,
      rootSeq: 1n,
      rootIndex: 40 + index,
    },
    nullifier: {
      leaf: input.nullifier(),
      merkleContext: { treeType: 1, tree: nullifierTree },
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

function mutateRecord(
  mutation: string,
  owner: Address,
  bump: number,
  material: MergeMaterial,
): Uint8Array {
  switch (mutation) {
    case "signing-rail":
      return encodeRecord({
        owner,
        bump,
        material,
        enabled: true,
        ownerP256: new Uint8Array(33).fill(2) as Bytes33,
      });
    case "nullifier":
      return encodeRecord({
        owner,
        bump,
        material,
        enabled: true,
        nullifierPublicKey: new Uint8Array(32).fill(0xff) as Bytes32,
      });
    case "viewing":
      return encodeRecord({
        owner,
        bump,
        material,
        enabled: true,
        viewingPublicKey: new Uint8Array(33).fill(0xff) as Bytes33,
      });
    default:
      throw new Error(`unknown mutation ${mutation}`);
  }
}

describe("wallet-submit-v1.json key mismatches (W03)", () => {
  const localKeypair = keypair();
  const material = MergeMaterial.fromKeypair(localKeypair);
  const owner = fixture.inputs.owner as Address;

  it("rebuilds the Rust seed into the recorded identity", () => {
    expect(owner).toBe(fixture.inputs.owner);
    expect(bytesToHex(material.nullifierKey.publicKey())).toBe(fixture.inputs.nullifierPubkeyHex);
    expect(bytesToHex(material.viewingPublicKey.toBytes())).toBe(fixture.inputs.viewingPubkeyHex);
    expect(bytesToHex(material.signingPublicKey.toBytes())).toBe(fixture.inputs.signingPubkeyHex);
  });

  for (const testCase of fixture.keyMismatches) {
    it(`rejects ${testCase.name} with Rust's ${testCase.error}`, async () => {
      const pda = internalUserRecordPda(owner);
      const rpc = {
        getAccount: () =>
          Promise.resolve({
            owner: REGISTRY_PROGRAM,
            data: mutateRecord(testCase.mutation, owner, pda.bump, material),
            lamports: 1n,
          }),
        proveMerge: () => Promise.reject(new Error("proof must not run")),
        finishMergeSubmissionUnsigned: () => {
          throw new Error("build must not run");
        },
      } as unknown as Rpc;

      const rejection = submitMergeTransaction({
        rpc,
        indexer: rpc,
        owner,
        payer: {
          address: owner,
          signNativeTransaction: (transaction) => Promise.resolve(transaction),
        },
        material,
        tree: fixture.trees.submit as Address,
        prepared: prepared(localKeypair, fixture.trees.submit as Address),
      });

      const expected = expectedCode(testCase.error);
      await expect(rejection).rejects.toEqual(
        expect.objectContaining({
          code: expected,
          ...(testCase.ownerDetail ? { details: { owner } } : {}),
        }),
      );
    });
  }
});

describe("wallet-submit-v1.json indexer proof trees (W03)", () => {
  const localKeypair = keypair();
  const material = MergeMaterial.fromKeypair(localKeypair);
  const owner = fixture.inputs.owner as Address;
  const submitTree = fixture.trees.submit as Address;

  for (const testCase of fixture.proofTrees.filter((entry) => entry.arm === "err")) {
    it(`refuses an indexer proof with ${testCase.name}`, async () => {
      const pda = internalUserRecordPda(owner);
      const merge = prepared(localKeypair, submitTree);
      let proved = false;
      const indexer = {
        getInputMerkleProofs: () =>
          Promise.resolve(
            merge.inputs
              .filter((input) => !input.isDummy())
              .map((input, index) =>
                spendProof(
                  input,
                  index,
                  testCase.stateTree as Address,
                  testCase.nullifierTree as Address,
                ),
              ),
          ),
      } as unknown as Rpc;
      const rpc = {
        tree: submitTree,
        getAccount: () =>
          Promise.resolve({
            owner: REGISTRY_PROGRAM,
            data: encodeRecord({ owner, bump: pda.bump, material, enabled: true }),
            lamports: 1n,
          }),
        proveMerge: async (input: {
          prepared: typeof merge;
          material: MergeMaterial;
          indexer: Pick<Rpc, "getInputMerkleProofs">;
        }) => {
          // Drive the same indexer wrap `submitMergeTransaction` installs so a
          // wrong-tree response is refused before the prover is paid.
          await input.indexer.getInputMerkleProofs(input.prepared.inputUtxoHashes());
          proved = true;
          throw new Error("proof must not run");
        },
        finishMergeSubmissionUnsigned: () => {
          throw new Error("build must not run");
        },
      } as unknown as Rpc;

      const rejection = submitMergeTransaction({
        rpc,
        indexer,
        owner,
        payer: {
          address: owner,
          signNativeTransaction: (transaction) => Promise.resolve(transaction),
        },
        material,
        tree: submitTree,
        prepared: merge,
      });

      await expect(rejection).rejects.toEqual(
        expect.objectContaining({
          code: expectedCode(testCase.error),
          details: {
            proofTree: testCase.proofTree,
            submitTree: testCase.submitTree,
          },
        }),
      );
      expect(proved).toBe(false);
    });
  }

  it("keeps the wallet tree-mismatch code through ZolanaClient.proveMerge", async () => {
    const wrongState = fixture.proofTrees.find((entry) => entry.name === "wrong-state-tree");
    expect(wrongState).toBeDefined();
    if (wrongState === undefined) return;

    const pda = internalUserRecordPda(owner);
    const merge = prepared(localKeypair, submitTree);
    const indexer = {
      getInputMerkleProofs: () =>
        Promise.resolve(
          merge.inputs
            .filter((input) => !input.isDummy())
            .map((input, index) =>
              spendProof(
                input,
                index,
                wrongState.stateTree as Address,
                wrongState.nullifierTree as Address,
              ),
            ),
        ),
    } as unknown as Rpc;
    const unsupported = (): Promise<never> => Promise.reject(new Error("unexpected RPC call"));
    const rpc = {
      getAccount: () =>
        Promise.resolve({
          owner: REGISTRY_PROGRAM,
          data: encodeRecord({ owner, bump: pda.bump, material, enabled: true }),
          lamports: 1n,
        }),
      getMultipleAccounts: unsupported,
      getBalance: unsupported,
      getLatestBlockhash: unsupported,
      sendTransaction: unsupported,
      confirmTransaction: unsupported,
      transactOutputViewTags: unsupported,
      getMerkleProofs: unsupported,
      getNonInclusionProofs: unsupported,
      getInputMerkleProofs: unsupported,
    } as Rpc;
    const proverFetch = vi.fn(() => Promise.reject(new Error("prover must not run")));
    const client = new ZolanaClient({
      rpc,
      indexer: Object.create(ZolanaIndexer.prototype) as ZolanaIndexer,
      prover: new ProverClient({ url: "https://prover.example.test", fetch: proverFetch }),
      tree: submitTree,
    });

    await expect(
      submitMergeTransaction({
        rpc: client,
        indexer,
        owner,
        payer: {
          address: owner,
          signNativeTransaction: (transaction) => Promise.resolve(transaction),
        },
        material,
        tree: submitTree,
        prepared: merge,
      }),
    ).rejects.toEqual(
      expect.objectContaining({
        code: expectedCode(wrongState.error),
        details: {
          proofTree: wrongState.proofTree,
          submitTree: wrongState.submitTree,
        },
      }),
    );
    expect(proverFetch).not.toHaveBeenCalled();
  });
});
