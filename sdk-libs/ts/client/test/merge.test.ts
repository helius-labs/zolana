import { sha256 } from "@noble/hashes/sha2.js";
import { ZolanaApi } from "@zolana/api";
import {
  SHIELDED_POOL_PROGRAM_ID,
  type Address,
  type Bytes31,
  type Bytes32,
  type Instruction,
} from "@zolana/interface";
import {
  mergeTransactInstruction,
  type MergeTransactInstructionData,
} from "@zolana/interface/instructions";
import { NullifierKey, ShieldedKeypair, SigningKey, ViewingKey } from "@zolana/keypair";
import { PreparedMerge, ProofInputUtxo, SOL_MINT, Utxo, deriveBlinding } from "@zolana/transaction";
import { describe, expect, it, vi } from "vitest";

import mergeFixture from "../../fixtures/transaction/merge-v1.json" with { type: "json" };
import proofFixture from "../../fixtures/client/proof-validity-v1.json" with { type: "json" };
import { ClientError, type Rpc, ZolanaClient, ZolanaIndexer } from "../src/index.js";
import { addressBytes, decodeBase58, encodeBase58, sha256Bytes } from "../src/internal.js";
import { ProverClient } from "../src/prover/index.js";
import type { SpendProof } from "../src/rpc.js";
import { createProofOutput } from "../../transaction/src/utxo.js";
import { bytes, hex } from "./helpers/prover-vectors.js";

const TREE = "4WnNSfDXkWSnFi1PgXxn8X8fhFwU2Jhe4Df82mL9rKmm" as Address;
const PAYER = "4Ss5JMkXAD9Z7cktFEdrqeMuT6jGMF1pVozTyPHZ6zT4" as Address;
const USER_RECORD = encodeBase58(new Uint8Array(32).fill(17)) as Address;
const COMPUTE_BUDGET = "ComputeBudget111111111111111111111111111111" as Address;
const BLOCKHASH = encodeBase58(new Uint8Array(32).fill(53));

function fakeRpc(overrides: Partial<Rpc> = {}): Rpc {
  const unsupported = (): Promise<never> => Promise.reject(new Error("unsupported"));
  return {
    getAccount: unsupported,
    getMultipleAccounts: unsupported,
    getBalance: unsupported,
    getLatestBlockhash: unsupported,
    sendTransaction: unsupported,
    confirmTransaction: unsupported,
    transactOutputViewTags: unsupported,
    getMerkleProofs: unsupported,
    getNonInclusionProofs: unsupported,
    getInputMerkleProofs: unsupported,
    ...overrides,
  };
}

function fixtureBytes(value: string): Uint8Array {
  return bytes(value);
}

function source(): Readonly<{
  prepared: PreparedMerge;
  material: Readonly<{
    signingPublicKey: ReturnType<ShieldedKeypair["signingPublicKey"]>;
    viewingPublicKey: ReturnType<ShieldedKeypair["viewingPublicKey"]>;
    nullifierKey: NullifierKey;
  }>;
  proofs: readonly SpendProof[];
}> {
  const signing = SigningKey.fromBytes(
    fixtureBytes(mergeFixture.inputs.signingSecretBytes) as Bytes32,
  );
  const nullifierKey = NullifierKey.fromSigningKey(signing);
  const keypair = ShieldedKeypair.fromKeys(
    signing,
    nullifierKey,
    ViewingKey.fromSeed(fixtureBytes(mergeFixture.inputs.viewingSeedBytes) as Bytes32, 0),
  );
  const seed = fixtureBytes(mergeFixture.inputs.blindingSeedBytes) as Bytes31;
  const real = mergeFixture.inputs.realInputAmounts.map(
    (amount, index) =>
      new ProofInputUtxo({
        utxo: new Utxo({
          owner: keypair.signingPublicKey(),
          asset: SOL_MINT,
          amount: BigInt(amount),
          blinding: deriveBlinding(seed, index),
        }),
        nullifierKey,
      }),
  );
  const prepared = new PreparedMerge({
    inputs: [
      ...real,
      ...Array.from({ length: 6 }, (_, index) =>
        ProofInputUtxo.dummy(deriveBlinding(seed, index + 2)),
      ),
    ],
    output: createProofOutput({
      ownerAddress: keypair.shieldedAddress(),
      asset: SOL_MINT,
      amount: 30n,
      blinding: deriveBlinding(seed, 2),
    }),
    expiryUnixTs: 0xffff_ffff_ffff_ffffn,
    signingPublicKey: keypair.signingPublicKey(),
    userViewingPublicKey: keypair.viewingPublicKey(),
    txViewingSecret: fixtureBytes(mergeFixture.inputs.txViewingSecretBytes) as Bytes32,
  });
  const proofs = real.map((input, index) => spendProof(input, index));
  return {
    prepared,
    material: {
      signingPublicKey: keypair.signingPublicKey(),
      viewingPublicKey: keypair.viewingPublicKey(),
      nullifierKey,
    },
    proofs,
  };
}

function spendProof(input: ProofInputUtxo, index: number): SpendProof {
  const stateRoot = new Uint8Array(32);
  stateRoot[31] = 20 + index;
  const nullifierRoot = new Uint8Array(32);
  nullifierRoot[31] = 30 + index;
  return {
    state: {
      leaf: input.hash(),
      merkleContext: { treeType: 1, tree: TREE },
      path: Object.freeze(Array.from({ length: 32 }, () => new Uint8Array(32) as Bytes32)),
      leafIndex: BigInt(index),
      root: stateRoot as Bytes32,
      rootSeq: 1n,
      rootIndex: 40 + index,
    },
    nullifier: {
      leaf: input.nullifier(),
      merkleContext: { treeType: 1, tree: TREE },
      path: Object.freeze(Array.from({ length: 40 }, () => new Uint8Array(32) as Bytes32)),
      lowElement: new Uint8Array(32) as Bytes32,
      lowElementIndex: BigInt(index),
      highElement: new Uint8Array(32).fill(1) as Bytes32,
      highElementIndex: BigInt(index + 1),
      root: nullifierRoot as Bytes32,
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

function client(proverFetch: typeof globalThis.fetch): ZolanaClient {
  const indexer = new ZolanaIndexer(
    new ZolanaApi({
      url: "https://indexer.example.test",
      fetch: vi.fn(() => Promise.reject(new Error("concrete indexer must not be called"))),
    }),
  );
  return new ZolanaClient({
    rpc: fakeRpc(),
    indexer,
    prover: new ProverClient({ url: "https://prover.example.test", fetch: proverFetch }),
    tree: TREE,
  });
}

async function expectCode(promise: Promise<unknown>, code: string): Promise<ClientError> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(ClientError);
    expect((error as ClientError).code).toBe(code);
    return error as ClientError;
  }
  throw new Error("expected client call to fail");
}

describe("merge proving and unsigned submission", () => {
  it("proves the frozen prepared merge and returns exact instruction material", async () => {
    const value = source();
    const fetch = vi.fn((_request: URL | RequestInfo, init?: RequestInit) => {
      const body = JSON.parse(typeof init?.body === "string" ? init.body : "") as Record<
        string,
        unknown
      >;
      expect(Object.keys(body)).toEqual([
        "circuitType",
        "inputs",
        "output",
        "p256PubX",
        "p256PubY",
        "ownerPkHash",
        "userNullifierPk",
        "userNullifierSecret",
        "txViewingSk",
        "userViewingPubkey",
        "externalDataHash",
        "privateTxHash",
        "publicInputHash",
        "zoneProgramId",
      ]);
      expect(body["circuitType"]).toBe("merge");
      expect(body["zoneProgramId"]).toBe("0x0");
      expect(body["inputs"]).toHaveLength(8);
      expect(body["userViewingPubkey"]).toHaveLength(65);
      expect(body["txViewingSk"]).toBe("0xf");
      return Promise.resolve(proofResponse());
    });
    const proved = await client(fetch).proveMerge({
      prepared: value.prepared,
      material: value.material,
      indexer: fakeRpc({ getInputMerkleProofs: () => Promise.resolve(value.proofs) }),
    });

    expect(hex(proved.outputHash)).toBe(mergeFixture.expected.outputHashBytes);
    expect(proved.data.nullifiers).toHaveLength(8);
    expect(proved.data.utxoTreeRootIndexes).toEqual([40, 41, 40, 40, 40, 40, 40, 40]);
    expect(proved.data.nullifierTreeRootIndexes).toEqual([50, 51, 50, 50, 50, 50, 50, 50]);
    expect(proved.data.encryptedUtxo).toHaveLength(110);
    expect(proved.data.encryptedUtxo.slice(0, 6)).toEqual(Uint8Array.of(2, 105, 0, 0, 0, 6));
    expect(proved.data.eddsaOwner).toBe(false);
    expect(fetch).toHaveBeenCalledOnce();
  });

  it("rejects mismatched material and malformed merge proofs", async () => {
    const value = source();
    const foreignNullifier = NullifierKey.fromSecret(new Uint8Array(31).fill(9) as Bytes31);
    const mismatch = client(vi.fn(() => Promise.resolve(proofResponse()))).proveMerge({
      prepared: value.prepared,
      material: { ...value.material, nullifierKey: foreignNullifier },
      indexer: fakeRpc({ getInputMerkleProofs: () => Promise.resolve(value.proofs) }),
    });
    await expectCode(mismatch, "CLIENT_MERGE_NULLIFIER_KEY_MISMATCH");

    const malformed = client(
      vi.fn(() =>
        Promise.resolve(
          Response.json({
            proof: {
              ar: ["0x0", "0x0"],
              bs: [
                ["0x0", "0x0"],
                ["0x0", "0x0"],
              ],
              krs: ["0x0", "0x0"],
            },
          }),
        ),
      ),
    ).proveMerge({
      prepared: value.prepared,
      material: value.material,
      indexer: fakeRpc({ getInputMerkleProofs: () => Promise.resolve(value.proofs) }),
    });
    await expectCode(malformed, "CLIENT_PROOF_RAIL_MISMATCH");
  });

  it("propagates merge aborts and timeouts through the prover request", async () => {
    const value = source();
    const indexer = fakeRpc({ getInputMerkleProofs: () => Promise.resolve(value.proofs) });
    const controller = new AbortController();
    controller.abort();
    await expectCode(
      client(vi.fn(() => Promise.resolve(proofResponse()))).proveMerge(
        { prepared: value.prepared, material: value.material, indexer },
        { signal: controller.signal },
      ),
      "CLIENT_ABORTED",
    );

    const pendingFetch = vi.fn((_request: URL | RequestInfo, init?: RequestInit) => {
      return new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener(
          "abort",
          () => {
            reject(new Error("aborted"));
          },
          { once: true },
        );
      });
    });
    await expectCode(
      client(pendingFetch).proveMerge(
        { prepared: value.prepared, material: value.material, indexer },
        { timeoutMs: 1 },
      ),
      "CLIENT_TIMEOUT",
    );
  });

  it("compiles the exact unsigned merge legacy message", () => {
    const data = fixedInstructionData();
    const transaction = client(
      vi.fn(() => Promise.reject(new Error("prover must not be called"))),
    ).finishMergeSubmissionUnsigned({
      proved: { data, outputHash: data.outputUtxoHash },
      feePayer: PAYER,
      userRecord: USER_RECORD,
      recentBlockhash: BLOCKHASH,
    });
    const merge = mergeTransactInstruction({
      tree: TREE,
      payer: PAYER,
      userRecord: USER_RECORD,
      data,
    });
    const expected = legacyMessage(merge);

    expect(transaction.messageBytes).toEqual(expected);
    expect(transaction.signatures).toEqual([undefined]);
    expect(hex(sha256Bytes(transaction.messageBytes))).toBe(hex(new Uint8Array(sha256(expected))));
  });
});

function fixedInstructionData(): MergeTransactInstructionData {
  const point32 = new Uint8Array(32) as Bytes32;
  return {
    expiryUnixTs: 42n,
    proof: {
      a: point32,
      b: new Uint8Array(64) as never,
      c: point32,
      commitment: point32,
      commitmentPok: point32,
    },
    outputUtxoHash: new Uint8Array(32).fill(9) as Bytes32,
    nullifiers: Object.freeze(
      Array.from({ length: 8 }, (_, index) => new Uint8Array(32).fill(index) as Bytes32),
    ),
    utxoTreeRootIndexes: Object.freeze(Array.from({ length: 8 }, (_, index) => index)),
    nullifierTreeRootIndexes: Object.freeze(Array.from({ length: 8 }, (_, index) => index + 10)),
    privateTxHash: new Uint8Array(32).fill(3) as Bytes32,
    encryptedUtxo: new Uint8Array(110),
    eddsaOwner: false,
  };
}

function legacyMessage(merge: Instruction): Uint8Array {
  const accounts = [PAYER, TREE, COMPUTE_BUDGET, USER_RECORD, SHIELDED_POOL_PROGRAM_ID];
  const computeData = Uint8Array.of(2, 0xc0, 0x5c, 0x15, 0);
  return concat(
    Uint8Array.of(1, 0, 3),
    compact(accounts.length),
    ...accounts.map(addressBytes),
    decodeBase58(BLOCKHASH, 32, "blockhash"),
    compact(2),
    Uint8Array.of(2),
    compact(0),
    compact(computeData.length),
    computeData,
    Uint8Array.of(4),
    compact(merge.accounts.length),
    Uint8Array.of(1, 0, 3, 4),
    compact(merge.data.length),
    merge.data,
  );
}

function compact(value: number): Uint8Array {
  const result: number[] = [];
  let remaining = value;
  do {
    let byte = remaining & 0x7f;
    remaining >>>= 7;
    if (remaining !== 0) byte |= 0x80;
    result.push(byte);
  } while (remaining !== 0);
  return Uint8Array.from(result);
}

function concat(...parts: readonly Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}
