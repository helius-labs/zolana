import { bn254 } from "@noble/curves/bn254.js";
import {
  AccountRole,
  address,
  decompileTransactionMessage,
  getCompiledTransactionMessageDecoder,
  getTransactionSize,
  type Transaction,
} from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import { ClientError, LocalKeys, ZolanaClient } from "../src/client/index.js";
import type {
  MergeAssembler,
  ProofService,
  RingMemberProofRequest,
  RingMemberRecordResult,
  RingMergeRegistryProof,
  SecretRingProofRequest,
  WalletKeys,
} from "../src/client/ports.js";
import { bigintToBytes } from "../src/client/internal.js";
import { asField } from "../src/client/prover/assembly.js";
import { mergeProverRequestBody, ProverClient } from "../src/client/prover/client.js";
import { decodeIndexedInputs, proveThroughAuthority } from "../src/client/prover/indexed.js";
import { assembleMergeWithProofs, prepareMerge } from "../src/client/prover/merge.js";
import { compressG2, decompressG2 } from "../src/client/prover/proof.js";
import type { RingProofRequest } from "../src/client/prover/ring.js";
import type { NonInclusionProof, SpendProof } from "../src/client/rpc.js";
import { hashBytes, initializePoseidon } from "../src/hasher/index.js";
import { encodeMergeTransactInstructionData } from "../src/interface/codecs/index.js";
import { MAX_MERGE_INPUTS, MAX_RING_MERGE_INPUTS } from "../src/interface/constants.js";
import { Reader, addressBytes } from "../src/interface/internal.js";
import {
  ringAuthAddress,
  ringConfigPda,
  ringMemberRegistryPda,
  treeAddress,
} from "../src/interface/pda/index.js";
import { InstructionTag } from "../src/interface/program.js";
import type {
  Address,
  Bytes32,
  Bytes64,
  Bytes128,
  MergeTransactInstructionData,
} from "../src/interface/types.js";
import {
  mergeDummyNullifier,
  mergeOutputBlinding,
  mergeOutputKey,
  mergePrivateTxBlinding,
} from "../src/keypair/merge/index.js";
import { ShieldedKeypair } from "../src/keypair/shielded.js";
import { X25519Keypair } from "../src/keypair/x25519.js";
import { RING_COSIGN_TRANSFERS, type RingCoSigner } from "../src/ring/codecs.js";
import { buildRingMergeTransaction, ringMergeInstruction } from "../src/ring/merge.js";
import {
  mergeDisclosureFieldCount,
  openRingMergeDisclosure,
  readRingMergeDisclosure,
  ringMergeAnonymousPublicInputHash,
} from "../src/ring/merge-disclosure.js";
import { escrowKeyHash } from "../src/ring/member-registry.js";
import { ListId, recordBit } from "../src/ring/policy.js";
import { AssetRegistry, SOL_MINT } from "../src/transaction/asset.js";
import { Data } from "../src/transaction/data.js";
import { Merge, PreparedMerge } from "../src/transaction/instructions/builders.js";
import { privateTxHash } from "../src/transaction/instructions/transact.js";
import { ProofInputUtxo, Utxo } from "../src/transaction/utxo.js";
import { approveUnattended, intentHash } from "../src/transaction/wallet/intent.js";
import { Wallet } from "../src/transaction/wallet/state.js";
import { BLOCKHASH } from "./helpers/clients.js";
import { recordTree, type FixtureRecord } from "./helpers/member-registry.js";
import { proofFor } from "./helpers/proofs.js";
import {
  memberRegistryData,
  ownedAccount,
  ringProgramConfigData,
} from "./helpers/ring-accounts.js";

const RING = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
/** The registry's newest root sits at this history slot. */
const ROOT_SLOT = 3;
/** Pays an anonymous ring's merge, the hidden owner signs nothing public. */
const RELAYER = address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");
function field(value: number): Bytes32 {
  const bytes = new Uint8Array(32);
  bytes[31] = value;
  return bytes as Bytes32;
}
await initializePoseidon();
const owner = ShieldedKeypair.generate();
const mergeAuditor = X25519Keypair.generate();
const OWNER_MEMBER = owner.signingPublicKey().ownerProofInputHash();
const SEALED_CIPHERTEXT = field(0x5e);

/** The owner's record escrowing `nullifierPk`, or holding no key on an anonymous ring. */
function ownerRecord(escrow: "own" | "foreign" | "none"): FixtureRecord {
  if (escrow === "none") return { member: OWNER_MEMBER, lists: 0n };
  const nullifierPk = escrow === "own" ? owner.nullifierPublicKey() : field(77);
  return {
    member: OWNER_MEMBER,
    lists: recordBit(ListId.escrow),
    escrowKey: escrowKeyHash({ nullifierPk, ciphertext: SEALED_CIPHERTEXT }),
    sealed: {
      owner: owner.shieldedAddress().solanaAddress(),
      nullifierPk,
      ephemeralPublicKey: mergeAuditor.publicKey(),
      ciphertext: SEALED_CIPHERTEXT,
    },
  };
}

function registryProof(): Extract<RingMergeRegistryProof, { ctHash: Bytes32 }> {
  const tree = recordTree([ownerRecord("own")]);
  const opening = tree.opening(OWNER_MEMBER);
  if (opening.kind !== "present") throw new Error("owner outside the fixture registry");
  const record = Object.freeze({
    kind: "present" as const,
    record: opening.record,
    path: opening.path,
  });
  return { root: tree.root, record, ctHash: hashBytes(SEALED_CIPHERTEXT) as Bytes32 };
}
const mergeRegistryProof = registryProof();
const anonymousProof: RingMergeRegistryProof = { anonymous: true };

function input(
  amount: bigint,
  ringProgramId: Address = RING,
  data = new Data(),
  ringDataHash?: Bytes32,
): ProofInputUtxo {
  return ProofInputUtxo.fromKeypair(
    new Utxo({
      owner: owner.signingPublicKey(),
      asset: SOL_MINT,
      amount,
      blinding: field(Number(amount)),
      ringProgramId,
      data,
    }),
    owner,
    ringDataHash === undefined ? {} : { ringDataHash },
    7,
  );
}
function merge(
  inputs: readonly ProofInputUtxo[],
  outputTreeId = 7,
  outputDataHash?: Bytes32,
): Merge {
  const first = inputs[0];
  if (first === undefined) throw new Error("empty fixture");
  const key = owner.nullifierKey();
  try {
    return new Merge({
      address: owner.shieldedAddress(),
      inputs,
      outputTreeId,
      ring: { programId: RING, ...(outputDataHash === undefined ? {} : { outputDataHash }) },
      outputBlinding: mergeOutputBlinding(key, first.nullifier()),
      privateTxBlinding: mergePrivateTxBlinding(key, first.nullifier()),
      dummyNullifiers: PreparedMerge.dummySlots(inputs.length).map((slot) =>
        mergeDummyNullifier(key, first.nullifier(), slot),
      ),
      outputKey: mergeOutputKey(key, first.nullifier()),
    });
  } finally {
    key.destroy();
  }
}
function nonInclusion(leaf: Bytes32): NonInclusionProof {
  return {
    leaf,
    merkleContext: { tree: treeAddress(7), treeType: 1 },
    path: Array.from({ length: 40 }, () => field(0)),
    lowElement: field(0),
    lowElementIndex: 0n,
    highElement: field(255),
    highElementIndex: 1n,
    root: field(2),
    rootSeq: 1n,
    rootIndex: 0,
  };
}
function spendProof(spend: ProofInputUtxo): SpendProof {
  return {
    state: {
      leaf: spend.hash(),
      merkleContext: { tree: treeAddress(7), treeType: 0 },
      path: Array.from({ length: 32 }, () => field(0)),
      leafIndex: 0n,
      root: field(1),
      rootSeq: 1n,
      rootIndex: 0,
    },
    nullifier: nonInclusion(spend.nullifier()),
  };
}

function ringWallet(amounts: readonly bigint[], hashes: readonly Bytes32[] = []): Wallet {
  const wallet = new Wallet({ identity: owner.shieldedAddress(), registry: new AssetRegistry() });
  wallet._replace({
    utxos: amounts.map((amount, index) => {
      const proof = input(amount, RING, new Data(), hashes[index]);
      return {
        utxo: proof.utxo,
        outputContext: {
          hash: proof.hash(),
          tree: treeAddress(7),
          treeId: 7,
          leafIndex: BigInt(index),
        },
        nullifier: proof.nullifier(),
        ...(proof.ringDataHash === undefined ? {} : { ringDataHash: proof.ringDataHash }),
        spent: false,
      };
    }),
    transactions: [],
    nullifiers: new Set(),
  });
  return wallet;
}
function provenMerge(
  prepared: PreparedMerge,
  registry: RingMergeRegistryProof = mergeRegistryProof,
  b: Bytes128 = new Uint8Array(128) as Bytes128,
): MergeTransactInstructionData {
  return prepareMerge(prepared, treeAddress(7), undefined, registry)
    .finish({
      slot: { id: 7, utxoRoot: field(1), nullifierRoot: field(2) },
      utxoRootIndex: 0,
      nullifierRootIndex: 0,
    })
    .instructionData({ a: field(0), b, c: field(0) });
}
/** Rust `CustomRingMergeIxData::serialize`, the SPP body with `proof.b` compressed. */
function compactBody(data: MergeTransactInstructionData): Uint8Array {
  const body = encodeMergeTransactInstructionData(data);
  return Uint8Array.from([
    ...body.subarray(0, 40),
    ...compressG2(body.slice(40, 168) as Bytes128),
    ...body.subarray(168),
  ]);
}
/** A G2 point off the zero placeholder, its compression keeps a sign flag. */
function g2Point(): Bytes128 {
  const point = bn254.G2.Point.BASE.multiply(5n).toAffine();
  return Uint8Array.from(
    [point.x.c1, point.x.c0, point.y.c1, point.y.c0].flatMap((value) => [
      ...bigintToBytes(value, "g2"),
    ]),
  ) as Bytes128;
}
function zeroRingProof() {
  const zero = (length: number) => new Uint8Array(length);
  return {
    a: zero(64) as Bytes64,
    b: zero(128) as Bytes128,
    c: zero(64) as Bytes64,
    commitment: zero(64) as Bytes64,
    commitmentPok: zero(64) as Bytes64,
  };
}
function proofService(proveRing: ProofService["proveRing"] = vi.fn()): ProofService {
  return { prove: vi.fn(), proveMerge: vi.fn(), proveRing };
}

/** A key holder reached only through `WalletKeys`, its secrets never cross the boundary. */
function remote(keys: LocalKeys): WalletKeys {
  return {
    address: () => keys.address(),
    viewingPublicKeys: () => keys.viewingPublicKeys(),
    decrypt: (requests) => keys.decrypt(requests),
    derive: (requests) => keys.derive(requests),
    transactionKeys: (requests) => keys.transactionKeys(requests),
    prove: (inputs, context) => keys.prove(inputs, context),
    proveMerge: (inputs, context) => keys.proveMerge(inputs, context),
    proveRingWithSecret: (request, context) => keys.proveRingWithSecret(request, context),
  };
}

async function ringMergeParams({
  proveMerge,
  wallet,
  keys,
  proofDataSource,
  anonymous = false,
  escrow = anonymous ? "none" : "own",
  coSigner,
}: Readonly<{
  proveMerge: MergeAssembler["proveMerge"];
  wallet: Wallet;
  keys: WalletKeys;
  proofDataSource: "client" | "prover";
  anonymous?: boolean;
  escrow?: "own" | "foreign" | "none";
  coSigner?: RingCoSigner;
}>) {
  const tree = recordTree([ownerRecord(escrow)]);
  const [config, configBump] = await ringConfigPda(RING);
  const [registry, registryBump] = await ringMemberRegistryPda(RING);
  return {
    client: {
      proofDataSource,
      tree: treeAddress(7),
      treeId: 7,
      getAccount: async (account: Address) => {
        if (account === config)
          return ownedAccount(
            RING,
            ringProgramConfigData({
              authority: RING,
              auditorPublicKey: mergeAuditor.publicKey().toBytes(),
              bump: configBump,
              hasPolicy: false,
              mode: anonymous ? "anonymous" : "registry",
              ...(coSigner === undefined ? {} : { coSigner }),
            }),
          );
        if (account === registry)
          return ownedAccount(
            RING,
            memberRegistryData({
              bump: registryBump,
              history: Array.from({ length: ROOT_SLOT + 1 }, (_, slot) =>
                slot === ROOT_SLOT ? { root: tree.root, applied: 4n, slot: 9n } : undefined,
              ),
              historyCursor: ROOT_SLOT,
              nextIndex: tree.nextIndex,
            }),
          );
        return undefined;
      },
      getRingMemberRecord: async (
        request: RingMemberProofRequest,
      ): Promise<RingMemberRecordResult> => ({
        context: { slot: 1n, blockTime: 1n },
        root: { root: tree.root, rootIndex: ROOT_SLOT, applied: 4n, nextIndex: tree.nextIndex },
        opening: tree.opening(request.member),
      }),
      getLatestBlockhash: async () => BLOCKHASH,
      proveMerge,
      proveRing: vi.fn<(request: RingProofRequest) => Promise<Uint8Array>>(),
    },
    ringProgramId: RING,
    wallet,
    keys,
    feePayer: anonymous ? RELAYER : owner.shieldedAddress().solanaAddress(),
  };
}

function ringCall(transaction: Transaction) {
  const compiled = getCompiledTransactionMessageDecoder().decode(transaction.messageBytes);
  if (compiled.version !== 1) throw new Error("expected V1");
  const instruction = decompileTransactionMessage(compiled, {
    lastValidBlockHeight: 1n,
  }).instructions.find((candidate) => candidate.programAddress === RING);
  if (instruction?.data === undefined) throw new Error("no ring instruction");
  return instruction;
}

function ringInstruction(transaction: Transaction): Uint8Array {
  return Uint8Array.from(ringCall(transaction).data ?? []);
}

function ringAccounts(transaction: Transaction): readonly Address[] {
  return (ringCall(transaction).accounts ?? []).map((account) => account.address);
}

describe("ring merge", () => {
  it.each([false, true])(
    "forwards the inherited ring hash and refuses mixed commitments (mixed=%s)",
    async (mixed) => {
      const wallet = ringWallet([3n, 5n], [field(7), field(mixed ? 8 : 7)]);
      const proveMerge = vi.fn<MergeAssembler["proveMerge"]>(async ({ prepared }) => {
        expect(prepared.output.ringDataHash).toEqual(field(7));
        const data = provenMerge(prepared);
        return { data, outputHash: data.outputUtxoHash };
      });
      const keys = LocalKeys.fromKeypair(owner, proofService());
      const derive = vi.spyOn(keys, "derive");
      try {
        const build = async () =>
          buildRingMergeTransaction(
            await ringMergeParams({ proveMerge, wallet, keys, proofDataSource: "client" }),
          );
        if (mixed) {
          await expect(build()).rejects.toMatchObject({
            code: "RING_BUILD_MERGE",
            causeCode: "TRANSACTION_MERGE_RING_DATA_MISMATCH",
          });
          expect(proveMerge).not.toHaveBeenCalled();
          expect(derive).not.toHaveBeenCalled();
          expect(wallet._reservationEntries()).toHaveLength(0);
        } else {
          const data = ringInstruction(await build());
          expect(data[0]).toBe(InstructionTag.ringMergeTransact);
          expect(data[1]).toBe(ROOT_SLOT);
          expect(data.slice(2, 34)).toEqual(field(7));
          expect(proveMerge).toHaveBeenCalledOnce();
          expect(proveMerge.mock.calls[0]?.[0].ringRegistry).toEqual(mergeRegistryProof);
        }
      } finally {
        keys.destroy();
      }
    },
  );

  it("refuses an owner whose record escrows another key before any proof", async () => {
    const wallet = ringWallet([3n, 5n]);
    const proveMerge = vi.fn<MergeAssembler["proveMerge"]>();
    const keys = LocalKeys.fromKeypair(owner, proofService());
    try {
      await expect(
        buildRingMergeTransaction(
          await ringMergeParams({
            proveMerge,
            wallet,
            keys,
            proofDataSource: "client",
            escrow: "foreign",
          }),
        ),
      ).rejects.toMatchObject({
        code: "RING_BUILD_MERGE",
        causeCode: "RING_UNREGISTERED_OUTPUT_KEY",
      });
      expect(proveMerge).not.toHaveBeenCalled();
      expect(wallet._reservationEntries()).toHaveLength(0);
    } finally {
      keys.destroy();
    }
  });

  it.each(["input", "output", "public"] as const)(
    "rejects changed %s ring data in structural merge requests before proving",
    async (changed) => {
      const inputs = [input(3n, RING, new Data(), field(7)), input(5n, RING, new Data(), field(7))];
      const prepared = merge(inputs).prepare();
      const indexed = prepareMerge(prepared, treeAddress(7), undefined, mergeRegistryProof).inputs;
      const complete = assembleMergeWithProofs(
        prepared,
        inputs.map(spendProof),
        treeAddress(7),
        prepared.dummyNullifiers().map(nonInclusion),
        undefined,
        mergeRegistryProof,
      );
      const alter = <T extends typeof indexed.payload>(payload: T): T => ({
        ...payload,
        ...(changed === "input"
          ? {
              inputs: payload.inputs.map((slot, index) =>
                index === 1
                  ? { ...slot, circuit: { ...slot.circuit, ringDataHash: asField(8n) } }
                  : slot,
              ),
            }
          : {}),
        ...(changed === "output"
          ? {
              output: {
                ...payload.output,
                circuit: { ...payload.output.circuit, ringDataHash: asField(8n) },
              },
            }
          : {}),
        ...(changed === "public" ? { outputRingDataHash: asField(8n) } : {}),
      });
      const fetch = vi.fn<typeof globalThis.fetch>(async () => {
        throw new Error("network reached");
      });
      const prover = new ProverClient({ tee: false, url: "https://prover.example", fetch });
      const authority = {
        prove: vi.fn(),
        proveMerge: vi.fn(),
        proveIndexed: vi.fn(),
        proveRingWithSecret: vi.fn(),
      };
      const refusal = {
        code: "CLIENT_TRANSACTION",
        details: { code: "TRANSACTION_MERGE_RING_DATA_MISMATCH" },
      };
      await expect(prover.proveMerge(alter(complete.proverInputs))).rejects.toMatchObject(refusal);
      await expect(
        proveThroughAuthority(authority, { ...indexed, payload: alter(indexed.payload) }),
      ).rejects.toMatchObject(refusal);
      expect(fetch).not.toHaveBeenCalled();
      expect(authority.proveIndexed).not.toHaveBeenCalled();
    },
  );

  it("inherits the common committed ring data hash and rejects changed input or output hashes", async () => {
    const hash = field(7);
    const inputs = [input(3n, RING, new Data(), hash), input(5n, RING, new Data(), hash)];
    const prepared = merge(inputs).prepare();
    expect(prepared.output.ringDataHash).toEqual(hash);
    expect(
      prepareMerge(prepared, treeAddress(7), undefined, mergeRegistryProof).inputs.payload
        .outputRingDataHash,
    ).toBe(7n);
    expect(() => merge(inputs, 7, field(8))).toThrow(
      expect.objectContaining({ code: "TRANSACTION_MERGE_RING_DATA_MISMATCH" }),
    );
    expect(() => merge([inputs[0]!, input(5n)])).toThrow(
      expect.objectContaining({ code: "TRANSACTION_MERGE_RING_DATA_MISMATCH" }),
    );
    expect(() => merge([inputs[0]!, input(5n, RING, new Data(), field(8))])).toThrow(
      expect.objectContaining({ code: "TRANSACTION_MERGE_RING_DATA_MISMATCH" }),
    );
    // Public byte buffers can change after construction, so the client rechecks them.
    inputs[1]?.ringDataHash?.set(field(9));
    const fetch = vi.fn<typeof globalThis.fetch>(async () => {
      throw new Error("network reached");
    });
    const keys = LocalKeys.fromKeypair(owner, proofService());
    try {
      for (const proofDataSource of ["client", "prover"] as const) {
        const client = new ZolanaClient({ treeId: 7, proofDataSource, fetch });
        await expect(
          client.proveMerge({ prepared, keys, ringRegistry: mergeRegistryProof }),
        ).rejects.toMatchObject({
          code: "CLIENT_TRANSACTION",
          details: { code: "TRANSACTION_MERGE_RING_DATA_MISMATCH" },
        });
      }
      expect(fetch).not.toHaveBeenCalled();
    } finally {
      keys.destroy();
    }
  });

  it.each(["client", "prover"] as const)(
    "keeps ring merge proofs complete with %s fetching",
    async (proofDataSource) => {
      const inputs = [input(3n), input(5n)];
      const prepared = merge(inputs, 9).prepare();
      const expected = assembleMergeWithProofs(
        prepared,
        inputs.map(spendProof),
        treeAddress(7),
        prepared.dummyNullifiers().map(nonInclusion),
        undefined,
        mergeRegistryProof,
      );
      const fetch = vi.fn<typeof globalThis.fetch>(async () =>
        Response.json({
          ...proofFor({ circuitType: "merge-ring", inputs: Array(prepared.inputs.length) }),
          resolution: {
            publicInputHash: `0x${expected.proverInputs.publicInputHash.toString(16)}`,
            trees: [
              {
                tree: treeAddress(7),
                id: 7,
                utxoRoot: "0x1",
                nullifierRoot: "0x2",
                utxoRootIndex: 0,
                nullifierRootIndex: 0,
              },
            ],
          },
        }),
      );
      const client = new ZolanaClient({ treeId: 7, proofDataSource, fetch });
      const state = vi
        .spyOn(client, "getInputMerkleProofs")
        .mockResolvedValue(inputs.map(spendProof));
      const nullifier = vi.spyOn(client, "getNonInclusionProofs").mockResolvedValue({
        context: { blockTime: 1n, slot: 1n },
        proofs: prepared.dummyNullifiers().map(nonInclusion),
      });
      const keys = LocalKeys.fromKeypair(owner, client.proofService);
      const indexed = vi.spyOn(keys, "proveIndexed");
      try {
        const result = await client.proveMerge({
          prepared,
          keys,
          ringRegistry: mergeRegistryProof,
        });
        expect(result.outputHash).toEqual(prepared.output.hash(9));
        expect(state).toHaveBeenCalledTimes(proofDataSource === "client" ? 1 : 0);
        expect(nullifier).toHaveBeenCalledTimes(proofDataSource === "client" ? 1 : 0);
        expect(indexed).toHaveBeenCalledTimes(proofDataSource === "prover" ? 1 : 0);
        expect(fetch).toHaveBeenCalledOnce();
        const body = JSON.parse(String(fetch.mock.calls[0]?.[1]?.body));
        expect(proofDataSource === "prover" ? body.prepared : body).toMatchObject({
          circuitType: "merge-ring",
          memberRegistryRoot: `0x${BigInt(`0x${Buffer.from(mergeRegistryProof.root).toString("hex")}`).toString(16)}`,
        });
        if (proofDataSource === "prover") expect(body.prepared).not.toHaveProperty("treeSlots");
        else expect(body).toHaveProperty("treeSlots");
      } finally {
        keys.destroy();
      }
    },
  );

  it.each(["spend", "dummy"] as const)(
    "refuses a %s proof from another tree on the client source",
    async (kind) => {
      const inputs = [input(3n), input(5n)];
      const prepared = merge(inputs, 9).prepare();
      const foreign = { tree: treeAddress(8), treeType: 0 };
      const client = new ZolanaClient({ treeId: 7, proofDataSource: "client", fetch: vi.fn() });
      vi.spyOn(client, "getInputMerkleProofs").mockResolvedValue(
        inputs.map(spendProof).map((proof, index) =>
          kind === "spend" && index === 1
            ? {
                state: { ...proof.state, merkleContext: foreign },
                nullifier: { ...proof.nullifier, merkleContext: foreign },
              }
            : proof,
        ),
      );
      vi.spyOn(client, "getNonInclusionProofs").mockResolvedValue({
        context: { blockTime: 1n, slot: 1n },
        proofs: prepared
          .dummyNullifiers()
          .map(nonInclusion)
          .map((proof, index) =>
            kind === "dummy" && index === 0 ? { ...proof, merkleContext: foreign } : proof,
          ),
      });
      const keys = LocalKeys.fromKeypair(owner, client.proofService);
      try {
        await expect(
          client.proveMerge({ prepared, keys, ringRegistry: mergeRegistryProof }),
        ).rejects.toMatchObject({
          code: "CLIENT_MERGE_TREE_MISMATCH",
          details: { proofTree: treeAddress(8), submitTree: treeAddress(7) },
        });
      } finally {
        keys.destroy();
      }
    },
  );

  it("refuses a forged output and retries a lagging prover indexer", async () => {
    const wallet = ringWallet([3n, 5n]);
    const answers: ("forged" | "lagging" | "proof")[] = ["forged", "lagging", "proof"];
    const proveMerge = vi.fn<MergeAssembler["proveMerge"]>(async ({ prepared }) => {
      const answer = answers.shift();
      if (answer === "lagging") throw new ClientError("CLIENT_INDEXER_PROOF_DATA_NOT_READY");
      const data = provenMerge(prepared);
      return {
        data: answer === "forged" ? { ...data, outputUtxoHash: field(9) } : data,
        outputHash: data.outputUtxoHash,
      };
    });
    const keys = LocalKeys.fromKeypair(owner, proofService());
    const build = async (proofDataSource: "client" | "prover") =>
      buildRingMergeTransaction(
        await ringMergeParams({ proveMerge, wallet, keys, proofDataSource }),
      );
    try {
      await expect(build("client")).rejects.toMatchObject({
        code: "RING_BUILD_MERGE",
        causeCode: "RING_INTENT_MISMATCH",
      });
      await expect(build("prover")).resolves.toBeDefined();
      expect(proveMerge).toHaveBeenCalledTimes(3);
    } finally {
      keys.destroy();
    }
  });

  it("caps custom merges at 50 before any read", async () => {
    const wallet = ringWallet(Array.from({ length: 51 }, (_, index) => BigInt(index + 1)));
    const proveMerge = vi.fn<MergeAssembler["proveMerge"]>(async ({ prepared }) => {
      const data = provenMerge(prepared);
      return { data, outputHash: data.outputUtxoHash };
    });
    const keys = LocalKeys.fromKeypair(owner, proofService());
    const derive = vi.spyOn(keys, "derive");
    const params = await ringMergeParams({ proveMerge, wallet, keys, proofDataSource: "client" });
    const getAccount = vi.fn(params.client.getAccount);
    const build = (maxInputs: number) =>
      buildRingMergeTransaction({ ...params, client: { ...params.client, getAccount }, maxInputs });
    try {
      expect(MAX_RING_MERGE_INPUTS).toBe(50);
      for (const [maxInputs, causeCode] of [
        [51, "RING_TOO_MANY_INPUTS"],
        [1, "RING_NOTHING_TO_MERGE"],
        [2.5, "RING_NOTHING_TO_MERGE"],
        [Number.NaN, "RING_NOTHING_TO_MERGE"],
      ] as const) {
        await expect(build(maxInputs)).rejects.toMatchObject({
          code: "RING_BUILD_MERGE",
          causeCode,
        });
      }
      expect(proveMerge).not.toHaveBeenCalled();
      expect(derive).not.toHaveBeenCalled();
      expect(getAccount).not.toHaveBeenCalled();
      expect(wallet._reservationEntries()).toHaveLength(0);
      const transaction = await build(50);
      expect(getTransactionSize(transaction)).toBeLessThanOrEqual(4096);
      const prepared = proveMerge.mock.calls[0]?.[0].prepared;
      expect(prepared?.inputs).toHaveLength(52);
      expect(prepared?.inputs.filter((spend) => !spend.isDummy())).toHaveLength(50);
    } finally {
      keys.destroy();
    }
  });

  it("demands the transfer co-signer and sizes the transaction with it before proving", async () => {
    const wallet = ringWallet(Array.from({ length: 50 }, (_, index) => BigInt(index + 1)));
    const proveMerge = vi.fn<MergeAssembler["proveMerge"]>(async ({ prepared }) => {
      const data = provenMerge(prepared);
      return { data, outputHash: data.outputUtxoHash };
    });
    const keys = LocalKeys.fromKeypair(owner, proofService());
    const cosigner = treeAddress(19);
    const params = await ringMergeParams({
      proveMerge,
      wallet,
      keys,
      proofDataSource: "client",
      coSigner: { signer: cosigner, scope: RING_COSIGN_TRANSFERS, thresholds: [] },
    });
    const approve = vi.fn(approveUnattended);
    try {
      await expect(buildRingMergeTransaction({ ...params, maxInputs: 2 })).rejects.toMatchObject({
        code: "RING_BUILD_MERGE",
        causeCode: "RING_COSIGNER_REQUIRED",
      });
      const transaction = await buildRingMergeTransaction({
        ...params,
        maxInputs: 50,
        cosigner,
        approve,
      });
      expect(getTransactionSize(transaction)).toBeLessThanOrEqual(4096);
      expect(proveMerge).toHaveBeenCalledOnce();
      expect(approve).toHaveBeenCalledOnce();
      expect(wallet._reservationEntries()).toHaveLength(1);
    } finally {
      keys.destroy();
    }
  });

  it.each([
    [2, 8],
    [8, 8],
    [9, 24],
    [24, 24],
    [25, 52],
    [52, 52],
  ])("preserves owner, asset, value and ring for %s fragmented inputs", (count, width) => {
    const inputs = Array.from({ length: count }, (_, index) => input(BigInt(index + 1)));
    const prepared = merge(inputs).prepare();
    expect(prepared.inputs).toHaveLength(width);
    expect(prepared.inputs.map((spend) => spend.isCompact())).toEqual(
      Array.from({ length: width }, (_, index) => index >= count),
    );
    expect(provenMerge(prepared).nullifiers).toHaveLength(count);
    expect(prepared.output.amount).toBe(BigInt((count * (count + 1)) / 2));
    expect(prepared.output.asset).toBe(SOL_MINT);
    expect(prepared.output.ringProgramId).toBe(RING);
    expect(prepared.output.ownerAddress?.toBytes()).toEqual(owner.shieldedAddress().toBytes());
    expect(prepared.outputTreeId).toBe(7);
  });

  it.each([2, 25, 52])("zeroes padding in the private tx hash of a %i-input merge", (count) => {
    const inputs = Array.from({ length: count }, (_, index) => input(BigInt(index + 1)));
    const prepared = merge(inputs).prepare();
    const assembly = assembleMergeWithProofs(
      prepared,
      inputs.map(spendProof),
      treeAddress(7),
      prepared.dummyNullifiers().map(nonInclusion),
      undefined,
      mergeRegistryProof,
    );
    expect(assembly.privateTxHash).toEqual(
      privateTxHash({
        inputHashes: prepared.inputs.map((spend) =>
          spend.isDummy() ? (new Uint8Array(32) as Bytes32) : spend.hash(),
        ),
        outputHashes: [assembly.outputHash],
        blinding: prepared.privateTxBlinding(),
      }),
    );
  });

  it("binds a separate output tree and sends the registered record in the proof request", () => {
    const inputs = [input(3n), input(5n)];
    const prepared = merge(inputs, 9).prepare();
    const assembly = assembleMergeWithProofs(
      prepared,
      inputs.map(spendProof),
      treeAddress(7),
      prepared.dummyNullifiers().map(nonInclusion),
      undefined,
      mergeRegistryProof,
    );
    expect(mergeProverRequestBody(assembly.proverInputs)).toMatchObject({
      circuitType: "merge-ring",
      memberRecord: { index: 1, path: expect.any(Array) },
      registeredCiphertextHash: `0x${BigInt(`0x${Buffer.from(hashBytes(SEALED_CIPHERTEXT)).toString("hex")}`).toString(16)}`,
    });
    expect(assembly.proverInputs.memberRegistryRoot).toBe(
      BigInt(`0x${Buffer.from(mergeRegistryProof.root).toString("hex")}`),
    );
    expect(assembly.proverInputs.ringProgramId).not.toBe(0n);
    expect(assembly.proverInputs.outputRingDataHash).toBe(0n);
    expect(assembly.outputHash).toEqual(prepared.output.hash(9));
    expect(assembly.outputHash).not.toEqual(prepared.output.hash(7));
  });

  it("refuses foreign rings, owner data, and more than 52 inputs", () => {
    expect(() => merge([input(3n), input(5n, treeAddress(1))])).toThrow(
      "TRANSACTION_MERGE_INPUT_RING_MISMATCH",
    );
    expect(() =>
      merge([input(3n, RING, new Data([{ kind: "utxoData", bytes: Uint8Array.of(1) }]))]),
    ).toThrow("TRANSACTION_MERGE_INPUT_HAS_DATA");
    expect(() =>
      merge(Array.from({ length: MAX_MERGE_INPUTS + 1 }, (_, index) => input(BigInt(index + 1)))),
    ).toThrow("TRANSACTION_TOO_MANY_INPUTS");
  });

  it("keeps the ordinary merge rail closed to ring notes", () => {
    expect(() => Merge.fromKeypair(owner, [input(3n)])).toThrow(
      "TRANSACTION_MERGE_INPUT_RING_MISMATCH",
    );
  });

  it("compresses proof b and places the registry and the co-signer ahead of SPP's accounts", async () => {
    const inputs = [input(3n), input(5n)];
    const data = provenMerge(merge(inputs).prepare(), mergeRegistryProof, g2Point());
    const cosigner = ShieldedKeypair.generate().shieldedAddress().solanaAddress();
    const instruction = await ringMergeInstruction({
      ringProgramId: RING,
      inputTree: treeAddress(7),
      outputTree: treeAddress(7),
      payer: owner.shieldedAddress().solanaAddress(),
      cosigner,
      outputRingDataHash: field(4),
      registryRootIndex: 11,
      data,
    });
    const bytes = instruction.data ?? new Uint8Array();
    expect(instruction.programAddress).toBe(RING);
    expect(bytes[0]).toBe(InstructionTag.ringMergeTransact);
    expect(bytes[1]).toBe(11);
    expect(bytes.slice(2, 34)).toEqual(field(4));
    expect(bytes[34]).toBe(0);
    const body = bytes.slice(35);
    expect(body).toEqual(compactBody(data));
    expect(body.length).toBe(encodeMergeTransactInstructionData(data).length - 64);
    expect(decompressG2(body.slice(40, 104) as Bytes64)).toEqual(data.proof.b);
    const [config] = await ringConfigPda(RING);
    const [registry] = await ringMemberRegistryPda(RING);
    expect(instruction.accounts?.slice(0, 3)).toEqual([
      { address: config, role: AccountRole.READONLY },
      { address: registry, role: AccountRole.READONLY },
      { address: cosigner, role: AccountRole.READONLY_SIGNER },
    ]);
    expect(instruction.accounts?.[5]).toEqual({
      address: await ringAuthAddress(RING),
      role: AccountRole.READONLY,
    });
    expect(instruction.accounts).toHaveLength(9 + inputs.length);
    const without = await ringMergeInstruction({
      ringProgramId: RING,
      inputTree: treeAddress(7),
      outputTree: treeAddress(7),
      payer: owner.shieldedAddress().solanaAddress(),
      outputRingDataHash: field(4),
      registryRootIndex: 11,
      data,
    });
    expect(without.accounts?.slice(2)).toEqual(instruction.accounts?.slice(3));
  });

  it("binds ring identity and destination into approval", () => {
    const intent = {
      kind: "ringMerge" as const,
      ringProgramId: RING,
      outputTree: treeAddress(7),
      asset: SOL_MINT,
      numInputs: 2,
      mergedAmount: 8n,
    };
    expect(intentHash(intent)).not.toEqual(
      intentHash({ ...intent, ringProgramId: treeAddress(1) }),
    );
    expect(intentHash(intent)).not.toEqual(intentHash({ ...intent, outputTree: treeAddress(9) }));
  });
});

describe("anonymous ring merge", () => {
  it("flags the SPP merge and drops the sealed key hash and the record from its request", () => {
    const inputs = [input(3n), input(5n)];
    const prepared = merge(inputs).prepare();
    const bodies = [mergeRegistryProof, anonymousProof].map((registry) => {
      const local = prepareMerge(prepared, treeAddress(7), undefined, registry);
      const decoded = decodeIndexedInputs(local.inputs).payload;
      if (registry === anonymousProof) {
        expect(decoded).toMatchObject({ anonymous: true, memberRegistryRoot: 0n });
        expect(decoded).not.toHaveProperty("memberRecord");
        expect(() =>
          decodeIndexedInputs({
            ...local.inputs,
            payload: { ...local.inputs.payload, memberRecord: mergeRegistryProof.record },
          }),
        ).toThrow();
      } else expect(decoded).toHaveProperty("memberRecord");
      return {
        flag: local.inputs.publicInputs[9],
        body: mergeProverRequestBody(
          assembleMergeWithProofs(
            prepared,
            inputs.map(spendProof),
            treeAddress(7),
            prepared.dummyNullifiers().map(nonInclusion),
            undefined,
            registry,
          ).proverInputs,
        ),
      };
    });
    const [ordinary, anonymous] = bodies;
    expect(ordinary?.flag).toBe(0n);
    expect(ordinary?.body).toHaveProperty("registeredCiphertextHash");
    expect(ordinary?.body).not.toHaveProperty("anonymous");
    expect(anonymous?.flag).toBe(1n);
    expect(anonymous?.body).not.toHaveProperty("registeredCiphertextHash");
    expect(anonymous?.body).not.toHaveProperty("memberRecord");
    expect(anonymous?.body).toMatchObject({
      circuitType: "merge-ring",
      anonymous: true,
      memberRegistryRoot: "0x0",
    });
  });

  it("proves the disclosure at a remote key holder and ships it in the instruction", async () => {
    const wallet = ringWallet([3n, 5n]);
    const proveMerge = vi.fn<MergeAssembler["proveMerge"]>(async ({ prepared, ringRegistry }) => {
      const data = provenMerge(prepared, ringRegistry);
      return { data, outputHash: data.outputUtxoHash };
    });
    const held: RingProofRequest[] = [];
    const local = LocalKeys.fromKeypair(
      owner,
      proofService(async (request) => {
        held.push(request);
        return zeroRingProof();
      }),
    );
    const keys = remote(local);
    const asked: SecretRingProofRequest[] = [];
    const proveRingWithSecret = keys.proveRingWithSecret;
    keys.proveRingWithSecret = async (request, context) => {
      asked.push(request);
      return proveRingWithSecret(request, context);
    };
    try {
      const transaction = await buildRingMergeTransaction(
        await ringMergeParams({
          proveMerge,
          wallet,
          keys,
          proofDataSource: "client",
          anonymous: true,
        }),
      );
      expect(proveMerge.mock.calls[0]?.[0].ringRegistry).toEqual(anonymousProof);
      const [request] = asked;
      if (request?.kind !== "anonymousMerge") throw new Error("no disclosure request");
      expect(request).not.toHaveProperty("nullifierSecret");
      // The sealing secrets are wiped once the proof is back.
      expect(request.ephSk.every((byte) => byte === 0)).toBe(true);
      expect(request.disclosureKey.every((byte) => byte === 0)).toBe(true);
      expect(held[0]).toHaveProperty("nullifierSecret");
      expect(request).toMatchObject({
        ringProgramId: hashBytes(addressBytes(RING)),
        ownerKey: owner.signingPublicKey().ed25519(),
      });
      expect(request).not.toHaveProperty("memberRegistryRoot");
      expect(request).not.toHaveProperty("memberRecord");
      expect(request.inputs).toHaveLength(8);

      const data = ringInstruction(transaction);
      expect(data[0]).toBe(InstructionTag.ringMergeTransact);
      expect(data[1]).toBe(0);
      const [config] = await ringConfigPda(RING);
      expect(ringAccounts(transaction).slice(0, 2)).toEqual([config, treeAddress(7)]);
      const disclosure = readRingMergeDisclosure(new Reader(data.slice(34)));
      if (disclosure === undefined) throw new Error("no disclosure");
      expect(disclosure.proof).toEqual(new Uint8Array(192));
      expect(disclosure.fields).toHaveLength(mergeDisclosureFieldCount(8));
      const prepared = proveMerge.mock.calls[0]?.[0].prepared;
      if (prepared === undefined) throw new Error("no merge");
      const spp = provenMerge(prepared, anonymousProof);
      expect(data.slice(34 + 1 + 192 + 33 + 32 + 1 + 32 * 13)).toEqual(compactBody(spp));
      expect(
        ringMergeAnonymousPublicInputHash({
          privateTxHash: spp.privateTxHash,
          outputUtxoHash: spp.outputUtxoHash,
          firstNullifier: spp.nullifiers[0]!,
          ringId: hashBytes(addressBytes(RING)) as Bytes32,
          auditorPublicKey: mergeAuditor.publicKey(),
          disclosure,
          salt: prepared.outputCiphertextSalt(),
        }),
      ).toEqual(request.publicInputHash);
      const opened = openRingMergeDisclosure(
        mergeAuditor,
        disclosure,
        prepared.outputCiphertextSalt(),
      );
      expect(opened.amount).toBe(8n);
      expect(opened.mint).toBe(SOL_MINT);
      expect(opened.nullifierPublicKey).toEqual(owner.nullifierPublicKey());
      expect(opened.inputCommitments.slice(0, 2)).toEqual(
        prepared.inputs.slice(0, 2).map((spend) => spend.hash()),
      );
    } finally {
      local.destroy();
    }
  });

  it("keeps the escrow path and no disclosure on an ordinary ring", async () => {
    const wallet = ringWallet([3n, 5n]);
    const proveMerge = vi.fn<MergeAssembler["proveMerge"]>(async ({ prepared, ringRegistry }) => {
      const data = provenMerge(prepared, ringRegistry);
      return { data, outputHash: data.outputUtxoHash };
    });
    const local = LocalKeys.fromKeypair(owner, proofService());
    const proveRingWithSecret = vi.spyOn(local, "proveRingWithSecret");
    try {
      const transaction = await buildRingMergeTransaction(
        await ringMergeParams({ proveMerge, wallet, keys: local, proofDataSource: "client" }),
      );
      expect(proveMerge.mock.calls[0]?.[0].ringRegistry).toEqual(mergeRegistryProof);
      expect(proveRingWithSecret).not.toHaveBeenCalled();
      expect(ringInstruction(transaction)[34]).toBe(0);
    } finally {
      local.destroy();
    }
  });

  it("refuses a merge the hidden owner pays or co-signs before any proof", async () => {
    const wallet = ringWallet([3n, 5n]);
    const proveMerge = vi.fn<MergeAssembler["proveMerge"]>();
    const local = LocalKeys.fromKeypair(owner, proofService());
    const hidden = owner.shieldedAddress().solanaAddress();
    try {
      for (const coSigned of [false, true]) {
        const params = await ringMergeParams({
          proveMerge,
          wallet,
          keys: local,
          proofDataSource: "client",
          anonymous: true,
          ...(coSigned
            ? { coSigner: { signer: hidden, scope: RING_COSIGN_TRANSFERS, thresholds: [] } }
            : {}),
        });
        await expect(
          buildRingMergeTransaction({
            ...params,
            ...(coSigned ? { cosigner: hidden } : { feePayer: hidden }),
          }),
        ).rejects.toMatchObject({
          code: "RING_BUILD_MERGE",
          causeCode: "RING_ANONYMOUS_SIGNER_LINKS_OWNER",
        });
      }
      expect(proveMerge).not.toHaveBeenCalled();
      expect(wallet._reservationEntries()).toHaveLength(0);
    } finally {
      local.destroy();
    }
  });

  it("refuses a 52-slot anonymous merge before any read or proof", async () => {
    const wallet = ringWallet(Array.from({ length: 25 }, (_, index) => BigInt(index + 1)));
    const proveMerge = vi.fn<MergeAssembler["proveMerge"]>();
    const local = LocalKeys.fromKeypair(owner, proofService());
    const derive = vi.spyOn(local, "derive");
    const proveRingWithSecret = vi.spyOn(local, "proveRingWithSecret");
    try {
      const params = await ringMergeParams({
        proveMerge,
        wallet,
        keys: local,
        proofDataSource: "client",
        anonymous: true,
      });
      const getRingMemberRecord = vi.fn(params.client.getRingMemberRecord);
      await expect(
        buildRingMergeTransaction({
          ...params,
          client: { ...params.client, getRingMemberRecord },
          maxInputs: 50,
        }),
      ).rejects.toMatchObject({
        code: "RING_BUILD_MERGE",
        causeCode: "RING_ANONYMOUS_MERGE_TOO_WIDE",
      });
      expect(proveMerge).not.toHaveBeenCalled();
      expect(proveRingWithSecret).not.toHaveBeenCalled();
      expect(getRingMemberRecord).not.toHaveBeenCalled();
      expect(derive).not.toHaveBeenCalled();
      expect(wallet._reservationEntries()).toHaveLength(0);
    } finally {
      local.destroy();
    }
  });
});
