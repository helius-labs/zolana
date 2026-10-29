import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";

import { bytesToBigInt } from "../src/interface/bytes.js";

import { LocalKeys } from "../src/client/keys.js";
import { proverRequestBody } from "../src/client/index.js";
import { bigintToBytes, hashBytesBigInt } from "../src/client/internal.js";
import {
  assemble,
  eddsaPublicFields,
  ownerSignerAddresses,
  prepareTransfer,
  signTransactMessage,
  transactMessageDigest,
  transferPublicInputHash,
} from "../src/client/prover/assembly.js";
import { ProverClient } from "../src/client/prover/client.js";
import { decodeIndexedInputs } from "../src/client/prover/indexed.js";
import { compressProof, parseProof } from "../src/client/prover/proof.js";
import type { EddsaOwnerAuthorization, TransferInputs } from "../src/client/prover/types.js";
import type { NonInclusionProof, SpendProof } from "../src/client/rpc.js";
import { solanaOwnerIdentity } from "../src/hasher/index.js";
import { encodeTransactInstructionData } from "../src/interface/codecs/index.js";
import { NO_CACHE_WRITES } from "../src/interface/index.js";
import { treeAddress } from "../src/interface/pda/index.js";
import { InterfaceError } from "../src/interface/errors.js";
import {
  CONFIDENTIAL_EDDSA_SHAPES,
  isSppShape,
  isTransactShape,
  selectConfidentialEddsaShape,
} from "../src/interface/shape.js";
import { inputTreeSlots } from "../src/interface/tree-slot.js";
import type {
  Bytes16,
  Bytes32,
  Bytes33,
  Bytes64,
  Bytes128,
  CircuitId,
  TransactInstructionData,
} from "../src/interface/types.js";
import { ShieldedKeypair, ShieldedPublicKey, SigningKey } from "../src/keypair/index.js";
import {
  ProofInputUtxo,
  SOL_MINT,
  SppProofInputs,
  Utxo,
  createExternalData,
  createProofOutput,
  outputBlindingSeed,
  transactOutputBlinding,
} from "../src/transaction/index.js";
import { proofFor } from "./helpers/proofs.js";

const TREE_ID = 0;
const TREE = treeAddress(TREE_ID);
const ZERO_POINT = ["0x0", "0x0"];

function bytes(value: number, length = 32): Uint8Array {
  return new Uint8Array(length).fill(value);
}

function blindingSeed(value: number): Bytes32 {
  const seed = bytes(value) as Bytes32;
  seed[0] = 0;
  return seed;
}

function nonInclusionProof(leaf: Bytes32): NonInclusionProof {
  return {
    leaf,
    merkleContext: { treeType: 1, tree: TREE },
    path: Array.from({ length: 40 }, () => bytes(0) as Bytes32),
    lowElement: bytes(4) as Bytes32,
    lowElementIndex: 0n,
    highElement: bytes(5) as Bytes32,
    highElementIndex: 1n,
    root: bytes(6) as Bytes32,
    rootSeq: 1n,
    rootIndex: 2,
  };
}

function spendProof(input: ProofInputUtxo): SpendProof {
  return {
    state: {
      leaf: input.hash(),
      merkleContext: { treeType: 0, tree: TREE },
      path: Array.from({ length: 32 }, () => bytes(2) as Bytes32),
      leafIndex: 3n,
      root: bytes(3) as Bytes32,
      rootSeq: 1n,
      rootIndex: 4,
    },
    nullifier: nonInclusionProof(input.nullifier()),
  };
}

type Fixture = Readonly<{
  owner: ShieldedKeypair;
  proofInputs: SppProofInputs;
  real: readonly ProofInputUtxo[];
  dummies: readonly ProofInputUtxo[];
}>;

/** One owner spending `realInputs` notes, padded to `inputs` x `outputs`. */
function fixture(
  options: Readonly<{ inputs?: number; outputs?: number; realInputs?: number }> = {},
): Fixture {
  const owner = ShieldedKeypair.generate();
  const inputs = options.inputs ?? 2;
  const outputs = options.outputs ?? 8;
  const real = Array.from({ length: options.realInputs ?? 1 }, (_, index) =>
    ProofInputUtxo.fromKeypair(
      new Utxo({
        owner: owner.signingPublicKey(),
        asset: SOL_MINT,
        amount: 7n,
        blinding: bytes(1 + index) as Bytes32,
      }),
      owner,
    ),
  );
  const dummies = Array.from({ length: inputs - real.length }, (_, index) =>
    ProofInputUtxo.dummy(bytes(10 + index) as Bytes32),
  );
  const seed = blindingSeed(9);
  const firstNullifier = real[0]?.nullifier() ?? (bytes(0) as Bytes32);
  const outputSeed = outputBlindingSeed(firstNullifier, seed);
  const ownerTag = bytes(8) as Bytes32;
  const outputList = Array.from({ length: outputs }, (_, index) =>
    createProofOutput({
      ...(index === 0 ? { ownerAddress: owner.shieldedAddress() } : { ownerTag }),
      asset: SOL_MINT,
      amount: index === 0 ? 7n * BigInt(real.length) : 0n,
      blinding: transactOutputBlinding(firstNullifier, outputSeed, index),
    }),
  );
  const proofInputs = new SppProofInputs({
    payer: owner.shieldedAddress().solanaAddress(),
    inputUtxos: [...real, ...dummies],
    outputs: outputList,
    externalData: createExternalData({
      txViewingPublicKey: owner.viewingPublicKey(),
      salt: new Uint8Array(16) as Bytes16,
      outputs: outputList.map((entry) => ({
        utxoHash: entry.hash(TREE_ID),
        ownerTag: { kind: "inline", value: ownerTag },
      })),
      resolvedOwnerTags: outputList.map(() => ownerTag),
      messages: [],
    }),
    blindingSeed: seed,
    outputTreeId: TREE_ID,
  });
  return { owner, proofInputs, real, dummies };
}

function assembled(value: Fixture, authorization: EddsaOwnerAuthorization) {
  return assemble(
    value.proofInputs,
    value.real.map(spendProof),
    value.dummies.map((dummy) => nonInclusionProof(dummy.nullifier())),
    { kind: "confidentialEddsa", authorization },
  );
}

function recomputedPublicInputHash(
  payload: TransferInputs,
  afterPrivateTxHash: readonly bigint[],
): bigint {
  return transferPublicInputHash({
    nullifiers: payload.inputs.map((entry) => entry.nullifier),
    outputHashes: payload.outputs.map((entry) => entry.hash),
    treeSlots: inputTreeSlots([
      { id: TREE_ID, utxoRoot: bytes(3) as Bytes32, nullifierRoot: bytes(6) as Bytes32 },
    ]),
    outputTreeId: TREE_ID,
    privateTxHash: payload.privateTxHash,
    afterPrivateTxHash,
    externalDataHash: payload.externalDataHash,
    publicSlots: payload.publicAssets.flatMap((asset, index) => [
      asset,
      payload.publicAmounts[index] ?? 0n,
    ]),
    ringProgramId: payload.ringProgramId,
    signerPublicKeyHashes: payload.signerPublicKeyHashes,
    inputFlags: payload.inputFlags,
    publishedOutputOwnerPublicKeyHashes: payload.publishedOutputOwnerPublicKeyHashes,
    cacheTreeId: payload.cacheTreeId,
    cacheReadHashChain: payload.cacheReadHashChain,
    cacheReadHashes: payload.cacheReadHashes,
    cacheIsCached: payload.cacheIsCached,
    cacheReadIndex: payload.cacheReadIndex,
  });
}

function transactData(circuit: CircuitId): TransactInstructionData {
  return {
    expiryUnixTs: 77n,
    txViewingPk: bytes(3, 33) as Bytes33,
    salt: bytes(4, 16) as Bytes16,
    interfaceTransfers: [],
    outputs: Array.from({ length: circuit.outputs }, (_, index) => ({
      utxoHash: blindingSeed(0x50 + index),
      ownerTag: { kind: "inline", value: blindingSeed(0x60 + index) },
    })),
    messages: [],
    privateTxHash: blindingSeed(5),
    circuit,
    proof: {
      a: bytes(6) as Bytes32,
      b: bytes(7, 128) as Bytes128,
      c: bytes(8) as Bytes32,
    },
    inputs: Array.from({ length: circuit.inputs }, (_, index) => ({
      nullifierHash: blindingSeed(0x10 + index),
      treeIndex: 0,
    })),
    treeContexts: [{ utxoTreeRootIndex: 9, nullifierTreeRootIndex: 10 }],
  };
}

const PROOF_DATA = Object.freeze({
  bsb22Commitment: Object.freeze({
    commitment: bytes(0xa1) as Bytes32,
    commitmentPok: bytes(0xa2) as Bytes32,
  }),
  ownerPk: bytes(0xa3) as Bytes32,
});

describe("CONFIDENTIAL_EDDSA_SHAPES", () => {
  it("lists the Rust shapes in proving cost order", () => {
    expect(CONFIDENTIAL_EDDSA_SHAPES.map((shape) => [shape.inputs, shape.outputs])).toEqual([
      [2, 8],
      [2, 16],
      [4, 8],
      [4, 16],
      [8, 8],
      [8, 16],
      [16, 8],
      [16, 16],
      [24, 8],
      [24, 16],
      [48, 8],
      [48, 16],
    ]);
  });

  it("picks the cheapest shape of its own list, as Rust canonical_shape does", () => {
    expect(selectConfidentialEddsaShape(1, 2)).toEqual({ inputs: 2, outputs: 8 });
    expect(selectConfidentialEddsaShape(17, 9)).toEqual({ inputs: 24, outputs: 16 });
    expect(() => selectConfidentialEddsaShape(49, 2)).toThrow(
      expect.objectContaining({ code: "INTERFACE_INVALID_SHAPE" }),
    );
    expect(() => selectConfidentialEddsaShape(-1, 2)).toThrow(InterfaceError);
  });

  it("is a transact shape without being a signer-rail shape", () => {
    expect(isTransactShape({ inputs: 16, outputs: 16 })).toBe(true);
    expect(isSppShape({ inputs: 16, outputs: 16 })).toBe(false);
    expect(isSppShape({ inputs: 2, outputs: 8 })).toBe(true);
    expect(isTransactShape({ inputs: 3, outputs: 16 })).toBe(false);
  });
});

describe("confidentialEddsa selector encoding", () => {
  const shape = { inputs: 2, outputs: 8, publicAssetSlots: 3 };
  const header = Uint8Array.from([0, 0, 2, 8, 3]);

  function circuitOffset(data: Uint8Array, tag = 0): number {
    const expected = Uint8Array.from([tag, ...header.subarray(1)]);
    const positions = Array.from(
      { length: data.length - header.length },
      (_, index) => index,
    ).filter((index) => expected.every((byte, offset) => data[index + offset] === byte));
    expect(positions).toHaveLength(1);
    return positions[0] ?? -1;
  }

  it("writes tag 7, the shape, then the commitment pair and the owner key", () => {
    const signer = encodeTransactInstructionData(
      transactData({ kind: "confidentialSigner", ...shape }),
    );
    const eddsa = encodeTransactInstructionData(
      transactData({ kind: "confidentialEddsa", ...shape, proofData: PROOF_DATA }),
    );
    const at = circuitOffset(signer);
    expect(eddsa.length).toBe(signer.length + 96);
    expect(bytesToHex(eddsa)).toBe(
      bytesToHex(signer.subarray(0, at)) +
        "0700" +
        "020803" +
        "a1".repeat(32) +
        "a2".repeat(32) +
        "a3".repeat(32) +
        bytesToHex(signer.subarray(at + header.length)),
    );
  });

  it("writes tag 8 with the cache selection after the proof data", () => {
    const cacheAccess = { readBitmap: 1n << 20n, writeSlots: NO_CACHE_WRITES };
    const signer = encodeTransactInstructionData(
      transactData({ kind: "confidentialSignerCached", ...shape, cacheAccess }),
    );
    const eddsa = encodeTransactInstructionData(
      transactData({
        kind: "confidentialEddsaCached",
        ...shape,
        proofData: PROOF_DATA,
        cacheAccess,
      }),
    );
    const at = circuitOffset(signer, 4);
    expect(bytesToHex(eddsa)).toBe(
      bytesToHex(signer.subarray(0, at)) +
        "0800" +
        "020803" +
        "a1".repeat(32) +
        "a2".repeat(32) +
        "a3".repeat(32) +
        bytesToHex(signer.subarray(at + header.length)),
    );
    expect(bytesToHex(eddsa.subarray(at + 5 + 96, at + 5 + 96 + 8))).toBe("0000100000000000");
  });
});

describe("signTransactMessage", () => {
  it("signs sha256(privateTxHash || externalDataHash) with the owner's Ed25519 key", async () => {
    const value = fixture();
    const authorization = await signTransactMessage(value.proofInputs, value.owner);
    const { payload } = assembled(value, authorization).proverInputs;
    const digest = sha256(
      Uint8Array.from([
        ...bigintToBytes(payload.privateTxHash, "private tx hash"),
        ...bigintToBytes(payload.externalDataHash, "external data hash"),
      ]),
    );
    expect(authorization.messageDigest).toEqual(digest);
    expect(transactMessageDigest(value.proofInputs)).toEqual(digest);
    expect(authorization.ownerPublicKey).toEqual(value.owner.signingPublicKey().ed25519());
    expect(ed25519.verify(authorization.ownerSignature, digest, authorization.ownerPublicKey)).toBe(
      true,
    );
  });

  it("refuses a PDA owner, which cannot sign", async () => {
    const value = fixture();
    const pda = ShieldedPublicKey.fromPda(bytes(0x33) as Bytes32);
    await expect(
      signTransactMessage(value.proofInputs, {
        signingPublicKey: () => pda,
        sign: () => bytes(0, 64) as Bytes64,
      }),
    ).rejects.toMatchObject({ code: "CLIENT_KEYPAIR" });
  });

  it("takes an asynchronous signer", async () => {
    const value = fixture();
    const signer = {
      signingPublicKey: () => Promise.resolve(value.owner.signingPublicKey()),
      sign: (message: Uint8Array) => Promise.resolve(value.owner.sign(message)),
    };
    const authorization = await signTransactMessage(value.proofInputs, signer);
    expect(authorization).toEqual(await signTransactMessage(value.proofInputs, value.owner));
  });
});

describe("a transfer on the confidentialEddsa rail", () => {
  it("publishes the message hash and the owner, and drops the owner from the signer vector", async () => {
    const value = fixture();
    const authorization = await signTransactMessage(value.proofInputs, value.owner);
    const result = assembled(value, authorization);
    const { proverInputs } = result;
    if (proverInputs.circuit !== "transferConfidentialEddsa") throw new Error("wrong rail");
    const { payload } = proverInputs;

    expect(result.instructionData.circuit).toEqual({
      kind: "confidentialEddsa",
      inputs: 2,
      outputs: 8,
      publicAssetSlots: 3,
      proofData: {
        bsb22Commitment: { commitment: bytes(0), commitmentPok: bytes(0) },
        ownerPk: authorization.ownerPublicKey,
      },
    });
    expect(payload.ownerAuthorization).toEqual(authorization);
    // The owner is the only input owner, so the vector is all padding.
    expect(payload.signerPublicKeyHashes).toEqual([0n, 0n, 0n]);
    expect(payload.ringProgramId).toBe(0n);
    expect(payload.publishedOutputOwnerPublicKeyHashes).toHaveLength(8);
    const fields = eddsaPublicFields(authorization);
    expect(fields).toEqual([
      hashBytesBigInt(authorization.messageDigest),
      bytesToBigInt(solanaOwnerIdentity(authorization.ownerPublicKey)),
    ]);
    expect(payload.publicInputHash).toBe(recomputedPublicInputHash(payload, fields));
    expect(payload.publicInputHash).not.toBe(recomputedPublicInputHash(payload, []));
    expect(
      ownerSignerAddresses(
        value.proofInputs.inputUtxos,
        value.proofInputs.outputs,
        authorization.ownerPublicKey,
      ),
    ).toEqual([]);
    expect(ownerSignerAddresses(value.proofInputs.inputUtxos, value.proofInputs.outputs)).toEqual([
      value.owner.shieldedAddress().solanaAddress(),
    ]);
  });

  it("keeps every other owner in the signer vector", async () => {
    const value = fixture({ realInputs: 2 });
    const other = ShieldedKeypair.generate();
    const authorization = await signTransactMessage(value.proofInputs, other);
    const { payload } = assembled(value, authorization).proverInputs;
    expect(payload.signerPublicKeyHashes).toEqual([
      bytesToBigInt(solanaOwnerIdentity(value.owner.signingPublicKey().ed25519())),
      0n,
      0n,
    ]);
  });

  it("refuses an authorization over another statement", async () => {
    const value = fixture();
    const stale = await signTransactMessage(fixture().proofInputs, value.owner);
    expect(() => assembled(value, stale)).toThrow(
      expect.objectContaining({ code: "CLIENT_INVALID_PROOF_INPUTS" }),
    );
  });

  it("refuses invalid owner signatures before assembling a proof request", async () => {
    const value = fixture();
    const authorization = await signTransactMessage(value.proofInputs, value.owner);
    expect(() =>
      assembled(value, { ...authorization, ownerSignature: bytes(0, 64) as Bytes64 }),
    ).toThrow(expect.objectContaining({ code: "CLIENT_INVALID_PROOF_INPUTS" }));
    await expect(
      signTransactMessage(value.proofInputs, {
        signingPublicKey: () => value.owner.signingPublicKey(),
        sign: () => bytes(0, 64) as Bytes64,
      }),
    ).rejects.toMatchObject({ code: "CLIENT_INVALID_PROOF_INPUTS" });
  });

  it("proves only on a shape the rail has keys for", async () => {
    const narrow = fixture({ inputs: 2, outputs: 2 });
    const authorization = await signTransactMessage(narrow.proofInputs, narrow.owner);
    expect(() =>
      prepareTransfer(narrow.proofInputs, { kind: "confidentialEddsa", authorization }),
    ).toThrow(
      expect.objectContaining({
        code: "CLIENT_TRANSACTION",
        details: { code: "TRANSACTION_UNSUPPORTED_SHAPE" },
      }),
    );
    const wide = fixture({ inputs: 16, outputs: 16 });
    expect(() => prepareTransfer(wide.proofInputs, { kind: "confidential" })).toThrow(
      expect.objectContaining({
        code: "CLIENT_TRANSACTION",
        details: { code: "TRANSACTION_UNSUPPORTED_SHAPE" },
      }),
    );
    const prepared = prepareTransfer(wide.proofInputs, {
      kind: "confidentialEddsa",
      authorization: await signTransactMessage(wide.proofInputs, wide.owner),
    });
    expect(prepared.inputs.circuit).toBe("transferConfidentialEddsa");
    expect(prepared.inputs.payload.inputs).toHaveLength(16);
  });

  it("takes the proof's commitment into the selector", async () => {
    const value = fixture();
    const authorization = await signTransactMessage(value.proofInputs, value.owner);
    const result = assembled(value, authorization);
    const proof = {
      a: bytes(0) as Bytes32,
      b: bytes(0, 128) as Bytes128,
      c: bytes(0) as Bytes32,
    };
    const commitment = bytes(0x21) as Bytes32;
    const commitmentPok = bytes(0x22) as Bytes32;
    const data = result.withProof({ ...proof, commitment, commitmentPok });
    expect(data.circuit).toMatchObject({
      kind: "confidentialEddsa",
      proofData: { bsb22Commitment: { commitment, commitmentPok } },
    });
    expect(data.proof).toEqual(proof);
    expect(() => result.withProof(proof)).toThrow(
      expect.objectContaining({ code: "CLIENT_PROOF_PARSE" }),
    );

    const signer = assemble(
      value.proofInputs,
      value.real.map(spendProof),
      value.dummies.map((dummy) => nonInclusionProof(dummy.nullifier())),
    );
    expect(signer.withProof(proof).circuit.kind).toBe("confidentialSigner");
    expect(() => signer.withProof({ ...proof, commitment, commitmentPok })).toThrow(
      expect.objectContaining({ code: "CLIENT_PROOF_PARSE" }),
    );
  });
});

describe("the prover request of the confidentialEddsa rail", () => {
  it("carries the Go request's owner fields with the digest split into limbs", async () => {
    const value = fixture();
    const authorization = await signTransactMessage(value.proofInputs, value.owner);
    const body = proverRequestBody(assembled(value, authorization).proverInputs);
    const digest = bytesToHex(authorization.messageDigest);
    expect(body).toMatchObject({
      circuitType: "transfer-confidential-eddsa",
      nInputs: 2,
      nOutputs: 8,
      ringProgramId: "0x0",
      ownerPublicKey: `0x${bytesToHex(authorization.ownerPublicKey)}`,
      ownerSignature: `0x${bytesToHex(authorization.ownerSignature)}`,
      messageHashHigh: `0x${digest.slice(0, 32)}`,
      messageHashLow: `0x${digest.slice(32)}`,
    });
    expect(body).not.toHaveProperty("defaultOwnerPkHash");
    const committed = JSON.parse(
      readFileSync(
        new URL(
          "../../../prover/server/prover/transfer_eddsa/testdata/confidential-eddsa-2x8.json",
          import.meta.url,
        ),
        "utf8",
      ),
    ) as Record<string, unknown>;
    for (const key of Object.keys(committed)) expect(body).toHaveProperty(key);
  });

  it("posts to the rail's proving key and reads the committed proof back", async () => {
    const value = fixture();
    const authorization = await signTransactMessage(value.proofInputs, value.owner);
    const result = assembled(value, authorization);
    let posted: Record<string, unknown> = {};
    let url = "";
    const fetch = vi.fn(async (input: URL | string, init?: RequestInit) => {
      url = String(input);
      posted = JSON.parse(String(init?.body)) as Record<string, unknown>;
      return new Response(
        JSON.stringify({
          ...proofFor(posted),
          proofCommitment: ZERO_POINT,
          proofCommitmentPok: ZERO_POINT,
        }),
        { headers: { "content-type": "application/json" } },
      );
    }) as typeof globalThis.fetch;
    const prover = new ProverClient({ url: "http://127.0.0.1:3001", fetch });
    const keys = LocalKeys.fromKeypair(value.owner, prover);
    const proof = await keys.prove(result.proverInputs);
    expect(url).toContain("transfer_confidential_eddsa_2_8");
    expect(posted["circuitType"]).toBe("transfer-confidential-eddsa");
    expect(posted["ownerPublicKey"]).toBe(`0x${bytesToHex(authorization.ownerPublicKey)}`);
    const data = result.withProof(compressProof(proof));
    expect(data.circuit).toMatchObject({
      kind: "confidentialEddsa",
      proofData: { bsb22Commitment: { commitment: bytes(0), commitmentPok: bytes(0) } },
    });
    expect(parseProof(proofFor(posted)).commitment).toBeUndefined();
  });
});

describe("an indexed confidentialEddsa request", () => {
  it("publishes 19 fields and round-trips through the decoder", async () => {
    const value = fixture();
    const authorization = await signTransactMessage(value.proofInputs, value.owner);
    const { inputs } = prepareTransfer(value.proofInputs, {
      kind: "confidentialEddsa",
      authorization,
    });
    expect(inputs.circuit).toBe("transferConfidentialEddsa");
    expect(inputs.publicInputs).toHaveLength(19);
    expect(inputs.publicInputs.slice(4, 6)).toEqual(eddsaPublicFields(authorization));
    expect(decodeIndexedInputs(inputs)).toEqual(inputs);
  });

  it("refuses an authorization that does not match the statement", async () => {
    const value = fixture();
    const authorization = await signTransactMessage(value.proofInputs, value.owner);
    const { inputs } = prepareTransfer(value.proofInputs, {
      kind: "confidentialEddsa",
      authorization,
    });
    if (inputs.circuit !== "transferConfidentialEddsa") throw new Error("wrong rail");
    const otherOwner = await signTransactMessage(value.proofInputs, ShieldedKeypair.generate());
    const stale = await signTransactMessage(fixture().proofInputs, value.owner);
    const requests: unknown[] = [
      { ...inputs, payload: { ...inputs.payload, ownerAuthorization: otherOwner } },
      { ...inputs, payload: { ...inputs.payload, ownerAuthorization: stale } },
      {
        ...inputs,
        payload: {
          ...inputs.payload,
          ownerAuthorization: { ...authorization, ownerSignature: bytes(0, 64) },
        },
      },
      { ...inputs, publicInputs: inputs.publicInputs.slice(0, 17) },
      { ...inputs, circuit: "transfer" },
      {
        ...inputs,
        circuit: "transfer",
        payload: { ...inputs.payload, ownerAuthorization: undefined },
        publicInputs: inputs.publicInputs.slice(0, 17),
      },
    ];
    for (const request of requests) {
      expect(() => decodeIndexedInputs(request)).toThrow(
        expect.objectContaining({ code: "CLIENT_INVALID_PROOF_INPUTS" }),
      );
    }
    const signerRail = prepareTransfer(value.proofInputs, { kind: "confidential" }).inputs;
    expect(signerRail.publicInputs).toHaveLength(17);
    expect(() =>
      decodeIndexedInputs({
        ...signerRail,
        payload: { ...signerRail.payload, ownerAuthorization: authorization },
      }),
    ).toThrow(expect.objectContaining({ code: "CLIENT_INVALID_PROOF_INPUTS" }));
  });
});

describe("SigningKey as a transact owner", () => {
  it("is not one on its own: it names its key as publicKey, a ShieldedKeypair as signingPublicKey", () => {
    const key = SigningKey.generate();
    try {
      const keypair = ShieldedKeypair.fromKeypair(key);
      expect(keypair.signingPublicKey().ed25519()).toEqual(key.publicKey().ed25519());
    } finally {
      key.destroy();
    }
  });
});
