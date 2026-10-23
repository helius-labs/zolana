import { address } from "@solana/kit";
import { afterEach, describe, expect, it, vi } from "vitest";

import { LocalKeys, ZolanaClient } from "../src/client/index.js";
import { assembleMergeWithProofs } from "../src/client/prover/merge.js";
import { assemble, prepareTransfer } from "../src/client/prover/assembly.js";
import { decodeIndexedInputs } from "../src/client/prover/indexed.js";
import type { NonInclusionProof } from "../src/client/rpc.js";
import { BN254_SCALAR_ORDER } from "../src/hasher/index.js";
import { NO_UTXO_ROOT, type Bytes32 } from "../src/interface/index.js";
import { treeAddress } from "../src/interface/pda/index.js";
import { bigIntToBytes, bytes16, bytes32 } from "../src/keypair/bytes.js";
import { ShieldedKeypair, ShieldedPublicKey } from "../src/keypair/index.js";
import {
  AssetRegistry,
  Data,
  type InputUtxo,
  PreparedMerge,
  ProofInputUtxo,
  SOL_MINT,
  SppProofInputs,
  Utxo,
  createEncryptedTransaction,
  createExternalData,
  createInputUtxo,
  createProofOutput,
  decodeProgramTransaction,
  outputBlindingSeed,
  privateTxHash,
  transactOutputBlinding,
  type ProgramFinalizedTransaction,
} from "../src/transaction/index.js";
import { proofFor } from "./helpers/proofs.js";
import { bytesToBigInt } from "../src/interface/bytes.js";

describe("reserved address inputs", () => {
  afterEach(() => {
    for (const keypair of allocatedKeypairs.splice(0)) keypair.destroy();
  });
  // Vectors from Rust `SppProofInputUtxo::new_address`.
  it.each([
    [
      0,
      "1780838c8c1ad3c6127efc4d70fd2f09f96bab7c2b078332f4e197b6cef535a7",
      "2ccadcb35e84b6f69c77ad0dd0fce90e3055b620fec2228851f9d157c5cf899d",
    ],
    [
      3,
      "208fcf3d74a4e39c2e6a58211cfec0b204955498a681f91aa9469be464705be8",
      "0a5483f98a28bfb399e0bc00c36590dd8565683ae6d4af4b62e794652e7360bb",
    ],
  ] as const)(
    "matches Rust address commitments and nullifiers in tree %s",
    (treeId, hash, nullifier) => {
      const input = ProofInputUtxo.address(
        ShieldedPublicKey.fromPda(bytes32(new Uint8Array(32).fill(9))),
        bytes32(new Uint8Array(32).fill(7)),
        treeId,
      );
      expect({
        hash: Buffer.from(input.hash()).toString("hex"),
        nullifier: Buffer.from(input.nullifier()).toString("hex"),
        nullifierPublicKey: Buffer.from(input.nullifierPublicKey).toString("hex"),
      }).toEqual({
        hash,
        nullifier,
        nullifierPublicKey: "2a09a9fd93c590c26b91effbb2499f07e8f7aa12e2b4940a3aed2411cb65e11c",
      });
    },
  );

  it("uses a real address nullifier and excludes the state commitment from the private hash", () => {
    // 1. Reserve an address without requesting state inclusion.
    const { proofInputs, reserved, padding } = fixture();
    expect({
      address: reserved.isAddress(),
      dummy: reserved.isDummy(),
      inclusion: reserved.requiresInclusion(),
      published: reserved.publishedNullifier(),
      commitments: proofInputs.inputUtxoHashes(),
      contexts: proofInputs.inputContexts(),
      nonInclusion: proofInputs.dummyNullifiers(),
    }).toEqual({
      address: true,
      dummy: false,
      inclusion: false,
      published: reserved.nullifier(),
      commitments: [],
      contexts: [],
      nonInclusion: [reserved.nullifier(), padding.nullifier()],
    });

    // 2. Commit to the address in its own chain.
    const expected = privateTxHash({
      inputHashes: [zero(), zero()],
      outputHashes: proofInputs.outputs.map((output) => output.hash(0)),
      addressNullifiers: [reserved.nullifier(), zero()],
      blinding: proofInputs.privateTxBlinding(),
    });
    expect(proofInputs.privateTxHash()).toEqual(expected);
    expect(
      createEncryptedTransaction({
        inputs: proofInputs.inputUtxos,
        outputs: proofInputs.outputs,
        externalData: proofInputs.externalData,
        outputTreeId: 0,
        privateTxBlinding: proofInputs.privateTxBlinding(),
      }).hash(),
    ).toEqual(expected);
    expect(expected).not.toEqual(
      privateTxHash({
        inputHashes: [reserved.hash(), zero()],
        outputHashes: proofInputs.outputs.map((output) => output.hash(0)),
        blinding: proofInputs.privateTxBlinding(),
      }),
    );
  });

  it("builds a domain 2 witness with a zero secret and no state root", () => {
    const { proofInputs, reserved, padding } = fixture();
    const result = assemble(proofInputs, [], [nonInclusion(reserved), nonInclusion(padding)]);
    const input = result.proverInputs.payload.inputs[0];
    expect(input).toMatchObject({
      circuit: {
        domain: 2n,
        amount: 0n,
        asset: 0n,
        dataHash: 0n,
        ringDataHash: 0n,
        ringProgramId: 0n,
      },
      isDummy: 0n,
      nullifierSecret: 0n,
      statePathIndex: 0n,
      statePathElements: Array.from({ length: 32 }, () => 0n),
      nullifier: bytesToBigInt(reserved.nullifier()),
    });
    expect(result.instructionData.inputs).toEqual([
      { nullifierHash: reserved.nullifier(), treeIndex: 0 },
    ]);
    expect(result.instructionData.treeContexts).toEqual([
      { utxoTreeRootIndex: NO_UTXO_ROOT, nullifierTreeRootIndex: 2 },
    ]);
    expect(result.proverInputs.payload.privateTxHash).toBe(
      bytesToBigInt(proofInputs.privateTxHash()),
    );
    expect(result.proverInputs.payload.inputFlags).toBe(1n);
  });

  it("decodes native reserved addresses and omits compact ciphertexts", async () => {
    const { value, keypair, proofInputs } = nativeFixture();
    const decoded = await decodeProgramTransaction(value, new AssetRegistry());
    const viewingKey = keypair.viewingKey();
    let encrypted: SppProofInputs;
    try {
      encrypted = decoded.encryptWithKeys(viewingKey);
    } finally {
      viewingKey.destroy();
    }
    expect({
      address: decoded.inputs[0]?.isAddress(),
      compactInput: decoded.inputs[1]?.isCompact(),
      compactOutput: decoded.outputs[1]?.isCompact(),
      outputHashes: encrypted.externalData.outputs.map((output) => output.utxoHash),
      ownerTags: encrypted.externalData.resolvedOwnerTags,
      privateHash: encrypted.privateTxHash(),
    }).toEqual({
      address: true,
      compactInput: true,
      compactOutput: true,
      outputHashes: [decoded.outputHashes[0]],
      ownerTags: [decoded.resolvedOwnerTags[0]],
      privateHash: proofInputs.privateTxHash(),
    });
  });

  it.each([
    [
      "nullifier public key",
      { nullifierPubkey: zero() },
      { code: "TRANSACTION_ADDRESS_INPUT_NULLIFIER_PUBLIC_KEY_MISMATCH" },
    ],
    ["nullifier", { nullifier: zero() }, { code: "TRANSACTION_ADDRESS_INPUT_NULLIFIER_MISMATCH" }],
    [
      "data hash",
      { dataHash: zero() },
      { code: "TRANSACTION_ADDRESS_INPUT_NONEMPTY_FIELD", details: { field: "data_hash" } },
    ],
    [
      "ring hash",
      { ringDataHash: zero() },
      { code: "TRANSACTION_ADDRESS_INPUT_NONEMPTY_FIELD", details: { field: "ring_data_hash" } },
    ],
    ["cache slot", { cacheSlot: 0 }, { code: "TRANSACTION_ADDRESS_INPUT_CACHED" }],
    [
      "leaf index",
      { leafIndex: 1n },
      { code: "TRANSACTION_ADDRESS_INPUT_NONEMPTY_FIELD", details: { field: "leaf_index" } },
    ],
    ["compact padding", { compact: true }, { code: "TRANSACTION_ADDRESS_INPUT_COMPACT" }],
  ] as const)("refuses native addresses with invalid %s", async (_, change, error) => {
    const { value } = nativeFixture();
    const [first, second] = value.inputUtxos;
    await expect(
      decodeProgramTransaction(
        { ...value, inputUtxos: [{ ...first, ...change }, second] },
        new AssetRegistry(),
      ),
    ).rejects.toMatchObject(error);
  });

  // Each case breaks exactly one field of an otherwise valid address input,
  // so the code names the check that refused it.
  it.each([
    ["asset", { asset: address("So11111111111111111111111111111111111111112") }, "asset"],
    ["amount", { amount: 1n }, "amount"],
    ["data", { data: new Data([{ kind: "memo", bytes: Uint8Array.of(1) }]) }, "data"],
    ["ring", { ringProgramId: SOL_MINT }, "ring_program_id"],
  ] as const)("refuses an address carrying %s", (_, change, field) => {
    const { reserved } = fixture();
    expect(() =>
      addressWith(reserved, { utxo: new Utxo({ ...reserved.utxo, ...change }) }),
    ).toThrow(
      expect.objectContaining({
        code: "TRANSACTION_ADDRESS_INPUT_NONEMPTY_FIELD",
        details: { field },
      }),
    );
  });

  it.each([
    ["a data hash", { dataHash: bytes32(new Uint8Array(32).fill(1)) }, "data_hash"],
    ["a zero data hash", { dataHash: zero() }, "data_hash"],
    ["a ring data hash", { ringDataHash: bytes32(new Uint8Array(32).fill(1)) }, "ring_data_hash"],
    // A zero ring data hash normalizes away on a state input; an address keeps it to refuse it.
    ["a zero ring data hash", { ringDataHash: zero() }, "ring_data_hash"],
  ] as const)("refuses an address carrying %s", (_, change, field) => {
    const { reserved } = fixture();
    expect(() => addressWith(reserved, change)).toThrow(
      expect.objectContaining({
        code: "TRANSACTION_ADDRESS_INPUT_NONEMPTY_FIELD",
        details: { field },
      }),
    );
  });

  it("refuses an address over a noncanonical seed", () => {
    const { reserved } = fixture();
    const seed = bytes32(bigIntToBytes(BN254_SCALAR_ORDER, 32));
    expect(() =>
      addressWith(reserved, { utxo: new Utxo({ ...reserved.utxo, blinding: seed }) }),
    ).toThrow(expect.objectContaining({ code: "TRANSACTION_ADDRESS_INPUT_NONCANONICAL_SEED" }));
    expect(() => ProofInputUtxo.address(reserved.utxo.owner, seed)).toThrow(
      expect.objectContaining({ code: "TRANSACTION_ADDRESS_INPUT_NONCANONICAL_SEED" }),
    );
  });

  it.each([
    ["zero", () => ShieldedPublicKey.zeroed(), "TRANSACTION_ADDRESS_INPUT_ZERO_OWNER"],
  ] as const)("refuses an address with a %s owner", (_, owner, code) => {
    const { reserved } = fixture();
    expect(() =>
      addressWith(reserved, { utxo: new Utxo({ ...reserved.utxo, owner: owner() }) }),
    ).toThrow(expect.objectContaining({ code }));
    expect(() => ProofInputUtxo.address(owner(), reserved.utxo.blinding)).toThrow(
      expect.objectContaining({ code }),
    );
  });

  it("refuses an address marked compact or cached", () => {
    const { reserved } = fixture();
    expect(() => addressWith(reserved, { compact: true })).toThrow(
      expect.objectContaining({ code: "TRANSACTION_ADDRESS_INPUT_COMPACT" }),
    );
    expect(() => addressWith(reserved, { cacheSlot: 0 })).toThrow(
      expect.objectContaining({ code: "TRANSACTION_ADDRESS_INPUT_CACHED" }),
    );
    expect(() => reserved.withCacheSlot(0)).toThrow(
      expect.objectContaining({ code: "TRANSACTION_ADDRESS_INPUT_CACHED" }),
    );
  });

  it("refuses an address with another nullifier key or nullifier", () => {
    const { reserved } = fixture();
    expect(() =>
      addressWith(reserved, { nullifierPublicKey: bytes32(new Uint8Array(32).fill(1)) }),
    ).toThrow(
      expect.objectContaining({ code: "TRANSACTION_ADDRESS_INPUT_NULLIFIER_PUBLIC_KEY_MISMATCH" }),
    );
    expect(() => addressWith(reserved, { nullifier: bytes32(new Uint8Array(32).fill(1)) })).toThrow(
      expect.objectContaining({ code: "TRANSACTION_ADDRESS_INPUT_NULLIFIER_MISMATCH" }),
    );
    // The unchanged fields rebuild the same address.
    expect(addressWith(reserved, {}).nullifier()).toEqual(reserved.nullifier());
  });

  it("refuses a non-boolean address flag and validating a state input", () => {
    const { reserved, padding } = fixture();
    expect(() =>
      Reflect.construct(ProofInputUtxo, [
        {
          utxo: reserved.utxo,
          nullifierPublicKey: reserved.nullifierPublicKey,
          nullifier: reserved.nullifier(),
          address: "yes",
        },
      ]),
    ).toThrow(
      expect.objectContaining({ code: "TRANSACTION_DESERIALIZE", details: { field: "address" } }),
    );
    expect(() => padding.validateAddress()).toThrow(
      expect.objectContaining({ code: "TRANSACTION_NOT_ADDRESS_INPUT" }),
    );
    expect(padding.addressNullifier).toBeUndefined();
  });

  it("checks an address again before using mutated public fields", () => {
    const noncanonical = fixture();
    noncanonical.reserved.utxo.blinding.fill(0xff);
    expect(() => noncanonical.proofInputs.checkShape()).toThrow(
      expect.objectContaining({ code: "TRANSACTION_ADDRESS_INPUT_NONCANONICAL_SEED" }),
    );
    const reseeded = fixture();
    reseeded.reserved.utxo.blinding.fill(0x01);
    expect(() => reseeded.proofInputs.checkShape()).toThrow(
      expect.objectContaining({ code: "TRANSACTION_ADDRESS_INPUT_NULLIFIER_MISMATCH" }),
    );
    expect(() => reseeded.proofInputs.privateTxHash()).toThrow(
      expect.objectContaining({ code: "TRANSACTION_ADDRESS_INPUT_NULLIFIER_MISMATCH" }),
    );
  });

  it("hashes an address input rebuilt by createInputUtxo or spread like the original", () => {
    const { proofInputs, reserved, padding } = fixture();
    const expected = proofInputs.privateTxHash();
    const hashWith = (first: InputUtxo) =>
      createEncryptedTransaction({
        inputs: [first, padding],
        outputs: proofInputs.outputs,
        externalData: proofInputs.externalData,
        outputTreeId: 0,
        privateTxBlinding: proofInputs.privateTxBlinding(),
      }).hash();
    const rebuilt = createInputUtxo({
      utxo: reserved.utxo,
      nullifierPublicKey: reserved.nullifierPublicKey,
      addressNullifier: reserved.nullifier(),
    });
    expect({
      address: rebuilt.addressNullifier,
      hash: rebuilt.hash(),
      dummy: rebuilt.isDummy(),
    }).toEqual({ address: reserved.nullifier(), hash: reserved.hash(), dummy: false });
    expect(hashWith(rebuilt)).toEqual(expected);
    // A spread keeps the address, so the structural input hashes as one.
    expect(reserved.addressNullifier).toEqual(reserved.nullifier());
    expect(hashWith(createInputUtxo({ ...reserved }))).toEqual(expected);
    expect(hashWith({ ...reserved, hash: () => reserved.hash(), isDummy: () => false })).toEqual(
      expected,
    );
  });

  it("refuses an address nullifier its fields do not derive", () => {
    const { proofInputs, reserved, padding } = fixture();
    const forged = bytes32(new Uint8Array(32).fill(1));
    expect(() =>
      createInputUtxo({
        utxo: reserved.utxo,
        nullifierPublicKey: reserved.nullifierPublicKey,
        addressNullifier: forged,
      }),
    ).toThrow(expect.objectContaining({ code: "TRANSACTION_ADDRESS_INPUT_NULLIFIER_MISMATCH" }));
    const transaction = createEncryptedTransaction({
      inputs: [
        {
          ...reserved,
          addressNullifier: forged,
          hash: () => reserved.hash(),
          isDummy: () => false,
        },
        padding,
      ],
      outputs: proofInputs.outputs,
      externalData: proofInputs.externalData,
      outputTreeId: 0,
      privateTxBlinding: proofInputs.privateTxBlinding(),
    });
    expect(() => transaction.hash()).toThrow(
      expect.objectContaining({ code: "TRANSACTION_ADDRESS_INPUT_NULLIFIER_MISMATCH" }),
    );
  });

  it("refuses an address on the ring authority rail before requesting proofs", () => {
    const { proofInputs } = fixture();
    expect(() => prepareTransfer(proofInputs, { kind: "ringAuthority", ring: SOL_MINT })).toThrow(
      expect.objectContaining({ code: "CLIENT_ADDRESS_INPUT_UNSUPPORTED", details: { index: 0 } }),
    );
  });

  it("proves an address on the owner-signed ring rail", () => {
    const { proofInputs } = fixture();
    const request = prepareTransfer(proofInputs, { kind: "ring", ring: SOL_MINT }).inputs;
    expect(request.circuit).toBe("transferRing");
    expect(decodeIndexedInputs(request).lookups.map((lookup) => lookup.commitment)).toEqual([
      null,
      null,
    ]);
  });

  it("refuses an indexed request that proves an address as another slot", () => {
    const { proofInputs } = fixture();
    const request = prepareTransfer(proofInputs).inputs;
    expect(decodeIndexedInputs(request).lookups.map((lookup) => lookup.commitment)).toEqual([
      null,
      null,
    ]);
    const [first, second] = request.payload.inputs;
    if (first === undefined || second === undefined) throw new Error("fixture inputs missing");
    const withFirst = (patch: object) => ({
      ...request,
      payload: { ...request.payload, inputs: [{ ...first, ...patch }, second] },
    });
    const invalidAddress = expect.objectContaining({
      code: "CLIENT_INVALID_ADDRESS_INPUT",
      details: { index: 0 },
    });
    expect(() => decodeIndexedInputs(withFirst({ isDummy: 1n }))).toThrow(invalidAddress);
    expect(() => decodeIndexedInputs(withFirst({ nullifierSecret: 1n }))).toThrow(invalidAddress);
    expect(() =>
      decodeIndexedInputs({
        ...request,
        payload: { ...request.payload, cacheIsCached: [1n, 0n] },
      }),
    ).toThrow(invalidAddress);
    expect(() =>
      decodeIndexedInputs({
        ...request,
        lookups: [
          { ...request.lookups[0], commitment: proofInputs.inputUtxos[0]?.hash() },
          request.lookups[1],
        ],
      }),
    ).toThrow(invalidAddress);
  });

  it("refuses an address on the merge rail", () => {
    const { reserved, padding, proofInputs } = fixture();
    const output = proofInputs.outputs[0];
    if (output === undefined) throw new Error("fixture output missing");
    const prepared = new PreparedMerge({
      inputs: [reserved, ...Array.from({ length: 7 }, () => padding)],
      output,
      expiryUnixTs: 0n,
      signingPublicKey: reserved.utxo.owner,
      nullifierPublicKey: reserved.nullifierPublicKey,
      dummyNullifiers: Array.from({ length: 7 }, () => padding.nullifier()),
      privateTxBlinding: zero(),
      outputCiphertextSalt: bytes16(new Uint8Array(16)),
      outputCiphertext: [zero(), zero(), zero()],
      outputTreeId: 0,
    });
    expect(() => assembleMergeWithProofs(prepared, [], treeAddress(0))).toThrow(
      expect.objectContaining({ code: "CLIENT_ADDRESS_INPUT_UNSUPPORTED", details: { index: 0 } }),
    );
  });

  it.each(["client", "prover"] as const)(
    "routes reserved address proofs with %s fetching",
    async (proofDataSource) => {
      // 1. Build the expected public statement from non-inclusion proofs.
      const { proofInputs, reserved, padding, keypair } = fixture();
      const proofs = [nonInclusion(reserved), nonInclusion(padding)];
      const expected = assemble(proofInputs, [], proofs);
      const fetch = vi.fn<typeof globalThis.fetch>(async (_url, init) => {
        const body: unknown = JSON.parse(String(init?.body));
        const payload =
          typeof body === "object" && body !== null && "prepared" in body ? body.prepared : body;
        return Response.json({
          ...proofFor(payload),
          resolution: {
            publicInputHash: `0x${expected.proverInputs.payload.publicInputHash.toString(16)}`,
            trees: [
              {
                tree: treeAddress(0),
                id: 0,
                utxoRoot: "0x0",
                nullifierRoot: "0x6",
                utxoRootIndex: NO_UTXO_ROOT,
                nullifierRootIndex: 2,
              },
            ],
          },
        });
      });
      const client = new ZolanaClient({
        solanaRpcUrl: "http://127.0.0.1:8899",
        indexerUrl: "http://127.0.0.1:8784",
        proverUrl: "http://127.0.0.1:3001",
        tree: treeAddress(0),
        fetch,
        proofDataSource,
      });
      const stateProofs = vi.spyOn(client, "getMerkleProofs");
      const nullifierProofs = vi
        .spyOn(client, "getNonInclusionProofs")
        .mockResolvedValue({ context: { slot: 1n, blockTime: 1n }, proofs });
      const authority = LocalKeys.fromKeypair(keypair, client.proofService);
      try {
        // 2. Prove without a state inclusion request.
        const result = await client.proveTransact(proofInputs, authority);
        expect(stateProofs).not.toHaveBeenCalled();
        expect(result.inputs).toEqual([{ nullifierHash: reserved.nullifier(), treeIndex: 0 }]);
        if (proofDataSource === "client")
          expect(nullifierProofs.mock.calls[0]?.slice(0, 2)).toEqual([
            treeAddress(0),
            [reserved.nullifier(), padding.nullifier()],
          ]);
        else expect(nullifierProofs).not.toHaveBeenCalled();
        expect(fetch).toHaveBeenCalledOnce();
      } finally {
        authority.destroy();
        keypair.destroy();
      }
    },
  );
});

const allocatedKeypairs: ShieldedKeypair[] = [];

/** The address input's own fields with `change` applied, through the public constructor. */
function addressWith(
  reserved: ProofInputUtxo,
  change: Partial<ConstructorParameters<typeof ProofInputUtxo>[0]>,
): ProofInputUtxo {
  return new ProofInputUtxo({
    utxo: reserved.utxo,
    nullifierPublicKey: reserved.nullifierPublicKey,
    nullifier: reserved.nullifier(),
    treeId: reserved.treeId,
    address: true,
    ...change,
  });
}

function fixture() {
  const keypair = ShieldedKeypair.generate();
  allocatedKeypairs.push(keypair);
  const reserved = ProofInputUtxo.address(
    ShieldedPublicKey.fromPda(bytes32(new Uint8Array(32).fill(9))),
    bytes32(new Uint8Array(32).fill(7)),
  );
  const padding = ProofInputUtxo.compact();
  const seed = bytes32(new Uint8Array(32).fill(8));
  const outputSeed = outputBlindingSeed(reserved.nullifier(), seed);
  const outputs = [
    createProofOutput({
      ownerAddress: keypair.shieldedAddress(),
      asset: SOL_MINT,
      amount: 0n,
      blinding: transactOutputBlinding(reserved.nullifier(), outputSeed, 0),
    }),
    createProofOutput({
      asset: SOL_MINT,
      amount: 0n,
      blinding: transactOutputBlinding(reserved.nullifier(), outputSeed, 1),
      compact: true,
    }),
  ];
  const proofInputs = new SppProofInputs({
    payer: keypair.shieldedAddress().solanaAddress(),
    inputUtxos: [reserved, padding],
    outputs,
    externalData: createExternalData({
      txViewingPublicKey: keypair.viewingPublicKey(),
      salt: bytes16(new Uint8Array(16)),
      outputs: [
        {
          utxoHash: outputs[0]?.hash(0) ?? zero(),
          ownerTag: { kind: "inline", value: keypair.signingPublicKey().confidentialViewTag() },
        },
      ],
      resolvedOwnerTags: [keypair.signingPublicKey().confidentialViewTag()],
      messages: [],
    }),
    blindingSeed: seed,
    outputTreeId: 0,
  });
  return { keypair, reserved, padding, proofInputs };
}

function nativeFixture() {
  const base = fixture();
  const { proofInputs, keypair } = base;
  const value: ProgramFinalizedTransaction = {
    inputUtxos: proofInputs.inputUtxos.map((input) => ({
      utxo: {
        owner: input.utxo.owner.toBytes(),
        asset: { asset: SOL_MINT, assetId: 1n },
        amount: 0n,
        blinding: input.utxo.blinding,
      },
      nullifierPubkey: input.nullifierPublicKey,
      utxoHash: input.hash(),
      nullifier: input.nullifier(),
      treeId: 0,
      leafIndex: 0n,
      ...(input.isAddress() ? { address: true } : {}),
      ...(input.isCompact() ? { compact: true } : {}),
    })),
    outputUtxos: proofInputs.outputs.map((output) => ({
      asset: { asset: SOL_MINT, assetId: 1n },
      amount: 0n,
      blinding: output.blinding,
      ...(output.ownerAddress === undefined ? {} : { ownerAddress: output.ownerAddress.toBytes() }),
      ...(output.isCompact() ? { compact: true } : {}),
    })),
    outputHashes: proofInputs.outputs.map((output) => output.hash(0)),
    ownerTags: [
      {
        tag: { kind: "inline", value: keypair.signingPublicKey().confidentialViewTag() },
        resolved: keypair.signingPublicKey().confidentialViewTag(),
      },
      { tag: { kind: "inline", value: zero() }, resolved: zero() },
    ],
    interfaceTransfers: [],
    firstNullifier: proofInputs.firstNullifier(),
    blindingSeed: proofInputs.blindingSeed,
    privateTxBlinding: proofInputs.privateTxBlinding(),
    paddingIndependentPrivateTxHash: proofInputs.privateTxHash(),
    outputTreeId: 0,
    payer: proofInputs.payer,
    sender: keypair.shieldedAddress().toBytes(),
  };
  return { ...base, value };
}

function nonInclusion(input: ProofInputUtxo): NonInclusionProof {
  return {
    leaf: input.nullifier(),
    merkleContext: { treeType: 1, tree: treeAddress(input.treeId) },
    path: Array.from({ length: 40 }, () => zero()),
    lowElement: zero(),
    lowElementIndex: 0n,
    highElement: bytes32(bigIntToBytes(BN254_SCALAR_ORDER - 1n, 32)),
    highElementIndex: 1n,
    root: bytes32(bigIntToBytes(6n, 32)),
    rootSeq: 1n,
    rootIndex: 2,
  };
}

function zero(): Bytes32 {
  return bytes32(new Uint8Array(32));
}
