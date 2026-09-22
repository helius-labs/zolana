import { LocalKeys, ZolanaClient, type IndexedProofInputs } from "../src/client/index.js";
import { prepareMerge } from "../src/client/prover/merge.js";
import { compressProof, parseProof } from "../src/client/prover/proof.js";
import { ShieldedKeypair, randomBlinding } from "../src/keypair/index.js";
import { Merge, ProofInputUtxo, SOL_MINT, Utxo } from "../src/transaction/index.js";
import { treeAddress } from "../src/interface/pda/index.js";
import { decodeIndexedInputs, indexedAuthority } from "../src/client/prover/indexed.js";
import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { wireDecoder } from "../src/interface/decode.js";
import { inputTreeSlots } from "../src/interface/tree-slot.js";
import { bigintToBytes, bytesToBigInt, checkedBytes } from "../src/client/internal.js";
import { asField, resolvedPublicInputHash } from "../src/client/prover/assembly.js";

const STANDARD_PROOF = {
  ar: ["0x0", "0x0"],
  bs: [
    ["0x0", "0x0"],
    ["0x0", "0x0"],
  ],
  krs: ["0x0", "0x0"],
};

const decode = wireDecoder(() => new Error("invalid shared vector"));

it.each([1, 8])("hashes each real merge input once with %i real inputs", (count) => {
  const owner = ShieldedKeypair.generate();
  try {
    const inputs = Array.from({ length: count }, () =>
      ProofInputUtxo.fromKeypair(
        new Utxo({
          owner: owner.signingPublicKey(),
          asset: SOL_MINT,
          amount: 5n,
          blinding: randomBlinding(),
        }),
        owner,
      ),
    );
    const prepared = Merge.fromKeypair(owner, inputs).prepare();
    const expected = inputs.map((input) => input.hash());
    const hashes = inputs.map((input) => vi.spyOn(input, "hash"));
    try {
      const tree = treeAddress(prepared.inputTreeId);
      const first = prepareMerge(prepared, tree);
      hashes.forEach((hash) => expect(hash).toHaveBeenCalledTimes(1));
      expect(first.inputs.lookups.map((lookup) => lookup.commitment)).toEqual([
        ...expected,
        ...Array.from({ length: 8 - count }, () => null),
      ]);
      const input = inputs[0];
      if (input === undefined) throw new Error("missing test input");
      input.utxo.blinding.fill(0);
      const second = prepareMerge(prepared, tree);
      expect(second.inputs.lookups[0]?.commitment).not.toEqual(expected[0]);
      expect(second.inputs.payload.privateTxHash).not.toBe(first.inputs.payload.privateTxHash);
      expect(first.inputs.lookups[0]?.commitment).toEqual(expected[0]);
    } finally {
      hashes.forEach((hash) => hash.mockRestore());
    }
  } finally {
    owner.destroy();
  }
});

describe("indexed proof transcript", () => {
  it("matches the Go and Rust transcript vector", () => {
    const json: unknown = JSON.parse(
      readFileSync(new URL("../../fixtures/indexed-proof.json", import.meta.url), "utf8"),
    );
    const vector = decode.record(json, "vector");
    const fields = decode
      .list(vector["publicInputs"], "publicInputs")
      .map((value) => BigInt(decode.string(value, "field")));
    const trees = decode.list(vector["trees"], "trees").map((value) => {
      const tree = decode.record(value, "tree");
      return {
        id: Number(decode.integer(tree["id"], "id")),
        utxoRoot: checkedBytes(
          bigintToBytes(BigInt(decode.string(tree["utxoRoot"], "root"))),
          32,
          "root",
        ),
        nullifierRoot: checkedBytes(
          bigintToBytes(BigInt(decode.string(tree["nullifierRoot"], "root"))),
          32,
          "root",
        ),
      };
    });
    expect(resolvedPublicInputHash(fields, inputTreeSlots(trees))).toBe(
      BigInt(decode.string(vector["publicInputHash"], "hash")),
    );
  });
});

it.each([
  null,
  {},
  { circuit: "transfer", payload: null },
  { circuit: "merge", payload: { inputs: null } },
])("rejects malformed indexed structures with a client code", (value) => {
  expect(() => decodeIndexedInputs(value)).toThrow(
    expect.objectContaining({ code: "CLIENT_INVALID_PROOF_INPUTS" }),
  );
});

it("binds merge resolution and keeps preparation free of indexer calls", async () => {
  const owner = ShieldedKeypair.generate();
  const input = ProofInputUtxo.fromKeypair(
    new Utxo({
      owner: owner.signingPublicKey(),
      asset: SOL_MINT,
      amount: 5n,
      blinding: randomBlinding(),
    }),
    owner,
  );
  const prepared = Merge.fromKeypair(owner, [input]).prepare();
  const tree = treeAddress(prepared.inputTreeId);
  const local = prepareMerge(prepared, tree);
  const resolved = {
    tree,
    id: prepared.inputTreeId,
    utxoRoot: checkedBytes(bigintToBytes(11n), 32, "root"),
    nullifierRoot: checkedBytes(bigintToBytes(12n), 32, "root"),
    utxoRootIndex: 3,
    nullifierRootIndex: 4,
  };
  const complete = local.finish({
    slot: { id: resolved.id, utxoRoot: resolved.utxoRoot, nullifierRoot: resolved.nullifierRoot },
    utxoRootIndex: 3,
    nullifierRootIndex: 4,
  });
  const fetch = vi.fn<typeof globalThis.fetch>(
    async () =>
      new Response(
        JSON.stringify({
          ...STANDARD_PROOF,
          resolution: {
            publicInputHash: `0x${bytesToBigInt(complete.publicInputHash).toString(16)}`,
            trees: [{ ...resolved, utxoRoot: "0xb", nullifierRoot: "0xc" }],
          },
        }),
        { headers: { "content-type": "application/json" } },
      ),
  );
  const client = new ZolanaClient({ proofDataSource: "prover", fetch });
  const keys = LocalKeys.fromKeypair(owner, client.proofService);
  try {
    const result = await client.proveMerge({ prepared, keys });
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(result.outputHash).toEqual(complete.outputHash);
    expect(result.data).toEqual(
      complete.instructionData(compressProof(parseProof(STANDARD_PROOF)).toTransactProof()),
    );
    const request: unknown = JSON.parse(String(fetch.mock.calls[0]?.[1]?.body));
    const envelope = decode.record(request, "request");
    const payload = decode.record(envelope["prepared"], "prepared");
    expect(envelope["circuitType"]).toBe("merge");
    expect(payload).not.toHaveProperty("treeSlots");
    expect(typeof payload["userNullifierSecret"]).toBe("string");
    expect(decode.list(payload["inputs"], "inputs")).toHaveLength(8);
    expect(payload["privateTxHash"]).toBe(`0x${local.inputs.payload.privateTxHash.toString(16)}`);
    const valid = {
      proof: parseProof(STANDARD_PROOF),
      resolution: { trees: [resolved], publicInputHash: complete.publicInputHash },
    };
    for (const part of ["commitment", "commitmentPok"]) {
      await expect(
        indexedAuthority({
          proveIndexed: () => ({
            ...valid,
            proof: { ...valid.proof, [part]: checkedBytes(new Uint8Array(64), 64, "point") },
          }),
        }).proveIndexed(local.inputs),
      ).rejects.toMatchObject({ code: "CLIENT_PROOF_PARSE" });
    }
    await expect(
      indexedAuthority({ proveIndexed: () => undefined }).proveIndexed(local.inputs),
    ).rejects.toMatchObject({ code: "CLIENT_PROOF_PARSE" });
    await expect(
      indexedAuthority({
        proveIndexed(request: IndexedProofInputs) {
          const publicInputs = request.publicInputs.map(() => asField(0n));
          Object.assign(request, { publicInputs });
          const hash = resolvedPublicInputHash(
            publicInputs,
            inputTreeSlots([
              {
                id: resolved.id,
                utxoRoot: resolved.utxoRoot,
                nullifierRoot: resolved.nullifierRoot,
              },
            ]),
          );
          return {
            ...valid,
            resolution: {
              ...valid.resolution,
              publicInputHash: checkedBytes(bigintToBytes(hash), 32, "hash"),
            },
          };
        },
      }).proveIndexed(local.inputs),
    ).rejects.toMatchObject({ code: "CLIENT_PROOF_PARSE" });
  } finally {
    keys.destroy();
    owner.destroy();
  }
});
