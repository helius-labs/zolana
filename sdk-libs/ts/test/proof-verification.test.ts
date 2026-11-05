import runtimeProof from "../../../test-vectors/runtime_key_proof.json" with { type: "json" };
import shared from "../../../test-vectors/proof_verification.json" with { type: "json" };
import catalogVector from "../../../test-vectors/runtime_proving_keys.json" with { type: "json" };
import transferRequest from "../../../prover/server/prover/request/testdata/transfer-2x2.json" with { type: "json" };

import { describe, expect, it, vi } from "vitest";

import { SprClient } from "../src/client/client.js";
import { BN254_MODULUS, checkedBytes } from "../src/client/internal.js";
import { asField } from "../src/client/prover/assembly.js";
import { provingKeySetFromCatalog } from "../src/client/prover/key-set.js";
import { compressProof, parseProof } from "../src/client/prover/proof.js";
import type {
  CircuitUtxo,
  Field,
  Proof,
  TransferInputs,
  TransferOutput,
} from "../src/client/prover/types.js";
import { verifyProofStatement } from "../src/client/prover/verify.js";
import { PROVING_KEY_SHA256S } from "../src/interface/proving-keys.js";

type Vector = Readonly<{ key: string; publicInputHash: string; proof: unknown }>;

/** Every proof a real prover made for a pinned key, with the statement it proves. */
const VECTORS: readonly Vector[] = [runtimeProof, ...shared.proofs];
const COMMITTED = VECTORS.filter((vector) => parseProof(vector.proof).commitment !== undefined);
const PLAIN = VECTORS.filter((vector) => parseProof(vector.proof).commitment === undefined);

function key(name: string): Readonly<{ name: string; sha256: string }> {
  return { name, sha256: PROVING_KEY_SHA256S[name] ?? "" };
}

function verify(proof: Proof, publicInputHash: bigint, name: string): void {
  verifyProofStatement(proof, publicInputHash, key(name), undefined);
}

const refused = (check: string) =>
  expect.objectContaining({ code: "CLIENT_PROOF_VERIFICATION", details: { check } });

/** `proof` with the last byte of `field` flipped. */
function flipped(proof: Proof, field: "a" | "b" | "c" | "commitment"): Proof {
  const bytes = proof[field];
  if (bytes === undefined) throw new Error(`no ${field}`);
  const copy = new Uint8Array(bytes);
  copy[copy.length - 1] = (copy[copy.length - 1] ?? 0) ^ 1;
  return field === "b"
    ? { ...proof, b: checkedBytes(copy, 128, field) }
    : { ...proof, [field]: checkedBytes(copy, 64, field) };
}

describe("verifyProofStatement", () => {
  it("accepts each prover's proof under the key the program verifies it with", () => {
    expect(COMMITTED.map((vector) => vector.key)).toEqual([
      "transfer_confidential_eddsa_2_8.key",
      "transfer_eddsa_ring_2_2.key",
    ]);
    for (const vector of VECTORS) {
      expect(() =>
        verify(parseProof(vector.proof), BigInt(vector.publicInputHash), vector.key),
      ).not.toThrow();
    }
  });

  it("refuses a proof for another statement or a public input outside the field", () => {
    for (const vector of VECTORS) {
      const proof = parseProof(vector.proof);
      const statement = BigInt(vector.publicInputHash);
      expect(() => verify(proof, statement ^ 1n, vector.key)).toThrow(refused("pairing"));
      expect(() => verify(proof, statement + BN254_MODULUS, vector.key)).toThrow(
        refused("encoding"),
      );
    }
  });

  it("refuses a proof with a changed point", () => {
    for (const vector of VECTORS) {
      const proof = parseProof(vector.proof);
      const statement = BigInt(vector.publicInputHash);
      // A valid point in the wrong place fails the equation, a changed byte
      // takes the point off the curve.
      expect(() => verify({ ...proof, a: proof.c, c: proof.a }, statement, vector.key)).toThrow(
        refused("pairing"),
      );
      for (const field of ["a", "b", "c"] as const) {
        expect(() => verify(flipped(proof, field), statement, vector.key)).toThrow(
          expect.objectContaining({ code: "CLIENT_PROOF_VERIFICATION" }),
        );
      }
    }
  });

  it("refuses a proof checked against another circuit's key", () => {
    const others: Readonly<Record<string, string>> = {
      "transfer_confidential_2_2.key": "transfer_confidential_2_4.key",
      "transfer_confidential_eddsa_2_8.key": "transfer_eddsa_ring_2_8.key",
      "transfer_eddsa_ring_2_2.key": "transfer_eddsa_ring_2_4.key",
      "merge_8_1.key": "merge_ring_8_1.key",
    };
    for (const vector of VECTORS) {
      const other = others[vector.key];
      if (other === undefined) throw new Error(`no other key for ${vector.key}`);
      expect(() => verify(parseProof(vector.proof), BigInt(vector.publicInputHash), other)).toThrow(
        refused("pairing"),
      );
    }
    expect(() =>
      verify(parseProof(runtimeProof.proof), 1n, "transfer_confidential_2_3.key"),
    ).toThrow(expect.objectContaining({ code: "CLIENT_PROVER_INPUT" }));
  });

  it("checks the BSB22 commitment and its proof of knowledge", () => {
    for (const vector of COMMITTED) {
      const proof = parseProof(vector.proof);
      const statement = BigInt(vector.publicInputHash);
      const { commitment, commitmentPok } = proof;
      if (commitment === undefined || commitmentPok === undefined) throw new Error("no commitment");
      const bare: Proof = { a: proof.a, b: proof.b, c: proof.c };
      expect(() => verify(bare, statement, vector.key)).toThrow(refused("commitment"));
      expect(() => verify({ ...bare, commitment }, statement, vector.key)).toThrow(
        refused("commitment"),
      );
      // Another commitment changes the hashed public input, another proof of
      // knowledge fails the Pedersen check.
      expect(() => verify({ ...proof, commitment: commitmentPok }, statement, vector.key)).toThrow(
        refused("pairing"),
      );
      expect(() => verify({ ...proof, commitmentPok: commitment }, statement, vector.key)).toThrow(
        refused("pairing"),
      );
      expect(() => verify(flipped(proof, "commitment"), statement, vector.key)).toThrow(
        refused("encoding"),
      );
    }
    const [plain] = PLAIN;
    const [committed] = COMMITTED;
    if (plain === undefined || committed === undefined) throw new Error("missing vectors");
    const { commitment, commitmentPok } = parseProof(committed.proof);
    if (commitment === undefined || commitmentPok === undefined) throw new Error("no commitment");
    expect(() =>
      verify(
        { ...parseProof(plain.proof), commitment, commitmentPok },
        BigInt(plain.publicInputHash),
        plain.key,
      ),
    ).toThrow(refused("commitment"));
  });
});

describe("a runtime key set", () => {
  function set(change?: (value: typeof catalogVector) => void) {
    const value = structuredClone(catalogVector);
    change?.(value);
    return provingKeySetFromCatalog(value);
  }
  const proof = parseProof(runtimeProof.proof);
  const statement = BigInt(runtimeProof.publicInputHash);

  it("verifies a proof against the set's own verifying key", () => {
    const keys = set();
    expect(() => verifyProofStatement(proof, statement, key(runtimeProof.key), keys)).not.toThrow();
    expect(() => verifyProofStatement(proof, statement ^ 1n, key(runtimeProof.key), keys)).toThrow(
      refused("pairing"),
    );
    expect(() => verifyProofStatement(proof, statement, key("merge_8_1.key"), keys)).toThrow(
      refused("pairing"),
    );
    expect(() => verifyProofStatement(proof, statement, key("merge_ring_8_1.key"), keys)).toThrow(
      expect.objectContaining({
        code: "CLIENT_PROVING_KEY_SET",
        details: { check: "unsupported_circuit" },
      }),
    );
  });

  it("uses the set's key, not the compiled one", () => {
    const keys = set((value) => {
      const verifier = value.runtime.verifyingKeys["transfer_confidential_2_2.key"];
      verifier.alphaG1 = verifier.ic[0] ?? "";
    });
    expect(() => verifyProofStatement(proof, statement, key(runtimeProof.key), keys)).toThrow(
      refused("pairing"),
    );
  });
});

/** The Go prover's 2-in 2-out request fixture, which `runtimeProof` proves, as `TransferInputs`. */
function transferInputs(): TransferInputs {
  const value = (hex: string): Field => asField(BigInt(hex));
  const values = (hexes: readonly string[]): readonly Field[] => hexes.map(value);
  const utxo = (raw: (typeof transferRequest.inputs)[number]["utxo"]): CircuitUtxo => ({
    domain: value(raw.domain),
    owner: value(raw.owner),
    asset: value(raw.asset),
    amount: value(raw.amount),
    blinding: value(raw.blinding),
    dataHash: value(raw.dataHash),
    ringDataHash: value(raw.ringDataHash),
    ringProgramId: value(raw.ringProgramId),
  });
  const output = (raw: (typeof transferRequest.outputs)[number]): TransferOutput => ({
    circuit: utxo(raw.utxo),
    isDummy: value(raw.isDummy),
    hash: value(raw.hash),
    ownerPublicKeyHash: value(raw.ownerPkHash),
    nullifierPublicKey: value(raw.nullifierPk),
  });
  const request = transferRequest;
  return {
    inputs: request.inputs.map((input) => ({
      circuit: utxo(input.utxo),
      isDummy: value(input.isDummy),
      statePathElements: values(input.statePathElements),
      statePathIndex: value(input.statePathIndex),
      nullifierLowValue: value(input.nullifierLowValue),
      nullifierNextValue: value(input.nullifierNextValue),
      nullifierLowPathElements: values(input.nullifierLowPathElements),
      nullifierLowPathIndex: value(input.nullifierLowPathIndex),
      treeSlot: value(input.treeSlot),
      nullifier: value(input.nullifier),
      ownerPublicKeyHash: value(input.ownerPkHash),
      nullifierSecret: value(input.nullifierSecret),
    })),
    outputs: request.outputs.map(output),
    treeSlots: request.treeSlots.map((slot) => ({
      id: value(slot.id),
      utxoRoot: value(slot.utxoRoot),
      nullifierRoot: value(slot.nullifierRoot),
    })),
    outputTreeId: value(request.outputTreeId),
    externalDataHash: value(request.externalDataHash),
    privateTxHash: value(request.privateTxHash),
    blindingSeed: value(request.blindingSeed),
    publicAssets: values(request.publicAssets),
    publicAmounts: values(request.publicAmounts),
    ringProgramId: value(request.ringProgramId),
    signerPublicKeyHashes: values(request.signerPkHashes),
    inputFlags: value(request.inputFlags),
    publishedOutputOwnerPublicKeyHashes: values(request.publishedOutputOwnerPkHashes),
    cacheTreeId: value(request.cacheTreeId),
    cacheReadHashChain: value(request.cacheReadHashChain),
    cacheReadHashes: values(request.cacheReadHashes),
    cacheIsCached: values(request.cacheIsCached),
    cacheReadIndex: values(request.cacheReadIndex),
    publicInputHash: value(request.publicInputHash),
  };
}

describe("SprClient.proveTransferInputs", () => {
  function proving(answer: Readonly<Record<string, unknown>>) {
    const fetch = vi.fn<typeof globalThis.fetch>(async () =>
      Response.json({
        ...answer,
        provingKeySha256: PROVING_KEY_SHA256S["transfer_confidential_2_2.key"],
      }),
    );
    const client = new SprClient({
      solanaRpcUrl: "http://127.0.0.1:8899",
      proverUrl: "http://127.0.0.1:3001",
      fetch,
    });
    return { client, fetch };
  }

  it("returns the prover's proof once it proves the inputs' statement", async () => {
    expect(transferRequest.publicInputHash).toBe(runtimeProof.publicInputHash);
    const { client, fetch } = proving(runtimeProof.proof);
    await expect(client.proveTransferInputs(transferInputs())).resolves.toEqual(
      compressProof(parseProof(runtimeProof.proof)).toTransactProof(),
    );
    expect(String(fetch.mock.calls[0]?.[0])).toBe(
      "http://127.0.0.1:3001/prove/transfer_confidential_2_2",
    );
  });

  it("refuses a proof that does not prove the statement before returning it", async () => {
    const { ar, krs } = runtimeProof.proof;
    for (const answer of [
      { ...runtimeProof.proof, ar: krs, krs: ar },
      shared.proofs.find((vector) => vector.key === "merge_8_1.key")?.proof ?? {},
    ]) {
      const { client } = proving(answer);
      await expect(client.proveTransferInputs(transferInputs())).rejects.toMatchObject({
        code: "CLIENT_PROOF_VERIFICATION",
        details: { check: "pairing" },
      });
    }
    const { client } = proving(runtimeProof.proof);
    await expect(
      client.proveTransferInputs({ ...transferInputs(), publicInputHash: asField(1n) }),
    ).rejects.toMatchObject({ code: "CLIENT_PROOF_VERIFICATION", details: { check: "pairing" } });
  });
});
