import type { Address, Bytes31, Bytes32 } from "@zolana/interface";
import { NullifierKey, ShieldedKeypair, SigningKey, ViewingKey } from "@zolana/keypair";
import {
  PreparedMerge,
  PreparedMergeZone,
  ProofInputUtxo,
  SOL_MINT,
  Utxo,
  deriveBlinding,
} from "@zolana/transaction";
import { describe, expect, it } from "vitest";

import { createProofOutput } from "../../../transaction/src/utxo.js";
import { encodeBase58 } from "../../src/internal.js";
import { mergeProverRequest } from "../../src/prover/client.js";
import { assembleMergeWithProofs, assembleMergeZoneWithProofs } from "../../src/prover/merge.js";
import type { MergeAssembly } from "../../src/prover/merge.js";
import type { SpendProof } from "../../src/rpc.js";
import { bytes, hex } from "../helpers/prover-vectors.js";
import oracle from "../oracles/merge-v1.json" with { type: "json" };

/// Replays `sdk-libs/client/src/prover/ts_merge_oracle.rs`. The Rust generator
/// builds both merge rails through the production `MergeProver` /
/// `MergeZoneProver` and serializes each request with the same `pub(crate)`
/// `to_json_merge` / `to_json_merge_zone` the client sends, so a divergence in
/// the key set, a field name, the hex encoding, or any element of the
/// public-input chain fails here rather than at the prover.
const MERGE_INPUTS = 8;
const TREE = oracle.inputs.tree as Address;
const ZONE_PROGRAM = encodeBase58(bytes(oracle.inputs.zoneProgramIdBytes)) as Address;

interface Material {
  readonly signingPublicKey: ReturnType<ShieldedKeypair["signingPublicKey"]>;
  readonly viewingPublicKey: ReturnType<ShieldedKeypair["viewingPublicKey"]>;
  readonly nullifierKey: NullifierKey;
}

function keypair(): Readonly<{ keypair: ShieldedKeypair; nullifierKey: NullifierKey }> {
  const signing = SigningKey.fromBytes(bytes(oracle.inputs.signingSecretBytes) as Bytes32);
  const nullifierKey = NullifierKey.fromSigningKey(signing);
  return {
    keypair: ShieldedKeypair.fromKeys(
      signing,
      nullifierKey,
      ViewingKey.fromSeed(bytes(oracle.inputs.viewingSeedBytes) as Bytes32, 0),
    ),
    nullifierKey,
  };
}

function seed(): Bytes31 {
  return bytes(oracle.inputs.blindingSeedBytes) as Bytes31;
}

function inputs(
  owner: ShieldedKeypair,
  nullifierKey: NullifierKey,
  zoneProgramId?: Address,
): readonly ProofInputUtxo[] {
  const real = oracle.inputs.realInputAmounts.map(
    (amount, index) =>
      new ProofInputUtxo({
        utxo: new Utxo({
          owner: owner.signingPublicKey(),
          asset: SOL_MINT,
          amount: BigInt(amount),
          blinding: deriveBlinding(seed(), index),
          ...(zoneProgramId === undefined ? {} : { zoneProgramId }),
        }),
        nullifierKey,
      }),
  );
  const dummies = Array.from({ length: MERGE_INPUTS - real.length }, (_, index) =>
    ProofInputUtxo.dummy(deriveBlinding(seed(), real.length + index)),
  );
  return [...real, ...dummies];
}

/// Mirrors `spend_proofs` in the Rust generator: one tree for both proofs,
/// per-slot roots and root indexes, all-zero path elements.
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

function material(owner: ShieldedKeypair, nullifierKey: NullifierKey): Material {
  return {
    signingPublicKey: owner.signingPublicKey(),
    viewingPublicKey: owner.viewingPublicKey(),
    nullifierKey,
  };
}

function buildMerge(): MergeAssembly {
  const { keypair: owner, nullifierKey } = keypair();
  const slots = inputs(owner, nullifierKey);
  const prepared = new PreparedMerge({
    inputs: [...slots],
    output: createProofOutput({
      ownerAddress: owner.shieldedAddress(),
      asset: SOL_MINT,
      amount: BigInt(oracle.inputs.outputAmount),
      blinding: deriveBlinding(seed(), 2),
    }),
    expiryUnixTs: BigInt(oracle.expected.merge.expiryUnixTs),
    signingPublicKey: owner.signingPublicKey(),
    userViewingPublicKey: owner.viewingPublicKey(),
    txViewingSecret: bytes(oracle.inputs.txViewingSecretBytes) as Bytes32,
  });
  const proofs = slots.filter((input) => !input.isDummy()).map(spendProof);
  return assembleMergeWithProofs(prepared, material(owner, nullifierKey), proofs, TREE);
}

function buildMergeZone(): MergeAssembly {
  const { keypair: owner, nullifierKey } = keypair();
  const slots = inputs(owner, nullifierKey, ZONE_PROGRAM);
  const prepared = new PreparedMergeZone({
    inputs: [...slots],
    output: createProofOutput({
      ownerAddress: owner.shieldedAddress(),
      asset: SOL_MINT,
      amount: BigInt(oracle.inputs.outputAmount),
      blinding: deriveBlinding(seed(), 2),
      zoneProgramId: ZONE_PROGRAM,
    }),
    expiryUnixTs: BigInt(oracle.expected.mergeZone.expiryUnixTs),
    signingPublicKey: owner.signingPublicKey(),
    userViewingPublicKey: owner.viewingPublicKey(),
    txViewingSecret: bytes(oracle.inputs.txViewingSecretBytes) as Bytes32,
    zoneProgramId: ZONE_PROGRAM,
  });
  const proofs = slots.filter((input) => !input.isDummy()).map(spendProof);
  return assembleMergeZoneWithProofs(prepared, material(owner, nullifierKey), proofs, TREE);
}

const rails = [
  { name: "merge", expected: oracle.expected.merge, build: buildMerge, circuit: "merge" },
  {
    name: "merge-zone",
    expected: oracle.expected.mergeZone,
    build: buildMergeZone,
    circuit: "merge-zone",
  },
] as const;

describe("merge assembly against the Rust oracle", () => {
  for (const rail of rails) {
    describe(rail.name, () => {
      it("assembles the values Rust assembled", () => {
        const assembly = rail.build();
        expect(hex(assembly.publicInputHash)).toBe(rail.expected.publicInputHashBytes);
        expect(hex(assembly.outputHash)).toBe(rail.expected.outputHashBytes);
        expect(hex(assembly.privateTxHash)).toBe(rail.expected.privateTxHashBytes);
        expect(hex(assembly.externalDataHash)).toBe(rail.expected.externalDataHashBytes);
        expect(assembly.nullifiers.map((nullifier) => hex(nullifier))).toEqual(
          rail.expected.nullifierBytes,
        );
        expect(assembly.utxoTreeRootIndexes).toEqual(rail.expected.utxoTreeRootIndices);
        expect(assembly.nullifierTreeRootIndexes).toEqual(rail.expected.nullifierTreeRootIndices);
        expect(hex(assembly.ciphertext as Bytes32)).toBe(rail.expected.ciphertextBytes);
        expect(hex(assembly.txViewingPublicKey.toBytes())).toBe(rail.expected.txViewingPkBytes);
        expect(assembly.eddsaOwner).toBe(rail.expected.eddsaOwner);
      });

      it("sends the request body Rust serializes", () => {
        const body = mergeProverRequest(rail.build().proverInputs, rail.circuit);
        const expected = JSON.parse(rail.expected.requestBodyJson) as Record<string, unknown>;
        expect(body).toEqual(expected);
        // The Go server ignores field order, but a reordering means one of the
        // two serializers was edited without the other; the key set is the part
        // a typo breaks silently.
        expect(Object.keys(body)).toEqual(Object.keys(expected));
      });
    });
  }

  /// The zone binding is the only value tying a merge-zone proof to its zone.
  it("binds the zone rail to a nonzero zone field the default rail leaves at zero", () => {
    const defaultBody = mergeProverRequest(buildMerge().proverInputs, "merge");
    const zoneBody = mergeProverRequest(buildMergeZone().proverInputs, "merge-zone");
    expect(defaultBody["zoneProgramId"]).toBe("0x0");
    expect(zoneBody["zoneProgramId"]).not.toBe("0x0");
    expect(zoneBody["publicInputHash"]).not.toBe(defaultBody["publicInputHash"]);
  });

  /// Rust `MergeProofInputs` clears both hashes before plain-merge assembly. A
  /// hand-built prepared value that still carries them must normalize to the
  /// same public inputs the clean oracle recorded.
  it("clears nonzero data hashes on the plain rail to match the Rust oracle", () => {
    const { keypair: owner, nullifierKey } = keypair();
    const dataHash = new Uint8Array(32).fill(0x1f) as Bytes32;
    const zoneDataHash = new Uint8Array(32).fill(0x2e) as Bytes32;
    const slots = inputs(owner, nullifierKey).map((input) =>
      input.isDummy()
        ? input
        : new ProofInputUtxo({
            utxo: input.utxo,
            nullifierKey: input.nullifierKey,
            dataHash,
            zoneDataHash,
          }),
    );
    const normalized = slots.map((input) =>
      input.isDummy()
        ? input
        : new ProofInputUtxo({ utxo: input.utxo, nullifierKey: input.nullifierKey }),
    );
    const prepared = new PreparedMerge({
      inputs: [...slots],
      output: createProofOutput({
        ownerAddress: owner.shieldedAddress(),
        asset: SOL_MINT,
        amount: BigInt(oracle.inputs.outputAmount),
        blinding: deriveBlinding(seed(), 2),
      }),
      expiryUnixTs: BigInt(oracle.expected.merge.expiryUnixTs),
      signingPublicKey: owner.signingPublicKey(),
      userViewingPublicKey: owner.viewingPublicKey(),
      txViewingSecret: bytes(oracle.inputs.txViewingSecretBytes) as Bytes32,
    });
    const proofs = normalized.filter((input) => !input.isDummy()).map(spendProof);
    const assembly = assembleMergeWithProofs(prepared, material(owner, nullifierKey), proofs, TREE);
    expect(hex(assembly.publicInputHash)).toBe(oracle.expected.merge.publicInputHashBytes);
    expect(hex(assembly.privateTxHash)).toBe(oracle.expected.merge.privateTxHashBytes);
    expect(assembly.nullifiers.map((nullifier) => hex(nullifier))).toEqual(
      oracle.expected.merge.nullifierBytes,
    );
  });
});
