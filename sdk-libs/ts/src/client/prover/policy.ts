import { getBase58Decoder } from "@solana/kit";
import { bytesToHex } from "@noble/hashes/utils.js";
import { wireDecoder } from "../../interface/decode.js";
import { treeAddress } from "../../interface/pda/index.js";
import { inputTreeSlots, treeSlotsHashChain } from "../../interface/tree-slot.js";
import {
  STATE_ROOT_HISTORY_CAPACITY,
  NULLIFIER_TREE_ROOT_HISTORY_CAPACITY,
} from "../../interface/state.js";
import { hashChain, equal as equalBytes } from "../../transaction/internal.js";
import { ClientError } from "../error.js";
import { checkedBytes, bytesField } from "../internal.js";
import type {
  IndexedPolicyInputs,
  IndexedDepositInputs,
  IndexedRegistry,
  ProofResolution,
} from "../ports.js";
import type { Bytes32 } from "../../interface/types.js";

const invalid = (): ClientError => new ClientError("CLIENT_INVALID_PROOF_INPUTS");
const decoder = wireDecoder(invalid);
const hex = (value: Uint8Array): string => {
  const bytes = checkedBytes(value, 32, "field");
  bytesField(bytes, "field");
  return `0x${bytesToHex(bytes)}`;
};
const base58 = (value: Uint8Array): string => {
  hex(value);
  return getBase58Decoder().decode(value);
};
const omit = (value: unknown, names: readonly string[]): Record<string, unknown> =>
  Object.fromEntries(
    Object.entries(decoder.record(value, "prepared")).filter(([key]) => !names.includes(key)),
  );

export function indexedPolicyEnvelope(
  inputs: IndexedPolicyInputs,
  serialized: Readonly<Record<string, unknown>>,
): Readonly<Record<string, unknown>> {
  const slot = policyContextSlot(inputs.minContextSlot);
  const compressed = inputs.circuit === "custom-ring-compressed-policy";
  if (
    ![
      "custom-ring-policy",
      "custom-ring-compressed-policy",
      "custom-ring-delegate-policy",
    ].includes(inputs.circuit) ||
    inputs.trees.length < 1 ||
    inputs.trees.length > 5 ||
    inputs.lookups.length !== 10 ||
    inputs.publicInputs.length !== (compressed ? 20 : 19)
  )
    throw invalid();
  if (
    inputs.circuit === "custom-ring-delegate-policy" &&
    (inputs.policy.velocity.windowIndex !== 0n || inputs.policy.velocity.approvalRequired)
  )
    throw invalid();
  if (compressed !== (inputs.transactionSalt !== undefined)) throw invalid();
  const prepared = omit(serialized, ["treeSlots", "publicInputHash"]);
  prepared["answers"] = decoder.list(prepared["answers"], "answers").map((answer, index) => {
    const fact = decoder.record(answer, "answer");
    const lookup = inputs.lookups[index];
    if (
      lookup === undefined ||
      !Number.isInteger(lookup.treeSlot) ||
      lookup.treeSlot < 0 ||
      lookup.treeSlot >= inputs.trees.length ||
      fact["enabled"] !== (lookup.nullifier !== null) ||
      fact["treeSlot"] !== lookup.treeSlot ||
      (lookup.nullifier !== null &&
        (fact["absentBranch"] === 2) !== (lookup.commitment !== null)) ||
      (lookup.nullifier === null && lookup.commitment !== null)
    )
      throw invalid();
    return omit(fact, [
      "statePathElements",
      "statePathIndex",
      "nfPathElements",
      "nfPathIndex",
      "low",
      "next",
    ]);
  });
  prepared["outputs"] = decoder
    .list(prepared["outputs"], "outputs")
    .map((output) => omit(output, ["key"]));
  const trees = inputs.trees.map((tree, index) => {
    if (
      tree.tree !== treeAddress(tree.id) ||
      inputs.trees.slice(0, index).some((known) => known.id === tree.id) ||
      !Number.isInteger(tree.utxoRootIndex) ||
      tree.utxoRootIndex < 0 ||
      tree.utxoRootIndex >= STATE_ROOT_HISTORY_CAPACITY ||
      !Number.isInteger(tree.nullifierRootIndex) ||
      tree.nullifierRootIndex < 0 ||
      tree.nullifierRootIndex >= NULLIFIER_TREE_ROOT_HISTORY_CAPACITY ||
      bytesField(tree.utxoRoot, "state root") === 0n
    )
      throw invalid();
    return {
      tree: tree.tree,
      id: tree.id,
      fallback: { ...tree, utxoRoot: hex(tree.utxoRoot), nullifierRoot: hex(tree.nullifierRoot) },
    };
  });
  if ((inputs.registry === undefined) !== (inputs.policy.keyRegistryRoot === undefined))
    throw invalid();
  const registry = inputs.registry;
  const wrapped =
    inputs.circuit === "custom-ring-policy"
      ? prepared
      : {
          circuitType: inputs.circuit,
          policy: prepared,
          ...(inputs.transactionSalt === undefined
            ? {}
            : {
                transactionSalt: `0x${bytesToHex(checkedBytes(inputs.transactionSalt, 16, "transaction salt"))}`,
              }),
        };
  return {
    ...(slot === undefined ? {} : { minContextSlot: Number(slot) }),
    circuitType: inputs.circuit,
    prepared: wrapped,
    trees,
    inputs: inputs.lookups.map((lookup) => ({
      treeSlot: lookup.treeSlot,
      commitment: lookup.commitment === null ? null : base58(lookup.commitment),
      nullifier: lookup.nullifier === null ? null : base58(lookup.nullifier),
    })),
    publicInputs: inputs.publicInputs.map(hex),
    ...(registry === undefined
      ? {}
      : {
          registry: registryEnvelope(registry, inputs.policy.keyRegistryRoot),
        }),
  };
}

function registryEnvelope(
  registry: IndexedRegistry,
  root?: Bytes32,
): Readonly<Record<string, unknown>> {
  if (
    root === undefined ||
    typeof registry.nextIndex !== "bigint" ||
    registry.nextIndex < 1n ||
    registry.nextIndex > 1n << 40n ||
    !equalBytes(registry.root, root)
  )
    throw invalid();
  return {
    ringProgramId: decoder.address(registry.ringProgramId, "ring"),
    root: base58(registry.root),
    nextIndex: Number(registry.nextIndex),
  };
}

export function indexedDepositEnvelope(
  inputs: IndexedDepositInputs,
  serialized: Readonly<Record<string, unknown>>,
): Readonly<Record<string, unknown>> {
  const slot = policyContextSlot(inputs.minContextSlot);
  return {
    circuitType: "custom-ring-deposit",
    prepared: omit(serialized, ["keys"]),
    publicInputs: [hex(inputs.deposit.publicInputHash)],
    registry: registryEnvelope(inputs.registry, inputs.deposit.keyRegistryRoot),
    ...(slot === undefined ? {} : { minContextSlot: Number(slot) }),
  };
}

export function policyContextSlot(requested?: bigint, required?: bigint): bigint | undefined {
  for (const slot of [requested, required]) {
    if (
      slot !== undefined &&
      (typeof slot !== "bigint" || slot < 0n || slot > BigInt(Number.MAX_SAFE_INTEGER))
    )
      throw invalid();
  }
  if (requested === undefined) return required;
  return required === undefined || requested > required ? requested : required;
}

export function validatePolicyResolution(
  inputs: IndexedPolicyInputs,
  resolution: ProofResolution,
): void {
  if (resolution.trees.length !== inputs.trees.length) throw invalid();
  const slots = resolution.trees.map((tree, index) => {
    const expected = inputs.trees[index];
    const state = inputs.lookups.some(
      (lookup) => lookup.treeSlot === index && lookup.commitment !== null,
    );
    const nullifier = inputs.lookups.some(
      (lookup) => lookup.treeSlot === index && lookup.nullifier !== null,
    );
    if (
      expected === undefined ||
      tree.tree !== expected.tree ||
      tree.id !== expected.id ||
      tree.utxoRootIndex >= STATE_ROOT_HISTORY_CAPACITY ||
      (!state &&
        (!equalBytes(tree.utxoRoot, expected.utxoRoot) ||
          tree.utxoRootIndex !== expected.utxoRootIndex)) ||
      (!nullifier &&
        (!equalBytes(tree.nullifierRoot, expected.nullifierRoot) ||
          tree.nullifierRootIndex !== expected.nullifierRootIndex))
    )
      throw invalid();
    return { id: tree.id, utxoRoot: tree.utxoRoot, nullifierRoot: tree.nullifierRoot };
  });
  // 1. Resolved roots must reproduce the policy statement authorized by the client.
  const expected = hashChain([
    inputs.publicInputs[0]!,
    treeSlotsHashChain(inputTreeSlots(slots)),
    ...inputs.publicInputs.slice(1),
  ]);
  if (!equalBytes(expected, resolution.publicInputHash)) throw invalid();
}

export function snapshotPolicyInputs(inputs: IndexedPolicyInputs): IndexedPolicyInputs {
  return {
    ...inputs,
    trees: inputs.trees.map((tree) => ({
      ...tree,
      utxoRoot: checkedBytes(tree.utxoRoot, 32, "state root"),
      nullifierRoot: checkedBytes(tree.nullifierRoot, 32, "nullifier root"),
    })),
    lookups: inputs.lookups.map((lookup) => ({
      ...lookup,
      commitment:
        lookup.commitment === null ? null : checkedBytes(lookup.commitment, 32, "commitment"),
      nullifier: lookup.nullifier === null ? null : checkedBytes(lookup.nullifier, 32, "nullifier"),
    })),
    publicInputs: inputs.publicInputs.map((value) => checkedBytes(value, 32, "public input")),
  };
}
