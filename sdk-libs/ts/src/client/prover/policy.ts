import { getBase58Decoder } from "@solana/kit";
import { bytesToHex } from "@noble/hashes/utils.js";
import { wireDecoder } from "../../interface/decode.js";
import { treeAddress } from "../../interface/pda/index.js";
import {
  STATE_ROOT_HISTORY_CAPACITY,
  NULLIFIER_TREE_ROOT_HISTORY_CAPACITY,
} from "../../interface/state.js";
import { equal as equalBytes } from "../../transaction/internal.js";
import { ClientError } from "../error.js";
import { checkedBytes, bytesField } from "../internal.js";
import type { IndexedPolicyInputs, IndexedDepositInputs, IndexedRegistry } from "../ports.js";
import { contextSlotJson } from "./indexed.js";
import type { Bytes32 } from "../../interface/types.js";

const invalid = (): ClientError => new ClientError("CLIENT_INVALID_PROOF_INPUTS");
/** The policy statement chain less the folded audit prefix and the tree commitment. */
const POLICY_PUBLIC_INPUTS = 8;
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
  if (
    inputs.policy.twoByThree === true ||
    !["custom-ring-policy", "custom-ring-delegate-policy"].includes(inputs.circuit) ||
    inputs.trees.length < 1 ||
    inputs.trees.length > 5 ||
    inputs.publicInputs.length !== POLICY_PUBLIC_INPUTS
  )
    throw invalid();
  if (inputs.circuit === "custom-ring-delegate-policy" && inputs.policy.limits.approvalRequired)
    throw invalid();
  const prepared = omit(serialized, [
    "treeSlots",
    "publicInputHash",
    "subjects",
    "foreignSubjects",
  ]);
  prepared["outputs"] = decoder
    .list(prepared["outputs"], "outputs")
    .map((output) => omit(output, ["ctHash"]));
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
  const registry = inputs.registry;
  const wrapped =
    inputs.circuit === "custom-ring-policy"
      ? prepared
      : { circuitType: inputs.circuit, policy: prepared };
  return {
    ...contextSlotJson(inputs.minContextSlot),
    circuitType: inputs.circuit,
    prepared: wrapped,
    trees,
    publicInputs: inputs.publicInputs.map(hex),
    registry: registryEnvelope(registry, inputs.policy.memberRegistryRoot),
    ...(inputs.foreignRegistry === undefined
      ? {}
      : { foreignRegistry: registryEnvelope(inputs.foreignRegistry, inputs.policy.foreignRoot) }),
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
    registry.nextIndex > 1n << 20n ||
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
  return {
    circuitType: "custom-ring-deposit",
    prepared: omit(serialized, ["members", "ctHashes"]),
    publicInputs: [hex(inputs.deposit.publicInputHash)],
    registry: registryEnvelope(inputs.registry, inputs.deposit.memberRegistryRoot),
    ...contextSlotJson(inputs.minContextSlot),
  };
}

export function snapshotPolicyInputs(inputs: IndexedPolicyInputs): IndexedPolicyInputs {
  return {
    ...inputs,
    registry: { ...inputs.registry, root: checkedBytes(inputs.registry.root, 32, "registry root") },
    ...(inputs.foreignRegistry === undefined
      ? {}
      : {
          foreignRegistry: {
            ...inputs.foreignRegistry,
            root: checkedBytes(inputs.foreignRegistry.root, 32, "foreign root"),
          },
        }),
    trees: inputs.trees.map((tree) => ({
      ...tree,
      utxoRoot: checkedBytes(tree.utxoRoot, 32, "state root"),
      nullifierRoot: checkedBytes(tree.nullifierRoot, 32, "nullifier root"),
    })),
    publicInputs: inputs.publicInputs.map((value) => checkedBytes(value, 32, "public input")),
  };
}
