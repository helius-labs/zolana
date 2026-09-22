import {
  STATE_ROOT_HISTORY_CAPACITY,
  NULLIFIER_TREE_ROOT_HISTORY_CAPACITY,
} from "../../interface/state.js";
import { getBase58Decoder } from "@solana/kit";
import { wireDecoder } from "../../interface/decode.js";
import { treeAddress } from "../../interface/pda/index.js";
import { inputTreeSlots } from "../../interface/tree-slot.js";
import { selectSppShape } from "../../interface/shape.js";
import type { Bytes32, RequestContext } from "../../interface/types.js";
import type {
  IndexedProofAuthority,
  IndexedProofInputs,
  IndexedProofResult,
  ProofResolution,
} from "../ports.js";
import { ClientError } from "../error.js";
import { BN254_MODULUS, bigintToBytes, bytesField, checkedBytes, field } from "../internal.js";
import { resolvedPublicInputHash, type InputTree } from "./assembly.js";
import type { CircuitUtxo, TransferOutput, Field, Proof } from "./types.js";
import type { PreparedTransferInput } from "../ports.js";
import { asField } from "./assembly.js";
import { compressProof, parseProof } from "./proof.js";

const invalid = (): ClientError => new ClientError("CLIENT_INVALID_PROOF_INPUTS");
const decoder = wireDecoder(() => new ClientError("CLIENT_PROOF_PARSE", { details: {} }));

interface UncheckedIndexedAuthority {
  proveIndexed(inputs: IndexedProofInputs, context?: RequestContext): unknown;
}

function hasIndexedMethod(value: unknown): value is UncheckedIndexedAuthority {
  return (
    typeof value === "object" &&
    value !== null &&
    "proveIndexed" in value &&
    typeof value.proveIndexed === "function"
  );
}

export function indexedAuthority(value: unknown): IndexedProofAuthority {
  if (!hasIndexedMethod(value)) throw invalid();
  return {
    async proveIndexed(inputs, context) {
      const snapshot = decodeIndexedInputs(inputs);
      // 2. The key holder receives its own copy of the caller's public statement.
      const result: unknown = await value.proveIndexed(decodeIndexedInputs(snapshot), context);
      return decodeAuthorityResult(result, snapshot);
    },
  };
}

const requestDecoder = wireDecoder(invalid);

export function decodeIndexedInputs(value: unknown): IndexedProofInputs {
  const request = requestDecoder.record(value, "request");
  const circuit = request["circuit"];
  if (circuit !== "transfer" && circuit !== "transferRing" && circuit !== "merge") throw invalid();
  const payload = requestDecoder.record(request["payload"], "payload");
  if ("treeSlots" in payload || "publicInputHash" in payload) throw invalid();
  const field = (name: string): Field => requestField(payload[name]);
  const fields = (name: string): readonly Field[] =>
    requestDecoder.list(payload[name], name).map(requestField);
  const inputs = requestDecoder.list(payload["inputs"], "inputs").map(decodePreparedInput);
  const common = {
    inputs,
    outputTreeId: field("outputTreeId"),
    externalDataHash: field("externalDataHash"),
    privateTxHash: field("privateTxHash"),
    ringProgramId: field("ringProgramId"),
  };
  const minContextSlot = request["minContextSlot"];
  if (
    minContextSlot !== undefined &&
    (typeof minContextSlot !== "bigint" ||
      minContextSlot < 0n ||
      minContextSlot > BigInt(Number.MAX_SAFE_INTEGER))
  )
    throw invalid();
  const envelope = {
    trees: requestDecoder.list(request["trees"], "trees").map((value) => {
      const tree = requestDecoder.record(value, "tree");
      return { tree: requestDecoder.address(tree["tree"], "tree"), id: requestU16(tree["id"]) };
    }),
    lookups: requestDecoder.list(request["lookups"], "lookups").map((value) => {
      const lookup = requestDecoder.record(value, "lookup");
      return {
        treeSlot: requestU16(lookup["treeSlot"]),
        commitment:
          lookup["commitment"] === null
            ? null
            : checkedBytes(lookup["commitment"], 32, "commitment"),
      };
    }),
    publicInputs: requestDecoder.list(request["publicInputs"], "publicInputs").map(requestField),
    ...(minContextSlot === undefined ? {} : { minContextSlot }),
  };
  const result: IndexedProofInputs =
    circuit === "merge"
      ? {
          ...envelope,
          circuit,
          payload: {
            ...common,
            output: decodeOutput(payload["output"]),
            ownerPublicKeyHash: field("ownerPublicKeyHash"),
            userNullifierPublicKey: field("userNullifierPublicKey"),
            ...(payload["userNullifierSecret"] === undefined
              ? {}
              : { userNullifierSecret: field("userNullifierSecret") }),
            allowDummyInputs: field("allowDummyInputs"),
            outputRingDataHash: field("outputRingDataHash"),
          },
        }
      : {
          ...envelope,
          circuit,
          payload: {
            ...common,
            outputs: requestDecoder.list(payload["outputs"], "outputs").map(decodeOutput),
            blindingSeed: field("blindingSeed"),
            publicAssets: fields("publicAssets"),
            publicAmounts: fields("publicAmounts"),
            signerPublicKeyHashes: fields("signerPublicKeyHashes"),
            inputFlags: field("inputFlags"),
            publishedOutputOwnerPublicKeyHashes: fields("publishedOutputOwnerPublicKeyHashes"),
          },
        };
  indexedRequestEnvelope(result, {});
  return result;
}

function decodePreparedInput(value: unknown): PreparedTransferInput {
  const input = requestDecoder.record(value, "input");
  for (const key of [
    "statePathElements",
    "statePathIndex",
    "nullifierLowValue",
    "nullifierNextValue",
    "nullifierLowPathElements",
    "nullifierLowPathIndex",
  ]) {
    if (key in input) throw invalid();
  }
  return {
    circuit: decodeCircuit(input["circuit"]),
    isDummy: requestField(input["isDummy"]),
    treeSlot: requestField(input["treeSlot"]),
    nullifier: requestField(input["nullifier"]),
    ownerPublicKeyHash: requestField(input["ownerPublicKeyHash"]),
    ...(input["nullifierSecret"] === undefined
      ? {}
      : { nullifierSecret: requestField(input["nullifierSecret"]) }),
  };
}

function decodeCircuit(value: unknown): CircuitUtxo {
  const circuit = requestDecoder.record(value, "circuit");
  return {
    domain: requestField(circuit["domain"]),
    owner: requestField(circuit["owner"]),
    asset: requestField(circuit["asset"]),
    amount: requestField(circuit["amount"]),
    blinding: requestField(circuit["blinding"]),
    dataHash: requestField(circuit["dataHash"]),
    ringDataHash: requestField(circuit["ringDataHash"]),
    ringProgramId: requestField(circuit["ringProgramId"]),
  };
}

function decodeOutput(value: unknown): TransferOutput {
  const output = requestDecoder.record(value, "output");
  return {
    circuit: decodeCircuit(output["circuit"]),
    isDummy: requestField(output["isDummy"]),
    hash: requestField(output["hash"]),
    ownerPublicKeyHash: requestField(output["ownerPublicKeyHash"]),
    nullifierPublicKey: requestField(output["nullifierPublicKey"]),
  };
}

function requestField(value: unknown): Field {
  if (typeof value !== "bigint" || value < 0n || value >= BN254_MODULUS) throw invalid();
  return asField(value);
}

function requestU16(value: unknown): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > 0xffff)
    throw invalid();
  return value;
}

function decodeAuthorityResult(value: unknown, inputs: IndexedProofInputs): IndexedProofResult {
  const result = decoder.record(value, "result");
  const rawProof = decoder.record(result["proof"], "proof");
  if ((rawProof["commitment"] === undefined) !== (rawProof["commitmentPok"] === undefined))
    throw new ClientError("CLIENT_PROOF_PARSE", { details: {} });
  const proof: Proof = {
    a: checkedBytes(rawProof["a"], 64, "proof.a"),
    b: checkedBytes(rawProof["b"], 128, "proof.b"),
    c: checkedBytes(rawProof["c"], 64, "proof.c"),
    ...(rawProof["commitment"] === undefined
      ? {}
      : { commitment: checkedBytes(rawProof["commitment"], 64, "proof.commitment") }),
    ...(rawProof["commitmentPok"] === undefined
      ? {}
      : { commitmentPok: checkedBytes(rawProof["commitmentPok"], 64, "proof.commitmentPok") }),
  };
  compressProof(proof);
  const raw = decoder.record(result["resolution"], "resolution");
  const resolution = {
    publicInputHash: checkedBytes(raw["publicInputHash"], 32, "public input hash"),
    trees: decoder.list(raw["trees"], "trees").map((value) => {
      const tree = decoder.record(value, "tree");
      return {
        tree: decoder.address(tree["tree"], "tree"),
        id: u16(tree["id"]),
        utxoRoot: checkedBytes(tree["utxoRoot"], 32, "utxo root"),
        nullifierRoot: checkedBytes(tree["nullifierRoot"], 32, "nullifier root"),
        utxoRootIndex: rootIndex(tree["utxoRootIndex"], STATE_ROOT_HISTORY_CAPACITY),
        nullifierRootIndex: rootIndex(
          tree["nullifierRootIndex"],
          NULLIFIER_TREE_ROOT_HISTORY_CAPACITY,
        ),
      };
    }),
  };
  validateResolution(inputs, resolution);
  return { proof, resolution };
}

export function indexedRequestEnvelope(
  inputs: IndexedProofInputs,
  prepared: Readonly<Record<string, unknown>>,
): Readonly<Record<string, unknown>> {
  if (
    inputs.circuit !== "transfer" &&
    inputs.circuit !== "transferRing" &&
    inputs.circuit !== "merge"
  )
    throw invalid();
  if (
    inputs.trees.length < 1 ||
    inputs.trees.length > 2 ||
    inputs.lookups.length !== inputs.payload.inputs.length ||
    inputs.publicInputs.length !== (inputs.circuit === "merge" ? 7 : 15)
  )
    throw invalid();
  if (inputs.circuit === "merge") {
    if (inputs.payload.inputs.length !== 8 && inputs.payload.inputs.length !== 36) throw invalid();
  } else {
    const shape = selectSppShape(inputs.payload.inputs.length, inputs.payload.outputs.length);
    if (
      shape.inputs !== inputs.payload.inputs.length ||
      shape.outputs !== inputs.payload.outputs.length
    )
      throw invalid();
  }
  const trees = inputs.trees.map((tree, index) => {
    if (
      !Number.isInteger(tree.id) ||
      tree.id < 0 ||
      tree.id > 0xffff ||
      tree.tree !== treeAddress(tree.id) ||
      inputs.trees.slice(0, index).some((previous) => previous.id === tree.id)
    )
      throw invalid();
    return { tree: tree.tree, id: tree.id };
  });
  const used = new Set<number>();
  let previous = -1;
  const lookups = inputs.lookups.map((lookup, index) => {
    const input = inputs.payload.inputs[index];
    if (
      input === undefined ||
      !Number.isInteger(lookup.treeSlot) ||
      lookup.treeSlot < previous ||
      lookup.treeSlot < 0 ||
      lookup.treeSlot >= trees.length ||
      BigInt(lookup.treeSlot) !== input.treeSlot ||
      (input.isDummy !== 0n && input.isDummy !== 1n) ||
      (lookup.commitment === null) !== (input.isDummy === 1n)
    )
      throw invalid();
    if (lookup.treeSlot !== previous && lookup.commitment === null) throw invalid();
    if (
      "statePathElements" in input ||
      "treeSlots" in inputs.payload ||
      "publicInputHash" in inputs.payload
    )
      throw invalid();
    previous = lookup.treeSlot;
    used.add(lookup.treeSlot);
    const commitment =
      lookup.commitment === null ? null : checkedBytes(lookup.commitment, 32, "commitment");
    if (commitment !== null) bytesField(commitment, "commitment");
    return {
      treeSlot: lookup.treeSlot,
      commitment: commitment === null ? null : getBase58Decoder().decode(commitment),
    };
  });
  if (used.size !== trees.length) throw invalid();
  const slot = inputs.minContextSlot;
  if (
    slot !== undefined &&
    (typeof slot !== "bigint" || slot < 0n || slot > BigInt(Number.MAX_SAFE_INTEGER))
  )
    throw invalid();
  return {
    circuitType: prepared["circuitType"],
    prepared,
    trees,
    inputs: lookups,
    publicInputs: inputs.publicInputs.map(
      (value) => `0x${field(value, "public input").toString(16)}`,
    ),
    ...(slot === undefined ? {} : { minContextSlot: Number(slot) }),
  };
}

export function parseIndexedResult(value: unknown, inputs: IndexedProofInputs): IndexedProofResult {
  const envelope = decoder.record(value, "proof");
  const proof = Object.hasOwn(envelope, "proof")
    ? decoder.record(envelope["proof"], "proof")
    : envelope;
  const raw = decoder.record(proof["resolution"], "resolution");
  const trees = decoder.list(raw["trees"], "trees").map((value, index) => {
    const tree = decoder.record(value, "tree");
    const requested = inputs.trees[index];
    const id = u16(tree["id"]);
    const address = decoder.address(tree["tree"], "tree");
    if (requested === undefined || id !== requested.id || address !== requested.tree)
      throw new ClientError("CLIENT_PROOF_PARSE", { details: {} });
    return Object.freeze({
      tree: address,
      id,
      utxoRoot: fieldBytes(tree["utxoRoot"]),
      nullifierRoot: fieldBytes(tree["nullifierRoot"]),
      utxoRootIndex: rootIndex(tree["utxoRootIndex"], STATE_ROOT_HISTORY_CAPACITY),
      nullifierRootIndex: rootIndex(
        tree["nullifierRootIndex"],
        NULLIFIER_TREE_ROOT_HISTORY_CAPACITY,
      ),
    });
  });
  const resolution = Object.freeze({
    trees: Object.freeze(trees),
    publicInputHash: fieldBytes(raw["publicInputHash"]),
  });
  validateResolution(inputs, resolution);
  return Object.freeze({ proof: parseProof(value), resolution });
}

export function validateResolution(
  inputs: IndexedProofInputs,
  resolution: ProofResolution,
): readonly InputTree[] {
  if (resolution.trees.length !== inputs.trees.length)
    throw new ClientError("CLIENT_PROOF_PARSE", { details: {} });
  const trees = resolution.trees.map((tree, index) => {
    const requested = inputs.trees[index];
    if (requested === undefined || tree.id !== requested.id || tree.tree !== requested.tree)
      throw new ClientError("CLIENT_PROOF_PARSE", { details: {} });
    return Object.freeze({
      treeId: tree.id,
      slot: {
        id: tree.id,
        utxoRoot: checkedBytes(tree.utxoRoot, 32, "utxo root"),
        nullifierRoot: checkedBytes(tree.nullifierRoot, 32, "nullifier root"),
      },
      utxoRootIndex: rootIndex(tree.utxoRootIndex, STATE_ROOT_HISTORY_CAPACITY),
      nullifierRootIndex: rootIndex(tree.nullifierRootIndex, NULLIFIER_TREE_ROOT_HISTORY_CAPACITY),
    });
  });
  // 1. Returned roots must reproduce the public statement authorized by the caller.
  const expected = resolvedPublicInputHash(
    inputs.publicInputs,
    inputTreeSlots(trees.map((tree) => tree.slot)),
  );
  if (expected !== bytesField(resolution.publicInputHash, "public input hash"))
    throw new ClientError("CLIENT_PROOF_PARSE", { details: {} });
  return trees;
}

function u16(value: unknown): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > 0xffff)
    throw new ClientError("CLIENT_PROOF_PARSE", { details: {} });
  return value;
}

function fieldBytes(value: unknown): Bytes32 {
  if (typeof value !== "string" || !/^0x[0-9a-f]{1,64}$/u.test(value))
    throw new ClientError("CLIENT_PROOF_PARSE", { details: {} });
  const integer = BigInt(value);
  if (integer >= BN254_MODULUS) throw new ClientError("CLIENT_PROOF_PARSE", { details: {} });
  return checkedBytes(bigintToBytes(integer), 32, "field");
}

function rootIndex(value: unknown, capacity: number): number {
  const index = u16(value);
  if (index >= capacity) throw new ClientError("CLIENT_PROOF_PARSE", { details: {} });
  return index;
}
