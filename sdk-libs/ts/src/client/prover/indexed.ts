import type { ExpectedProvingKey } from "../../interface/proving-keys.js";
import {
  STATE_ROOT_HISTORY_CAPACITY,
  NULLIFIER_TREE_ROOT_HISTORY_CAPACITY,
} from "../../interface/state.js";
import { getBase58Decoder } from "@solana/kit";
import { wireDecoder } from "../../interface/decode.js";
import { treeAddress } from "../../interface/pda/index.js";
import {
  inputTreeSlots,
  treeSlotsHashChain,
  NO_UTXO_ROOT,
  type TreeSlot,
} from "../../interface/tree-slot.js";
import { selectSppShape } from "../../interface/shape.js";
import type { Bytes32, RequestContext } from "../../interface/types.js";
import { hashChain } from "../../transaction/internal.js";
import type {
  IndexedPolicyInputs,
  IndexedProofAuthority,
  IndexedProofInputs,
  IndexedProofResult,
  IndexedTree,
  PreparedTransferInput,
  ProofResolution,
} from "../ports.js";
import { ClientError } from "../error.js";
import {
  BN254_MODULUS,
  bigintToBytes,
  bytesField,
  bytesToBigInt,
  checkedBytes,
  hasIndexedMethod,
} from "../internal.js";
import { asField, resolvedPublicInputHash, type InputTree } from "./assembly.js";
import type { CircuitUtxo, TransferOutput, Field, Proof } from "./types.js";
import { compressProof, parseCheckedProof } from "./proof.js";

const invalid = (): ClientError => new ClientError("CLIENT_INVALID_PROOF_INPUTS");
const unparsable = (): ClientError => new ClientError("CLIENT_PROOF_PARSE", { details: {} });
const requestDecoder = wireDecoder(invalid);
const resultDecoder = wireDecoder(unparsable);

export function checkIndexedAuthority(value: unknown): asserts value is IndexedProofAuthority {
  if (!hasIndexedMethod(value)) throw new ClientError("CLIENT_INVALID_PROOF_AUTHORITY");
}

/** Proves through a key holder the client does not trust, the result bound to `inputs`. */
export async function proveThroughAuthority(
  authority: unknown,
  inputs: IndexedProofInputs,
  context?: RequestContext,
): Promise<Readonly<{ proof: Proof; trees: readonly InputTree[] }>> {
  checkIndexedAuthority(authority);
  // The key holder edits only its own copy, never the statement checked below.
  const result: unknown = await authority.proveIndexed(decodeIndexedInputs(inputs), context);
  const decoded = resultDecoder.record(result, "result");
  return Object.freeze({
    proof: authorityProof(decoded["proof"]),
    trees: resolvedTrees(inputs, checkedResolution(decoded["resolution"], authorityField)),
  });
}

export function decodeIndexedInputs(value: unknown): IndexedProofInputs {
  const request = requestDecoder.record(value, "request");
  const circuit = request["circuit"];
  if (
    circuit !== "transfer" &&
    circuit !== "transferRing" &&
    circuit !== "transferRingAuthority" &&
    circuit !== "merge"
  )
    throw invalid();
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
  const minContextSlot = checkedContextSlot(request["minContextSlot"]);
  const envelope = {
    trees: requestDecoder.list(request["trees"], "trees").map((value) => {
      const tree = requestDecoder.record(value, "tree");
      return { tree: requestDecoder.address(tree["tree"], "tree"), id: u16(tree["id"], invalid) };
    }),
    lookups: requestDecoder.list(request["lookups"], "lookups").map((value) => {
      const lookup = requestDecoder.record(value, "lookup");
      return {
        treeSlot: u16(lookup["treeSlot"], invalid),
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
            cacheTreeId: field("cacheTreeId"),
            cacheReadHashChain: field("cacheReadHashChain"),
            cacheReadHashes: fields("cacheReadHashes"),
            cacheIsCached: fields("cacheIsCached"),
            cacheReadIndex: fields("cacheReadIndex"),
            publishedOutputOwnerPublicKeyHashes: fields("publishedOutputOwnerPublicKeyHashes"),
          },
        };
  checkStatement(result);
  return result;
}

/** The `/prove/indexed` body for a request `decodeIndexedInputs` returned. */
export function indexedRequestEnvelope(
  inputs: IndexedProofInputs,
  prepared: Readonly<Record<string, unknown>>,
): Readonly<Record<string, unknown>> {
  return {
    circuitType: prepared["circuitType"],
    prepared,
    trees: inputs.trees.map(({ tree, id }) => ({ tree, id })),
    inputs: inputs.lookups.map(({ treeSlot, commitment }) => ({
      treeSlot,
      commitment: commitment === null ? null : getBase58Decoder().decode(commitment),
    })),
    publicInputs: inputs.publicInputs.map((value) => `0x${value.toString(16)}`),
    ...contextSlotJson(inputs.minContextSlot),
  };
}

export function parseIndexedResponse(value: unknown, key: ExpectedProvingKey): IndexedProofResult {
  const proof = parseCheckedProof(value, key);
  const envelope = resultDecoder.record(value, "proof");
  const body = Object.hasOwn(envelope, "proof")
    ? resultDecoder.record(envelope["proof"], "proof")
    : envelope;
  return Object.freeze({ proof, resolution: checkedResolution(body["resolution"], wireField) });
}

/** A tree carries a state root exactly when an input opens a commitment in it. */
export function resolvedTrees(
  inputs: IndexedProofInputs,
  resolution: ProofResolution,
): readonly InputTree[] {
  bindResolution(resolution, inputs.trees, (slots) =>
    resolvedPublicInputHash(inputs.publicInputs, inputTreeSlots(slots)),
  );
  return Object.freeze(
    resolution.trees.map((tree, index) => {
      const opensState = opensAt(inputs.lookups, index, "commitment");
      if (
        opensState === (tree.utxoRootIndex === NO_UTXO_ROOT) ||
        (!opensState && bytesToBigInt(tree.utxoRoot) !== 0n)
      )
        throw unparsable();
      return Object.freeze({
        treeId: tree.id,
        slot: Object.freeze({
          id: tree.id,
          utxoRoot: tree.utxoRoot,
          nullifierRoot: tree.nullifierRoot,
        }),
        utxoRootIndex: tree.utxoRootIndex,
        nullifierRootIndex: tree.nullifierRootIndex,
      });
    }),
  );
}

/** A tree without a state or nullifier lookup keeps the root and position the client sent for it. */
export function checkPolicyResolution(
  inputs: IndexedPolicyInputs,
  resolution: ProofResolution,
): void {
  bindResolution(resolution, inputs.trees, (slots) =>
    bytesToBigInt(
      hashChain([
        ...inputs.publicInputs.slice(0, 1),
        treeSlotsHashChain(inputTreeSlots(slots)),
        ...inputs.publicInputs.slice(1),
      ]),
    ),
  );
  resolution.trees.forEach((tree, index) => {
    const sent = inputs.trees[index];
    if (
      sent === undefined ||
      tree.utxoRootIndex >= STATE_ROOT_HISTORY_CAPACITY ||
      (!opensAt(inputs.lookups, index, "commitment") &&
        (bytesToBigInt(tree.utxoRoot) !== bytesToBigInt(sent.utxoRoot) ||
          tree.utxoRootIndex !== sent.utxoRootIndex)) ||
      (!opensAt(inputs.lookups, index, "nullifier") &&
        (bytesToBigInt(tree.nullifierRoot) !== bytesToBigInt(sent.nullifierRoot) ||
          tree.nullifierRootIndex !== sent.nullifierRootIndex))
    )
      throw unparsable();
  });
}

/** A deposit resolves no tree, its statement is the hash the request carries. */
export function checkDepositResolution(
  publicInputHash: Bytes32,
  resolution: ProofResolution,
): void {
  bindResolution(resolution, [], () => bytesToBigInt(publicInputHash));
}

export function contextSlotJson(slot: unknown): Readonly<{ minContextSlot?: number }> {
  const checked = checkedContextSlot(slot);
  return checked === undefined ? {} : { minContextSlot: Number(checked) };
}

/** A slot the prover's JSON number carries exactly. */
export function checkedContextSlot(slot: unknown): bigint | undefined {
  if (slot === undefined) return undefined;
  if (typeof slot !== "bigint" || slot < 0n || slot > BigInt(Number.MAX_SAFE_INTEGER))
    throw invalid();
  return slot;
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

/** Rejects a request the prover would refuse or resolve against other trees. */
function checkStatement(inputs: IndexedProofInputs): void {
  if (
    inputs.trees.length < 1 ||
    inputs.trees.length > 2 ||
    inputs.lookups.length !== inputs.payload.inputs.length ||
    inputs.publicInputs.length !==
      (inputs.circuit === "merge" ? 8 : inputs.circuit === "transferRingAuthority" ? 14 : 17)
  )
    throw invalid();
  if (inputs.circuit === "merge") {
    if (inputs.payload.inputs.length !== 8 && inputs.payload.inputs.length !== 36) throw invalid();
  } else {
    if (
      inputs.payload.cacheIsCached.length !== 0 &&
      inputs.payload.cacheIsCached.length !== inputs.payload.inputs.length
    )
      throw invalid();
    const shape = selectSppShape(inputs.payload.inputs.length, inputs.payload.outputs.length);
    if (
      shape.inputs !== inputs.payload.inputs.length ||
      shape.outputs !== inputs.payload.outputs.length
    )
      throw invalid();
  }
  inputs.trees.forEach((tree, index) => {
    if (
      tree.tree !== treeAddress(tree.id) ||
      inputs.trees.slice(0, index).some((previous) => previous.id === tree.id)
    )
      throw invalid();
  });
  const used = new Set<number>();
  let previous = -1;
  inputs.lookups.forEach((lookup, index) => {
    const input = inputs.payload.inputs[index];
    const cached = inputs.circuit === "merge" ? 0n : (inputs.payload.cacheIsCached[index] ?? 0n);
    if (
      (cached !== 0n && cached !== 1n) ||
      (cached === 1n && (input?.isDummy !== 0n || inputs.circuit === "transferRingAuthority"))
    )
      throw invalid();
    if (
      input === undefined ||
      lookup.treeSlot < previous ||
      lookup.treeSlot >= inputs.trees.length ||
      BigInt(lookup.treeSlot) !== input.treeSlot ||
      (input.isDummy !== 0n && input.isDummy !== 1n) ||
      (lookup.commitment === null) !== (input.isDummy === 1n || cached === 1n)
    )
      throw invalid();
    if (lookup.treeSlot !== previous && input.isDummy === 1n) throw invalid();
    if (lookup.commitment !== null) bytesField(lookup.commitment, "commitment");
    previous = lookup.treeSlot;
    used.add(lookup.treeSlot);
  });
  if (used.size !== inputs.trees.length) throw invalid();
}

/** The requested trees in order, their slots reproducing the statement the caller authorized. */
function bindResolution(
  resolution: ProofResolution,
  requested: readonly IndexedTree[],
  statement: (slots: readonly TreeSlot[]) => bigint,
): void {
  if (
    resolution.trees.length !== requested.length ||
    resolution.trees.some(
      (tree, index) => tree.tree !== requested[index]?.tree || tree.id !== requested[index]?.id,
    )
  )
    throw unparsable();
  const slots = resolution.trees.map(({ id, utxoRoot, nullifierRoot }) => ({
    id,
    utxoRoot,
    nullifierRoot,
  }));
  if (statement(slots) !== bytesToBigInt(resolution.publicInputHash)) throw unparsable();
}

function checkedResolution(value: unknown, root: (value: unknown) => Bytes32): ProofResolution {
  const raw = resultDecoder.record(value, "resolution");
  const trees = resultDecoder.list(raw["trees"], "trees").map((value) => {
    const tree = resultDecoder.record(value, "tree");
    return Object.freeze({
      tree: resultDecoder.address(tree["tree"], "tree"),
      id: u16(tree["id"], unparsable),
      utxoRoot: root(tree["utxoRoot"]),
      nullifierRoot: root(tree["nullifierRoot"]),
      utxoRootIndex:
        tree["utxoRootIndex"] === NO_UTXO_ROOT
          ? NO_UTXO_ROOT
          : rootIndex(tree["utxoRootIndex"], STATE_ROOT_HISTORY_CAPACITY),
      nullifierRootIndex: rootIndex(
        tree["nullifierRootIndex"],
        NULLIFIER_TREE_ROOT_HISTORY_CAPACITY,
      ),
    });
  });
  return Object.freeze({
    trees: Object.freeze(trees),
    publicInputHash: root(raw["publicInputHash"]),
  });
}

function authorityProof(value: unknown): Proof {
  const raw = resultDecoder.record(value, "proof");
  if ((raw["commitment"] === undefined) !== (raw["commitmentPok"] === undefined))
    throw unparsable();
  const proof: Proof = {
    a: checkedBytes(raw["a"], 64, "proof.a"),
    b: checkedBytes(raw["b"], 128, "proof.b"),
    c: checkedBytes(raw["c"], 64, "proof.c"),
    ...(raw["commitment"] === undefined
      ? {}
      : { commitment: checkedBytes(raw["commitment"], 64, "proof.commitment") }),
    ...(raw["commitmentPok"] === undefined
      ? {}
      : { commitmentPok: checkedBytes(raw["commitmentPok"], 64, "proof.commitmentPok") }),
  };
  compressProof(proof);
  return proof;
}

function wireField(value: unknown): Bytes32 {
  if (typeof value !== "string" || !/^0x[0-9a-f]{1,64}$/u.test(value)) throw unparsable();
  return canonicalField(BigInt(value));
}

function authorityField(value: unknown): Bytes32 {
  if (!(value instanceof Uint8Array) || value.length !== 32) throw unparsable();
  return canonicalField(bytesToBigInt(value));
}

/** A value at or above the modulus aliases a smaller field element. */
function canonicalField(value: bigint): Bytes32 {
  if (value >= BN254_MODULUS) throw unparsable();
  return checkedBytes(bigintToBytes(value, "root"), 32, "root");
}

function u16(value: unknown, fail: () => ClientError): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > 0xffff)
    throw fail();
  return value;
}

function opensAt<Kind extends "commitment" | "nullifier">(
  lookups: readonly Readonly<Record<Kind, Uint8Array | null> & { treeSlot: number }>[],
  index: number,
  kind: Kind,
): boolean {
  return lookups.some((lookup) => lookup.treeSlot === index && lookup[kind] !== null);
}

function rootIndex(value: unknown, capacity: number): number {
  const index = u16(value, unparsable);
  if (index >= capacity) throw unparsable();
  return index;
}
