import type { ChainReader, ProofReader, Prover } from "../client/ports.js";
import { bytesField, bytesToBigInt } from "../client/internal.js";
import {
  NULLIFIER_TREE_HEIGHT,
  STATE_TREE_HEIGHT,
  asField,
  signerIdentity,
  transferPublicInputHash,
  treeSlotFields,
} from "../client/prover/assembly.js";
import type {
  CircuitUtxo,
  TransferInput,
  TransferInputs,
  TransferOutput,
} from "../client/prover/types.js";
import type { NonInclusionProof } from "../client/rpc.js";
import { externalDataHash } from "../interface/external-data-hash.js";
import { addressBytes } from "../interface/internal.js";
import { ADDRESS_DOMAIN, InstructionTag, UTXO_DOMAIN } from "../interface/program.js";
import { inputTreeSlots, type TreeSlot } from "../interface/tree-slot.js";
import type {
  Address,
  Bytes16,
  Bytes31,
  Bytes32,
  Bytes33,
  RequestContext,
  TransactProof,
} from "../interface/types.js";
import { randomBytes } from "../keypair/bytes.js";
import { NullifierKey } from "../keypair/nullifier-key.js";
import {
  outputBlindingSeed,
  privateTxBlinding,
  transactOutputBlinding,
} from "../keypair/transact/index.js";
import { privateTxHash } from "../transaction/instructions/transact.js";
import { U64_MAX, ZERO_32 } from "../transaction/internal.js";
import type { TreeId } from "../transaction/utxo.js";

import { ringPolicyNamespaceAddress } from "./config.js";
import { checkedEntryProof, readEntriesTreeHeads } from "./entries-tree.js";
import {
  RingListNamespace,
  encodeListEntry,
  entrySeed,
  solAssetField,
  type ListEntry,
} from "./policy.js";

export type RingEntryProofClient = Pick<ChainReader, "getAccount"> &
  Pick<ProofReader, "getMerkleProofs" | "getNonInclusionProofs"> &
  Pick<Prover, "proveTransferInputs">;

/** An entry before the proof derives its blinding, Rust `EntryDraft`. */
export type ListEntryDraft = Omit<ListEntry, "blinding">;

export interface RingEntryTransitionInput {
  readonly client: RingEntryProofClient;
  readonly ringProgramId: Address;
  readonly entriesTree: Address;
  readonly entriesTreeId: TreeId;
  readonly payer: Address;
  readonly entry: ListEntryDraft;
  /** Absent for a claim. */
  readonly spent?: ListEntry;
}

export interface RingEntryProof {
  readonly proof: TransactProof;
  readonly utxoTreeRootIndex: number;
  readonly nullifierTreeRootIndex: number;
  /** Derives the writable nullifier account the instruction takes. */
  readonly nullifier: Bytes32;
  /** The program folds it into the private transaction hash, the record never carries it. */
  readonly privateTxBlinding: Bytes32;
}

export interface RingEntryTransition {
  /** The draft with the blinding SPP derived from the spend. */
  readonly entry: ListEntry;
  readonly proof: RingEntryProof;
}

/** Mirrors Rust `EntryWitness::prove`, a claim spends the address slot, an update the live leaf. */
export async function proveRingEntryTransition(
  input: RingEntryTransitionInput,
  context?: RequestContext,
): Promise<RingEntryTransition> {
  const namespace = await ringPolicyNamespaceAddress(input.ringProgramId);
  const listNamespace = RingListNamespace.of(namespace, input.entriesTreeId);
  const slot = entrySlot(listNamespace, input.entry, input.spent);
  const [absence, state] = await Promise.all([
    nonInclusionProof(input, slot.nullifier, context),
    slot.spentHash === undefined
      ? headState(input, context)
      : spentLeaf(input, slot.spentHash, context),
  ]);
  const {
    entry,
    inputs,
    privateTxBlinding: blinding,
  } = transitionInputs(slot, {
    namespace,
    entriesTreeId: input.entriesTreeId,
    payer: input.payer,
    entry: input.entry,
    state,
    absence,
    blindingSeed: blindingSeed(),
  });
  const proof = await input.client.proveTransferInputs(inputs, context);
  return Object.freeze({
    entry,
    proof: Object.freeze({
      proof,
      utxoTreeRootIndex: state.rootIndex,
      nullifierTreeRootIndex: absence.rootIndex,
      nullifier: slot.nullifier,
      privateTxBlinding: blinding,
    }),
  });
}

/** The state leaf the input spends, a claim opens the current head with a zero path. */
export interface RingEntryStateLeaf {
  readonly root: Bytes32;
  readonly rootIndex: number;
  readonly path: readonly Bytes32[];
  readonly leafIndex: bigint;
}

export interface RingEntryTransitionProofInputs {
  readonly namespace: Address;
  readonly entriesTreeId: TreeId;
  readonly payer: Address;
  readonly entry: ListEntryDraft;
  readonly spent?: ListEntry;
  readonly state: RingEntryStateLeaf;
  readonly absence: NonInclusionProof;
  /** The private seed every blinding of the transition derives from. */
  readonly blindingSeed: Bytes32;
}

export interface RingEntryTransitionInputs {
  readonly entry: ListEntry;
  readonly inputs: TransferInputs;
  readonly nullifier: Bytes32;
  readonly privateTxBlinding: Bytes32;
}

/** The payer and the namespace sign. */
export function ringEntryTransitionInputs(
  input: RingEntryTransitionProofInputs,
): RingEntryTransitionInputs {
  const namespace = RingListNamespace.of(input.namespace, input.entriesTreeId);
  const slot = entrySlot(namespace, input.entry, input.spent);
  return Object.freeze({ ...transitionInputs(slot, input), nullifier: slot.nullifier });
}

function transitionInputs(
  slot: InputSlot,
  input: Omit<RingEntryTransitionProofInputs, "spent">,
): Omit<RingEntryTransitionInputs, "nullifier"> {
  const namespace = RingListNamespace.of(input.namespace, input.entriesTreeId);
  // SPP derives every output blinding from the first nullifier, the record publishes it.
  const outputSeed = outputBlindingSeed(slot.nullifier, input.blindingSeed);
  const entry: ListEntry = Object.freeze({
    ...input.entry,
    blinding: transactOutputBlinding(slot.nullifier, outputSeed, 0),
  });
  const txBlinding = privateTxBlinding(slot.nullifier, input.blindingSeed);
  const hashes = namespace.entryHashes(entry);
  const namespaceBytes = addressBytes(input.namespace, "namespace") as Bytes32;
  const external = externalDataHash({
    instructionDiscriminator: InstructionTag.transact,
    expiryUnixTs: U64_MAX,
    interfaceTransfers: [],
    txViewingPk: new Uint8Array(33) as Bytes33,
    salt: new Uint8Array(16) as Bytes16,
    outputs: [
      { utxoHash: hashes.utxoHash, ownerTag: namespaceBytes, data: encodeListEntry(entry) },
    ],
    messages: [],
  });
  const privateHash = privateTxHash({
    inputHashes: [slot.inputHash],
    outputHashes: [hashes.utxoHash],
    ...(slot.addressNullifier === undefined ? {} : { addressNullifiers: [slot.addressNullifier] }),
    externalDataHash: external,
    blinding: txBlinding,
  });
  const namespaceHash = signerIdentity(input.namespace);
  const payerHash = signerIdentity(input.payer);
  const inputTree: TreeSlot = Object.freeze({
    id: input.entriesTreeId,
    utxoRoot: input.state.root,
    nullifierRoot: input.absence.root,
  });
  const treeSlots = inputTreeSlots(inputTree);
  const publicInputHash = transferPublicInputHash({
    nullifiers: [bytesToBigInt(slot.nullifier)],
    outputHashes: [bytesToBigInt(hashes.utxoHash)],
    treeSlots,
    outputTreeId: input.entriesTreeId,
    privateTxHash: bytesToBigInt(privateHash),
    externalDataHash: bytesToBigInt(external),
    publicSlots: Array.from({ length: 6 }, () => 0n),
    ringProgramId: 0n,
    signerPublicKeyHashes: [payerHash, namespaceHash],
    allowDummyInputs: 1n,
    publishedOutputOwnerPublicKeyHashes: [namespaceHash],
  });
  const transferInput: TransferInput = Object.freeze({
    circuit: slot.circuit,
    isDummy: asField(0n),
    statePathElements: Object.freeze(
      input.state.path.map((item) => asField(bytesField(item, "state path element"))),
    ),
    statePathIndex: asField(input.state.leafIndex),
    nullifierLowValue: asField(bytesField(input.absence.lowElement, "low element")),
    nullifierNextValue: asField(bytesField(input.absence.highElement, "high element")),
    nullifierLowPathElements: Object.freeze(
      input.absence.path.map((item) => asField(bytesField(item, "nullifier path element"))),
    ),
    nullifierLowPathIndex: asField(input.absence.lowElementIndex),
    treeSlot: asField(0n),
    nullifier: asField(bytesField(slot.nullifier, "nullifier")),
    ownerPublicKeyHash: asField(namespaceHash),
    nullifierSecret: asField(0n),
  });
  const transferOutput: TransferOutput = Object.freeze({
    circuit: entryCircuitUtxo(namespace, entry, hashes.dataHash),
    isDummy: asField(0n),
    hash: asField(bytesField(hashes.utxoHash, "output hash")),
    ownerPublicKeyHash: asField(namespaceHash),
    nullifierPublicKey: asField(
      bytesField(
        NullifierKey.fromSecret(new Uint8Array(31) as Bytes31).publicKey(),
        "output nullifier public key",
      ),
    ),
  });
  const inputs: TransferInputs = Object.freeze({
    inputs: Object.freeze([transferInput]),
    outputs: Object.freeze([transferOutput]),
    treeSlots: Object.freeze(treeSlots.map(treeSlotFields)),
    outputTreeId: asField(BigInt(input.entriesTreeId)),
    externalDataHash: asField(bytesToBigInt(external)),
    privateTxHash: asField(bytesToBigInt(privateHash)),
    blindingSeed: asField(bytesField(input.blindingSeed, "blinding seed")),
    publicAssets: Object.freeze([asField(0n), asField(0n), asField(0n)]),
    publicAmounts: Object.freeze([asField(0n), asField(0n), asField(0n)]),
    ringProgramId: asField(0n),
    signerPublicKeyHashes: Object.freeze([asField(payerHash), asField(namespaceHash)]),
    allowDummyInputs: asField(1n),
    publishedOutputOwnerPublicKeyHashes: Object.freeze([asField(namespaceHash)]),
    publicInputHash: asField(publicInputHash),
  });
  return Object.freeze({ entry, inputs, privateTxBlinding: txBlinding });
}

/** A random field element, the top byte stays zero. */
function blindingSeed(): Bytes32 {
  const seed = new Uint8Array(32);
  seed.set(randomBytes(31), 1);
  return seed as Bytes32;
}

interface InputSlot {
  readonly circuit: CircuitUtxo;
  readonly inputHash: Bytes32;
  /** The address a claim inserts, the chain element of its slot. */
  readonly addressNullifier?: Bytes32;
  readonly nullifier: Bytes32;
  readonly spentHash?: Bytes32;
}

function entrySlot(
  namespace: RingListNamespace,
  entry: ListEntryDraft,
  spent: ListEntry | undefined,
): InputSlot {
  if (spent === undefined) {
    const seed = entrySeed(entry);
    const address = namespace.entryAddress(entry);
    return {
      circuit: circuitUtxo({
        domain: ADDRESS_DOMAIN,
        owner: namespace.ownerHash,
        asset: 0n,
        blinding: bytesToBigInt(seed),
        dataHash: 0n,
      }),
      inputHash: ZERO_32,
      addressNullifier: address,
      nullifier: address,
    };
  }
  const hashes = namespace.entryHashes(spent);
  return {
    circuit: entryCircuitUtxo(namespace, spent, hashes.dataHash),
    inputHash: hashes.utxoHash,
    nullifier: hashes.nullifier,
    spentHash: hashes.utxoHash,
  };
}

async function spentLeaf(
  input: RingEntryTransitionInput,
  spentHash: Bytes32,
  context: RequestContext | undefined,
): Promise<RingEntryStateLeaf> {
  const { proofs } = await input.client.getMerkleProofs(
    input.entriesTree,
    [spentHash],
    undefined,
    context,
  );
  const proof = checkedEntryProof(proofs.length === 1 ? proofs[0] : undefined, {
    entriesTree: input.entriesTree,
    leaf: spentHash,
    pathLength: STATE_TREE_HEIGHT,
  });
  return {
    root: proof.root,
    rootIndex: proof.rootIndex,
    path: proof.path,
    leafIndex: proof.leafIndex,
  };
}

async function nonInclusionProof(
  input: RingEntryTransitionInput,
  target: Bytes32,
  context: RequestContext | undefined,
): Promise<NonInclusionProof> {
  const { proofs } = await input.client.getNonInclusionProofs(
    input.entriesTree,
    [target],
    undefined,
    context,
  );
  return checkedEntryProof(proofs.length === 1 ? proofs[0] : undefined, {
    entriesTree: input.entriesTree,
    leaf: target,
    pathLength: NULLIFIER_TREE_HEIGHT,
  });
}

/** Mirrors Rust `read_state_root`, a claim opens the head with a zero path. */
async function headState(
  input: RingEntryTransitionInput,
  context: RequestContext | undefined,
): Promise<RingEntryStateLeaf> {
  const roots = await readEntriesTreeHeads(input.client, input.entriesTree, context);
  return {
    root: roots.stateRoot,
    rootIndex: roots.stateRootIndex,
    path: Array.from({ length: STATE_TREE_HEIGHT }, () => ZERO_32),
    leafIndex: 0n,
  };
}

function entryCircuitUtxo(
  namespace: RingListNamespace,
  entry: ListEntry,
  dataHash: Bytes32,
): CircuitUtxo {
  return circuitUtxo({
    domain: UTXO_DOMAIN,
    owner: namespace.ownerHash,
    asset: bytesToBigInt(solAssetField()),
    blinding: bytesToBigInt(entry.blinding),
    dataHash: bytesToBigInt(dataHash),
  });
}

function circuitUtxo(
  value: Readonly<{
    domain: number;
    owner: Bytes32;
    asset: bigint;
    blinding: bigint;
    dataHash: bigint;
  }>,
): CircuitUtxo {
  return Object.freeze({
    domain: asField(BigInt(value.domain)),
    owner: asField(bytesField(value.owner, "namespace owner")),
    asset: asField(value.asset),
    amount: asField(0n),
    blinding: asField(value.blinding),
    dataHash: asField(value.dataHash),
    ringDataHash: asField(0n),
    ringProgramId: asField(0n),
  });
}
