import type { ChainReader, ProofReader, Prover } from "../client/ports.js";
import { bytesField, bytesToBigInt, hashBytesBigInt } from "../client/internal.js";
import {
  NULLIFIER_TREE_HEIGHT,
  STATE_TREE_HEIGHT,
  asField,
  transferPublicInputHash,
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
import type {
  Address,
  Bytes16,
  Bytes31,
  Bytes32,
  Bytes33,
  RequestContext,
  TransactProof,
} from "../interface/types.js";
import { NullifierKey } from "../keypair/nullifier-key.js";
import { privateTxHash } from "../transaction/instructions/transact.js";
import { U64_MAX, ZERO_32 } from "../transaction/internal.js";

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

export interface RingEntryTransitionInput {
  readonly client: RingEntryProofClient;
  readonly ringProgramId: Address;
  readonly entriesTree: Address;
  readonly payer: Address;
  readonly entry: ListEntry;
  /** Absent for a claim. */
  readonly spent?: ListEntry;
}

export interface RingEntryProof {
  readonly proof: TransactProof;
  readonly utxoTreeRootIndex: number;
  readonly nullifierTreeRootIndex: number;
  /** Derives the writable nullifier account the instruction takes. */
  readonly nullifier: Bytes32;
}

/** Mirrors Rust `EntryWitness::prove`, a claim spends the address slot, an update the live leaf. */
export async function proveRingEntryTransition(
  input: RingEntryTransitionInput,
  context?: RequestContext,
): Promise<RingEntryProof> {
  const namespace = await ringPolicyNamespaceAddress(input.ringProgramId);
  const slot = entrySlot(RingListNamespace.of(namespace), input.entry, input.spent);
  const [absence, state] = await Promise.all([
    nonInclusionProof(input, slot.nullifier, context),
    slot.spentHash === undefined
      ? headState(input, context)
      : spentLeaf(input, slot.spentHash, context),
  ]);
  const inputs = transitionInputs(slot, {
    namespace,
    payer: input.payer,
    entry: input.entry,
    state,
    absence,
  });
  const proof = await input.client.proveTransferInputs(inputs, context);
  return Object.freeze({
    proof,
    utxoTreeRootIndex: state.rootIndex,
    nullifierTreeRootIndex: absence.rootIndex,
    nullifier: slot.nullifier,
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
  readonly payer: Address;
  readonly entry: ListEntry;
  readonly spent?: ListEntry;
  readonly state: RingEntryStateLeaf;
  readonly absence: NonInclusionProof;
}

/** The payer and the namespace sign. */
export function ringEntryTransitionInputs(
  input: RingEntryTransitionProofInputs,
): Readonly<{ inputs: TransferInputs; nullifier: Bytes32 }> {
  const slot = entrySlot(RingListNamespace.of(input.namespace), input.entry, input.spent);
  return Object.freeze({ inputs: transitionInputs(slot, input), nullifier: slot.nullifier });
}

function transitionInputs(
  slot: InputSlot,
  input: Omit<RingEntryTransitionProofInputs, "spent">,
): TransferInputs {
  const namespace = RingListNamespace.of(input.namespace);
  const hashes = namespace.entryHashes(input.entry);
  const namespaceBytes = addressBytes(input.namespace, "namespace") as Bytes32;
  const external = externalDataHash({
    instructionDiscriminator: InstructionTag.transact,
    expiryUnixTs: U64_MAX,
    interfaceTransfers: [],
    txViewingPk: new Uint8Array(33) as Bytes33,
    salt: new Uint8Array(16) as Bytes16,
    outputs: [
      { utxoHash: hashes.utxoHash, ownerTag: namespaceBytes, data: encodeListEntry(input.entry) },
    ],
    messages: [],
  });
  const privateHash = privateTxHash({
    inputHashes: [slot.inputHash],
    outputHashes: [hashes.utxoHash],
    ...(slot.addressHash === undefined ? {} : { addressHashes: [slot.addressHash] }),
    externalDataHash: external,
  });
  const namespaceHash = hashBytesBigInt(namespaceBytes);
  const payerHash = hashBytesBigInt(addressBytes(input.payer, "payer"));
  const publicInputHash = transferPublicInputHash({
    nullifiers: [bytesToBigInt(slot.nullifier)],
    outputHashes: [bytesToBigInt(hashes.utxoHash)],
    utxoRoots: [bytesToBigInt(input.state.root)],
    nullifierRoots: [bytesToBigInt(input.absence.root)],
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
    utxoTreeRoot: asField(bytesField(input.state.root, "state root")),
    nullifierTreeRoot: asField(bytesField(input.absence.root, "nullifier root")),
    nullifier: asField(bytesField(slot.nullifier, "nullifier")),
    ownerPublicKeyHash: asField(namespaceHash),
    nullifierSecret: asField(0n),
  });
  const transferOutput: TransferOutput = Object.freeze({
    circuit: entryCircuitUtxo(namespace, input.entry, hashes.dataHash),
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
  return Object.freeze({
    inputs: Object.freeze([transferInput]),
    outputs: Object.freeze([transferOutput]),
    externalDataHash: asField(bytesToBigInt(external)),
    privateTxHash: asField(bytesToBigInt(privateHash)),
    publicAssets: Object.freeze([asField(0n), asField(0n), asField(0n)]),
    publicAmounts: Object.freeze([asField(0n), asField(0n), asField(0n)]),
    ringProgramId: asField(0n),
    signerPublicKeyHashes: Object.freeze([asField(payerHash), asField(namespaceHash)]),
    allowDummyInputs: asField(1n),
    publishedOutputOwnerPublicKeyHashes: Object.freeze([asField(namespaceHash)]),
    publicInputHash: asField(publicInputHash),
  });
}

interface InputSlot {
  readonly circuit: CircuitUtxo;
  readonly inputHash: Bytes32;
  readonly addressHash?: Bytes32;
  readonly nullifier: Bytes32;
  readonly spentHash?: Bytes32;
}

function entrySlot(
  namespace: RingListNamespace,
  entry: ListEntry,
  spent: ListEntry | undefined,
): InputSlot {
  if (spent === undefined) {
    const seed = entrySeed(entry);
    return {
      circuit: circuitUtxo({
        domain: ADDRESS_DOMAIN,
        owner: namespace.ownerHash,
        asset: 0n,
        blinding: bytesToBigInt(seed),
        dataHash: 0n,
      }),
      inputHash: ZERO_32,
      addressHash: namespace.addressSlotHash(seed),
      nullifier: namespace.entryAddress(entry),
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
    blinding: entry.version,
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
