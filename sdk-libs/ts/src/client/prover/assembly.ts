import { getAddressDecoder } from "@solana/kit";

import type {
  Address,
  Bytes32,
  CircuitId,
  TransactInstructionData,
  TransactProof,
} from "../../interface/types.js";
import { DUMMY_DOMAIN, UTXO_DOMAIN } from "../../interface/program.js";
import {
  RING_AUTHORITY_MAX_WIDTH,
  selectSppShape,
  signerWidth,
  type Shape,
} from "../../interface/shape.js";
import { treeAddress } from "../../interface/pda/index.js";
import {
  MAX_INPUT_TREES,
  inputTreeSlots,
  treeIdField,
  treeSlotsHashChain,
  type TreeSlot,
} from "../../interface/tree-slot.js";
import { solanaOwnerIdentity } from "../../hasher/index.js";
import { SppProofInputs, type ExternalData } from "../../transaction/instructions/transact.js";
import { EncryptedScheme } from "../../transaction/serialization/codecs.js";
import {
  ProofInputUtxo,
  transactOutputBlinding,
  type ProofOutputUtxo,
  type TreeId,
} from "../../transaction/utxo.js";
import { SOL_MINT } from "../../transaction/asset.js";

import type {
  IndexedProofInputs,
  PreparedTransferInput,
  PreparedTransferInputs,
} from "../ports.js";
import { ClientError, fromClientCause } from "../error.js";
import {
  BN254_MODULUS,
  addressBytes,
  bigintToBytes,
  bytesField,
  bytesToBigInt,
  checkedBytes,
  field,
  hashChain4,
  hashBytesBigInt,
  inputFlags,
  poseidon,
  rightHashChain,
} from "../internal.js";
import type { NonInclusionProof, SpendProof } from "../rpc.js";
import { RING_INPUT_SLOTS, RING_OUTPUT_SLOTS } from "./types.js";
import type {
  AssembledTransfer,
  CircuitUtxo,
  CustomRingOpening,
  Field,
  InputRootIndexes,
  ProverInputs,
  TransferCircuit,
  TransferInput,
  TransferInputs,
  TransferOutput,
  TreeSlotFields,
} from "./types.js";

export const STATE_TREE_HEIGHT = 32;
export const NULLIFIER_TREE_HEIGHT = 40;
const ZERO_PROOF = Object.freeze({
  a: new Uint8Array(32),
  b: new Uint8Array(64),
  c: new Uint8Array(32),
}) as TransactProof;

let lastResolvedHash:
  | Readonly<{
      fields: readonly bigint[];
      trees: readonly TreeSlot[];
      hash: bigint;
    }>
  | undefined;

/** Unique non-payer Ed25519 input owners in first-input order, mirrors Rust `owner_signer_pubkeys`. */
export function ownerSignerAddresses(
  inputs: readonly ProofInputUtxo[],
  payer: Address,
): readonly Address[] {
  const seen = new Set<string>();
  const signers: Address[] = [];
  for (const input of inputs) {
    if (input.isDummy() || input.utxo.owner.signatureType() === "p256") continue;
    const address = getAddressDecoder().decode(input.utxo.owner.confidentialViewTag());
    if (address === payer || seen.has(address)) continue;
    seen.add(address);
    signers.push(address);
  }
  return Object.freeze(signers);
}

/** The tagged identity a Solana signer enters the proof's signer chain as. */
export function signerIdentity(address: Address): bigint {
  return bytesToBigInt(solanaOwnerIdentity(addressBytes(address)));
}

/** Selects owner and signer commitments for each transaction rail. */
interface CircuitPlan {
  readonly ring: Address | undefined;
  readonly authority: boolean;
  readonly prover: ProverInputs["circuit"];
  readonly data: CircuitId["kind"];
  readonly signerSlots: number;
  readonly owners: "every" | "confidentialMarked" | "none";
}

function circuitPlan(circuit: TransferCircuit, shape: Shape): CircuitPlan {
  switch (circuit.kind) {
    case "confidential":
      return {
        ring: undefined,
        authority: false,
        prover: "transfer",
        data: "confidentialEddsa",
        signerSlots: signerWidth(shape),
        owners: "every",
      };
    case "ring":
      return {
        ring: circuit.ring,
        authority: false,
        prover: "transferRing",
        data: "ringEddsa",
        signerSlots: signerWidth(shape),
        owners: "confidentialMarked",
      };
    case "ringAuthority":
      return {
        ring: circuit.ring,
        authority: true,
        prover: "transferRingAuthority",
        data: "ringAuthority",
        signerSlots: 1,
        owners: "none",
      };
  }
}

/** The authority rail forbids default ring inputs and outputs. */
export function assemble(
  proofInputs: SppProofInputs,
  spendProofs: readonly SpendProof[],
  dummyNullifierProofs: readonly NonInclusionProof[] = [],
  circuit: TransferCircuit = { kind: "confidential" },
): AssembledTransfer {
  try {
    return assembleUnchecked(proofInputs, spendProofs, dummyNullifierProofs, circuit);
  } catch (cause) {
    throw fromClientCause(cause);
  }
}

interface PreparedTransferAssembly<
  C extends ProverInputs["circuit"] = "transfer" | "transferRing",
> {
  readonly inputs: Omit<IndexedProofInputs, "circuit" | "payload"> & {
    readonly circuit: C;
    readonly payload: PreparedTransferInputs;
  };
  finish(trees: readonly InputTree[]): Omit<AssembledTransfer, "proverInputs">;
}

export function prepareTransfer(
  proofInputs: SppProofInputs,
  ring?: Address,
): PreparedTransferAssembly {
  try {
    const slots = prepareSlots(proofInputs.inputUtxos, (input) =>
      bytesField(input.utxo.owner.ownerProofInputHash(), "owner public key"),
    );
    const prepared = prepareTransferUnchecked(
      proofInputs,
      slots,
      ring === undefined ? { kind: "confidential" } : { kind: "ring", ring },
    );
    const { inputs } = prepared;
    if (inputs.circuit === "transferRingAuthority") {
      throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
    }
    return Object.freeze({
      ...prepared,
      inputs: Object.freeze({ ...inputs, circuit: inputs.circuit }),
    });
  } catch (cause) {
    throw fromClientCause(cause);
  }
}

function assembleUnchecked(
  proofInputs: SppProofInputs,
  spendProofs: readonly SpendProof[],
  dummyNullifierProofs: readonly NonInclusionProof[],
  circuit: TransferCircuit,
): AssembledTransfer {
  const slots = assembleSlots(proofInputs, spendProofs, dummyNullifierProofs, (input) =>
    bytesField(input.utxo.owner.ownerProofInputHash(), "owner public key"),
  );
  const prepared = prepareTransferUnchecked(proofInputs, slots, circuit);
  const complete = prepared.finish(slots.inputTrees);
  return Object.freeze({
    ...complete,
    proverInputs: Object.freeze({
      circuit: prepared.inputs.circuit,
      payload: Object.freeze({
        ...prepared.inputs.payload,
        inputs: slots.transferInputs,
        treeSlots: Object.freeze(
          inputTreeSlots(slots.inputTrees.map((tree) => tree.slot)).map(treeSlotFields),
        ),
        publicInputHash: asField(bytesToBigInt(complete.publicInputHash)),
      }),
    }),
  });
}

function prepareTransferUnchecked(
  proofInputs: SppProofInputs,
  slots: PreparedSlots,
  circuit: TransferCircuit,
): PreparedTransferAssembly<ProverInputs["circuit"]> {
  if (!(proofInputs instanceof SppProofInputs)) {
    throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
  }
  const shape = proofInputs.checkShape();
  const plan = circuitPlan(circuit, shape);
  if (
    plan.authority &&
    (shape.inputs !== shape.outputs ||
      shape.inputs > RING_AUTHORITY_MAX_WIDTH ||
      proofInputs.externalData.interfaceTransfers.length !== 0 ||
      proofInputs.inputUtxos.some(
        (input) => !input.isDummy() && input.utxo.ringProgramId !== plan.ring,
      ) ||
      proofInputs.outputs.some((output) => !output.isDummy() && output.ringProgramId !== plan.ring))
  ) {
    throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
  }
  const realInputs = proofInputs.inputUtxos.filter((input) => !input.isDummy());
  if (realInputs.length === 0) throw new ClientError("CLIENT_NO_INPUTS");
  const outputTreeId = proofInputs.outputTreeId;
  validateOutputBlindings(proofInputs);

  const { transferInputs, inputHashes, nullifiers, treeIndexes } = slots;
  const transferOutputs = proofInputs.outputs.map((output) => createOutput(output, outputTreeId));
  const outputHashes = transferOutputs.map((output) => output.hash as bigint);
  const privateOutputHashes = proofInputs.outputs.map((output, index) =>
    output.isDummy() ? 0n : (outputHashes[index] as bigint),
  );
  const outputOwnerFields = publishedOwnerFields(plan, transferOutputs, proofInputs.externalData);
  const externalDataHash = bytesField(proofInputs.externalData.hash(), "external data hash");
  const privateTxHash = poseidon([
    hashChain4(inputHashes),
    hashChain4(privateOutputHashes),
    hashChain4(Array.from({ length: inputHashes.length }, () => 0n)),
    externalDataHash,
    bytesField(proofInputs.privateTxBlinding(), "private tx blinding"),
  ]);
  const movements = publicMovements(proofInputs);
  const publicSlots = movements.assets.flatMap((asset, index) => [
    asset,
    movements.amounts[index] ?? 0n,
  ]);
  // The circuit authorizes an input owner by finding its tagged identity in
  // the vector, the payer in slot zero and unique non-payer owners after it,
  // matching Rust's `signer_pk_hashes`.
  const ownerSignerHashes = plan.authority
    ? []
    : ownerSignerAddresses(proofInputs.inputUtxos, proofInputs.payer).map(signerIdentity);
  const signerPublicKeyHashes = [
    signerIdentity(proofInputs.payer),
    ...ownerSignerHashes,
    ...Array.from({ length: plan.signerSlots - 1 - ownerSignerHashes.length }, () => 0n),
  ];
  const flags = inputFlags(true, treeIndexes);
  const ringProgramId = plan.ring === undefined ? 0n : hashBytesBigInt(addressBytes(plan.ring));
  const outputTreeIdField = bytesToBigInt(treeIdField(outputTreeId));
  const publicInputs = transferPublicInputs({
    nullifiers: nullifiers.map(bytesToBigInt),
    outputHashes,
    outputTreeId,
    privateTxHash,
    externalDataHash,
    publicSlots,
    ringProgramId,
    signerPublicKeyHashes,
    inputFlags: flags,
    publishedOutputOwnerPublicKeyHashes: outputOwnerFields,
  });
  const common: PreparedTransferInputs = Object.freeze({
    inputs: Object.freeze(transferInputs),
    outputs: Object.freeze(transferOutputs),
    outputTreeId: asField(outputTreeIdField),
    externalDataHash: asField(externalDataHash),
    privateTxHash: asField(privateTxHash),
    blindingSeed: asField(bytesField(proofInputs.blindingSeed, "blinding seed")),
    publicAssets: Object.freeze(movements.assets.map(asField)),
    publicAmounts: Object.freeze(movements.amounts.map(asField)),
    ringProgramId: asField(ringProgramId),
    signerPublicKeyHashes: Object.freeze(signerPublicKeyHashes.map(asField)),
    inputFlags: asField(flags),
    publishedOutputOwnerPublicKeyHashes: Object.freeze((outputOwnerFields ?? []).map(asField)),
  });
  const instructionBase: Omit<TransactInstructionData, "treeContexts"> = Object.freeze({
    expiryUnixTs: proofInputs.externalData.expiryUnixTs,
    privateTxHash: bigintToBytes(privateTxHash) as Bytes32,
    circuit: Object.freeze({
      kind: plan.data,
      inputs: proofInputs.inputUtxos.length,
      outputs: proofInputs.outputs.length,
      publicAssetSlots: 3,
    }),
    txViewingPk: proofInputs.externalData.txViewingPublicKey.toBytes(),
    salt: new Uint8Array(proofInputs.externalData.salt) as never,
    proof: ZERO_PROOF,
    inputs: Object.freeze(
      proofInputs.inputUtxos.map((_input, index) => {
        const nullifier = nullifiers[index];
        const treeIndex = treeIndexes[index];
        if (!nullifier || treeIndex === undefined) {
          throw new ClientError("CLIENT_PROOF_INPUT_COUNT_MISMATCH", {
            details: { got: nullifiers.length, expected: proofInputs.inputUtxos.length },
          });
        }
        return Object.freeze({ nullifierHash: nullifier, treeIndex });
      }),
    ),
    interfaceTransfers: Object.freeze(
      proofInputs.externalData.interfaceTransfers.map((transfer) =>
        transfer.kind === "sol"
          ? Object.freeze({
              kind: transfer.isDeposit ? ("solDeposit" as const) : ("solWithdrawal" as const),
              amount: transfer.amount,
            })
          : Object.freeze({
              kind: transfer.isDeposit ? ("splDeposit" as const) : ("splWithdrawal" as const),
              amount: transfer.amount,
              splInterfaceBump: transfer.splInterfaceBump,
            }),
      ),
    ),
    ...(proofInputs.externalData.dataHash === undefined
      ? {}
      : { dataHash: new Uint8Array(proofInputs.externalData.dataHash) as Bytes32 }),
    ...(proofInputs.externalData.ringDataHash === undefined
      ? {}
      : { ringDataHash: new Uint8Array(proofInputs.externalData.ringDataHash) as Bytes32 }),
    outputs: Object.freeze(
      proofInputs.externalData.outputs.map((output) =>
        Object.freeze({
          ...output,
          utxoHash: new Uint8Array(output.utxoHash) as Bytes32,
          ...(output.data === undefined ? {} : { data: new Uint8Array(output.data) }),
        }),
      ),
    ),
    messages: Object.freeze(
      proofInputs.externalData.messages.map((message) =>
        Object.freeze({
          viewTag: new Uint8Array(message.viewTag) as Bytes32,
          data: new Uint8Array(message.data),
        }),
      ),
    ),
  });
  return Object.freeze({
    inputs: Object.freeze({
      circuit: plan.prover,
      payload: common,
      trees: slots.treeIds.map((id) => Object.freeze({ id, tree: treeAddress(id) })),
      lookups: proofInputs.inputUtxos.map((input, index) =>
        Object.freeze({
          treeSlot: treeIndexes[index] ?? 0,
          commitment: input.isDummy() ? null : input.hash(),
        }),
      ),
      publicInputs: Object.freeze(publicInputs.map(asField)),
    }),
    finish(inputTrees: readonly InputTree[]): Omit<AssembledTransfer, "proverInputs"> {
      const firstTree = inputTrees[0];
      if (firstTree === undefined) throw new ClientError("CLIENT_NO_INPUTS");
      const treeSlots = inputTreeSlots(inputTrees.map((tree) => tree.slot));
      const publicInputHash = resolvedPublicInputHash(publicInputs, treeSlots);
      const rootIndexes: InputRootIndexes = Object.freeze({
        utxoTree: firstTree.utxoRootIndex,
        nullifierTree: firstTree.nullifierRootIndex,
      });
      const instructionData: TransactInstructionData = Object.freeze({
        ...instructionBase,
        treeContexts: Object.freeze(
          inputTrees.map((tree) =>
            Object.freeze({
              utxoTreeRootIndex: tree.utxoRootIndex,
              nullifierTreeRootIndex: tree.nullifierRootIndex,
            }),
          ),
        ),
      });
      // Slot 0 is always a real spend, so the first tree's roots are the pair a
      // ring statement binds.
      return Object.freeze({
        instructionData,
        publicInputHash: bigintToBytes(publicInputHash) as Bytes32,
        nullifiers: Object.freeze(
          nullifiers.map((nullifier) => new Uint8Array(nullifier) as Bytes32),
        ),
        outputHashes: Object.freeze(outputHashes.map((hash) => bigintToBytes(hash) as Bytes32)),
        privateTxHash: bigintToBytes(privateTxHash) as Bytes32,
        rootIndexes,
        roots: Object.freeze({
          stateRoot: firstTree.slot.utxoRoot,
          stateRootIndex: firstTree.utxoRootIndex,
          nullifierRoot: firstTree.slot.nullifierRoot,
          nullifierRootIndex: firstTree.nullifierRootIndex,
        }),
        withProof(proof: TransactProof): TransactInstructionData {
          return Object.freeze({ ...instructionData, proof: copyProof(proof) });
        },
      });
    },
  });
}

/**
 * Mirrors Rust `validate_output_blindings`: the circuit asserts every output
 * blinding, padding included, equals the derivation from the first nullifier,
 * the derived seed, and the slot index, so a proof request with any other
 * blinding would be rejected after the expensive round trip.
 */
function validateOutputBlindings(proofInputs: SppProofInputs): void {
  const firstNullifier = proofInputs.firstNullifier();
  const outputSeed = proofInputs.outputBlindingSeed();
  proofInputs.outputs.forEach((output, index) => {
    if (!equal(output.blinding, transactOutputBlinding(firstNullifier, outputSeed, index))) {
      throw new ClientError("CLIENT_OUTPUT_BLINDING_MISMATCH", { details: { index } });
    }
  });
}

/** `undefined` on the authority rail, its statement folds no owner list. */
function publishedOwnerFields(
  plan: CircuitPlan,
  outputs: readonly TransferOutput[],
  external: ExternalData,
): readonly bigint[] | undefined {
  switch (plan.owners) {
    case "none":
      return undefined;
    case "every":
      return outputs.map((output) => output.ownerPublicKeyHash);
    case "confidentialMarked":
      return confidentialMarkedOutputOwnerHashes(external);
  }
}

/**
 * Mirrors Rust `confidential_marked_output_owner_pk_hashes`, the ring rails
 * publish an owner hash only for a `Confidential` scheme output, a
 * `RingConfidential` one contributes zero. The tag is a Solana signer, so it
 * enters as its tagged identity.
 */
function confidentialMarkedOutputOwnerHashes(external: ExternalData): bigint[] {
  if (external.outputs.length !== external.resolvedOwnerTags.length) {
    throw new ClientError("CLIENT_PROVER_INPUT");
  }
  return external.outputs.map((output, index) => {
    const tag = external.resolvedOwnerTags[index];
    if (tag === undefined) throw new ClientError("CLIENT_PROVER_INPUT");
    return output.data !== undefined && isConfidentialEncryptedOutput(output.data)
      ? bytesToBigInt(solanaOwnerIdentity(tag))
      : 0n;
  });
}

/** Mirrors Rust `is_confidential_encrypted_output`. */
function isConfidentialEncryptedOutput(data: Uint8Array): boolean {
  if (data.length <= 5 || data[0] !== 1) return false;
  const bodyLength = new DataView(data.buffer, data.byteOffset, data.byteLength).getUint32(1, true);
  return bodyLength === data.length - 5 && data[5] === EncryptedScheme.confidential;
}

/**
 * One tree a proof opens against: its id, the state root and nullifier root
 * the proofs were taken at, and the root history positions the instruction
 * references.
 */
export interface InputTree {
  readonly treeId: TreeId;
  readonly slot: TreeSlot;
  readonly utxoRootIndex: number;
  readonly nullifierRootIndex: number;
}

export interface PreparedSlots {
  readonly transferInputs: readonly PreparedTransferInput[];
  readonly inputHashes: readonly bigint[];
  readonly nullifiers: readonly Bytes32[];
  readonly inputOwnerFields: readonly bigint[];
  readonly treeIds: readonly TreeId[];
  readonly treeIndexes: readonly number[];
}

export interface AssembledSlots extends PreparedSlots {
  readonly transferInputs: readonly TransferInput[];
  readonly inputTrees: readonly InputTree[];
}

export function prepareInput(
  input: ProofInputUtxo,
  options: Readonly<{ owner: bigint; treeSlot: number; nullifier?: Bytes32 }>,
): PreparedTransferInput {
  const dummy = input.isDummy();
  return Object.freeze({
    circuit: inputCircuitUtxo(input, dummy),
    isDummy: asField(dummy ? 1n : 0n),
    treeSlot: asField(BigInt(options.treeSlot)),
    nullifier: asField(bytesField(options.nullifier ?? input.nullifier(), "nullifier")),
    ownerPublicKeyHash: asField(dummy ? 0n : options.owner),
    ...(dummy ? { nullifierSecret: asField(0n) } : {}),
  });
}

export function prepareSlots(
  inputs: readonly ProofInputUtxo[],
  ownerField: (input: ProofInputUtxo, index: number) => bigint,
): PreparedSlots {
  const treeIds: TreeId[] = [];
  const treeIndexes: number[] = [];
  const transferInputs = inputs.map((input, index) => {
    const current = treeIds.at(-1);
    if (input.isDummy()) {
      if (current === undefined) throw new ClientError("CLIENT_NO_INPUTS");
      if (current !== input.treeId)
        throw new ClientError("CLIENT_INPUTS_NOT_GROUPED_BY_TREE", { details: { index } });
    } else if (current !== input.treeId) {
      if (treeIds.includes(input.treeId))
        throw new ClientError("CLIENT_INPUTS_NOT_GROUPED_BY_TREE", { details: { index } });
      if (treeIds.length === MAX_INPUT_TREES)
        throw new ClientError("CLIENT_TOO_MANY_INPUT_TREES", {
          details: { got: treeIds.length + 1, max: MAX_INPUT_TREES },
        });
      treeIds.push(input.treeId);
    }
    const treeSlot = treeIds.length - 1;
    treeIndexes.push(treeSlot);
    return prepareInput(input, {
      owner: input.isDummy() ? 0n : ownerField(input, index),
      treeSlot,
    });
  });
  if (treeIds.length === 0) throw new ClientError("CLIENT_NO_INPUTS");
  return Object.freeze({
    transferInputs: Object.freeze(transferInputs),
    inputHashes: Object.freeze(
      inputs.map((input) => (input.isDummy() ? 0n : bytesToBigInt(input.hash()))),
    ),
    nullifiers: Object.freeze(
      transferInputs.map((input) => bigintToBytes(input.nullifier) as Bytes32),
    ),
    inputOwnerFields: Object.freeze(transferInputs.map((input) => input.ownerPublicKeyHash)),
    treeIds: Object.freeze(treeIds),
    treeIndexes: Object.freeze(treeIndexes),
  });
}

export function assembleSlots(
  proofInputs: SppProofInputs,
  spendProofs: readonly SpendProof[],
  dummyNullifierProofs: readonly NonInclusionProof[],
  ownerField: (input: ProofInputUtxo, index: number) => bigint,
): AssembledSlots {
  const prepared = prepareSlots(proofInputs.inputUtxos, ownerField);
  const inputTrees: InputTree[] = [];
  let real = 0;
  let dummy = 0;
  const transferInputs = prepared.transferInputs.map((local, index) => {
    const input = proofInputs.inputUtxos[index];
    const treeIndex = prepared.treeIndexes[index];
    if (input === undefined || treeIndex === undefined)
      throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
    const expectedTree = treeAddress(input.treeId);
    if (input.isDummy()) {
      const proof = dummyNullifierProofs[dummy++];
      const tree = inputTrees[treeIndex];
      if (proof === undefined || tree === undefined)
        throw new ClientError("CLIENT_MISSING_INPUT_MERKLE_PROOF", { details: { index } });
      validateDummyNullifierProof(input, proof, index);
      checkNullifierRoot(tree, proof, expectedTree, index);
      return attachPaths(local, { nullifier: proof });
    }
    const proof = spendProofs[real++];
    if (proof === undefined)
      throw new ClientError("CLIENT_MISSING_INPUT_MERKLE_PROOF", { details: { index } });
    validateSpendProof(input, proof, index);
    if (
      proof.state.merkleContext.tree !== expectedTree ||
      proof.nullifier.merkleContext.tree !== expectedTree
    )
      throw new ClientError("CLIENT_PROOF_TREE_MISMATCH", { details: { index } });
    const tree = inputTrees[treeIndex];
    if (tree === undefined) {
      inputTrees.push(
        Object.freeze({
          treeId: input.treeId,
          slot: Object.freeze({
            id: input.treeId,
            utxoRoot: checkedBytes(proof.state.root, 32, "utxo root"),
            nullifierRoot: checkedBytes(proof.nullifier.root, 32, "nullifier root"),
          }),
          utxoRootIndex: proof.state.rootIndex,
          nullifierRootIndex: proof.nullifier.rootIndex,
        }),
      );
    } else {
      if (
        !equal(proof.state.root, tree.slot.utxoRoot) ||
        proof.state.rootIndex !== tree.utxoRootIndex
      )
        throw new ClientError("CLIENT_INPUT_TREE_ROOT_MISMATCH", { details: { index } });
      checkNullifierRoot(tree, proof.nullifier, expectedTree, index);
    }
    return attachPaths(local, proof);
  });
  return Object.freeze({
    ...prepared,
    transferInputs: Object.freeze(transferInputs),
    inputTrees: Object.freeze(inputTrees),
  });
}

function attachPaths(
  local: PreparedTransferInput,
  proofs: Readonly<{ state?: SpendProof["state"]; nullifier: NonInclusionProof }>,
): TransferInput {
  return Object.freeze({
    ...local,
    statePathElements: Object.freeze(
      proofs.state?.path.map((value) => asField(bytesField(value, "state path element"))) ??
        Array.from({ length: STATE_TREE_HEIGHT }, () => asField(0n)),
    ),
    statePathIndex: asField(proofs.state?.leafIndex ?? 0n),
    nullifierLowValue: asField(bytesField(proofs.nullifier.lowElement, "low element")),
    nullifierNextValue: asField(bytesField(proofs.nullifier.highElement, "high element")),
    nullifierLowPathElements: Object.freeze(
      proofs.nullifier.path.map((value) => asField(bytesField(value, "nullifier path element"))),
    ),
    nullifierLowPathIndex: asField(proofs.nullifier.lowElementIndex),
  });
}

interface TransferPublicInputFields {
  nullifiers: readonly bigint[];
  outputHashes: readonly bigint[];
  outputTreeId: TreeId;
  privateTxHash: bigint;
  externalDataHash: bigint;
  publicSlots: readonly bigint[];
  ringProgramId: bigint;
  signerPublicKeyHashes: readonly bigint[];
  /** The packed dummy policy and per-input tree indexes, `inputFlags`. */
  inputFlags: bigint;
  publishedOutputOwnerPublicKeyHashes: readonly bigint[] | undefined;
}

export function transferPublicInputs(input: TransferPublicInputFields): readonly bigint[] {
  return [
    hashChain4(input.nullifiers),
    hashChain4(input.outputHashes),
    bytesToBigInt(treeIdField(input.outputTreeId)),
    input.privateTxHash,
    input.externalDataHash,
    ...input.publicSlots,
    input.ringProgramId,
    rightHashChain(input.signerPublicKeyHashes),
    input.inputFlags,
    ...(input.publishedOutputOwnerPublicKeyHashes === undefined
      ? []
      : [hashChain4(input.publishedOutputOwnerPublicKeyHashes)]),
  ];
}

export function resolvedPublicInputHash(
  publicInputs: readonly bigint[],
  trees: readonly TreeSlot[],
): bigint {
  // 1. Cache equality and hashing must use the same copied public statement.
  const fields = Array.from(publicInputs);
  if (fields.some((value) => typeof value !== "bigint")) {
    throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
  }
  const slots = Array.from(trees, (tree) => ({
    id: tree.id,
    utxoRoot: checkedBytes(tree.utxoRoot, 32, "utxo root"),
    nullifierRoot: checkedBytes(tree.nullifierRoot, 32, "nullifier root"),
  }));
  if (slots.some((slot) => slot.utxoRoot.length !== 32 || slot.nullifierRoot.length !== 32)) {
    throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
  }
  const previous = lastResolvedHash;
  if (
    previous !== undefined &&
    fields.length === previous.fields.length &&
    fields.every((field, index) => field === previous.fields[index]) &&
    slots.length === previous.trees.length &&
    slots.every((slot, index) => {
      const old = previous.trees[index];
      return (
        old !== undefined &&
        slot.id === old.id &&
        slot.utxoRoot.length === old.utxoRoot.length &&
        slot.nullifierRoot.length === old.nullifierRoot.length &&
        slot.utxoRoot.every((byte, offset) => byte === old.utxoRoot[offset]) &&
        slot.nullifierRoot.every((byte, offset) => byte === old.nullifierRoot[offset])
      );
    })
  )
    return previous.hash;
  const hash = hashChain4([
    ...fields.slice(0, 2),
    bytesToBigInt(treeSlotsHashChain(slots)),
    ...fields.slice(2),
  ]);
  lastResolvedHash = { fields, trees: slots, hash };
  return hash;
}

export function transferPublicInputHash(
  input: TransferPublicInputFields & { readonly treeSlots: readonly TreeSlot[] },
): bigint {
  return resolvedPublicInputHash(transferPublicInputs(input), input.treeSlots);
}

function checkNullifierRoot(
  inputTree: InputTree,
  proof: NonInclusionProof,
  expectedTree: Address,
  index: number,
): void {
  if (
    proof.merkleContext.tree !== expectedTree ||
    !equal(proof.root, inputTree.slot.nullifierRoot) ||
    proof.rootIndex !== inputTree.nullifierRootIndex
  ) {
    throw new ClientError("CLIENT_NULLIFIER_ROOT_MISMATCH", { details: { index } });
  }
}

/** The prover-facing encoding of a tree slot. */
export function treeSlotFields(slot: TreeSlot): TreeSlotFields {
  return Object.freeze({
    id: asField(bytesToBigInt(treeIdField(slot.id))),
    utxoRoot: asField(bytesField(slot.utxoRoot, "tree slot utxo root")),
    nullifierRoot: asField(bytesField(slot.nullifierRoot, "tree slot nullifier root")),
  });
}

/** Slot 0, the only slot a single-tree proof opens against. */
const INPUT_TREE_SLOT = 0;

export function createRealInput(
  input: ProofInputUtxo,
  proof: SpendProof,
  ownerPublicKeyHash: bigint,
  treeSlot: number = INPUT_TREE_SLOT,
): TransferInput {
  return attachPaths(prepareInput(input, { owner: ownerPublicKeyHash, treeSlot }), proof);
}

export function createDummyTransferInput(
  input: ProofInputUtxo,
  proof: NonInclusionProof,
  nullifier = input.nullifier(),
  treeSlot: number = INPUT_TREE_SLOT,
): TransferInput {
  return attachPaths(prepareInput(input, { owner: 0n, treeSlot, nullifier }), { nullifier: proof });
}

/**
 * The output as the prover reads it, hashed under `outputTreeId`. A dummy's
 * published owner field is the tagged Solana identity of its owner tag, the
 * participant the pad names.
 */
export function createOutput(output: ProofOutputUtxo, outputTreeId: TreeId): TransferOutput {
  const ownerPublicKeyHash = output.ownerAddress
    ? bytesField(
        output.ownerAddress.signingPublicKey.ownerProofInputHash(),
        "output owner public key",
      )
    : bytesToBigInt(solanaOwnerIdentity(output.ownerTag ?? new Uint8Array(32)));
  return Object.freeze({
    circuit: outputCircuitUtxo(output),
    isDummy: asField(output.isDummy() ? 1n : 0n),
    hash: asField(bytesField(output.hash(outputTreeId), "output hash")),
    ownerPublicKeyHash: asField(ownerPublicKeyHash),
    nullifierPublicKey: asField(
      output.ownerAddress
        ? bytesField(output.ownerAddress.nullifierPublicKey, "output nullifier public key")
        : 0n,
    ),
  });
}

function inputCircuitUtxo(input: ProofInputUtxo, dummy = false): CircuitUtxo {
  const owner = dummy
    ? 0n
    : poseidon([
        bytesField(input.utxo.owner.ownerProofInputHash(), "owner public key"),
        bytesField(input.nullifierPublicKey, "nullifier public key"),
      ]);
  return Object.freeze({
    domain: asField(BigInt(dummy ? DUMMY_DOMAIN : UTXO_DOMAIN)),
    owner: asField(owner),
    asset: asField(dummy ? 0n : hashBytesBigInt(addressBytes(input.utxo.asset))),
    amount: asField(dummy ? 0n : input.utxo.amount),
    blinding: asField(bytesToBigInt(input.utxo.blinding)),
    dataHash: asField(dummy ? 0n : input.dataHash ? bytesField(input.dataHash, "data hash") : 0n),
    ringDataHash: asField(
      dummy ? 0n : input.ringDataHash ? bytesField(input.ringDataHash, "ring data hash") : 0n,
    ),
    ringProgramId: asField(
      dummy
        ? 0n
        : input.utxo.ringProgramId
          ? hashBytesBigInt(addressBytes(input.utxo.ringProgramId))
          : 0n,
    ),
  });
}

function outputCircuitUtxo(output: ProofOutputUtxo): CircuitUtxo {
  const dummy = output.isDummy();
  return Object.freeze({
    domain: asField(BigInt(dummy ? DUMMY_DOMAIN : UTXO_DOMAIN)),
    owner: asField(dummy ? 0n : bytesField(output.ownerHash(), "output owner")),
    asset: asField(dummy ? 0n : hashBytesBigInt(addressBytes(output.asset))),
    amount: asField(dummy ? 0n : output.amount),
    blinding: asField(bytesToBigInt(output.blinding)),
    dataHash: asField(
      dummy ? 0n : output.dataHash ? bytesField(output.dataHash, "output data hash") : 0n,
    ),
    ringDataHash: asField(
      dummy
        ? 0n
        : output.ringDataHash
          ? bytesField(output.ringDataHash, "output ring data hash")
          : 0n,
    ),
    ringProgramId: asField(
      dummy ? 0n : output.ringProgramId ? hashBytesBigInt(addressBytes(output.ringProgramId)) : 0n,
    ),
  });
}

export interface RingOpenings {
  readonly nIn: number;
  readonly nOut: number;
  readonly inputs: readonly CustomRingOpening[];
  readonly outputs: readonly CustomRingOpening[];
}

/** A dummy output retains the tree and blinding bound by its SPP commitment and auditor disclosure. */
export function ringOpenings(proofInputs: SppProofInputs): RingOpenings {
  if (!(proofInputs instanceof SppProofInputs)) {
    throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
  }
  if (
    proofInputs.inputUtxos.length > RING_INPUT_SLOTS ||
    proofInputs.outputs.length > RING_OUTPUT_SLOTS
  ) {
    throw new ClientError("CLIENT_PROVER_INPUT");
  }
  const outputTreeId = treeIdField(proofInputs.outputTreeId);
  const inputs = Array.from({ length: RING_INPUT_SLOTS }, (_, index) => {
    const input = proofInputs.inputUtxos[index];
    return input === undefined ? zeroOpening(0) : inputOpening(input);
  });
  const outputs = Array.from({ length: RING_OUTPUT_SLOTS }, (_, index) => {
    const output = proofInputs.outputs[index];
    return output === undefined ? zeroOpening(0) : outputOpening(output, outputTreeId);
  });
  return Object.freeze({
    nIn: proofInputs.inputUtxos.length,
    nOut: proofInputs.outputs.length,
    inputs: Object.freeze(inputs),
    outputs: Object.freeze(outputs),
  });
}

/** Mirrors Rust `input_opening`, each slot opens under its own tree. */
function inputOpening(input: ProofInputUtxo): CustomRingOpening {
  if (input.isDummy()) return zeroOpening(DUMMY_DOMAIN);
  const utxo = inputCircuitUtxo(input);
  return Object.freeze({
    domain: openingField(BigInt(UTXO_DOMAIN)),
    treeId: treeIdField(input.treeId),
    ownerPkHash: input.utxo.owner.ownerProofInputHash(),
    nullifierPk: input.nullifierPublicKey,
    asset: openingField(utxo.asset),
    amount: openingField(utxo.amount),
    blinding: openingField(utxo.blinding),
    dataHash: openingField(utxo.dataHash),
    ringDataHash: openingField(utxo.ringDataHash),
    ringProgramId: openingField(utxo.ringProgramId),
  });
}

/** Owner address presence determines the dummy domain independently of the public owner tag. */
function outputOpening(output: ProofOutputUtxo, treeId: Bytes32): CustomRingOpening {
  const owner = output.ownerAddress;
  if (owner === undefined) {
    return Object.freeze({
      ...zeroOpening(DUMMY_DOMAIN),
      treeId,
      blinding: output.blinding,
    });
  }
  const utxo = outputCircuitUtxo(output);
  return Object.freeze({
    domain: openingField(BigInt(UTXO_DOMAIN)),
    treeId,
    ownerPkHash: owner.signingPublicKey.ownerProofInputHash(),
    nullifierPk: owner.nullifierPublicKey,
    asset: openingField(utxo.asset),
    amount: openingField(utxo.amount),
    blinding: openingField(utxo.blinding),
    dataHash: openingField(utxo.dataHash),
    ringDataHash: openingField(utxo.ringDataHash),
    ringProgramId: openingField(utxo.ringProgramId),
  });
}

function zeroOpening(domain: number): CustomRingOpening {
  return Object.freeze({
    domain: openingField(BigInt(domain)),
    treeId: openingField(0n),
    ownerPkHash: openingField(0n),
    nullifierPk: openingField(0n),
    asset: openingField(0n),
    amount: openingField(0n),
    blinding: openingField(0n),
    dataHash: openingField(0n),
    ringDataHash: openingField(0n),
    ringProgramId: openingField(0n),
  });
}

function openingField(value: bigint): Bytes32 {
  return bigintToBytes(value) as Bytes32;
}

/** Refuses a shape or a path length the prover does not take. */
export function checkedProverInputs(inputs: TransferInputs): ProverInputs {
  try {
    selectSppShape(inputs.inputs.length, inputs.outputs.length);
  } catch {
    throw new ClientError("CLIENT_PROVER_INPUT");
  }
  const malformed = inputs.inputs.some(
    (input) =>
      input.statePathElements.length !== STATE_TREE_HEIGHT ||
      input.nullifierLowPathElements.length !== NULLIFIER_TREE_HEIGHT,
  );
  if (malformed) throw new ClientError("CLIENT_PROVER_INPUT");
  return Object.freeze({
    circuit: inputs.ringProgramId === 0n ? "transfer" : "transferRing",
    payload: inputs,
  });
}

export function validateSpendProof(input: ProofInputUtxo, proof: SpendProof, index: number): void {
  if (!equal(input.hash(), proof.state.leaf)) {
    throw new ClientError("CLIENT_STATE_PROOF_LEAF_MISMATCH", { details: { index } });
  }
  if (!equal(input.nullifier(), proof.nullifier.leaf)) {
    throw new ClientError("CLIENT_NULLIFIER_PROOF_LEAF_MISMATCH", {
      details: { index },
    });
  }
  if (proof.state.merkleContext.tree !== proof.nullifier.merkleContext.tree) {
    throw new ClientError("CLIENT_PROOF_TREE_MISMATCH", { details: { index } });
  }
  if (proof.state.path.length !== STATE_TREE_HEIGHT) {
    throw new ClientError("CLIENT_PROOF_PATH_LENGTH", {
      details: { index, kind: "state", expected: STATE_TREE_HEIGHT, got: proof.state.path.length },
    });
  }
  if (proof.nullifier.path.length !== NULLIFIER_TREE_HEIGHT) {
    throw new ClientError("CLIENT_PROOF_PATH_LENGTH", {
      details: {
        index,
        kind: "nullifier",
        expected: NULLIFIER_TREE_HEIGHT,
        got: proof.nullifier.path.length,
      },
    });
  }
}

function validateDummyNullifierProof(
  input: ProofInputUtxo,
  proof: NonInclusionProof,
  index: number,
): void {
  if (!equal(input.nullifier(), proof.leaf)) {
    throw new ClientError("CLIENT_NULLIFIER_PROOF_LEAF_MISMATCH", { details: { index } });
  }
  if (proof.path.length !== NULLIFIER_TREE_HEIGHT) {
    throw new ClientError("CLIENT_PROOF_PATH_LENGTH", {
      details: {
        index,
        kind: "nullifier",
        expected: NULLIFIER_TREE_HEIGHT,
        got: proof.path.length,
      },
    });
  }
}

function publicMovements(proofInputs: SppProofInputs): Readonly<{
  assets: readonly bigint[];
  amounts: readonly bigint[];
}> {
  const aggregated = new Map<Address, bigint>();
  for (const transfer of proofInputs.externalData.interfaceTransfers) {
    const asset = transfer.kind === "sol" ? SOL_MINT : transfer.mint;
    const signed = transfer.isDeposit ? transfer.amount : -transfer.amount;
    aggregated.set(asset, (aggregated.get(asset) ?? 0n) + signed);
  }
  if (aggregated.size > 3) {
    throw new ClientError("CLIENT_PROVER_INPUT");
  }
  const assets = [...aggregated.keys()].map((asset) => hashBytesBigInt(addressBytes(asset)));
  const amounts = [...aggregated.values()].map((amount) => signedField(amount, "public amount"));
  while (assets.length < 3) assets.push(0n);
  while (amounts.length < 3) amounts.push(0n);
  return Object.freeze({ assets: Object.freeze(assets), amounts: Object.freeze(amounts) });
}

export function signedField(value: bigint, name: string): bigint {
  const result = ((value % BN254_MODULUS) + BN254_MODULUS) % BN254_MODULUS;
  return field(result, name);
}

export function asField(value: bigint): Field {
  return field(value, "field") as Field;
}

export function asInteger(value: bigint): Field {
  return value as Field;
}

function equal(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}

function copyProof(proof: TransactProof): TransactProof {
  return Object.freeze({
    a: new Uint8Array(proof.a) as never,
    b: new Uint8Array(proof.b) as never,
    c: new Uint8Array(proof.c) as never,
  });
}
