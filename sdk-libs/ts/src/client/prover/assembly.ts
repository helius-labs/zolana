import { getAddressDecoder } from "@solana/kit";

import type {
  Address,
  Bytes32,
  TransactInstructionData,
  TransactProof,
} from "../../interface/types.js";
import { DUMMY_DOMAIN, UTXO_DOMAIN } from "../../interface/program.js";
import { treeAddress } from "../../interface/pda/index.js";
import {
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

import { ClientError, fromClientCause } from "../error.js";
import {
  BN254_MODULUS,
  addressBytes,
  bigintToBytes,
  bytesField,
  bytesToBigInt,
  field,
  hashChain,
  hashBytesBigInt,
  poseidon,
  rightHashChain,
} from "../internal.js";
import type { NonInclusionProof, SpendProof } from "../rpc.js";
import type {
  AssembledTransfer,
  CircuitUtxo,
  Field,
  InputRootIndexes,
  ProverInputs,
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

/** With `ring` set, every real UTXO is in that ring or in the default ring, per its own fields. */
export function assemble(
  proofInputs: SppProofInputs,
  spendProofs: readonly SpendProof[],
  dummyNullifierProofs: readonly NonInclusionProof[] = [],
  ring?: Address,
): AssembledTransfer {
  try {
    return assembleUnchecked(proofInputs, spendProofs, dummyNullifierProofs, ring);
  } catch (cause) {
    throw fromClientCause(cause);
  }
}

function assembleUnchecked(
  proofInputs: SppProofInputs,
  spendProofs: readonly SpendProof[],
  dummyNullifierProofs: readonly NonInclusionProof[],
  ring: Address | undefined,
): AssembledTransfer {
  if (!(proofInputs instanceof SppProofInputs)) {
    throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
  }
  proofInputs.checkShape();
  const realInputs = proofInputs.inputUtxos.filter((input) => !input.isDummy());
  if (realInputs.length === 0) throw new ClientError("CLIENT_NO_INPUTS");
  const outputTreeId = proofInputs.outputTreeId;
  validateOutputBlindings(proofInputs);

  const { transferInputs, inputHashes, nullifiers, inputTree } = assembleSlots(
    proofInputs,
    spendProofs,
    dummyNullifierProofs,
    (input) => bytesField(input.utxo.owner.ownerProofInputHash(), "owner public key"),
  );

  const transferOutputs = proofInputs.outputs.map((output) => createOutput(output, outputTreeId));
  const outputHashes = transferOutputs.map((output) => output.hash as bigint);
  const privateOutputHashes = proofInputs.outputs.map((output, index) =>
    output.isDummy() ? 0n : (outputHashes[index] as bigint),
  );
  const outputOwnerFields =
    ring === undefined
      ? transferOutputs.map((output) => output.ownerPublicKeyHash)
      : confidentialMarkedOutputOwnerHashes(proofInputs.externalData);
  const externalDataHash = bytesField(proofInputs.externalData.hash(), "external data hash");
  const privateTxHash = poseidon([
    hashChain(inputHashes),
    hashChain(privateOutputHashes),
    hashChain(Array.from({ length: inputHashes.length }, () => 0n)),
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
  const ownerSignerHashes = ownerSignerAddresses(proofInputs.inputUtxos, proofInputs.payer).map(
    signerIdentity,
  );
  const signerPublicKeyHashes = [
    signerIdentity(proofInputs.payer),
    ...ownerSignerHashes,
    ...Array.from({ length: inputHashes.length - ownerSignerHashes.length }, () => 0n),
  ];
  const allowDummyInputs = 1n;
  const ringProgramId = ring === undefined ? 0n : hashBytesBigInt(addressBytes(ring));
  const treeSlots = inputTreeSlots(inputTree.slot);
  const outputTreeIdField = bytesToBigInt(treeIdField(outputTreeId));
  const publicInputHash = hashChain([
    hashChain(nullifiers.map(bytesToBigInt)),
    hashChain(outputHashes),
    bytesToBigInt(treeSlotsHashChain(treeSlots)),
    outputTreeIdField,
    privateTxHash,
    externalDataHash,
    ...publicSlots,
    ringProgramId,
    rightHashChain(signerPublicKeyHashes),
    allowDummyInputs,
    hashChain(outputOwnerFields),
  ]);
  const common: TransferInputs = Object.freeze({
    inputs: Object.freeze(transferInputs),
    outputs: Object.freeze(transferOutputs),
    treeSlots: Object.freeze(treeSlots.map(treeSlotFields)),
    outputTreeId: asField(outputTreeIdField),
    externalDataHash: asField(externalDataHash),
    privateTxHash: asField(privateTxHash),
    blindingSeed: asField(bytesField(proofInputs.blindingSeed, "blinding seed")),
    publicAssets: Object.freeze(movements.assets.map(asField)),
    publicAmounts: Object.freeze(movements.amounts.map(asField)),
    ringProgramId: asField(ringProgramId),
    signerPublicKeyHashes: Object.freeze(signerPublicKeyHashes.map(asField)),
    allowDummyInputs: asField(allowDummyInputs),
    publishedOutputOwnerPublicKeyHashes: Object.freeze(outputOwnerFields.map(asField)),
    publicInputHash: asField(publicInputHash),
  });
  const proverInputs: ProverInputs = Object.freeze({
    circuit: ring === undefined ? "transfer" : "transferRing",
    payload: common,
  });

  // Every input references the same root history positions: the shielded pool
  // resolves one input tree slot and rejects an instruction whose inputs
  // disagree (`InputTreeRootIndexMismatch`).
  const rootIndexes: InputRootIndexes = Object.freeze({
    utxoTree: inputTree.utxoRootIndex,
    nullifierTree: inputTree.nullifierRootIndex,
  });
  const instructionData: TransactInstructionData = Object.freeze({
    expiryUnixTs: proofInputs.externalData.expiryUnixTs,
    privateTxHash: bigintToBytes(privateTxHash) as Bytes32,
    circuit: Object.freeze({
      kind: ring === undefined ? "confidentialEddsa" : "ringEddsa",
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
        if (!nullifier) {
          throw new ClientError("CLIENT_PROOF_INPUT_COUNT_MISMATCH", {
            details: { got: nullifiers.length, expected: proofInputs.inputUtxos.length },
          });
        }
        return Object.freeze({
          nullifierHash: nullifier,
          nullifierTreeRootIndex: rootIndexes.nullifierTree,
          utxoTreeRootIndex: rootIndexes.utxoTree,
        });
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
    instructionData,
    proverInputs,
    publicInputHash: bigintToBytes(publicInputHash) as Bytes32,
    nullifiers: Object.freeze(nullifiers.map((nullifier) => new Uint8Array(nullifier) as Bytes32)),
    outputHashes: Object.freeze(outputHashes.map((hash) => bigintToBytes(hash) as Bytes32)),
    privateTxHash: bigintToBytes(privateTxHash) as Bytes32,
    rootIndexes,
    withProof(proof: TransactProof): TransactInstructionData {
      return Object.freeze({ ...instructionData, proof: copyProof(proof) });
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
 * The one tree every input of a proof opens against: its id, the state root
 * and nullifier root the proofs were taken at, and the root history positions
 * the instruction references.
 */
export interface InputTree {
  readonly treeId: TreeId;
  readonly slot: TreeSlot;
  readonly utxoRootIndex: number;
  readonly nullifierRootIndex: number;
}

export interface AssembledSlots {
  readonly transferInputs: readonly TransferInput[];
  readonly inputHashes: readonly bigint[];
  readonly nullifiers: readonly Bytes32[];
  readonly inputOwnerFields: readonly bigint[];
  readonly inputTree: InputTree;
}

/**
 * Mirrors Rust `assemble_inputs` and `resolve_input_tree`. Padding is not
 * decided here: a slot with a spend proof is a real spend, a slot without one
 * is a dummy with its own non-inclusion proof. Every proof, real or dummy,
 * must open against the same tree, state root, and nullifier root as the first
 * real input: the circuit publishes one tree slot and the shielded pool reads
 * one root position pair, so a disagreement here fails closed instead of
 * producing an unverifiable proof or a rejected instruction. `ownerField` is
 * the caller's rail: it is the one thing Rust's `OwnerMode` varies, and every
 * rail shares the rest of this loop.
 */
export function assembleSlots(
  proofInputs: SppProofInputs,
  spendProofs: readonly SpendProof[],
  dummyNullifierProofs: readonly NonInclusionProof[],
  ownerField: (input: ProofInputUtxo, index: number) => bigint,
): AssembledSlots {
  const treeId = proofInputs.inputTreeId();
  const expectedTree = treeAddress(treeId);
  const transferInputs: TransferInput[] = [];
  const inputHashes: bigint[] = [];
  const nullifiers: Bytes32[] = [];
  const inputOwnerFields: bigint[] = [];
  let inputTree: InputTree | undefined;
  let proofIndex = 0;
  let dummyProofIndex = 0;
  for (let index = 0; index < proofInputs.inputUtxos.length; index++) {
    const input = proofInputs.inputUtxos[index];
    if (!input) {
      throw new ClientError("CLIENT_PROOF_INPUT_COUNT_MISMATCH", {
        details: { got: index, expected: proofInputs.inputUtxos.length },
      });
    }
    if (input.isDummy()) {
      if (inputTree === undefined) throw new ClientError("CLIENT_NO_INPUTS");
      const proof = dummyNullifierProofs[dummyProofIndex++];
      if (!proof) {
        throw new ClientError("CLIENT_MISSING_INPUT_MERKLE_PROOF", {
          details: { index },
        });
      }
      validateDummyNullifierProof(input, proof, index);
      checkNullifierRoot(inputTree, proof, expectedTree, index);
      const converted = createDummyTransferInput(input, proof);
      transferInputs.push(converted);
      inputHashes.push(0n);
      nullifiers.push(bigintToBytes(converted.nullifier) as Bytes32);
      inputOwnerFields.push(converted.ownerPublicKeyHash);
      continue;
    }
    const proof = spendProofs[proofIndex++];
    if (!proof) {
      throw new ClientError("CLIENT_MISSING_INPUT_MERKLE_PROOF", {
        details: { index: proofIndex - 1 },
      });
    }
    validateSpendProof(input, proof, proofIndex - 1);
    if (inputTree === undefined) {
      // The first real spend anchors the tree; both of its proofs must name it.
      if (
        proof.state.merkleContext.tree !== expectedTree ||
        proof.nullifier.merkleContext.tree !== expectedTree
      ) {
        throw new ClientError("CLIENT_PROOF_TREE_MISMATCH", { details: { index } });
      }
      inputTree = Object.freeze({
        treeId,
        slot: Object.freeze({
          id: treeId,
          utxoRoot: new Uint8Array(proof.state.root) as Bytes32,
          nullifierRoot: new Uint8Array(proof.nullifier.root) as Bytes32,
        }),
        utxoRootIndex: proof.state.rootIndex,
        nullifierRootIndex: proof.nullifier.rootIndex,
      });
    } else {
      if (
        proof.state.merkleContext.tree !== expectedTree ||
        !equal(proof.state.root, inputTree.slot.utxoRoot) ||
        proof.state.rootIndex !== inputTree.utxoRootIndex
      ) {
        throw new ClientError("CLIENT_INPUT_TREE_ROOT_MISMATCH", { details: { index } });
      }
      checkNullifierRoot(inputTree, proof.nullifier, expectedTree, index);
    }
    const owner = ownerField(input, index);
    const converted = createRealInput(input, proof, owner);
    transferInputs.push(converted);
    inputHashes.push(bytesToBigInt(input.hash()));
    nullifiers.push(new Uint8Array(input.nullifier()) as Bytes32);
    inputOwnerFields.push(owner);
  }
  if (inputTree === undefined) throw new ClientError("CLIENT_NO_INPUTS");
  return Object.freeze({
    transferInputs: Object.freeze(transferInputs),
    inputHashes: Object.freeze(inputHashes),
    nullifiers: Object.freeze(nullifiers),
    inputOwnerFields: Object.freeze(inputOwnerFields),
    inputTree,
  });
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

/** Every input of a single-tree proof opens against slot 0. */
const INPUT_TREE_SLOT = 0n;

export function createRealInput(
  input: ProofInputUtxo,
  proof: SpendProof,
  ownerPublicKeyHash: bigint,
): TransferInput {
  return Object.freeze({
    utxo: input,
    circuit: inputCircuitUtxo(input),
    isDummy: asField(0n),
    statePathElements: Object.freeze(
      proof.state.path.map((item) => asField(bytesField(item, "state path element"))),
    ),
    statePathIndex: asField(proof.state.leafIndex),
    nullifierLowValue: asField(bytesField(proof.nullifier.lowElement, "low element")),
    nullifierNextValue: asField(bytesField(proof.nullifier.highElement, "high element")),
    nullifierLowPathElements: Object.freeze(
      proof.nullifier.path.map((item) => asField(bytesField(item, "nullifier path element"))),
    ),
    nullifierLowPathIndex: asField(proof.nullifier.lowElementIndex),
    treeSlot: asField(INPUT_TREE_SLOT),
    nullifier: asField(bytesField(input.nullifier(), "nullifier")),
    ownerPublicKeyHash: asField(ownerPublicKeyHash),
    nullifierSecret: asField(bytesField(input.nullifierKey.secretBytes(), "nullifier secret")),
  });
}

export function createDummyTransferInput(
  input: ProofInputUtxo,
  proof: NonInclusionProof,
  nullifier = input.nullifier(),
): TransferInput {
  return Object.freeze({
    utxo: input,
    circuit: inputCircuitUtxo(input, true),
    isDummy: asField(1n),
    statePathElements: Object.freeze(Array.from({ length: STATE_TREE_HEIGHT }, () => asField(0n))),
    statePathIndex: asField(0n),
    nullifierLowValue: asField(bytesField(proof.lowElement, "dummy low element")),
    nullifierNextValue: asField(bytesField(proof.highElement, "dummy high element")),
    nullifierLowPathElements: Object.freeze(
      proof.path.map((item) => asField(bytesField(item, "dummy nullifier path element"))),
    ),
    nullifierLowPathIndex: asField(proof.lowElementIndex),
    treeSlot: asField(INPUT_TREE_SLOT),
    nullifier: asField(bytesField(nullifier, "dummy nullifier")),
    ownerPublicKeyHash: asField(0n),
    nullifierSecret: asField(0n),
  });
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
    utxo: output,
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
        bytesField(input.nullifierKey.publicKey(), "nullifier public key"),
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
