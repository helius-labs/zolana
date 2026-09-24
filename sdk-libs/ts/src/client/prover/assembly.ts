import { getAddressDecoder } from "@solana/kit";

import type {
  Address,
  Bytes32,
  CacheAccess,
  CacheWrite,
  CircuitId,
  TransactInstructionData,
  TransactProof,
} from "../../interface/types.js";
import {
  bindCacheWrite,
  cachedInputFields,
  emptyCachedInputFields,
  NO_CACHE_WRITES,
  type CachedInputFields,
} from "../../interface/cache.js";
import { CACHE_CAPACITY } from "../../interface/state.js";
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
  NO_UTXO_ROOT,
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
  readonly data: "confidentialEddsa" | "ringEddsa" | "ringAuthority";
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

function assembleUnchecked(
  proofInputs: SppProofInputs,
  spendProofs: readonly SpendProof[],
  dummyNullifierProofs: readonly NonInclusionProof[],
  circuit: TransferCircuit,
): AssembledTransfer {
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
      proofInputs.outputs.some(
        (output) => !output.isDummy() && output.ringProgramId !== plan.ring,
      ) ||
      proofInputs.cacheAccounts.read !== undefined ||
      proofInputs.cacheAccounts.write !== undefined ||
      proofInputs.inputUtxos.some((input) => input.cacheSlot !== undefined) ||
      proofInputs.outputs.some((output) => output.cacheSlot !== undefined))
  ) {
    throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
  }
  const realInputs = proofInputs.inputUtxos.filter((input) => !input.isDummy());
  if (realInputs.length === 0) throw new ClientError("CLIENT_NO_INPUTS");
  const outputTreeId = proofInputs.outputTreeId;
  validateOutputBlindings(proofInputs);
  const cache = checkedTransferCache(proofInputs);

  const { transferInputs, inputHashes, nullifiers, inputTrees, treeIndexes } = assembleSlots(
    proofInputs,
    spendProofs,
    dummyNullifierProofs,
    (input) => bytesField(input.utxo.owner.ownerProofInputHash(), "owner public key"),
  );
  const firstTree = inputTrees[0];
  if (firstTree === undefined) throw new ClientError("CLIENT_NO_INPUTS");

  const transferOutputs = proofInputs.outputs.map((output) => createOutput(output, outputTreeId));
  const outputHashes = transferOutputs.map((output) => output.hash as bigint);
  const privateOutputHashes = proofInputs.outputs.map((output, index) =>
    output.isDummy() ? 0n : (outputHashes[index] as bigint),
  );
  const outputOwnerFields = publishedOwnerFields(plan, transferOutputs, proofInputs.externalData);
  const externalDataHash = bytesField(
    bindCacheWrite(proofInputs.externalData.hash(), cacheWriteDestination(cache)),
    "external data hash",
  );
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
  const treeSlots = inputTreeSlots(inputTrees.map((tree) => tree.slot));
  const outputTreeIdField = bytesToBigInt(treeIdField(outputTreeId));
  const cachedInputs = selectedCachedInputs(cache, proofInputs.inputUtxos);
  const publicInputHash = transferPublicInputHash({
    nullifiers: nullifiers.map(bytesToBigInt),
    outputHashes,
    treeSlots,
    outputTreeId,
    privateTxHash,
    externalDataHash,
    publicSlots,
    ringProgramId,
    signerPublicKeyHashes,
    inputFlags: flags,
    publishedOutputOwnerPublicKeyHashes: outputOwnerFields,
    ...cachedInputs,
  });
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
    inputFlags: asField(flags),
    publishedOutputOwnerPublicKeyHashes: Object.freeze((outputOwnerFields ?? []).map(asField)),
    ...cacheProverFields(cachedInputs),
    publicInputHash: asField(publicInputHash),
  });
  const proverInputs: ProverInputs = Object.freeze({ circuit: plan.prover, payload: common });

  const rootIndexes: InputRootIndexes = Object.freeze({
    utxoTree: firstTree.utxoRootIndex,
    nullifierTree: firstTree.nullifierRootIndex,
  });
  const instructionData: TransactInstructionData = Object.freeze({
    expiryUnixTs: proofInputs.externalData.expiryUnixTs,
    privateTxHash: bigintToBytes(privateTxHash) as Bytes32,
    circuit: transferCircuit(
      plan,
      cache,
      proofInputs.inputUtxos.length,
      proofInputs.outputs.length,
    ),
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
    treeContexts: Object.freeze(
      inputTrees.map((tree) =>
        Object.freeze({
          utxoTreeRootIndex: tree.utxoRootIndex,
          nullifierTreeRootIndex: tree.nullifierRootIndex,
        }),
      ),
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
  // Slot 0 is always a real spend, so the first tree's roots are the pair a
  // ring statement binds.
  return Object.freeze({
    instructionData,
    proverInputs,
    publicInputHash: bigintToBytes(publicInputHash) as Bytes32,
    nullifiers: Object.freeze(nullifiers.map((nullifier) => new Uint8Array(nullifier) as Bytes32)),
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

export interface CheckedTransferCache {
  readonly read: Readonly<{ address: Address; treeId: number }> | undefined;
  readonly write: Address | undefined;
  readonly access: CacheAccess;
}

export function checkedTransferCache(
  proofInputs: SppProofInputs,
): CheckedTransferCache | undefined {
  const { read, write } = proofInputs.cacheAccounts;
  if (read !== undefined) addressBytes(read);
  if (write !== undefined) addressBytes(write);
  let readBitmap = 0n;
  let cacheTreeId: number | undefined;
  proofInputs.inputUtxos.forEach((input, index) => {
    const slot = input.cacheSlot;
    if (slot === undefined) return;
    if (read === undefined) {
      throw new ClientError("CLIENT_CACHED_INPUT_WITHOUT_READ_CACHE", { details: { index } });
    }
    if (((readBitmap >> BigInt(slot)) & 1n) === 1n) {
      throw new ClientError("CLIENT_DUPLICATE_CACHE_READ_SLOT", { details: { index, slot } });
    }
    cacheTreeId ??= input.treeId;
    if (input.treeId !== cacheTreeId) {
      throw new ClientError("CLIENT_CACHE_READ_TREE_MISMATCH", {
        details: { index, treeId: input.treeId, cacheTreeId },
      });
    }
    readBitmap |= 1n << BigInt(slot);
  });
  if (read !== undefined && cacheTreeId === undefined) {
    throw new ClientError("CLIENT_UNUSED_READ_CACHE");
  }
  const writes: CacheWrite[] = [];
  proofInputs.outputs.forEach((output, index) => {
    const slot = output.cacheSlot;
    if (slot === undefined) return;
    if (write === undefined) {
      throw new ClientError("CLIENT_CACHED_OUTPUT_WITHOUT_WRITE_CACHE", { details: { index } });
    }
    if (output.isDummy()) {
      throw new ClientError("CLIENT_CACHED_DUMMY_OUTPUT", { details: { index } });
    }
    if (!Number.isInteger(slot)) {
      throw new ClientError("CLIENT_INVALID_CACHE_ACCESS", {
        details: { field: "cacheSlot", index },
      });
    }
    if (slot < 0 || slot >= CACHE_CAPACITY) {
      throw new ClientError("CLIENT_CACHE_WRITE_SLOT_OUT_OF_RANGE", { details: { index, slot } });
    }
    if (writes.some((entry) => entry.slot === slot)) {
      throw new ClientError("CLIENT_DUPLICATE_CACHE_WRITE_SLOT", { details: { index, slot } });
    }
    writes.push(Object.freeze({ output: index, slot }));
  });
  if (write !== undefined && writes.length === 0) {
    throw new ClientError("CLIENT_UNUSED_WRITE_CACHE");
  }
  if (read === undefined && write === undefined) return undefined;
  return Object.freeze({
    read:
      read === undefined || cacheTreeId === undefined
        ? undefined
        : Object.freeze({ address: read, treeId: cacheTreeId }),
    write,
    access: Object.freeze({
      readBitmap,
      writeSlots: Object.freeze([...writes, ...NO_CACHE_WRITES.slice(writes.length)]),
    }),
  });
}

function cacheWriteDestination(
  cache: CheckedTransferCache | undefined,
): Readonly<{ cache: Address; writeSlots: readonly CacheWrite[] }> | undefined {
  if (cache?.write === undefined) return undefined;
  return Object.freeze({ cache: cache.write, writeSlots: cache.access.writeSlots });
}

function transferCircuit(
  plan: CircuitPlan,
  cache: CheckedTransferCache | undefined,
  inputs: number,
  outputs: number,
): CircuitId {
  if (cache === undefined) {
    return Object.freeze({ kind: plan.data, inputs, outputs, publicAssetSlots: 3 });
  }
  switch (plan.data) {
    case "confidentialEddsa":
      return Object.freeze({
        kind: "confidentialEddsaCached",
        inputs,
        outputs,
        publicAssetSlots: 3,
        cacheAccess: cache.access,
      });
    case "ringEddsa":
      return Object.freeze({
        kind: "ringEddsaCached",
        inputs,
        outputs,
        publicAssetSlots: 3,
        cacheAccess: cache.access,
      });
    case "ringAuthority":
      throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
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

export interface AssembledSlots {
  readonly transferInputs: readonly TransferInput[];
  readonly inputHashes: readonly bigint[];
  readonly nullifiers: readonly Bytes32[];
  readonly inputOwnerFields: readonly bigint[];
  /** The input trees in first-use order, at most `MAX_INPUT_TREES` of them. */
  readonly inputTrees: readonly InputTree[];
  /** Each input's position in `inputTrees`, never decreasing. */
  readonly treeIndexes: readonly number[];
}

/**
 * Mirrors Rust `assemble_inputs` and `resolve_input_trees`. Padding is not
 * decided here: a slot with a spend proof is a real spend, a slot without one
 * is a dummy with its own non-inclusion proof.
 *
 * Inputs are grouped by tree: each tree owns one contiguous run, so an input's
 * tree index never decreases and the program can queue every run's nullifiers
 * as consecutive numbers under its own tree. A tree is opened by a real spend,
 * whose nullifier proof fixes the slot's nullifier root; the first uncached
 * real spend of the run fixes its state root, and every later input of that
 * run must open against the same roots and root positions, since the proof
 * publishes one slot per tree and the instruction one root position pair per
 * tree. A run the cache supplies entirely publishes a zero state root at root
 * position `NO_UTXO_ROOT`. A dummy or cached input carries no state proof, so it
 * rides the run it sits in, and takes the next dummy non-inclusion proof.
 * `ownerField` is the caller's rail: it is the one thing Rust's `OwnerMode`
 * varies, and every rail shares the rest of this loop.
 */
export function assembleSlots(
  proofInputs: SppProofInputs,
  spendProofs: readonly SpendProof[],
  dummyNullifierProofs: readonly NonInclusionProof[],
  ownerField: (input: ProofInputUtxo, index: number) => bigint,
): AssembledSlots {
  const transferInputs: TransferInput[] = [];
  const inputHashes: bigint[] = [];
  const nullifiers: Bytes32[] = [];
  const inputOwnerFields: bigint[] = [];
  const runs: InputTreeRun[] = [];
  const treeIndexes: number[] = [];
  let proofIndex = 0;
  let dummyProofIndex = 0;
  for (let index = 0; index < proofInputs.inputUtxos.length; index++) {
    const input = proofInputs.inputUtxos[index];
    if (!input) {
      throw new ClientError("CLIENT_PROOF_INPUT_COUNT_MISMATCH", {
        details: { got: index, expected: proofInputs.inputUtxos.length },
      });
    }
    const treeId = input.treeId;
    const expectedTree = treeAddress(treeId);
    const openRun = runs.at(-1);
    const openIndex = runs.length - 1;
    if (input.isDummy()) {
      if (openRun === undefined) throw new ClientError("CLIENT_NO_INPUTS");
      if (treeId !== openRun.treeId) {
        throw new ClientError("CLIENT_INPUTS_NOT_GROUPED_BY_TREE", { details: { index } });
      }
      const proof = dummyNullifierProofs[dummyProofIndex++];
      if (!proof) {
        throw new ClientError("CLIENT_MISSING_INPUT_MERKLE_PROOF", {
          details: { index },
        });
      }
      validateNullifierProof(input, proof, index);
      checkNullifierRoot(openRun, proof, expectedTree, index);
      const converted = createDummyTransferInput(input, proof, input.nullifier(), openIndex);
      transferInputs.push(converted);
      inputHashes.push(0n);
      nullifiers.push(bigintToBytes(converted.nullifier) as Bytes32);
      inputOwnerFields.push(converted.ownerPublicKeyHash);
      treeIndexes.push(openIndex);
      continue;
    }
    let treeIndex: number;
    let converted: TransferInput;
    let owner: bigint;
    if (input.cacheSlot !== undefined) {
      const proof = dummyNullifierProofs[dummyProofIndex++];
      if (!proof) {
        throw new ClientError("CLIENT_MISSING_INPUT_MERKLE_PROOF", { details: { index } });
      }
      validateNullifierProof(input, proof, index);
      if (openRun !== undefined && openRun.treeId === treeId) {
        treeIndex = openIndex;
        checkNullifierRoot(openRun, proof, expectedTree, index);
      } else {
        checkNewRun(runs, treeId, index);
        if (proof.merkleContext.tree !== expectedTree) {
          throw new ClientError("CLIENT_PROOF_TREE_MISMATCH", { details: { index } });
        }
        runs.push({
          treeId,
          nullifierRoot: new Uint8Array(proof.root) as Bytes32,
          nullifierRootIndex: proof.rootIndex,
          state: undefined,
        });
        treeIndex = runs.length - 1;
      }
      owner = ownerField(input, index);
      converted = createCachedInput(input, proof, owner, treeIndex);
    } else {
      const proof = spendProofs[proofIndex++];
      if (!proof) {
        throw new ClientError("CLIENT_MISSING_INPUT_MERKLE_PROOF", {
          details: { index: proofIndex - 1 },
        });
      }
      validateSpendProof(input, proof, proofIndex - 1);
      if (openRun !== undefined && openRun.treeId === treeId) {
        treeIndex = openIndex;
        if (openRun.state === undefined) {
          if (proof.state.merkleContext.tree !== expectedTree) {
            throw new ClientError("CLIENT_PROOF_TREE_MISMATCH", { details: { index } });
          }
          openRun.state = Object.freeze({
            root: new Uint8Array(proof.state.root) as Bytes32,
            index: proof.state.rootIndex,
          });
        } else if (
          proof.state.merkleContext.tree !== expectedTree ||
          !equal(proof.state.root, openRun.state.root) ||
          proof.state.rootIndex !== openRun.state.index
        ) {
          throw new ClientError("CLIENT_INPUT_TREE_ROOT_MISMATCH", { details: { index } });
        }
        checkNullifierRoot(openRun, proof.nullifier, expectedTree, index);
      } else {
        checkNewRun(runs, treeId, index);
        // The real spend that opens a tree anchors it; both of its proofs must
        // name that tree.
        if (
          proof.state.merkleContext.tree !== expectedTree ||
          proof.nullifier.merkleContext.tree !== expectedTree
        ) {
          throw new ClientError("CLIENT_PROOF_TREE_MISMATCH", { details: { index } });
        }
        runs.push({
          treeId,
          nullifierRoot: new Uint8Array(proof.nullifier.root) as Bytes32,
          nullifierRootIndex: proof.nullifier.rootIndex,
          state: Object.freeze({
            root: new Uint8Array(proof.state.root) as Bytes32,
            index: proof.state.rootIndex,
          }),
        });
        treeIndex = runs.length - 1;
      }
      owner = ownerField(input, index);
      converted = createRealInput(input, proof, owner, treeIndex);
    }
    transferInputs.push(converted);
    inputHashes.push(bytesToBigInt(input.hash()));
    nullifiers.push(new Uint8Array(input.nullifier()) as Bytes32);
    inputOwnerFields.push(owner);
    treeIndexes.push(treeIndex);
  }
  if (runs.length === 0) throw new ClientError("CLIENT_NO_INPUTS");
  return Object.freeze({
    transferInputs: Object.freeze(transferInputs),
    inputHashes: Object.freeze(inputHashes),
    nullifiers: Object.freeze(nullifiers),
    inputOwnerFields: Object.freeze(inputOwnerFields),
    inputTrees: Object.freeze(runs.map(inputTreeOf)),
    treeIndexes: Object.freeze(treeIndexes),
  });
}

interface InputTreeRun {
  readonly treeId: TreeId;
  readonly nullifierRoot: Bytes32;
  readonly nullifierRootIndex: number;
  state: Readonly<{ root: Bytes32; index: number }> | undefined;
}

function checkNewRun(runs: readonly InputTreeRun[], treeId: TreeId, index: number): void {
  // A tree whose run already closed cannot be reopened: its nullifiers
  // would no longer be consecutive.
  if (runs.some((run) => run.treeId === treeId)) {
    throw new ClientError("CLIENT_INPUTS_NOT_GROUPED_BY_TREE", { details: { index } });
  }
  if (runs.length === MAX_INPUT_TREES) {
    throw new ClientError("CLIENT_TOO_MANY_INPUT_TREES", {
      details: { got: runs.length + 1, max: MAX_INPUT_TREES },
    });
  }
}

function inputTreeOf(run: InputTreeRun): InputTree {
  const state = run.state ?? { root: new Uint8Array(32) as Bytes32, index: NO_UTXO_ROOT };
  return Object.freeze({
    treeId: run.treeId,
    slot: Object.freeze({
      id: run.treeId,
      utxoRoot: state.root,
      nullifierRoot: run.nullifierRoot,
    }),
    utxoRootIndex: state.index,
    nullifierRootIndex: run.nullifierRootIndex,
  });
}

export interface CachedInputs {
  readonly cacheTreeId: bigint;
  readonly cacheReadHashChain: bigint;
  readonly cacheReadHashes: readonly bigint[];
  readonly cacheIsCached: readonly bigint[];
  readonly cacheReadIndex: readonly bigint[];
}

export function emptyCachedInputs(inputCount: number): CachedInputs {
  const [treeId, chain] = emptyCachedInputFields(inputCount);
  return Object.freeze({
    cacheTreeId: bytesToBigInt(treeId),
    cacheReadHashChain: bytesToBigInt(chain),
    cacheReadHashes: Object.freeze([]),
    cacheIsCached: Object.freeze([]),
    cacheReadIndex: Object.freeze([]),
  });
}

function selectedCachedInputs(
  cache: CheckedTransferCache | undefined,
  inputs: readonly ProofInputUtxo[],
): CachedInputs {
  if (cache?.read === undefined) return emptyCachedInputs(inputs.length);
  const { readBitmap } = cache.access;
  const slots: Uint8Array[] = Array.from({ length: CACHE_CAPACITY }, () => new Uint8Array(32));
  inputs.forEach((input) => {
    if (input.cacheSlot !== undefined) slots[input.cacheSlot] = input.hash();
  });
  const fields: CachedInputFields = cachedInputFields(
    readBitmap,
    cache.read.treeId,
    slots,
    inputs.length,
  );
  const [treeId, chain] = fields;
  const ordered = slots.flatMap((hash, slot) =>
    ((readBitmap >> BigInt(slot)) & 1n) === 1n ? [bytesToBigInt(hash)] : [],
  );
  const readHashes = [
    ...ordered,
    ...Array.from({ length: inputs.length - ordered.length }, () => 0n),
  ];
  const rank = (slot: number): bigint => {
    let below = 0n;
    for (let other = 0; other < slot; other++) {
      below += (readBitmap >> BigInt(other)) & 1n;
    }
    return below;
  };
  return Object.freeze({
    cacheTreeId: bytesToBigInt(treeId),
    cacheReadHashChain: bytesToBigInt(chain),
    cacheReadHashes: Object.freeze(readHashes),
    cacheIsCached: Object.freeze(inputs.map((input) => (input.cacheSlot === undefined ? 0n : 1n))),
    cacheReadIndex: Object.freeze(
      inputs.map((input) => (input.cacheSlot === undefined ? 0n : rank(input.cacheSlot))),
    ),
  });
}

export function cacheProverFields(cachedInputs: CachedInputs): Readonly<{
  cacheTreeId: Field;
  cacheReadHashChain: Field;
  cacheReadHashes: readonly Field[];
  cacheIsCached: readonly Field[];
  cacheReadIndex: readonly Field[];
}> {
  return Object.freeze({
    cacheTreeId: asField(cachedInputs.cacheTreeId),
    cacheReadHashChain: asField(cachedInputs.cacheReadHashChain),
    cacheReadHashes: Object.freeze(cachedInputs.cacheReadHashes.map(asField)),
    cacheIsCached: Object.freeze(cachedInputs.cacheIsCached.map(asField)),
    cacheReadIndex: Object.freeze(cachedInputs.cacheReadIndex.map(asField)),
  });
}

/**
 * Mirrors Rust `PublicInputs::hash`: the nullifier, output, owner and outer
 * chains fold three elements per call, the signer chain folds from the right.
 * The cache selection closes the preimage, appended by the same rails that
 * append the output-owner chain.
 */
export function transferPublicInputHash(
  input: Readonly<{
    nullifiers: readonly bigint[];
    outputHashes: readonly bigint[];
    treeSlots: readonly TreeSlot[];
    outputTreeId: TreeId;
    privateTxHash: bigint;
    externalDataHash: bigint;
    publicSlots: readonly bigint[];
    ringProgramId: bigint;
    signerPublicKeyHashes: readonly bigint[];
    /** The packed dummy policy and per-input tree indexes, `inputFlags`. */
    inputFlags: bigint;
    /** `undefined` folds no owner list, and then no cache selection either. */
    publishedOutputOwnerPublicKeyHashes: readonly bigint[] | undefined;
  }> &
    CachedInputs,
): bigint {
  return hashChain4([
    hashChain4(input.nullifiers),
    hashChain4(input.outputHashes),
    bytesToBigInt(treeSlotsHashChain(input.treeSlots)),
    bytesToBigInt(treeIdField(input.outputTreeId)),
    input.privateTxHash,
    input.externalDataHash,
    ...input.publicSlots,
    input.ringProgramId,
    rightHashChain(input.signerPublicKeyHashes),
    input.inputFlags,
    ...(input.publishedOutputOwnerPublicKeyHashes === undefined
      ? []
      : [
          hashChain4(input.publishedOutputOwnerPublicKeyHashes),
          input.cacheTreeId,
          input.cacheReadHashChain,
        ]),
  ]);
}

function checkNullifierRoot(
  run: Readonly<{ nullifierRoot: Bytes32; nullifierRootIndex: number }>,
  proof: NonInclusionProof,
  expectedTree: Address,
  index: number,
): void {
  if (
    proof.merkleContext.tree !== expectedTree ||
    !equal(proof.root, run.nullifierRoot) ||
    proof.rootIndex !== run.nullifierRootIndex
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
  return spendInput(
    input,
    proof.state.path.map((item) => asField(bytesField(item, "state path element"))),
    proof.state.leafIndex,
    proof.nullifier,
    ownerPublicKeyHash,
    treeSlot,
  );
}

function createCachedInput(
  input: ProofInputUtxo,
  proof: NonInclusionProof,
  ownerPublicKeyHash: bigint,
  treeSlot: number,
): TransferInput {
  return spendInput(
    input,
    Array.from({ length: STATE_TREE_HEIGHT }, () => asField(0n)),
    0n,
    proof,
    ownerPublicKeyHash,
    treeSlot,
  );
}

function spendInput(
  input: ProofInputUtxo,
  statePathElements: readonly Field[],
  statePathIndex: bigint,
  nullifierProof: NonInclusionProof,
  ownerPublicKeyHash: bigint,
  treeSlot: number,
): TransferInput {
  return Object.freeze({
    circuit: inputCircuitUtxo(input),
    isDummy: asField(0n),
    statePathElements: Object.freeze(statePathElements),
    statePathIndex: asField(statePathIndex),
    nullifierLowValue: asField(bytesField(nullifierProof.lowElement, "low element")),
    nullifierNextValue: asField(bytesField(nullifierProof.highElement, "high element")),
    nullifierLowPathElements: Object.freeze(
      nullifierProof.path.map((item) => asField(bytesField(item, "nullifier path element"))),
    ),
    nullifierLowPathIndex: asField(nullifierProof.lowElementIndex),
    treeSlot: asField(BigInt(treeSlot)),
    nullifier: asField(bytesField(input.nullifier(), "nullifier")),
    ownerPublicKeyHash: asField(ownerPublicKeyHash),
  });
}

export function createDummyTransferInput(
  input: ProofInputUtxo,
  proof: NonInclusionProof,
  nullifier = input.nullifier(),
  treeSlot: number = INPUT_TREE_SLOT,
): TransferInput {
  return Object.freeze({
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
    treeSlot: asField(BigInt(treeSlot)),
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

function validateNullifierProof(
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
