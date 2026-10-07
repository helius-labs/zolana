import type {
  Address,
  Bytes32,
  MergeBody,
  MergeEnvelope,
  MergeInstructionData,
  MergeProofCommitment,
  RequestContext,
} from "../../interface/types.js";
import { mergeExternalDataHash } from "../../interface/codecs/index.js";
import {
  MAX_MERGE_INPUTS,
  MERGE_SUPPORTED_INPUT_COUNTS,
  mergePaddedInputCount,
} from "../../interface/constants.js";
import { mergeEnvelopePublicElements } from "../../interface/merge-utils.js";
import { InstructionTag } from "../../interface/program.js";
import { treeAddress } from "../../interface/pda/index.js";
import { inputTreeSlots, treeIdField, type TreeSlot } from "../../interface/tree-slot.js";
import type { EncryptedMergeEnvelope } from "../../keypair/merge/index.js";
import { MergeOutputEnvelope, PreparedMerge } from "../../transaction/instructions/builders.js";
import type { TreeId } from "../../transaction/utxo.js";
import { privateTxHash as computePrivateTxHash } from "../../transaction/instructions/transact.js";

import { CACHE_CAPACITY } from "../../interface/state.js";
import type {
  MergeCacheTarget,
  ProofReader,
  IndexedProofInputs,
  PreparedMergeInputs,
} from "../ports.js";
import { ClientError, fromClientCause } from "../error.js";
import {
  addressBytes,
  bigintToBytes,
  bytesField,
  bytesToBigInt,
  checkedBytes,
  field,
  rightHashChain4,
} from "../internal.js";
import type { NonInclusionProof, SpendProof } from "../rpc.js";
import {
  createDummyTransferInput,
  createOutput,
  createRealInput,
  prepareInput,
  resolvedPublicInputHash,
  treeSlotFields,
  validateSpendProof,
} from "./assembly.js";
import type { CompressedProofParts } from "./proof.js";
import type { Field, MergeEnvelopeInputs, MergeInputs, TransferInput } from "./types.js";

export interface MergeAssembly {
  /**
   * Lends the complete prover inputs to `use`. A default merge's inputs carry
   * a copy of the envelope's ephemeral secret, wiped once `use` settles.
   */
  withProverInputs<T>(use: (inputs: MergeInputs) => Promise<T> | T): Promise<T>;
  readonly expiryUnixTs: bigint;
  readonly outputHash: Bytes32;
  readonly nullifiers: readonly Bytes32[];
  readonly utxoTreeRootIndex: number;
  readonly nullifierTreeRootIndex: number;
  readonly privateTxHash: Bytes32;
  readonly publicInputHash: Bytes32;
  /// Recomputed on-chain from the instruction; surfaced so the caller need not
  /// re-derive it.
  readonly externalDataHash: Bytes32;
  readonly eddsaOwner: boolean;
  readonly cacheSlot?: number;
  /**
   * The default merge's `merge_transact` data, or the ring merge's shared body,
   * which `merge_ring` sends after the output `ring_data_hash`.
   */
  instructionData(proof: CompressedProofParts): MergeInstructionData;
}

export async function assembleMerge(
  prepared: PreparedMerge,
  indexer: Pick<ProofReader, "getInputMerkleProofs" | "getNonInclusionProofs">,
  tree: Address,
  context?: RequestContext,
  cache?: MergeCacheTarget,
): Promise<MergeAssembly> {
  try {
    validatePreparedMerge(prepared);
    const target = cache === undefined ? undefined : checkedMergeCacheTarget(cache);
    const dummyNullifiers = prepared.dummyNullifiers();
    const [proofs, dummyResponse] = await Promise.all([
      indexer.getInputMerkleProofs(prepared.inputUtxoHashes(), undefined, context),
      dummyNullifiers.length === 0
        ? Promise.resolve(undefined)
        : indexer.getNonInclusionProofs(tree, dummyNullifiers, undefined, context),
    ]);
    return assembleMergeUnchecked(prepared, proofs, dummyResponse?.proofs ?? [], tree, target);
  } catch (cause) {
    throw fromClientCause(cause);
  }
}

export function assembleMergeWithProofs(
  prepared: PreparedMerge,
  proofs: readonly SpendProof[],
  tree: Address,
  dummyNullifierProofs: readonly NonInclusionProof[] = [],
  cache?: MergeCacheTarget,
): MergeAssembly {
  try {
    return assembleMergeUnchecked(
      prepared,
      proofs,
      dummyNullifierProofs,
      tree,
      cache === undefined ? undefined : checkedMergeCacheTarget(cache),
    );
  } catch (cause) {
    throw fromClientCause(cause);
  }
}

function checkedMergeCacheTarget(cache: MergeCacheTarget): MergeCacheTarget {
  const candidate: unknown = cache;
  if (typeof candidate !== "object" || candidate === null) {
    throw new ClientError("CLIENT_INVALID_CACHE_ACCESS", {
      details: { field: "cache" },
    });
  }
  addressBytes(cache.address);
  if (!Number.isSafeInteger(cache.slot) || cache.slot < 0 || cache.slot >= CACHE_CAPACITY) {
    throw new ClientError("CLIENT_INVALID_CACHE_ACCESS", {
      details: { field: "slot" },
    });
  }
  return Object.freeze({ address: cache.address, slot: cache.slot });
}

/** The one tree slot a merge opens against, and the root positions its instruction references. */
interface MergeInputTree {
  readonly slot: TreeSlot;
  readonly utxoRootIndex: number;
  readonly nullifierRootIndex: number;
}

function assembleMergeUnchecked(
  prepared: PreparedMerge,
  proofs: readonly SpendProof[],
  dummyNullifierProofs: readonly NonInclusionProof[],
  tree: Address,
  cache: MergeCacheTarget | undefined,
): MergeAssembly {
  validateMergeTree(prepared, tree);
  const realInputs = prepared.inputs.filter((input) => !input.isDummy());
  if (proofs.length !== realInputs.length) {
    throw new ClientError("CLIENT_INCOMPLETE_INPUT_PROOFS", {
      details: {
        expected: realInputs.length,
        state: proofs.length,
        nullifier: proofs.length,
      },
    });
  }
  if (realInputs.length === 0) throw new ClientError("CLIENT_NO_INPUTS");
  const dummyNullifiers = prepared.dummyNullifiers();
  if (dummyNullifierProofs.length !== dummyNullifiers.length) {
    throw new ClientError("CLIENT_INCOMPLETE_INPUT_PROOFS", {
      details: {
        expected: dummyNullifiers.length,
        state: 0,
        nullifier: dummyNullifierProofs.length,
      },
    });
  }
  const inputs: TransferInput[] = [];
  let inputTree: MergeInputTree | undefined;
  let proofIndex = 0;
  let dummyIndex = 0;
  for (const [index, input] of prepared.inputs.entries()) {
    // A padding slot proves non-inclusion of its deterministic dummy
    // nullifier; compact padding publishes 0 in its place.
    if (input.isDummy()) {
      if (inputTree === undefined) throw new ClientError("CLIENT_NO_INPUTS");
      const nullifier = dummyNullifiers[dummyIndex];
      const proof = dummyNullifierProofs[dummyIndex++];
      if (!nullifier || !proof) {
        throw new ClientError("CLIENT_MISSING_INPUT_MERKLE_PROOF", {
          details: { index: dummyIndex - 1 },
        });
      }
      if (!equal(proof.leaf, nullifier)) {
        throw new ClientError("CLIENT_NULLIFIER_PROOF_LEAF_MISMATCH", {
          details: { index: dummyIndex - 1 },
        });
      }
      if (proof.merkleContext.tree !== tree) {
        throw new ClientError("CLIENT_MERGE_TREE_MISMATCH", {
          details: { proofTree: proof.merkleContext.tree, submitTree: tree },
        });
      }
      checkNullifierRoot(inputTree, proof, index);
      const converted = createDummyTransferInput(
        input,
        proof,
        input.isCompact() ? input.publishedNullifier() : nullifier,
      );
      inputs.push(converted);
      continue;
    }
    const proof = proofs[proofIndex];
    if (!proof) {
      throw new ClientError("CLIENT_MISSING_INPUT_MERKLE_PROOF", {
        details: { index: proofIndex },
      });
    }
    validateSpendProof(input, proof, proofIndex);
    if (proof.state.merkleContext.tree !== tree) {
      throw new ClientError("CLIENT_MERGE_TREE_MISMATCH", {
        details: {
          proofTree: proof.state.merkleContext.tree,
          submitTree: tree,
        },
      });
    }
    if (proof.nullifier.merkleContext.tree !== tree) {
      throw new ClientError("CLIENT_MERGE_TREE_MISMATCH", {
        details: {
          proofTree: proof.nullifier.merkleContext.tree,
          submitTree: tree,
        },
      });
    }
    if (inputTree === undefined) {
      inputTree = Object.freeze({
        slot: Object.freeze({
          id: prepared.inputTreeId,
          utxoRoot: new Uint8Array(proof.state.root) as Bytes32,
          nullifierRoot: new Uint8Array(proof.nullifier.root) as Bytes32,
        }),
        utxoRootIndex: proof.state.rootIndex,
        nullifierRootIndex: proof.nullifier.rootIndex,
      });
    } else {
      if (
        !equal(proof.state.root, inputTree.slot.utxoRoot) ||
        proof.state.rootIndex !== inputTree.utxoRootIndex
      ) {
        throw new ClientError("CLIENT_INPUT_TREE_ROOT_MISMATCH", {
          details: { index },
        });
      }
      checkNullifierRoot(inputTree, proof.nullifier, index);
    }
    // A P256 owner contributes the 0 sentinel: the merge circuit recomputes its
    // pk_field from the witnessed point and ignores the per-input value.
    const ownerPublicKeyHash =
      input.utxo.owner.signatureType() === "p256"
        ? 0n
        : bytesField(input.utxo.owner.ownerProofInputHash(), "merge owner public key");
    const converted = createRealInput(input, proof, ownerPublicKeyHash);
    inputs.push(converted);
    proofIndex++;
  }
  if (inputTree === undefined) throw new ClientError("CLIENT_NO_INPUTS");

  const local = prepareMerge(prepared, tree, cache);
  const complete = local.finish(inputTree);
  const treeSlots = Object.freeze(inputTreeSlots([inputTree.slot]).map(treeSlotFields));
  const publicInputHash = asField(bytesToBigInt(complete.publicInputHash));
  return Object.freeze({
    ...complete,
    withProverInputs: <T>(use: (inputs: MergeInputs) => Promise<T> | T): Promise<T> =>
      local.withInputs((request) =>
        use(
          Object.freeze({
            ...request.payload,
            inputs: Object.freeze(inputs),
            treeSlots,
            publicInputHash,
          }),
        ),
      ),
  });
}

type MergeRailPublicInputs =
  | Readonly<{
      kind: "default";
      ownerPublicKeyHash: bigint;
      nullifierPublicKey: bigint;
      recipient: Uint8Array;
      ephemeralPublicKey: Uint8Array;
      ciphertext: Uint8Array;
    }>
  | Readonly<{ kind: "ring"; ringDataHash: bigint; ringProgramId: bigint }>;

interface MergePublicInputFields {
  /** One per circuit slot, 0 for compact padding. */
  readonly nullifiers: readonly bigint[];
  readonly outputHash: bigint;
  readonly outputTreeId: TreeId;
  readonly privateTxHash: bigint;
  readonly externalDataHash: bigint;
  readonly rail: MergeRailPublicInputs;
}

/**
 * The merge public inputs without the tree slots, which
 * `resolvedPublicInputHash` inserts. The nullifier chain folds to the right
 * over the circuit width; the 1 is the dummy-input policy merge always
 * publishes. Mirrors the element order of Rust `MergeProver::build`.
 */
export function mergePublicInputs(input: MergePublicInputFields): readonly bigint[] {
  return [
    rightHashChain4(input.nullifiers),
    input.outputHash,
    bytesToBigInt(treeIdField(input.outputTreeId)),
    input.privateTxHash,
    input.externalDataHash,
    1n,
    ...(input.rail.kind === "ring"
      ? [input.rail.ringDataHash, input.rail.ringProgramId]
      : [
          input.rail.ownerPublicKeyHash,
          input.rail.nullifierPublicKey,
          ...mergeEnvelopePublicElements(
            input.rail.recipient,
            input.rail.ephemeralPublicKey,
            input.rail.ciphertext,
          ).map(bytesToBigInt),
        ]),
  ];
}

type IndexedMergeInputs = IndexedProofInputs & {
  readonly circuit: "merge";
  readonly payload: PreparedMergeInputs;
};

interface PreparedMergeAssembly {
  /**
   * Lends the prover request to `use`. A default merge's request carries a
   * copy of the envelope's ephemeral secret, wiped once `use` settles.
   */
  withInputs<T>(use: (inputs: IndexedMergeInputs) => Promise<T> | T): Promise<T>;
  finish(tree: MergeInputTree): Omit<MergeAssembly, "withProverInputs">;
}

export function prepareMerge(
  prepared: PreparedMerge,
  tree: Address,
  cacheTarget?: MergeCacheTarget,
): PreparedMergeAssembly {
  const validated = validateMergeTree(prepared, tree);
  const cache = cacheTarget === undefined ? undefined : checkedMergeCacheTarget(cacheTarget);
  const expiryUnixTs = prepared.expiryUnixTs;
  // 1. Reuse commitments within one call to keep mutable input bytes bound to the statement.
  const realCommitments = new Map(
    prepared.inputUtxoHashes().map(({ index, utxoHash }) => [index, utxoHash]),
  );
  const commitments = prepared.inputs.map((input, index) => {
    if (input.isDummy()) return null;
    const commitment = realCommitments.get(index);
    if (commitment === undefined) throw new ClientError("CLIENT_INVALID_MERGE");
    return commitment;
  });
  const dummyNullifiers = prepared.dummyNullifiers();
  let dummyIndex = 0;
  // A padding slot's deterministic dummy nullifier is what the prover fetches
  // the witness for; compact padding publishes 0 and carries it in its lookup.
  const slots = prepared.inputs.map((input, index) => {
    const nullifier = input.isDummy() ? dummyNullifiers[dummyIndex++] : input.nullifier();
    if (nullifier === undefined) throw new ClientError("CLIENT_INVALID_MERGE");
    const owner =
      input.isDummy() || input.utxo.owner.signatureType() === "p256"
        ? 0n
        : bytesField(input.utxo.owner.ownerProofInputHash(), "merge owner public key");
    return Object.freeze({
      input: prepareInput(input, {
        owner,
        treeSlot: 0,
        nullifier: input.isCompact() ? input.publishedNullifier() : nullifier,
      }),
      lookup: Object.freeze({
        treeSlot: 0,
        commitment: commitments[index] ?? null,
        nullifier: input.isCompact() ? nullifier : null,
      }),
    });
  });
  const inputs = slots.map((slot) => slot.input);
  const inputHashes = commitments.map(
    (commitment) => commitment ?? (new Uint8Array(32) as Bytes32),
  );
  const nullifiers = inputs.map((input) =>
    checkedBytes(bigintToBytes(input.nullifier, "nullifier"), 32, "nullifier"),
  );
  const output = createOutput(prepared.output, prepared.outputTreeId);
  if (prepared.output.isDummy()) throw new ClientError("CLIENT_INVALID_MERGE_OUTPUT");
  const outputHash = checkedBytes(prepared.outputHash(), 32, "merge output hash");
  const externalDataHash = mergeExternalDataHash({
    instructionTag:
      prepared.output.ringProgramId === undefined
        ? InstructionTag.mergeTransact
        : InstructionTag.ringMergeTransact,
    expiryUnixTs,
    outputUtxoHash: outputHash,
    ...(cache === undefined ? {} : { cache }),
  });
  // Merge has no blinding seed: the owner's nullifier secret takes its place
  // in the private transaction blinding, so a reader holding the secret
  // recovers the output without any disclosed value.
  const firstNullifier = nullifiers[0];
  if (firstNullifier === undefined) throw new ClientError("CLIENT_NO_INPUTS");
  const privateTxBlinding = prepared.privateTxBlinding();
  const privateTxHash = computePrivateTxHash({
    inputHashes,
    outputHashes: [outputHash],
    blinding: privateTxBlinding,
  });
  const eddsaOwner = prepared.signingPublicKey.signatureType() === "ed25519";
  const ownerPublicKeyHash = bytesField(
    prepared.signingPublicKey.ownerProofInputHash(),
    "merge owner public key",
  );
  const outputTreeIdField = bytesToBigInt(treeIdField(prepared.outputTreeId));
  const nullifierPublicKey = bytesField(prepared.nullifierPublicKey, "merge nullifier public key");
  const publicInputs = mergePublicInputs({
    nullifiers: nullifiers.map(bytesToBigInt),
    outputHash: bytesToBigInt(outputHash),
    outputTreeId: prepared.outputTreeId,
    privateTxHash: bytesToBigInt(privateTxHash),
    externalDataHash: bytesToBigInt(externalDataHash),
    rail:
      validated === undefined
        ? {
            kind: "ring",
            ringDataHash: BigInt(output.circuit.ringDataHash),
            ringProgramId: BigInt(output.circuit.ringProgramId),
          }
        : {
            kind: "default",
            ownerPublicKeyHash,
            nullifierPublicKey,
            recipient: validated.envelope.recipient.toBytes(),
            ephemeralPublicKey: validated.encrypted.ephemeralPublicKey.toBytes(),
            ciphertext: validated.encrypted.ciphertext,
          },
  }).map(asField);
  const payload: Omit<PreparedMergeInputs, "envelope"> = Object.freeze({
    inputs: Object.freeze(inputs),
    output,
    outputTreeId: asField(outputTreeIdField),
    mint: addressBytes(prepared.output.asset),
    ownerPublicKeyHash: asField(ownerPublicKeyHash),
    userNullifierPublicKey: asField(nullifierPublicKey),
    externalDataHash: asField(bytesToBigInt(externalDataHash)),
    privateTxHash: asField(bytesToBigInt(privateTxHash)),
    allowDummyInputs: asField(1n),
    outputRingDataHash: output.circuit.ringDataHash,
    ringProgramId: output.circuit.ringProgramId,
  });
  const trees = Object.freeze([{ tree, id: prepared.inputTreeId }]);
  const lookups = Object.freeze(slots.map((slot) => slot.lookup));
  const frozenPublicInputs = Object.freeze(publicInputs);
  const request = (envelope?: MergeEnvelopeInputs): IndexedMergeInputs =>
    Object.freeze({
      circuit: "merge",
      payload: Object.freeze({ ...payload, ...(envelope === undefined ? {} : { envelope }) }),
      trees,
      lookups,
      publicInputs: frozenPublicInputs,
    });
  return Object.freeze({
    async withInputs<T>(use: (inputs: IndexedMergeInputs) => Promise<T> | T): Promise<T> {
      if (validated === undefined) return await use(request());
      const viewingPublicKey = validated.envelope.recipient.toUncompressed();
      return await validated.envelope.withEphemeralSecret((ephemeralSecret) =>
        use(request(Object.freeze({ viewingPublicKey, ephemeralSecret }))),
      );
    },
    finish(inputTree: MergeInputTree): Omit<MergeAssembly, "withProverInputs"> {
      const publicInputHash = checkedBytes(
        bigintToBytes(
          resolvedPublicInputHash(publicInputs, inputTreeSlots([inputTree.slot])),
          "public input hash",
        ),
        32,
        "public input hash",
      );
      const utxoTreeRootIndex = inputTree.utxoRootIndex;
      const nullifierTreeRootIndex = inputTree.nullifierRootIndex;
      const instructionData = (proof: CompressedProofParts): MergeInstructionData =>
        Object.freeze({
          expiryUnixTs,
          proof: copyMergeProof(proof),
          ...mergeEnvelopeData(proof, validated?.encrypted),
          outputUtxoHash: new Uint8Array(outputHash) as Bytes32,
          eddsaOwner,
          privateTxHash: new Uint8Array(privateTxHash) as Bytes32,
          // The trailing compact padding is left out; SPP fills it back in.
          nullifiers: Object.freeze(
            nullifiers
              .filter((_nullifier, index) => !prepared.inputs[index]?.isCompact())
              .map((nullifier) => new Uint8Array(nullifier) as Bytes32),
          ),
          utxoTreeRootIndex,
          nullifierTreeRootIndex,
          ...(cache === undefined ? {} : { cacheSlot: cache.slot }),
        });
      return Object.freeze({
        expiryUnixTs,
        // `Object.freeze` seals the assembly and the nullifier array but not the
        // buffers inside them, and those are the buffers `instructionData` copies
        // from on every call. Hand out copies of everything the closure reads so a
        // frozen assembly cannot be steered into emitting different instruction
        // data than the one it was proved with.
        outputHash: new Uint8Array(outputHash) as Bytes32,
        nullifiers: Object.freeze(
          nullifiers.map((nullifier) => new Uint8Array(nullifier) as Bytes32),
        ),
        utxoTreeRootIndex,
        nullifierTreeRootIndex,
        privateTxHash: new Uint8Array(privateTxHash) as Bytes32,
        publicInputHash,
        externalDataHash,
        eddsaOwner,
        ...(cache === undefined ? {} : { cacheSlot: cache.slot }),
        instructionData,
      });
    },
  });
}

function validateMergeTree(prepared: PreparedMerge, tree: Address): ValidatedEnvelope | undefined {
  const validated = validatePreparedMerge(prepared);
  // The submit tree must be the tree the inputs are hashed under, or the proof
  // and the instruction would name different trees.
  if (treeAddress(prepared.inputTreeId) !== tree) {
    throw new ClientError("CLIENT_MERGE_TREE_MISMATCH", {
      details: {
        proofTree: treeAddress(prepared.inputTreeId),
        submitTree: tree,
      },
    });
  }
  // The merge instruction appends its output to the same tree it spends from,
  // so an output hashed under another tree would prove a commitment the
  // instruction's output tree rejects.
  if (
    prepared.output.ringProgramId === undefined &&
    prepared.outputTreeId !== prepared.inputTreeId
  ) {
    throw new ClientError("CLIENT_TREE_ID_MISMATCH", {
      details: {
        expected: prepared.inputTreeId,
        actual: prepared.outputTreeId,
      },
    });
  }
  return validated;
}

function checkNullifierRoot(
  inputTree: MergeInputTree,
  proof: NonInclusionProof,
  index: number,
): void {
  if (
    !equal(proof.root, inputTree.slot.nullifierRoot) ||
    proof.rootIndex !== inputTree.nullifierRootIndex
  ) {
    throw new ClientError("CLIENT_NULLIFIER_ROOT_MISMATCH", {
      details: { index },
    });
  }
}

function validatePreparedMerge(prepared: PreparedMerge): ValidatedEnvelope | undefined {
  if (!(prepared instanceof PreparedMerge)) throw new ClientError("CLIENT_INVALID_MERGE");
  const actual = prepared.inputs.length;
  if (!MERGE_SUPPORTED_INPUT_COUNTS.includes(actual)) {
    throw new ClientError("CLIENT_INVALID_MERGE_SHAPE", {
      details: {
        expected: mergePaddedInputCount(actual) ?? MAX_MERGE_INPUTS,
        actual,
      },
    });
  }
  let total = 0n;
  prepared.inputs.forEach((input) => {
    if (!input.isDummy()) {
      if (
        input.utxo.ringProgramId !== prepared.output.ringProgramId ||
        input.utxo.asset !== prepared.output.asset
      )
        throw new ClientError("CLIENT_INVALID_MERGE");
      total += input.utxo.amount;
    }
    if (!input.isDummy() && !equal(input.nullifierPublicKey, prepared.nullifierPublicKey)) {
      throw new ClientError("CLIENT_MERGE_NULLIFIER_KEY_MISMATCH");
    }
    if (
      !input.isDummy() &&
      !equal(input.utxo.owner.toBytes(), prepared.signingPublicKey.toBytes())
    ) {
      throw new ClientError("CLIENT_MERGE_SIGNING_KEY_MISMATCH");
    }
  });
  if (
    !equal(
      prepared.output.ownerAddress?.signingPublicKey.toBytes() ?? new Uint8Array(),
      prepared.signingPublicKey.toBytes(),
    )
  )
    throw new ClientError("CLIENT_INVALID_MERGE_OUTPUT");
  if (total !== prepared.output.amount || total > 0xffff_ffff_ffff_ffffn)
    throw new ClientError("CLIENT_INVALID_MERGE_OUTPUT");
  return validatedEnvelope(prepared);
}

interface ValidatedEnvelope {
  readonly envelope: MergeOutputEnvelope;
  readonly encrypted: EncryptedMergeEnvelope;
}

function validatedEnvelope(prepared: PreparedMerge): ValidatedEnvelope | undefined {
  const envelope = prepared.envelope;
  if (envelope !== undefined && !(envelope instanceof MergeOutputEnvelope)) {
    throw new ClientError("CLIENT_INVALID_MERGE");
  }
  if ((envelope === undefined) !== (prepared.output.ringProgramId !== undefined)) {
    throw new ClientError("CLIENT_MERGE_ENVELOPE_RAIL_MISMATCH");
  }
  if (envelope === undefined) return undefined;
  const viewingPublicKey = prepared.output.ownerAddress?.viewingPublicKey;
  if (viewingPublicKey === undefined || !viewingPublicKey.equals(envelope.recipient)) {
    throw new ClientError("CLIENT_MERGE_OUTPUT_MISMATCH");
  }
  const encrypted = prepared.encryptedEnvelope();
  if (encrypted === undefined || !equal(encrypted.outputBlinding, prepared.output.blinding)) {
    throw new ClientError("CLIENT_OUTPUT_BLINDING_MISMATCH", { details: { index: 0 } });
  }
  return Object.freeze({ envelope, encrypted });
}

function mergeEnvelopeData(
  proof: CompressedProofParts,
  encrypted: EncryptedMergeEnvelope | undefined,
): Readonly<{ proofCommitment?: MergeProofCommitment; envelope?: MergeEnvelope }> {
  const { commitment, commitmentPok } = proof;
  if (encrypted === undefined) {
    if (commitment !== undefined || commitmentPok !== undefined) {
      throw commitmentError("unexpected commitment");
    }
    return {};
  }
  if (commitment === undefined || commitmentPok === undefined) {
    throw commitmentError("missing commitment");
  }
  return {
    proofCommitment: Object.freeze({
      commitment: checkedBytes(commitment, 32, "merge proof commitment"),
      commitmentPok: checkedBytes(commitmentPok, 32, "merge proof commitmentPok"),
    }),
    envelope: Object.freeze({
      ephemeralPk: encrypted.ephemeralPublicKey.toBytes(),
      ciphertext: new Uint8Array(encrypted.ciphertext),
    }),
  };
}

function commitmentError(reason: string): ClientError {
  return new ClientError("CLIENT_PROOF_PARSE", {
    details: { path: "$.proof.proofCommitment", reason },
  });
}

function copyMergeProof(proof: CompressedProofParts): MergeBody["proof"] {
  return Object.freeze({
    a: checkedBytes(proof.a, 32, "merge proof a"),
    b: checkedBytes(proof.b, 128, "merge proof b"),
    c: checkedBytes(proof.c, 32, "merge proof c"),
  });
}

function asField(value: bigint): Field {
  return field(value, "merge field") as Field;
}

function equal(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}
