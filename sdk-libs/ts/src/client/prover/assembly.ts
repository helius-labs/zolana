import type {
  Address,
  Bytes32,
  TransactInstructionData,
  TransactProof,
} from "../../interface/types.js";
import { DUMMY_DOMAIN, UTXO_DOMAIN } from "../../interface/program.js";
import { SppProofInputs, type ExternalData } from "../../transaction/instructions/transact.js";
import { EncryptedScheme } from "../../transaction/serialization/codecs.js";
import { ProofInputUtxo, type ProofOutputUtxo } from "../../transaction/utxo.js";
import { SOL_MINT } from "../../transaction/wallet/asset.js";

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
import { RING_INPUT_SLOTS, RING_OUTPUT_SLOTS } from "./types.js";
import type {
  AssembledTransfer,
  CustomRingOpening,
  Field,
  ProverInputs,
  TransferInput,
  TransferInputs,
  TransferOutput,
} from "./types.js";

const STATE_TREE_HEIGHT = 32;
const NULLIFIER_TREE_HEIGHT = 40;
const ZERO_PROOF = Object.freeze({
  a: new Uint8Array(32),
  b: new Uint8Array(64),
  c: new Uint8Array(32),
}) as TransactProof;

interface CircuitUtxo {
  readonly domain: Field;
  readonly owner: Field;
  readonly asset: Field;
  readonly amount: Field;
  readonly blinding: Field;
  readonly dataHash: Field;
  readonly ringDataHash: Field;
  readonly ringProgramId: Field;
}

const CIRCUIT_UTXOS = new WeakMap<object, CircuitUtxo>();

export function circuitUtxo(value: object): CircuitUtxo {
  const result = CIRCUIT_UTXOS.get(value);
  if (!result) throw new ClientError("CLIENT_PROVER_INPUT");
  return result;
}

/** With `ring` set, the circuit binds every real input's ring field to `ringProgramId`. */
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

  const { transferInputs, inputHashes, nullifiers, utxoRoots, nullifierRoots, rootIndexes } =
    assembleSlots(proofInputs, spendProofs, dummyNullifierProofs, (input) =>
      bytesField(input.utxo.owner.ownerProofInputHash(), "owner public key"),
    );

  const transferOutputs = proofInputs.outputs.map(createOutput);
  const outputHashes = proofInputs.outputs.map((output) => bytesToBigInt(output.hash()));
  const privateOutputHashes = proofInputs.outputs.map((output) =>
    output.isDummy() ? 0n : bytesToBigInt(output.hash()),
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
  ]);
  const movements = publicMovements(proofInputs);
  const publicSlots = movements.assets.flatMap((asset, index) => [
    asset,
    movements.amounts[index] ?? 0n,
  ]);
  // The circuit authorizes an input owner by finding its Poseidon owner hash in
  // this vector, so the payer enters as `hashBytesBigInt`, matching Rust's
  // `signer_pk_hashes`.
  const payerSignerHash = hashBytesBigInt(addressBytes(proofInputs.payer));
  const signerPublicKeyHashes = [
    payerSignerHash,
    ...Array.from({ length: inputHashes.length }, () => 0n),
  ];
  const allowDummyInputs = 1n;
  const ringProgramId = ring === undefined ? 0n : hashBytesBigInt(addressBytes(ring));
  const publicInputHash = hashChain([
    hashChain(nullifiers.map(bytesToBigInt)),
    hashChain(outputHashes),
    hashChain(utxoRoots),
    hashChain(nullifierRoots),
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
    externalDataHash: asField(externalDataHash),
    privateTxHash: asField(privateTxHash),
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
        const roots = rootIndexes[index];
        const nullifier = nullifiers[index];
        if (!roots || !nullifier) {
          throw new ClientError("CLIENT_PROOF_INPUT_COUNT_MISMATCH", {
            details: {
              got: Math.min(rootIndexes.length, nullifiers.length),
              expected: proofInputs.inputUtxos.length,
            },
          });
        }
        return Object.freeze({
          nullifierHash: nullifier,
          nullifierTreeRootIndex: roots[1],
          utxoTreeRootIndex: roots[0],
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
  // Slot 0 is always a real spend, its roots are the pair a ring statement binds.
  const firstInput = transferInputs[0];
  const firstRootIndexes = rootIndexes[0];
  if (!firstInput || !firstRootIndexes) throw new ClientError("CLIENT_NO_INPUTS");
  return Object.freeze({
    instructionData,
    proverInputs,
    publicInputHash: bigintToBytes(publicInputHash) as Bytes32,
    nullifiers: Object.freeze(nullifiers.map((nullifier) => new Uint8Array(nullifier) as Bytes32)),
    outputHashes: Object.freeze(outputHashes.map((hash) => bigintToBytes(hash) as Bytes32)),
    privateTxHash: bigintToBytes(privateTxHash) as Bytes32,
    inputRootIndexes: Object.freeze(rootIndexes),
    roots: Object.freeze({
      stateRoot: bigintToBytes(firstInput.utxoTreeRoot) as Bytes32,
      stateRootIndex: firstRootIndexes[0],
      nullifierRoot: bigintToBytes(firstInput.nullifierTreeRoot) as Bytes32,
      nullifierRootIndex: firstRootIndexes[1],
    }),
    withProof(proof: TransactProof): TransactInstructionData {
      return Object.freeze({ ...instructionData, proof: copyProof(proof) });
    },
  });
}

/**
 * Mirrors Rust `confidential_marked_output_owner_pk_hashes`, the ring rails
 * publish an owner hash only for a `Confidential` scheme output, a
 * `RingConfidential` one contributes zero.
 */
function confidentialMarkedOutputOwnerHashes(external: ExternalData): bigint[] {
  if (external.outputs.length !== external.resolvedOwnerTags.length) {
    throw new ClientError("CLIENT_PROVER_INPUT");
  }
  return external.outputs.map((output, index) => {
    const tag = external.resolvedOwnerTags[index];
    if (tag === undefined) throw new ClientError("CLIENT_PROVER_INPUT");
    return output.data !== undefined && isConfidentialEncryptedOutput(output.data)
      ? hashBytesBigInt(tag)
      : 0n;
  });
}

/** Mirrors Rust `is_confidential_encrypted_output`. */
function isConfidentialEncryptedOutput(data: Uint8Array): boolean {
  if (data.length <= 5 || data[0] !== 1) return false;
  const bodyLength = new DataView(data.buffer, data.byteOffset, data.byteLength).getUint32(1, true);
  return bodyLength === data.length - 5 && data[5] === EncryptedScheme.confidential;
}

export interface AssembledSlots {
  readonly transferInputs: readonly TransferInput[];
  readonly inputHashes: readonly bigint[];
  readonly nullifiers: readonly Bytes32[];
  readonly utxoRoots: readonly bigint[];
  readonly nullifierRoots: readonly bigint[];
  readonly inputOwnerFields: readonly bigint[];
  readonly rootIndexes: readonly (readonly [number, number])[];
}

/// Mirrors Rust `assemble_inputs`. Padding is not decided here: a slot with a
/// spend proof is a real spend, a slot without one is a dummy that copies the
/// first real input's roots, root indexes, and owner field so the public-input
/// chain and the on-chain root lookup agree. `ownerField` is the caller's rail:
/// it is the one thing Rust's `OwnerMode` varies, and every rail shares the rest
/// of this loop.
export function assembleSlots(
  proofInputs: SppProofInputs,
  spendProofs: readonly SpendProof[],
  dummyNullifierProofs: readonly NonInclusionProof[],
  ownerField: (input: ProofInputUtxo, index: number) => bigint,
): AssembledSlots {
  const transferInputs: TransferInput[] = [];
  const inputHashes: bigint[] = [];
  const nullifiers: Bytes32[] = [];
  const utxoRoots: bigint[] = [];
  const nullifierRoots: bigint[] = [];
  const inputOwnerFields: bigint[] = [];
  const rootIndexes: Array<readonly [number, number]> = [];
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
      const first = transferInputs[0];
      const roots = rootIndexes[0];
      if (!first || !roots) throw new ClientError("CLIENT_NO_INPUTS");
      const proof = dummyNullifierProofs[dummyProofIndex++];
      if (!proof) {
        throw new ClientError("CLIENT_MISSING_INPUT_MERKLE_PROOF", {
          details: { index },
        });
      }
      validateDummyNullifierProof(input, proof, index);
      const converted = createDummyTransferInput(input, first.utxoTreeRoot, proof);
      transferInputs.push(converted);
      inputHashes.push(0n);
      nullifiers.push(bigintToBytes(converted.nullifier) as Bytes32);
      utxoRoots.push(converted.utxoTreeRoot);
      nullifierRoots.push(converted.nullifierTreeRoot);
      inputOwnerFields.push(converted.ownerPublicKeyHash);
      rootIndexes.push([roots[0], proof.rootIndex]);
      continue;
    }
    const proof = spendProofs[proofIndex++];
    if (!proof) {
      throw new ClientError("CLIENT_MISSING_INPUT_MERKLE_PROOF", {
        details: { index: proofIndex - 1 },
      });
    }
    validateSpendProof(input, proof, proofIndex - 1);
    const owner = ownerField(input, index);
    const converted = createRealInput(input, proof, owner);
    transferInputs.push(converted);
    inputHashes.push(bytesToBigInt(input.hash()));
    nullifiers.push(new Uint8Array(input.nullifier()) as Bytes32);
    utxoRoots.push(converted.utxoTreeRoot);
    nullifierRoots.push(converted.nullifierTreeRoot);
    inputOwnerFields.push(owner);
    rootIndexes.push([proof.state.rootIndex, proof.nullifier.rootIndex]);
  }
  return Object.freeze({
    transferInputs: Object.freeze(transferInputs),
    inputHashes: Object.freeze(inputHashes),
    nullifiers: Object.freeze(nullifiers),
    utxoRoots: Object.freeze(utxoRoots),
    nullifierRoots: Object.freeze(nullifierRoots),
    inputOwnerFields: Object.freeze(inputOwnerFields),
    rootIndexes: Object.freeze(rootIndexes),
  });
}

export function createRealInput(
  input: ProofInputUtxo,
  proof: SpendProof,
  ownerPublicKeyHash: bigint,
): TransferInput {
  const value = Object.freeze({
    utxo: input,
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
    utxoTreeRoot: asField(bytesField(proof.state.root, "state root")),
    nullifierTreeRoot: asField(bytesField(proof.nullifier.root, "nullifier root")),
    nullifier: asField(bytesField(input.nullifier(), "nullifier")),
    ownerPublicKeyHash: asField(ownerPublicKeyHash),
    nullifierSecret: asField(bytesField(input.nullifierKey.secretBytes(), "nullifier secret")),
  });
  CIRCUIT_UTXOS.set(value, inputCircuitUtxo(input));
  return value;
}

export function createDummyTransferInput(
  input: ProofInputUtxo,
  utxoRoot: bigint,
  proof: NonInclusionProof,
  nullifier = input.nullifier(),
): TransferInput {
  const value = Object.freeze({
    utxo: input,
    isDummy: asField(1n),
    statePathElements: Object.freeze(Array.from({ length: STATE_TREE_HEIGHT }, () => asField(0n))),
    statePathIndex: asField(0n),
    nullifierLowValue: asField(bytesField(proof.lowElement, "dummy low element")),
    nullifierNextValue: asField(bytesField(proof.highElement, "dummy high element")),
    nullifierLowPathElements: Object.freeze(
      proof.path.map((item) => asField(bytesField(item, "dummy nullifier path element"))),
    ),
    nullifierLowPathIndex: asField(proof.lowElementIndex),
    utxoTreeRoot: asField(utxoRoot),
    nullifierTreeRoot: asField(bytesField(proof.root, "dummy nullifier root")),
    nullifier: asField(bytesField(nullifier, "dummy nullifier")),
    ownerPublicKeyHash: asField(0n),
    nullifierSecret: asField(0n),
  });
  CIRCUIT_UTXOS.set(value, inputCircuitUtxo(input, true));
  return value;
}

export function createOutput(output: ProofOutputUtxo): TransferOutput {
  const ownerPublicKeyHash = output.ownerAddress
    ? bytesField(
        output.ownerAddress.signingPublicKey.ownerProofInputHash(),
        "output owner public key",
      )
    : hashBytesBigInt(output.ownerTag ?? new Uint8Array(32));
  const value = Object.freeze({
    utxo: output as unknown as ProofInputUtxo,
    isDummy: asField(output.isDummy() ? 1n : 0n),
    hash: asField(bytesField(output.hash(), "output hash")),
    ownerPublicKeyHash: asField(ownerPublicKeyHash),
    nullifierPublicKey: asField(
      output.ownerAddress
        ? bytesField(output.ownerAddress.nullifierPublicKey, "output nullifier public key")
        : 0n,
    ),
  });
  CIRCUIT_UTXOS.set(value, outputCircuitUtxo(output));
  return value;
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

export interface RingOpenings {
  readonly nIn: number;
  readonly nOut: number;
  readonly inputs: readonly CustomRingOpening[];
  readonly outputs: readonly CustomRingOpening[];
}

/**
 * Mirrors Rust `CustomRingWitnessInput`, a dummy slot is the DUMMY-domain
 * all-zero opening and a slot past the shape stays fully zero.
 */
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
  const inputs = Array.from({ length: RING_INPUT_SLOTS }, (_, index) => {
    const input = proofInputs.inputUtxos[index];
    return input === undefined ? zeroOpening(0) : inputOpening(input);
  });
  const outputs = Array.from({ length: RING_OUTPUT_SLOTS }, (_, index) => {
    const output = proofInputs.outputs[index];
    return output === undefined ? zeroOpening(0) : outputOpening(output);
  });
  return Object.freeze({
    nIn: proofInputs.inputUtxos.length,
    nOut: proofInputs.outputs.length,
    inputs: Object.freeze(inputs),
    outputs: Object.freeze(outputs),
  });
}

function inputOpening(input: ProofInputUtxo): CustomRingOpening {
  if (input.isDummy()) return zeroOpening(DUMMY_DOMAIN);
  const utxo = inputCircuitUtxo(input);
  return Object.freeze({
    domain: openingField(BigInt(UTXO_DOMAIN)),
    ownerPkHash: input.utxo.owner.ownerProofInputHash(),
    nullifierPk: input.nullifierKey.publicKey(),
    asset: openingField(utxo.asset),
    amount: openingField(utxo.amount),
    blinding: openingField(utxo.blinding),
    dataHash: openingField(utxo.dataHash),
    ringDataHash: openingField(utxo.ringDataHash),
    ringProgramId: openingField(utxo.ringProgramId),
  });
}

/** Rust keys a dummy output on its absent owner address, never on the owner tag. */
function outputOpening(output: ProofOutputUtxo): CustomRingOpening {
  const owner = output.ownerAddress;
  if (owner === undefined) return zeroOpening(DUMMY_DOMAIN);
  const utxo = outputCircuitUtxo(output);
  return Object.freeze({
    domain: openingField(BigInt(UTXO_DOMAIN)),
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
