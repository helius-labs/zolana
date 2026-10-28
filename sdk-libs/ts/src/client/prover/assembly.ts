import { getAddressDecoder } from "@solana/kit";
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";

import { bytesToBigInt, equalBytes } from "../../interface/bytes.js";
import type {
  Address,
  Bytes32,
  CacheAccess,
  CircuitId,
  TransactInstructionData,
  TransactProof,
} from "../../interface/types.js";
import {
  cachedInputFields,
  emptyCachedInputFields,
  NO_CACHE_WRITES,
  type CachedInputFields,
} from "../../interface/cache.js";
import { CACHE_CAPACITY } from "../../interface/state.js";
import { ADDRESS_DOMAIN, DUMMY_DOMAIN, UTXO_DOMAIN } from "../../interface/program.js";
import {
  RING_AUTHORITY_WIDTHS,
  isConfidentialEddsaShape,
  isSppShape,
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
import {
  SppProofInputs,
  cacheBoundExternalDataHash,
  cacheWriteSlots,
  type CacheWriteRefusal,
  type ExternalData,
} from "../../transaction/instructions/transact.js";
import { EncryptedScheme } from "../../transaction/serialization/codecs.js";
import {
  ProofInputUtxo,
  transactOutputBlinding,
  type ProofOutputUtxo,
  type TreeId,
} from "../../transaction/utxo.js";
import { SOL_MINT } from "../../transaction/asset.js";
import { TransactionError } from "../../transaction/error.js";

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
  checkedBytes,
  field,
  hashChain4,
  hashBytesBigInt,
  inputFlags,
  poseidon,
  rightHashChain,
  rightHashChain4,
} from "../internal.js";
import type { NonInclusionProof, SpendProof } from "../rpc.js";
import type {
  AssembledTransfer,
  CircuitUtxo,
  EddsaOwnerAuthorization,
  Field,
  InputRootIndexes,
  ProvedTransactProof,
  ProverInputs,
  TransactOwnerSigner,
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

/**
 * Unique Ed25519 and PDA owners of real inputs, address inputs included, then
 * of outputs that carry data, in first-occurrence order; mirrors Rust
 * `owner_signer_pubkeys`. The fee payer gets no special treatment: it is
 * listed only when it is one of those owners. `inCircuitOwner`, the Ed25519
 * key a `confidentialEddsa` proof verifies, is left out: it signs no account,
 * Rust `confidential_eddsa_signer_pk_hashes`.
 */
export function ownerSignerAddresses(
  inputs: readonly ProofInputUtxo[],
  outputs: readonly ProofOutputUtxo[],
  inCircuitOwner?: Bytes32,
): readonly Address[] {
  const owners = [
    ...inputs.filter((input) => !input.isDummy()).map((input) => input.utxo.owner),
    ...outputs.flatMap((output) =>
      output.ownerAddress !== undefined && output.dataHash?.some((byte) => byte !== 0) === true
        ? [output.ownerAddress.signingPublicKey]
        : [],
    ),
  ];
  const seen = new Set<string>();
  if (inCircuitOwner !== undefined) {
    seen.add(getAddressDecoder().decode(checkedBytes(inCircuitOwner, 32, "in-circuit owner")));
  }
  const signers: Address[] = [];
  for (const owner of owners) {
    const address = getAddressDecoder().decode(owner.confidentialViewTag());
    if (seen.has(address)) continue;
    seen.add(address);
    signers.push(address);
  }
  return Object.freeze(signers);
}

/**
 * The message a `confidentialEddsa` owner signs,
 * `sha256(privateTxHash || externalDataHash)` with the external data hash
 * bound to the cache writes; Rust `transact_message_hash`.
 */
export function transactMessageDigest(proofInputs: SppProofInputs): Bytes32 {
  if (!(proofInputs instanceof SppProofInputs)) {
    throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
  }
  const cache = checkedTransferCache(proofInputs);
  return messageDigest(
    proofInputs.privateTxHash(),
    cacheBoundExternalDataHash(
      proofInputs.externalData,
      cache?.access.writeSlots ?? NO_CACHE_WRITES,
      cache?.write,
    ),
  );
}

/** `transactMessageDigest` over the statement's field elements. */
export function transactMessageDigestOf(privateTxHash: bigint, externalDataHash: bigint): Bytes32 {
  return messageDigest(
    bigintToBytes(privateTxHash, "private tx hash"),
    bigintToBytes(externalDataHash, "external data hash"),
  );
}

function messageDigest(privateTxHash: Uint8Array, externalDataHash: Uint8Array): Bytes32 {
  const message = new Uint8Array(64);
  message.set(checkedBytes(privateTxHash, 32, "private tx hash"), 0);
  message.set(checkedBytes(externalDataHash, 32, "external data hash"), 32);
  return sha256(message) as Bytes32;
}

/**
 * `owner`'s authorization of `proofInputs` for the `confidentialEddsa` rail:
 * its Ed25519 signature over the transact message digest. The owner must
 * hold an Ed25519 key, a PDA cannot sign.
 */
export async function signTransactMessage(
  proofInputs: SppProofInputs,
  owner: TransactOwnerSigner,
): Promise<EddsaOwnerAuthorization> {
  try {
    const digest = transactMessageDigest(proofInputs);
    const ownerPublicKey = (await owner.signingPublicKey()).ed25519();
    const ownerSignature = checkedBytes(
      await owner.sign(new Uint8Array(digest)),
      64,
      "owner signature",
    );
    return checkedAuthorization({ ownerPublicKey, ownerSignature, messageDigest: digest }, digest);
  } catch (cause) {
    throw fromClientCause(cause);
  }
}

/**
 * Revalidates an authorization at the method boundary and binds it to the
 * statement: the signed digest must be the one these proof inputs hash to.
 */
export function checkedAuthorization(
  authorization: EddsaOwnerAuthorization,
  expectedDigest: Bytes32,
): EddsaOwnerAuthorization {
  const ownerPublicKey = checkedBytes(authorization.ownerPublicKey, 32, "owner public key");
  const ownerSignature = checkedBytes(authorization.ownerSignature, 64, "owner signature");
  const digest = checkedBytes(authorization.messageDigest, 32, "message digest");
  if (
    !equalBytes(digest, expectedDigest) ||
    !ed25519.verify(ownerSignature, digest, ownerPublicKey, { zip215: false })
  ) {
    throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
  }
  return Object.freeze({ ownerPublicKey, ownerSignature, messageDigest: digest });
}

/**
 * The public input hash fields that follow `privateTxHash` on the
 * `confidentialEddsa` rail: the message hash and the verified owner's tagged
 * Solana identity, Rust `EddsaAuthorization::public_fields`.
 */
export function eddsaPublicFields(authorization: EddsaOwnerAuthorization): readonly bigint[] {
  return Object.freeze([
    hashBytesBigInt(authorization.messageDigest),
    bytesToBigInt(solanaOwnerIdentity(authorization.ownerPublicKey)),
  ]);
}

/** The tagged identity a Solana signer enters the proof's signer chain as. */
export function signerIdentity(address: Address): bigint {
  return bytesToBigInt(solanaOwnerIdentity(addressBytes(address)));
}

/** Selects owner and signer commitments for each transaction rail. */
type CircuitPlan = Readonly<{
  ring: Address | undefined;
  authority: boolean;
  signerSlots: number;
  owners: "every" | "confidentialMarked" | "none";
}> &
  Readonly<
    | {
        prover: "transfer" | "transferRing" | "transferRingAuthority";
        data: "confidentialSigner" | "confidentialRingEddsa" | "ringAuthority";
        authorization?: undefined;
      }
    | {
        prover: "transferConfidentialEddsa";
        data: "confidentialEddsa";
        /** The owner the proof verifies, left out of the signer vector. */
        authorization: EddsaOwnerAuthorization;
      }
  >;

function circuitPlan(circuit: TransferCircuit, shape: Shape): CircuitPlan {
  switch (circuit.kind) {
    case "confidential":
      return {
        ring: undefined,
        authority: false,
        prover: "transfer",
        data: "confidentialSigner",
        signerSlots: signerWidth(shape),
        owners: "every",
      };
    case "confidentialEddsa":
      return {
        ring: undefined,
        authority: false,
        prover: "transferConfidentialEddsa",
        data: "confidentialEddsa",
        signerSlots: signerWidth(shape),
        owners: "every",
        authorization: circuit.authorization,
      };
    case "ring":
      return {
        ring: circuit.ring,
        authority: false,
        prover: "transferRing",
        data: "confidentialRingEddsa",
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

/** A transfer request for the prover's indexed route, any transfer rail. */
type PreparedTransferRequest = Exclude<IndexedProofInputs, { circuit: "merge" }>;

interface PreparedTransferAssembly {
  readonly inputs: PreparedTransferRequest;
  finish(trees: readonly InputTree[]): Omit<AssembledTransfer, "proverInputs">;
}

export function prepareTransfer(
  proofInputs: SppProofInputs,
  circuit: TransferCircuit = { kind: "confidential" },
): PreparedTransferAssembly {
  try {
    const checked = checkedTransferPlan(proofInputs, circuit);
    const slots = prepareSlots(proofInputs.inputUtxos, (input) =>
      bytesField(input.utxo.owner.ownerProofInputHash(), "owner public key"),
    );
    return prepareTransferUnchecked(proofInputs, slots, checked);
  } catch (cause) {
    throw fromClientCause(cause);
  }
}

/** The request with the paths and the resolved statement filled in. */
function completedProverInputs(
  request: PreparedTransferRequest,
  completed: Readonly<{
    inputs: readonly TransferInput[];
    treeSlots: readonly TreeSlotFields[];
    publicInputHash: Field;
  }>,
): ProverInputs {
  if (request.circuit === "transferConfidentialEddsa") {
    return Object.freeze({
      circuit: request.circuit,
      payload: Object.freeze({ ...request.payload, ...completed }),
    });
  }
  return Object.freeze({
    circuit: request.circuit,
    payload: Object.freeze({ ...request.payload, ...completed }),
  });
}

function assembleUnchecked(
  proofInputs: SppProofInputs,
  spendProofs: readonly SpendProof[],
  dummyNullifierProofs: readonly NonInclusionProof[],
  circuit: TransferCircuit,
): AssembledTransfer {
  const checked = checkedTransferPlan(proofInputs, circuit);
  const slots = assembleSlots(proofInputs, spendProofs, dummyNullifierProofs, (input) =>
    bytesField(input.utxo.owner.ownerProofInputHash(), "owner public key"),
  );
  const prepared = prepareTransferUnchecked(proofInputs, slots, checked);
  const complete = prepared.finish(slots.inputTrees);
  return Object.freeze({
    ...complete,
    proverInputs: completedProverInputs(prepared.inputs, {
      inputs: slots.transferInputs,
      treeSlots: Object.freeze(
        inputTreeSlots(slots.inputTrees.map((tree) => tree.slot)).map(treeSlotFields),
      ),
      publicInputHash: asField(bytesToBigInt(complete.publicInputHash)),
    }),
  });
}

function checkedTransferPlan(proofInputs: SppProofInputs, circuit: TransferCircuit) {
  if (!(proofInputs instanceof SppProofInputs)) {
    throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
  }
  const shape = proofInputs.checkShape();
  const address = proofInputs.inputUtxos.findIndex((input) => input.isAddress());
  // The ring authority statement has no address slot; the owner-signed rails
  // prove addresses.
  if (circuit.kind === "ringAuthority" && address >= 0) {
    throw new ClientError("CLIENT_ADDRESS_INPUT_UNSUPPORTED", { details: { index: address } });
  }
  const plan = circuitPlan(circuit, shape);
  // Each rail proves on its own key set, Rust `check_shape_for`.
  if (plan.data === "confidentialEddsa" ? !isConfidentialEddsaShape(shape) : !isSppShape(shape)) {
    throw new TransactionError("TRANSACTION_UNSUPPORTED_SHAPE", {
      inputs: shape.inputs,
      outputs: shape.outputs,
    });
  }
  if (
    plan.authority &&
    (shape.inputs !== shape.outputs ||
      !RING_AUTHORITY_WIDTHS.includes(shape.inputs) ||
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
  validateOutputBlindings(proofInputs);
  const cache = checkedTransferCache(proofInputs);

  return { plan, cache };
}

function prepareTransferUnchecked(
  proofInputs: SppProofInputs,
  slots: PreparedSlots,
  checked: ReturnType<typeof checkedTransferPlan>,
): PreparedTransferAssembly {
  const { plan, cache } = checked;
  const outputTreeId = proofInputs.outputTreeId;

  const { transferInputs, nullifiers, treeIndexes } = slots;
  const transferOutputs = proofInputs.outputs.map((output) => createOutput(output, outputTreeId));
  const outputHashes = transferOutputs.map((output) => output.hash as bigint);
  const outputOwnerFields = publishedOwnerFields(plan, transferOutputs, proofInputs.externalData);
  const externalDataHashBytes = cacheBoundExternalDataHash(
    proofInputs.externalData,
    cache?.access.writeSlots ?? NO_CACHE_WRITES,
    cache?.write,
  );
  const externalDataHash = bytesField(externalDataHashBytes, "external data hash");
  const privateTxHashBytes = proofInputs.privateTxHash();
  const privateTxHash = bytesField(privateTxHashBytes, "private tx hash");
  const authorization =
    plan.authorization === undefined
      ? undefined
      : checkedAuthorization(
          plan.authorization,
          messageDigest(privateTxHashBytes, externalDataHashBytes),
        );
  const transfers = publicTransfers(proofInputs);
  const publicSlots = transfers.assets.flatMap((asset, index) => [
    asset,
    transfers.amounts[index] ?? 0n,
  ]);
  // The circuit authorizes an input owner by finding its tagged identity in
  // the vector. Owner-signed rails list the unique Ed25519 and PDA owners of
  // inputs and of outputs that carry data, the payer only when it is one of them,
  // matching Rust's `signer_pk_hashes`. The authority rail's width-1 vector
  // is the payer. An owner the proof verifies holds no slot.
  const signerHashes = plan.authority
    ? [signerIdentity(proofInputs.payer)]
    : ownerSignerAddresses(
        proofInputs.inputUtxos,
        proofInputs.outputs,
        authorization?.ownerPublicKey,
      ).map(signerIdentity);
  if (signerHashes.length > plan.signerSlots) {
    throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
  }
  const signerPublicKeyHashes = [
    ...signerHashes,
    ...Array.from({ length: plan.signerSlots - signerHashes.length }, () => 0n),
  ];
  const flags = inputFlags(true, treeIndexes);
  const ringProgramId = plan.ring === undefined ? 0n : hashBytesBigInt(addressBytes(plan.ring));
  const outputTreeIdField = bytesToBigInt(treeIdField(outputTreeId));
  const cachedInputs = selectedCachedInputs(cache, proofInputs.inputUtxos);
  const publicInputs = transferPublicInputs({
    nullifiers: nullifiers.map(bytesToBigInt),
    outputHashes,
    outputTreeId,
    privateTxHash,
    afterPrivateTxHash: authorization === undefined ? [] : eddsaPublicFields(authorization),
    externalDataHash,
    publicSlots,
    ringProgramId,
    signerPublicKeyHashes,
    inputFlags: flags,
    publishedOutputOwnerPublicKeyHashes: outputOwnerFields,
    ...cachedInputs,
  });
  const common: PreparedTransferInputs = Object.freeze({
    inputs: Object.freeze(transferInputs),
    outputs: Object.freeze(transferOutputs),
    outputTreeId: asField(outputTreeIdField),
    externalDataHash: asField(externalDataHash),
    privateTxHash: asField(privateTxHash),
    blindingSeed: asField(bytesField(proofInputs.blindingSeed, "blinding seed")),
    publicAssets: Object.freeze(transfers.assets.map(asField)),
    publicAmounts: Object.freeze(transfers.amounts.map(asField)),
    ringProgramId: asField(ringProgramId),
    signerPublicKeyHashes: Object.freeze(signerPublicKeyHashes.map(asField)),
    inputFlags: asField(flags),
    publishedOutputOwnerPublicKeyHashes: Object.freeze((outputOwnerFields ?? []).map(asField)),
    ...cacheProverFields(cachedInputs),
  });
  const instructionBase: Omit<TransactInstructionData, "treeContexts"> = Object.freeze({
    expiryUnixTs: proofInputs.externalData.expiryUnixTs,
    privateTxHash: bigintToBytes(privateTxHash, "private tx hash") as Bytes32,
    circuit: transferCircuit(
      plan,
      cache,
      proofInputs.inputUtxos.length,
      proofInputs.outputs.length,
      authorization,
    ),
    txViewingPk: proofInputs.externalData.txViewingPublicKey.toBytes(),
    salt: new Uint8Array(proofInputs.externalData.salt) as never,
    proof: ZERO_PROOF,
    // The trailing compact padding is left out; SPP fills it back in.
    inputs: Object.freeze(
      proofInputs.inputUtxos
        .map((_input, index) => {
          const nullifier = nullifiers[index];
          const treeIndex = treeIndexes[index];
          if (!nullifier || treeIndex === undefined) {
            throw new ClientError("CLIENT_PROOF_INPUT_COUNT_MISMATCH", {
              details: {
                got: nullifiers.length,
                expected: proofInputs.inputUtxos.length,
              },
            });
          }
          return Object.freeze({ nullifierHash: nullifier, treeIndex });
        })
        .filter((_input, index) => !proofInputs.inputUtxos[index]?.isCompact()),
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
      : {
          dataHash: new Uint8Array(proofInputs.externalData.dataHash) as Bytes32,
        }),
    ...(proofInputs.externalData.ringDataHash === undefined
      ? {}
      : {
          ringDataHash: new Uint8Array(proofInputs.externalData.ringDataHash) as Bytes32,
        }),
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
  const envelope = Object.freeze({
    trees: slots.treeIds.map((id) => Object.freeze({ id, tree: treeAddress(id) })),
    lookups: proofInputs.inputUtxos.map((input, index) =>
      Object.freeze({
        treeSlot: treeIndexes[index] ?? 0,
        commitment: input.requiresInclusion() ? input.hash() : null,
        nullifier: input.isCompact() ? input.nullifier() : null,
      }),
    ),
    publicInputs: Object.freeze(publicInputs.map(asField)),
  });
  let inputs: PreparedTransferRequest;
  if (plan.prover === "transferConfidentialEddsa") {
    if (authorization === undefined) throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
    inputs = Object.freeze({
      ...envelope,
      circuit: plan.prover,
      payload: Object.freeze({ ...common, ownerAuthorization: authorization }),
    });
  } else {
    inputs = Object.freeze({ ...envelope, circuit: plan.prover, payload: common });
  }
  return Object.freeze({
    inputs,
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
        publicInputHash: bigintToBytes(publicInputHash, "public input hash") as Bytes32,
        nullifiers: Object.freeze(
          nullifiers.map((nullifier) => new Uint8Array(nullifier) as Bytes32),
        ),
        outputHashes: Object.freeze(
          outputHashes.map((hash) => bigintToBytes(hash, "output hash") as Bytes32),
        ),
        privateTxHash: bigintToBytes(privateTxHash, "private tx hash") as Bytes32,
        rootIndexes,
        roots: Object.freeze({
          stateRoot: firstTree.slot.utxoRoot,
          stateRootIndex: firstTree.utxoRootIndex,
          nullifierRoot: firstTree.slot.nullifierRoot,
          nullifierRootIndex: firstTree.nullifierRootIndex,
        }),
        withProof(proof: ProvedTransactProof): TransactInstructionData {
          return Object.freeze({
            ...instructionData,
            circuit: committedCircuit(instructionData.circuit, proof),
            proof: copyProof(proof),
          });
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
    if (!equalBytes(output.blinding, transactOutputBlinding(firstNullifier, outputSeed, index))) {
      throw new ClientError("CLIENT_OUTPUT_BLINDING_MISMATCH", {
        details: { index },
      });
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
      return confidentialMarkedOutputOwnerHashes(external, outputs.length);
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
      throw new ClientError("CLIENT_CACHED_INPUT_WITHOUT_READ_CACHE", {
        details: { index },
      });
    }
    if (((readBitmap >> BigInt(slot)) & 1n) === 1n) {
      throw new ClientError("CLIENT_DUPLICATE_CACHE_READ_SLOT", {
        details: { index, slot },
      });
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
  const writeSlots = cacheWriteSlots(proofInputs.outputs, write, clientCacheWriteRefusal);
  if (read === undefined && write === undefined) return undefined;
  return Object.freeze({
    read:
      read === undefined || cacheTreeId === undefined
        ? undefined
        : Object.freeze({ address: read, treeId: cacheTreeId }),
    write,
    access: Object.freeze({ readBitmap, writeSlots }),
  });
}

function clientCacheWriteRefusal(refusal: CacheWriteRefusal): ClientError {
  switch (refusal.reason) {
    case "withoutWriteCache":
      return new ClientError("CLIENT_CACHED_OUTPUT_WITHOUT_WRITE_CACHE", {
        details: { index: refusal.index },
      });
    case "paddingOutput":
      return new ClientError("CLIENT_CACHED_DUMMY_OUTPUT", {
        details: { index: refusal.index },
      });
    case "fractionalSlot":
      return new ClientError("CLIENT_INVALID_CACHE_ACCESS", {
        details: { field: "cacheSlot", index: refusal.index },
      });
    case "slotOutOfRange":
      return new ClientError("CLIENT_CACHE_WRITE_SLOT_OUT_OF_RANGE", {
        details: { index: refusal.index, slot: refusal.slot },
      });
    case "duplicateSlot":
      return new ClientError("CLIENT_DUPLICATE_CACHE_WRITE_SLOT", {
        details: { index: refusal.index, slot: refusal.slot },
      });
    case "unusedWriteCache":
      return new ClientError("CLIENT_UNUSED_WRITE_CACHE");
  }
}

function transferCircuit(
  plan: CircuitPlan,
  cache: CheckedTransferCache | undefined,
  inputs: number,
  outputs: number,
  authorization: EddsaOwnerAuthorization | undefined,
): CircuitId {
  const shape = { inputs, outputs, publicAssetSlots: 3 };
  if (plan.data === "confidentialEddsa") {
    if (authorization === undefined) throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
    // The proof fills the commitment in, see `committedCircuit`.
    const proofData = Object.freeze({
      bsb22Commitment: Object.freeze({
        commitment: new Uint8Array(32) as Bytes32,
        commitmentPok: new Uint8Array(32) as Bytes32,
      }),
      ownerPk: new Uint8Array(authorization.ownerPublicKey) as Bytes32,
    });
    return cache === undefined
      ? Object.freeze({ kind: "confidentialEddsa", ...shape, proofData })
      : Object.freeze({
          kind: "confidentialEddsaCached",
          ...shape,
          proofData,
          cacheAccess: cache.access,
        });
  }
  if (cache === undefined) return Object.freeze({ kind: plan.data, ...shape });
  switch (plan.data) {
    case "confidentialSigner":
      return Object.freeze({
        kind: "confidentialSignerCached",
        ...shape,
        cacheAccess: cache.access,
      });
    case "confidentialRingEddsa":
      return Object.freeze({
        kind: "confidentialRingEddsaCached",
        ...shape,
        cacheAccess: cache.access,
      });
    case "ringAuthority":
      throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
  }
}

/**
 * A `confidentialEddsa` selector carries its proof's BSB22 commitment; the
 * standard Groth16 rails carry none, so a proof with one proves another
 * statement than the selector names.
 */
function committedCircuit(circuit: CircuitId, proof: ProvedTransactProof): CircuitId {
  const committed =
    circuit.kind === "confidentialEddsa" || circuit.kind === "confidentialEddsaCached";
  if (!committed) {
    if (proof.commitment !== undefined || proof.commitmentPok !== undefined) {
      throw new ClientError("CLIENT_PROOF_PARSE", {
        details: { path: "$.proof.proofCommitment", reason: "unexpected commitment" },
      });
    }
    return circuit;
  }
  if (proof.commitment === undefined || proof.commitmentPok === undefined) {
    throw new ClientError("CLIENT_PROOF_PARSE", {
      details: { path: "$.proof.proofCommitment", reason: "missing commitment" },
    });
  }
  const proofData = Object.freeze({
    bsb22Commitment: Object.freeze({
      commitment: new Uint8Array(checkedBytes(proof.commitment, 32, "proof.commitment")) as Bytes32,
      commitmentPok: new Uint8Array(
        checkedBytes(proof.commitmentPok, 32, "proof.commitmentPok"),
      ) as Bytes32,
    }),
    ownerPk: circuit.proofData.ownerPk,
  });
  return Object.freeze({ ...circuit, proofData });
}

/**
 * Mirrors Rust `confidential_marked_output_owner_pk_hashes`, the ring rails
 * publish an owner hash only for a `Confidential` scheme output, a
 * `RingConfidential` one contributes zero. The tag is a Solana signer, so it
 * enters as its tagged identity. One entry per circuit output slot: the
 * trailing compact padding the instruction leaves out contributes zero.
 */
function confidentialMarkedOutputOwnerHashes(external: ExternalData, nOutputs: number): bigint[] {
  if (
    external.outputs.length !== external.resolvedOwnerTags.length ||
    external.outputs.length > nOutputs
  ) {
    throw new ClientError("CLIENT_PROVER_INPUT");
  }
  const published = external.outputs.map((output, index) => {
    const tag = external.resolvedOwnerTags[index];
    if (tag === undefined) throw new ClientError("CLIENT_PROVER_INPUT");
    return output.data !== undefined && isConfidentialEncryptedOutput(output.data)
      ? bytesToBigInt(solanaOwnerIdentity(tag))
      : 0n;
  });
  return [...published, ...Array.from({ length: nOutputs - published.length }, () => 0n)];
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
  readonly nullifiers: readonly Bytes32[];
  readonly inputOwnerFields: readonly bigint[];
  /** The input trees in first-use order, at most `MAX_INPUT_TREES` of them. */
  readonly treeIds: readonly TreeId[];
  /** Each input's position in `treeIds`. */
  readonly treeIndexes: readonly number[];
}

export interface AssembledSlots extends PreparedSlots {
  readonly transferInputs: readonly TransferInput[];
  readonly inputTrees: readonly InputTree[];
}

/** The slot's published nullifier enters the statement; compact padding publishes 0. */
export function prepareInput(
  input: ProofInputUtxo,
  options: Readonly<{ owner: bigint; treeSlot: number; nullifier?: Bytes32 }>,
): PreparedTransferInput {
  const dummy = input.isDummy();
  return Object.freeze({
    circuit: inputCircuitUtxo(input, dummy),
    isDummy: asField(dummy ? 1n : 0n),
    treeSlot: asField(BigInt(options.treeSlot)),
    nullifier: asField(bytesField(options.nullifier ?? input.publishedNullifier(), "nullifier")),
    ownerPublicKeyHash: asField(dummy ? 0n : options.owner),
    ...(dummy || input.isAddress() ? { nullifierSecret: asField(0n) } : {}),
  });
}

export function prepareSlots(
  inputs: readonly ProofInputUtxo[],
  ownerField: (input: ProofInputUtxo, index: number) => bigint,
): PreparedSlots {
  const treeIds: TreeId[] = [];
  const treeIndexes: number[] = [];
  const transferInputs = inputs.map((input, index) => {
    let treeSlot = treeIds.indexOf(input.treeId);
    if (input.isDummy()) {
      if (treeIds.length === 0) throw new ClientError("CLIENT_NO_INPUTS");
      // SPP packs tree index 0 for the slots it never receives, so compact
      // padding must name the first tree.
      if (treeSlot === -1 || (input.isCompact() && treeSlot !== INPUT_TREE_SLOT))
        throw new ClientError("CLIENT_INPUT_TREE_UNRESOLVED", {
          details: { index },
        });
    } else if (treeSlot === -1) {
      if (treeIds.length === MAX_INPUT_TREES)
        throw new ClientError("CLIENT_TOO_MANY_INPUT_TREES", {
          details: { got: treeIds.length + 1, max: MAX_INPUT_TREES },
        });
      treeIds.push(input.treeId);
      treeSlot = treeIds.length - 1;
    }
    treeIndexes.push(treeSlot);
    return prepareInput(input, {
      owner: input.isDummy() ? 0n : ownerField(input, index),
      treeSlot,
    });
  });
  if (treeIds.length === 0) throw new ClientError("CLIENT_NO_INPUTS");
  return Object.freeze({
    transferInputs: Object.freeze(transferInputs),
    nullifiers: Object.freeze(
      transferInputs.map((input) => bigintToBytes(input.nullifier, "nullifier") as Bytes32),
    ),
    inputOwnerFields: Object.freeze(transferInputs.map((input) => input.ownerPublicKeyHash)),
    treeIds: Object.freeze(treeIds),
    treeIndexes: Object.freeze(treeIndexes),
  });
}

/**
 * Mirrors Rust `assemble_inputs` and `resolve_input_trees`. Padding is not
 * decided here: a slot with a spend proof is a real spend, a slot without one
 * is a dummy with its own non-inclusion proof.
 *
 * Inputs from different trees may interleave. A tree is opened by a real
 * spend, whose nullifier proof fixes the slot's nullifier root; the first
 * uncached real spend of the tree fixes its state root, and every later input
 * of that tree must open against the same roots and root positions, since the
 * proof publishes one slot per tree and the instruction one root position pair
 * per tree. A tree the cache supplies entirely publishes a zero state root at
 * root position `NO_UTXO_ROOT`. A dummy or cached input has no state proof, so
 * it joins the tree it names and takes the next dummy non-inclusion proof.
 * Compact padding is a dummy that publishes 0 in place of the nullifier its
 * proof is taken for, and it must name the first tree.
 *
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
    const openIndex = runs.findIndex((run) => run.treeId === treeId);
    const openRun = runs[openIndex];
    if (input.isDummy()) {
      if (runs.length === 0) throw new ClientError("CLIENT_NO_INPUTS");
      if (openRun === undefined || (input.isCompact() && openIndex !== INPUT_TREE_SLOT)) {
        throw new ClientError("CLIENT_INPUT_TREE_UNRESOLVED", {
          details: { index },
        });
      }
      const proof = dummyNullifierProofs[dummyProofIndex++];
      if (!proof) {
        throw new ClientError("CLIENT_MISSING_INPUT_MERKLE_PROOF", {
          details: { index },
        });
      }
      validateNullifierProof(input, proof, index);
      checkNullifierRoot(openRun, proof, expectedTree, index);
      const converted = createDummyTransferInput(
        input,
        proof,
        input.publishedNullifier(),
        openIndex,
      );
      transferInputs.push(converted);
      nullifiers.push(bigintToBytes(converted.nullifier, "nullifier") as Bytes32);
      inputOwnerFields.push(converted.ownerPublicKeyHash);
      treeIndexes.push(openIndex);
      continue;
    }
    let treeIndex: number;
    let converted: TransferInput;
    let owner: bigint;
    if (!input.requiresInclusion()) {
      const proof = dummyNullifierProofs[dummyProofIndex++];
      if (!proof) {
        throw new ClientError("CLIENT_MISSING_INPUT_MERKLE_PROOF", {
          details: { index },
        });
      }
      validateNullifierProof(input, proof, index);
      if (openRun !== undefined) {
        treeIndex = openIndex;
        checkNullifierRoot(openRun, proof, expectedTree, index);
      } else {
        checkNewTree(runs);
        if (proof.merkleContext.tree !== expectedTree) {
          throw new ClientError("CLIENT_PROOF_TREE_MISMATCH", {
            details: { index },
          });
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
      if (openRun !== undefined) {
        treeIndex = openIndex;
        if (openRun.state === undefined) {
          if (proof.state.merkleContext.tree !== expectedTree) {
            throw new ClientError("CLIENT_PROOF_TREE_MISMATCH", {
              details: { index },
            });
          }
          openRun.state = Object.freeze({
            root: new Uint8Array(proof.state.root) as Bytes32,
            index: proof.state.rootIndex,
          });
        } else if (
          proof.state.merkleContext.tree !== expectedTree ||
          !equalBytes(proof.state.root, openRun.state.root) ||
          proof.state.rootIndex !== openRun.state.index
        ) {
          throw new ClientError("CLIENT_INPUT_TREE_ROOT_MISMATCH", {
            details: { index },
          });
        }
        checkNullifierRoot(openRun, proof.nullifier, expectedTree, index);
      } else {
        checkNewTree(runs);
        // The real spend that opens a tree anchors it; both of its proofs must
        // name that tree.
        if (
          proof.state.merkleContext.tree !== expectedTree ||
          proof.nullifier.merkleContext.tree !== expectedTree
        ) {
          throw new ClientError("CLIENT_PROOF_TREE_MISMATCH", {
            details: { index },
          });
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
    nullifiers.push(new Uint8Array(input.nullifier()) as Bytes32);
    inputOwnerFields.push(owner);
    treeIndexes.push(treeIndex);
  }
  if (runs.length === 0) throw new ClientError("CLIENT_NO_INPUTS");
  return Object.freeze({
    transferInputs: Object.freeze(transferInputs),
    treeIds: Object.freeze(runs.map((run) => run.treeId)),
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

function checkNewTree(runs: readonly InputTreeRun[]): void {
  if (runs.length === MAX_INPUT_TREES) {
    throw new ClientError("CLIENT_TOO_MANY_INPUT_TREES", {
      details: { got: runs.length + 1, max: MAX_INPUT_TREES },
    });
  }
}

function inputTreeOf(run: InputTreeRun): InputTree {
  const state = run.state ?? {
    root: new Uint8Array(32) as Bytes32,
    index: NO_UTXO_ROOT,
  };
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

function attachPaths(
  local: PreparedTransferInput,
  proofs: Readonly<{
    state?: SpendProof["state"];
    nullifier: NonInclusionProof;
  }>,
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

interface TransferPublicInputFields extends CachedInputs {
  nullifiers: readonly bigint[];
  outputHashes: readonly bigint[];
  outputTreeId: TreeId;
  privateTxHash: bigint;
  /**
   * The fields a rail inserts right after `privateTxHash`: none on the
   * signer, ring and authority rails, `eddsaPublicFields` on the
   * `confidentialEddsa` rail.
   */
  afterPrivateTxHash?: readonly bigint[];
  externalDataHash: bigint;
  publicSlots: readonly bigint[];
  ringProgramId: bigint;
  signerPublicKeyHashes: readonly bigint[];
  /** The packed dummy policy and per-input tree indexes, `inputFlags`. */
  inputFlags: bigint;
  publishedOutputOwnerPublicKeyHashes: readonly bigint[] | undefined;
}

/**
 * The nullifier, output and output owner chains fold to the right over the
 * circuit width; compact padding contributes zeros, and a published owner
 * vector shorter than the outputs is padded with them.
 */
export function transferPublicInputs(input: TransferPublicInputFields): readonly bigint[] {
  return [
    rightHashChain4(input.nullifiers),
    rightHashChain4(input.outputHashes),
    bytesToBigInt(treeIdField(input.outputTreeId)),
    input.privateTxHash,
    ...(input.afterPrivateTxHash ?? []),
    input.externalDataHash,
    ...input.publicSlots,
    input.ringProgramId,
    rightHashChain(input.signerPublicKeyHashes),
    input.inputFlags,
    ...(input.publishedOutputOwnerPublicKeyHashes === undefined
      ? []
      : [
          rightHashChain4([
            ...input.publishedOutputOwnerPublicKeyHashes,
            ...Array<bigint>(
              Math.max(
                input.outputHashes.length - input.publishedOutputOwnerPublicKeyHashes.length,
                0,
              ),
            ).fill(0n),
          ]),
          input.cacheTreeId,
          input.cacheReadHashChain,
        ]),
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
  input: TransferPublicInputFields & {
    readonly treeSlots: readonly TreeSlot[];
  },
): bigint {
  return resolvedPublicInputHash(transferPublicInputs(input), input.treeSlots);
}

function checkNullifierRoot(
  run: Readonly<{ nullifierRoot: Bytes32; nullifierRootIndex: number }>,
  proof: NonInclusionProof,
  expectedTree: Address,
  index: number,
): void {
  if (
    proof.merkleContext.tree !== expectedTree ||
    !equalBytes(proof.root, run.nullifierRoot) ||
    proof.rootIndex !== run.nullifierRootIndex
  ) {
    throw new ClientError("CLIENT_NULLIFIER_ROOT_MISMATCH", {
      details: { index },
    });
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

/**
 * Slot 0, the only slot a single-tree proof opens against and the tree index
 * SPP packs into `input_flags` for a compact slot it never receives.
 */
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
    ...(input.isAddress() ? { nullifierSecret: asField(0n) } : {}),
  });
}

/**
 * A padding slot with the non-inclusion proof of `input.nullifier()`, the
 * nullifier the circuit derives for it, publishing `nullifier`: that same
 * value for a random dummy, 0 for compact padding, the deterministic dummy
 * nullifier of a merge slot.
 */
export function createDummyTransferInput(
  input: ProofInputUtxo,
  proof: NonInclusionProof,
  nullifier = input.publishedNullifier(),
  treeSlot: number = INPUT_TREE_SLOT,
): TransferInput {
  return attachPaths(prepareInput(input, { owner: 0n, treeSlot, nullifier }), {
    nullifier: proof,
  });
}

/**
 * The output as the prover reads it, hashed under `outputTreeId`. A dummy's
 * published owner field is the tagged Solana identity of its owner tag, the
 * participant the pad names.
 */
export function createOutput(output: ProofOutputUtxo, outputTreeId: TreeId): TransferOutput {
  // Compact padding publishes owner tag 0; no identity folds to 0.
  const ownerPublicKeyHash = output.ownerAddress
    ? bytesField(
        output.ownerAddress.signingPublicKey.ownerProofInputHash(),
        "output owner public key",
      )
    : output.isCompact()
      ? 0n
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

export function inputCircuitUtxo(input: ProofInputUtxo, dummy = false): CircuitUtxo {
  const owner = dummy
    ? 0n
    : poseidon([
        bytesField(input.utxo.owner.ownerProofInputHash(), "owner public key"),
        bytesField(input.nullifierPublicKey, "nullifier public key"),
      ]);
  return Object.freeze({
    domain: asField(
      BigInt(dummy ? DUMMY_DOMAIN : input.isAddress() ? ADDRESS_DOMAIN : UTXO_DOMAIN),
    ),
    owner: asField(owner),
    asset: asField(
      dummy || input.isAddress() ? 0n : hashBytesBigInt(addressBytes(input.utxo.asset)),
    ),
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

export function outputCircuitUtxo(output: ProofOutputUtxo): CircuitUtxo {
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
  if (!equalBytes(input.hash(), proof.state.leaf)) {
    throw new ClientError("CLIENT_STATE_PROOF_LEAF_MISMATCH", {
      details: { index },
    });
  }
  if (!equalBytes(input.nullifier(), proof.nullifier.leaf)) {
    throw new ClientError("CLIENT_NULLIFIER_PROOF_LEAF_MISMATCH", {
      details: { index },
    });
  }
  if (proof.state.merkleContext.tree !== proof.nullifier.merkleContext.tree) {
    throw new ClientError("CLIENT_PROOF_TREE_MISMATCH", { details: { index } });
  }
  if (proof.state.path.length !== STATE_TREE_HEIGHT) {
    throw new ClientError("CLIENT_PROOF_PATH_LENGTH", {
      details: {
        index,
        kind: "state",
        expected: STATE_TREE_HEIGHT,
        got: proof.state.path.length,
      },
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
  if (!equalBytes(input.nullifier(), proof.leaf)) {
    throw new ClientError("CLIENT_NULLIFIER_PROOF_LEAF_MISMATCH", {
      details: { index },
    });
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

function publicTransfers(proofInputs: SppProofInputs): Readonly<{
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
  return Object.freeze({
    assets: Object.freeze(assets),
    amounts: Object.freeze(amounts),
  });
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

function copyProof(proof: ProvedTransactProof): TransactProof {
  return Object.freeze({
    a: new Uint8Array(proof.a) as never,
    b: new Uint8Array(proof.b) as never,
    c: new Uint8Array(proof.c) as never,
  });
}
