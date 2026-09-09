import { address } from "@solana/kit";

import { externalDataHash as interfaceExternalDataHash } from "../../interface/external-data-hash.js";
import { InstructionTag } from "../../interface/program.js";
import {
  SPP_SUPPORTED_SHAPES as INTERFACE_SUPPORTED_SHAPES,
  selectSppShape,
  type Shape,
  validateSppShape,
} from "../../interface/shape.js";
import {
  type Address,
  type Bytes16,
  type Bytes32,
  type OwnerTag,
  type Signature,
  type TransactOutput,
} from "../../interface/types.js";
import { randomBlinding, randomSalt } from "../../keypair/bytes.js";
import { P256PublicKey } from "../../keypair/public-key.js";
import { ShieldedKeypair, type ShieldedAddress } from "../../keypair/shielded.js";
import { ViewingKey } from "../../keypair/viewing-key.js";

import { Data } from "../data.js";
import { TransactionError } from "../error.js";
import {
  ZERO_32,
  bigIntBytes,
  checkU64,
  checked,
  copy,
  decodeAddress,
  equal,
  hashChain,
  hashBytes,
  poseidon,
  sha256Bytes,
} from "../internal.js";
import { EncryptedScheme, encodeOutputData, encryptConfidential } from "../serialization/codecs.js";
import {
  ProofInputUtxo,
  Utxo,
  createProofOutput,
  outputBlindingSeed,
  privateTxBlinding,
  transactOutputBlinding,
  type ProofOutputInit,
  type ProofOutputUtxo,
  type TreeId,
} from "../utxo.js";
import { DEFAULT_TREE_ID } from "../../interface/tree-slot.js";
import { SOL_ASSET_ID, type AssetRegistry } from "../asset.js";

export type { Shape };
export const SPP_SUPPORTED_SHAPES = INTERFACE_SUPPORTED_SHAPES;

/**
 * Fixed number of leading sender-owned output slots in a transfer: SPL change at
 * slot 0, SOL change at slot 1. Recipients always start at slot 2.
 */
export const SENDER_SLOT_COUNT = 2;

/** The BN254 scalar modulus, as the decimal literal Rust pins. */
export const BN254_MODULUS_DEC =
  "21888242871839275222246405745257275088548364400416034343698204186575808495617";

const BN254_MODULUS = BigInt(BN254_MODULUS_DEC);
const I64_MIN = -(2n ** 63n);
const I64_MAX = 2n ** 63n - 1n;

/**
 * A signed public amount as the field element a proof's public inputs carry: a
 * negative amount wraps around the BN254 modulus. Rust takes an `i64`, so the
 * range check here stands in for the type.
 */
export function signedToField(value: bigint): Bytes32 {
  if (typeof value !== "bigint" || value < I64_MIN || value > I64_MAX) {
    throw new TransactionError("TRANSACTION_INVALID_AMOUNT", {
      name: "signed amount",
      minimum: I64_MIN.toString(),
      maximum: I64_MAX.toString(),
      actual: String(value),
    });
  }
  return bigIntBytes(value < 0n ? BN254_MODULUS + value : value) as Bytes32;
}

/** The field element an asset mint contributes to a proof's public inputs. */
export function assetField(asset: Address): Bytes32 {
  return hashBytes(decodeAddress(asset)) as Bytes32;
}

function checkedCount(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TransactionError("TRANSACTION_UNSUPPORTED_SHAPE", { [name]: value });
  }
  return value;
}

export function canonicalShape(inputs: number, outputs: number): Shape {
  checkedCount(inputs, "inputs");
  checkedCount(outputs, "outputs");
  try {
    return selectSppShape(inputs, outputs);
  } catch (error) {
    throw new TransactionError("TRANSACTION_UNSUPPORTED_SHAPE", { inputs, outputs }, error);
  }
}

/**
 * The proving system whose slot counts the padded transaction already matches.
 * Unlike `canonicalShape` this rounds nothing up: the counts are final by the
 * time a proof is assembled.
 */
export function exactShape(inputs: number, outputs: number): Shape {
  const exact = SPP_SUPPORTED_SHAPES.find(
    (shape) => shape.inputs === inputs && shape.outputs === outputs,
  );
  if (!exact) {
    throw new TransactionError("TRANSACTION_UNSUPPORTED_SHAPE", { inputs, outputs });
  }
  return Object.freeze({ ...exact });
}

export function resolveShape(inputs: number, outputs: number, declared?: Shape): Shape {
  if (declared === undefined) return canonicalShape(inputs, outputs);
  checkedCount(inputs, "inputs");
  checkedCount(outputs, "outputs");
  const candidate: unknown = declared;
  if (typeof candidate !== "object" || candidate === null) {
    throw new TransactionError("TRANSACTION_UNSUPPORTED_SHAPE", {
      declared: String(candidate),
    });
  }
  const shape = candidate as Shape;
  checkedCount(shape.inputs, "declaredInputs");
  checkedCount(shape.outputs, "declaredOutputs");
  const supported = SPP_SUPPORTED_SHAPES.some(
    (supportedShape) =>
      supportedShape.inputs === shape.inputs && supportedShape.outputs === shape.outputs,
  );
  if (!supported) {
    throw new TransactionError("TRANSACTION_UNSUPPORTED_SHAPE", {
      inputs: shape.inputs,
      outputs: shape.outputs,
    });
  }
  if (inputs > shape.inputs) {
    throw new TransactionError("TRANSACTION_TOO_MANY_INPUTS", {
      got: inputs,
      max: shape.inputs,
    });
  }
  if (outputs > shape.outputs) {
    throw new TransactionError("TRANSACTION_TOO_MANY_OUTPUTS_FOR_SHAPE", {
      got: outputs,
      max: shape.outputs,
    });
  }
  return validateSppShape(inputs, outputs, shape);
}

/**
 * The ciphertext ordinal that keys AES-CTR for the slot at `position`, the
 * counterpart of Rust `slot_ordinal`. Every published output of a confidential
 * transfer carries a ciphertext, so the ordinal is the output position. It is a
 * `u32` in the HKDF `info` string, and a wrapped value would reuse a
 * `(key, nonce)` pair across two slots.
 */
export function slotOrdinal(position: number): number {
  if (!Number.isInteger(position) || position < 0 || position > 0xffff_ffff) {
    throw new TransactionError("TRANSACTION_OUTPUT_SLOT_OVERFLOW", { position });
  }
  return position;
}

export interface PublicAmounts {
  readonly sol?: bigint;
  readonly spl?: bigint;
}

export type SettlementTransfer =
  | Readonly<{
      kind: "sol";
      isDeposit: boolean;
      amount: bigint;
      userSolAccount: Address;
    }>
  | Readonly<{
      kind: "spl";
      mint: Address;
      isDeposit: boolean;
      amount: bigint;
      tokenAccount: Address;
      splTokenInterface: Address;
      splInterfaceBump: number;
    }>;

export interface InputUtxoContext {
  readonly index: number;
  readonly utxoHash: Bytes32;
  readonly nullifier: Bytes32;
}

export interface ExternalData {
  readonly instructionDiscriminator: number;
  readonly expiryUnixTs: bigint;
  readonly interfaceTransfers: readonly SettlementTransfer[];
  readonly dataHash?: Bytes32;
  readonly ringDataHash?: Bytes32;
  readonly txViewingPublicKey: P256PublicKey;
  readonly salt: Bytes16;
  readonly outputs: readonly TransactOutput[];
  readonly resolvedOwnerTags: readonly Bytes32[];
  readonly messages: readonly Readonly<{ viewTag: Bytes32; data: Uint8Array }>[];
  hash(): Bytes32;
  withInterfaceTransfer(transfer: SettlementTransfer): ExternalData;
  withInterfaceTransfers(transfers: readonly SettlementTransfer[]): ExternalData;
}

/**
 * What a caller must supply, the counterpart of Rust `ExternalData::new`. The
 * interface transfers, optional hashes, and expiry carry Rust's defaults, so a
 * confidential transfer names only the fields it actually has.
 */
export interface ExternalDataInit {
  readonly instructionDiscriminator?: number;
  readonly expiryUnixTs?: bigint;
  readonly interfaceTransfers?: readonly SettlementTransfer[];
  readonly dataHash?: Bytes32;
  readonly ringDataHash?: Bytes32;
  readonly txViewingPublicKey: P256PublicKey;
  readonly salt: Bytes16;
  readonly outputs: readonly TransactOutput[];
  readonly resolvedOwnerTags: readonly Bytes32[];
  readonly messages: readonly Readonly<{ viewTag: Bytes32; data: Uint8Array }>[];
}

/** Rust's default expiry: `u64::MAX`, meaning no expiry. */
const NO_EXPIRY = 0xffff_ffff_ffff_ffffn;
function externalDataHash(data: ExternalDataFields): Bytes32 {
  if (data.outputs.length !== data.resolvedOwnerTags.length) {
    throw new TransactionError("TRANSACTION_OUTPUT_TAG_MISMATCH");
  }
  if (data.outputs.length > 0xffff || data.messages.length > 0xffff) {
    throw new TransactionError("TRANSACTION_TOO_MANY_OUTPUTS");
  }
  const checkedInteger = (value: bigint, byteLength: number, signed = false): void => {
    const bits = byteLength * 8;
    if (
      (!signed && (value < 0n || value >= 1n << BigInt(bits))) ||
      (signed && BigInt.asIntN(bits, value) !== value)
    ) {
      throw new TransactionError("TRANSACTION_INVALID_AMOUNT", {
        value: value.toString(),
        byteLength,
        signed,
      });
    }
  };
  const checkedLength = (bytes: Uint8Array): void => {
    if (bytes.length > 0xffff) {
      throw new TransactionError("TRANSACTION_INVALID_DATA_LENGTH", {
        maximum: 0xffff,
        actual: bytes.length,
      });
    }
  };
  checkedInteger(data.expiryUnixTs, 8);
  if (data.interfaceTransfers.length > 0xff) {
    throw new TransactionError("TRANSACTION_TOO_MANY_INTERFACE_TRANSFERS", {
      got: data.interfaceTransfers.length,
      max: 0xff,
    });
  }
  for (const transfer of data.interfaceTransfers) {
    checkedInteger(transfer.amount, 8);
    if (transfer.amount === 0n) {
      throw new TransactionError("TRANSACTION_ZERO_INTERFACE_TRANSFER_AMOUNT");
    }
  }
  data.outputs.forEach((output, index) => {
    if (data.resolvedOwnerTags[index] === undefined) {
      throw new TransactionError("TRANSACTION_OUTPUT_TAG_MISMATCH");
    }
    if (output.data !== undefined) checkedLength(output.data);
  });
  data.messages.forEach((message) => {
    checkedLength(message.data);
  });
  return interfaceExternalDataHash({
    instructionDiscriminator: data.instructionDiscriminator,
    expiryUnixTs: data.expiryUnixTs,
    interfaceTransfers: data.interfaceTransfers.map((transfer) =>
      transfer.kind === "sol"
        ? {
            kind: transfer.isDeposit ? ("solDeposit" as const) : ("solWithdrawal" as const),
            amount: transfer.amount,
            recipient: transfer.userSolAccount,
          }
        : {
            kind: transfer.isDeposit ? ("splDeposit" as const) : ("splWithdrawal" as const),
            amount: transfer.amount,
            tokenAccount: transfer.tokenAccount,
            splInterfacePda: transfer.splTokenInterface,
          },
    ),
    ...(data.dataHash === undefined ? {} : { dataHash: data.dataHash }),
    ...(data.ringDataHash === undefined ? {} : { ringDataHash: data.ringDataHash }),
    txViewingPk: data.txViewingPublicKey.toBytes(),
    salt: data.salt,
    outputs: data.outputs.map((output, index) => ({
      utxoHash: output.utxoHash,
      ownerTag: data.resolvedOwnerTags[index] as Bytes32,
      ...(output.data === undefined ? {} : { data: output.data }),
    })),
    messages: data.messages,
  });
}

type ExternalDataFields = Omit<
  ExternalData,
  "hash" | "withInterfaceTransfer" | "withInterfaceTransfers"
>;

export function createExternalData(input: ExternalDataInit): ExternalData {
  const snapshot: ExternalDataFields = {
    ...input,
    instructionDiscriminator: input.instructionDiscriminator ?? InstructionTag.transact,
    expiryUnixTs: input.expiryUnixTs ?? NO_EXPIRY,
    interfaceTransfers: Object.freeze(
      (input.interfaceTransfers ?? []).map((transfer) => Object.freeze({ ...transfer })),
    ),
    salt: checked<Bytes16>(input.salt, 16, "salt"),
    // The hash closes over these arrays, so freezing them is what keeps a
    // holder of the returned value from changing the preimage under it.
    outputs: Object.freeze(
      input.outputs.map((output) =>
        Object.freeze({
          ...output,
          utxoHash: checked<Bytes32>(output.utxoHash, 32, "output hash"),
          ownerTag:
            output.ownerTag.kind === "inline"
              ? Object.freeze({
                  kind: "inline" as const,
                  value: checked<Bytes32>(output.ownerTag.value, 32, "output owner tag"),
                })
              : Object.freeze({ ...output.ownerTag }),
          ...(output.data === undefined ? {} : { data: new Uint8Array(output.data) }),
        }),
      ),
    ),
    resolvedOwnerTags: Object.freeze(
      input.resolvedOwnerTags.map((tag) => checked<Bytes32>(tag, 32, "resolved owner tag")),
    ),
    messages: Object.freeze(
      input.messages.map((message) =>
        Object.freeze({
          viewTag: checked<Bytes32>(message.viewTag, 32, "message view tag"),
          data: new Uint8Array(message.data),
        }),
      ),
    ),
  };
  return sealExternalData(snapshot);
}

/// The builders re-enter through `createExternalData` so a derived value is
/// copied and frozen exactly like the original; a caller keeping the value it
/// passed cannot reach into either.
function sealExternalData(fields: ExternalDataFields): ExternalData {
  const set = (changed: Partial<ExternalDataFields>): ExternalData =>
    createExternalData({ ...fields, ...changed });
  return Object.freeze({
    ...fields,
    hash: (): Bytes32 => externalDataHash(fields),
    withInterfaceTransfer: (transfer: SettlementTransfer): ExternalData =>
      set({ interfaceTransfers: [...fields.interfaceTransfers, transfer] }),
    withInterfaceTransfers: (transfers: readonly SettlementTransfer[]): ExternalData =>
      set({ interfaceTransfers: [...transfers] }),
  });
}

/**
 * A spent UTXO carrying the nullifier public key rather than the secret, for
 * callers that hash a transaction they cannot sign.
 */
export interface InputUtxo {
  readonly utxo: Utxo;
  readonly nullifierPublicKey: Bytes32;
  /** The tree the UTXO is spent from. */
  readonly treeId: TreeId;
  readonly ringDataHash?: Bytes32;
  readonly dataHash?: Bytes32;
  hash(): Bytes32;
  isDummy(): boolean;
}

export function createInputUtxo(
  input: Readonly<{
    utxo: Utxo;
    nullifierPublicKey: Bytes32;
    /** Defaults to `DEFAULT_TREE_ID`, the one live tree. */
    treeId?: TreeId;
    ringDataHash?: Bytes32;
    dataHash?: Bytes32;
  }>,
): InputUtxo {
  const nullifierPublicKey = checked<Bytes32>(input.nullifierPublicKey, 32, "nullifier public key");
  const utxo = new Utxo(input.utxo);
  const treeId = input.treeId ?? DEFAULT_TREE_ID;
  return Object.freeze({
    ...input,
    utxo,
    nullifierPublicKey,
    treeId,
    hash(): Bytes32 {
      return utxo.hash(nullifierPublicKey, treeId, input.dataHash, input.ringDataHash);
    },
    isDummy(): boolean {
      return utxo.owner.isZero();
    },
  });
}

export interface PrivateTxHashInput {
  readonly inputHashes: readonly Bytes32[];
  readonly outputHashes: readonly Bytes32[];
  /**
   * One per input slot: the public nullifier of each address slot, which is
   * the compressed address, and zero for spends and padding. Omitted means a
   * chain of zeros of the same length.
   */
  readonly addressNullifiers?: readonly Bytes32[];
  readonly externalDataHash: Bytes32;
  /**
   * The private transaction blinding, `privateTxBlinding(firstNullifier,
   * secret)`. Every other preimage element is public or computable, so
   * without it an observer could test candidate input hashes against the
   * published value.
   */
  readonly blinding: Bytes32;
}

/**
 * `Poseidon(chain(inputs), chain(outputs), chain(address nullifiers),
 * external_data_hash, blinding)`, the value a transact proof publishes and the
 * owners sign over. The circuit reads one address nullifier per input slot, so
 * a set of a different length would silently shift the address chain rather
 * than fail.
 */
export function privateTxHash(input: PrivateTxHashInput): Bytes32 {
  if (
    input.addressNullifiers !== undefined &&
    input.addressNullifiers.length !== input.inputHashes.length
  ) {
    throw new TransactionError("TRANSACTION_ADDRESS_HASH_COUNT_MISMATCH", {
      expected: input.inputHashes.length,
      actual: input.addressNullifiers.length,
    });
  }
  const addressNullifiers = input.addressNullifiers ?? input.inputHashes.map(() => copy(ZERO_32));
  return poseidon([
    hashChain(input.inputHashes),
    hashChain(input.outputHashes),
    hashChain(addressNullifiers),
    input.externalDataHash,
    checked<Bytes32>(input.blinding, 32, "private tx blinding"),
  ]);
}

export interface EncryptedTransaction {
  readonly inputs: readonly InputUtxo[];
  readonly outputs: readonly ProofOutputUtxo[];
  readonly externalData: ExternalData;
  /** The tree the outputs are appended to. */
  readonly outputTreeId: TreeId;
  /** The private transaction blinding the hash folds in last. */
  readonly privateTxBlinding: Bytes32;
  hash(): Bytes32;
}

export function createEncryptedTransaction(
  input: Readonly<{
    inputs: readonly InputUtxo[];
    outputs: readonly ProofOutputUtxo[];
    externalData: ExternalData;
    outputTreeId: TreeId;
    privateTxBlinding: Bytes32;
  }>,
): EncryptedTransaction {
  const inputs = Object.freeze([...input.inputs]);
  const outputs = Object.freeze([...input.outputs]);
  const blinding = checked<Bytes32>(input.privateTxBlinding, 32, "private tx blinding");
  return Object.freeze({
    ...input,
    inputs,
    outputs,
    privateTxBlinding: blinding,
    // An unused slot contributes a zero hash, matching the circuit and
    // `SppProofInputs.messageHash`.
    hash(): Bytes32 {
      return privateTxHash({
        inputHashes: inputs.map((entry) => (entry.isDummy() ? copy(ZERO_32) : entry.hash())),
        outputHashes: outputs.map((entry) =>
          entry.isDummy() ? copy(ZERO_32) : entry.hash(input.outputTreeId),
        ),
        externalDataHash: input.externalData.hash(),
        blinding,
      });
    },
  });
}

/**
 * The tree every input of one proof is spent from. Mirrors Rust
 * `input_tree_id`: the circuit publishes one input tree slot, so inputs from
 * two trees cannot share a proof.
 */
export function inputTreeId(inputs: readonly ProofInputUtxo[]): TreeId {
  const first = inputs[0];
  if (first === undefined) throw new TransactionError("TRANSACTION_NO_INPUTS");
  inputs.forEach((input, index) => {
    if (input.treeId !== first.treeId) {
      throw new TransactionError("TRANSACTION_INPUT_TREE_MISMATCH", {
        index,
        treeId: input.treeId,
        expected: first.treeId,
      });
    }
  });
  return first.treeId;
}

export class SppProofInputs {
  readonly payer: Address;
  readonly inputUtxos: readonly ProofInputUtxo[];
  readonly outputs: readonly ProofOutputUtxo[];
  readonly externalData: ExternalData;
  /**
   * The private root of this proof's blinding family. It reaches the prover
   * and nothing else: the derived output seed is what bundles disclose.
   */
  readonly blindingSeed: Bytes32;
  /** The tree the outputs are appended to. */
  readonly outputTreeId: TreeId;
  constructor(
    input: Readonly<{
      payer: Address;
      inputUtxos: readonly ProofInputUtxo[];
      outputs: readonly ProofOutputUtxo[];
      externalData: ExternalData;
      blindingSeed: Bytes32;
      outputTreeId: TreeId;
    }>,
  ) {
    this.payer = input.payer;
    this.inputUtxos = Object.freeze([...input.inputUtxos]);
    if (
      this.inputUtxos.some(
        (entry) => !entry.isDummy() && entry.utxo.owner.signatureType() === "p256",
      )
    ) {
      throw new TransactionError("TRANSACTION_P256_TRANSACT_UNSUPPORTED");
    }
    inputTreeId(this.inputUtxos);
    this.outputs = Object.freeze([...input.outputs]);
    this.externalData = input.externalData;
    this.blindingSeed = checked<Bytes32>(input.blindingSeed, 32, "blinding seed");
    if (
      !Number.isInteger(input.outputTreeId) ||
      input.outputTreeId < 0 ||
      input.outputTreeId > 0xffff
    ) {
      throw new TransactionError("TRANSACTION_INVALID_TREE_ID", { treeId: input.outputTreeId });
    }
    this.outputTreeId = input.outputTreeId;
    this.checkShape();
  }

  checkShape(): Shape {
    return exactShape(this.inputUtxos.length, this.outputs.length);
  }

  /** The tree every input is spent from. */
  inputTreeId(): TreeId {
    return inputTreeId(this.inputUtxos);
  }

  /**
   * The published nullifier of input slot 0, which the circuit derives every
   * output blinding and the private transaction blinding from. Slot 0 must be
   * a real spend.
   */
  firstNullifier(): Bytes32 {
    const first = this.inputUtxos[0];
    if (first === undefined || first.isDummy()) {
      throw new TransactionError("TRANSACTION_NO_INPUTS");
    }
    return first.nullifier();
  }

  /** The seed a reader needs to recover every output blinding; safe to disclose. */
  outputBlindingSeed(): Bytes32 {
    return outputBlindingSeed(this.firstNullifier(), this.blindingSeed);
  }

  /** The blinding the private transaction hash folds in; never disclosed. */
  privateTxBlinding(): Bytes32 {
    return privateTxBlinding(this.firstNullifier(), this.blindingSeed);
  }

  inputUtxoHashes(): readonly Bytes32[] {
    return this.inputUtxos.filter((input) => !input.isDummy()).map((input) => input.hash());
  }

  inputContexts(): readonly InputUtxoContext[] {
    return this.inputUtxos
      .filter((input) => !input.isDummy())
      .map((input, index) =>
        Object.freeze({
          index,
          utxoHash: input.hash(),
          nullifier: input.nullifier(),
        }),
      );
  }

  dummyNullifiers(): readonly Bytes32[] {
    return this.inputUtxos
      .filter((input) => input.isDummy())
      .map((input) => new Uint8Array(input.nullifier()) as Bytes32);
  }

  /** The private transaction hash the proof publishes. */
  privateTxHash(): Bytes32 {
    const inputHashes = this.inputUtxos.map((input) =>
      input.isDummy() ? copy(ZERO_32) : input.hash(),
    );
    const outputHashes = this.outputs.map((output) =>
      output.isDummy() ? copy(ZERO_32) : output.hash(this.outputTreeId),
    );
    return privateTxHash({
      inputHashes,
      outputHashes,
      externalDataHash: this.externalData.hash(),
      blinding: this.privateTxBlinding(),
    });
  }

  /** The digest the owners sign: `sha256(privateTxHash)`. */
  messageHash(): Bytes32 {
    return sha256Bytes(this.privateTxHash());
  }
}

export type WithdrawalTarget =
  | Readonly<{ kind: "sol"; recipient: Address }>
  | Readonly<{
      kind: "spl";
      recipientTokenAccount: Address;
      splTokenInterface: Address;
      splInterfaceBump: number;
    }>;

export const WithdrawalTarget = Object.freeze({
  sol(input: Readonly<{ recipient: Address }>): Extract<WithdrawalTarget, { kind: "sol" }> {
    return Object.freeze({ ...input, kind: "sol" });
  },
  spl(
    input: Readonly<{
      recipientTokenAccount: Address;
      splTokenInterface: Address;
      splInterfaceBump: number;
    }>,
  ): Extract<WithdrawalTarget, { kind: "spl" }> {
    return Object.freeze({ ...input, kind: "spl" });
  },
});

/** Whether `prepare` keeps a change slot holding no value. */
export type ChangeLayout = "padded" | "compact";

export interface PreparedTransfer {
  readonly owner: ShieldedAddress;
  readonly inputs: readonly ProofInputUtxo[];
  readonly outputs: readonly ProofOutputUtxo[];
  readonly firstNullifier: Bytes32;
  /** The private root seed; only the prover request may carry it. */
  readonly blindingSeed: Bytes32;
  /** The tree every input is spent from. */
  readonly inputTreeId: TreeId;
  /** The tree the outputs are appended to. */
  readonly outputTreeId: TreeId;
  readonly shape: Shape;
  readonly payer: Address;
  readonly interfaceTransfers: readonly SettlementTransfer[];
  /** Leading outputs the sender owns, Rust `PreparedOutputLayout::sender_output_count`. */
  readonly senderOutputCount: number;
  /** Mirrors Rust `ChangeLayout`. */
  readonly changeLayout: ChangeLayout;
  /** The seed the sender-side bundles disclose so a reader recovers every output blinding. */
  outputBlindingSeed(): Bytes32;
  /** Ring transacts bind the auditor message and the `RING_TRANSACT` tag into the external data hash. */
  finalize(
    input: Readonly<{
      txViewingPublicKey: P256PublicKey;
      salt: Bytes16;
      payload: readonly (Readonly<{ viewTag: Bytes32; data: Uint8Array }> | undefined)[];
      messages?: readonly Readonly<{ viewTag: Bytes32; data: Uint8Array }>[];
      instructionDiscriminator?: number;
    }>,
  ): SppProofInputs;
}

type RecipientRing = "transfer" | "default" | Readonly<{ programId: Address }>;

interface Recipient {
  readonly address: ShieldedAddress;
  readonly asset: Address;
  readonly amount: bigint;
  /** Resolved at `prepare`, mirrors Rust `RecipientRing`, `default` is an exit when the transfer runs in a ring. */
  readonly ring: RecipientRing;
}

const ZERO_ADDRESS = address("11111111111111111111111111111111");

export class ConfidentialTransfer {
  readonly #owner: ShieldedAddress;
  readonly #inputs: readonly ProofInputUtxo[];
  readonly #payer: Address;
  readonly #recipients: Recipient[] = [];
  readonly #blindingSeed = randomBlinding();
  readonly #inputTreeId: TreeId;
  #outputTreeId: TreeId = DEFAULT_TREE_ID;
  #withdrawal?: Readonly<{ asset: Address; amount: bigint; target: WithdrawalTarget }>;
  #shape?: Shape;
  #changeLayout: ChangeLayout = "padded";
  #ringProgramId?: Address;

  constructor(owner: ShieldedAddress, inputs: readonly ProofInputUtxo[], feePayer: Address) {
    if (inputs.length === 0) throw new TransactionError("TRANSACTION_NO_INPUTS");
    if (owner.signingPublicKey.signatureType() === "p256") {
      throw new TransactionError("TRANSACTION_P256_TRANSACT_UNSUPPORTED");
    }
    inputs.forEach((input, index) => {
      if (input.isDummy()) {
        throw new TransactionError("TRANSACTION_DUMMY_INPUT_NOT_ALLOWED", { index });
      }
      if (
        !equal(input.utxo.owner.toBytes(), owner.signingPublicKey.toBytes()) ||
        !equal(input.nullifierKey.publicKey(), owner.nullifierPublicKey)
      ) {
        throw new TransactionError("TRANSACTION_INPUT_OWNER_MISMATCH", { index });
      }
    });
    this.#inputTreeId = inputTreeId(inputs);
    this.#owner = owner;
    this.#inputs = [...inputs];
    this.#payer = feePayer;
  }

  /** Mirrors Rust `ConfidentialTransfer::with_compact_change`. */
  withCompactChange(): this {
    this.#changeLayout = "compact";
    return this;
  }

  /**
   * The tree the outputs are appended to; `DEFAULT_TREE_ID` unless set.
   * Mirrors Rust `with_output_tree_id`.
   */
  withOutputTreeId(outputTreeId: TreeId): this {
    if (!Number.isInteger(outputTreeId) || outputTreeId < 0 || outputTreeId > 0xffff) {
      throw new TransactionError("TRANSACTION_INVALID_TREE_ID", { treeId: outputTreeId });
    }
    this.#outputTreeId = outputTreeId;
    return this;
  }

  withShape(shape: Shape): this {
    this.#shape = shape;
    return this;
  }

  requiresP256Owner(): boolean {
    return false;
  }

  /** Binds the change and every `send` to one ring, mirrors Rust `with_ring_program_id`. */
  withRingProgramId(ringProgramId: Address): this {
    this.#ringProgramId = ringProgramId;
    return this;
  }

  /** The UTXO joins the ring of the transfer, the default ring without one. */
  send(recipient: ShieldedAddress, asset: Address, amount: bigint): void {
    this.#push({ address: recipient, asset, amount, ring: "transfer" });
  }

  /** The UTXO leaves the transfer ring for the default ring. Mirrors Rust `send_default_ring`. */
  sendDefaultRing(recipient: ShieldedAddress, asset: Address, amount: bigint): void {
    this.#push({ address: recipient, asset, amount, ring: "default" });
  }

  sendToRing(
    recipient: ShieldedAddress,
    asset: Address,
    amount: bigint,
    ringProgramId: Address,
  ): void {
    this.#push({ address: recipient, asset, amount, ring: { programId: ringProgramId } });
  }

  // Rust `send` performs no amount check; `checkU64` stands in for its `u64`
  // parameter and nothing more. A zero-amount recipient is a slot Rust builds.
  #push(recipient: Recipient): void {
    checkU64(recipient.amount, "recipient amount");
    this.#recipients.push(recipient);
  }

  withdraw(asset: Address, amount: bigint, target: WithdrawalTarget): void {
    if (this.#withdrawal) throw new TransactionError("TRANSACTION_WITHDRAWAL_ALREADY_SET");
    checkU64(amount, "withdrawal amount");
    if (amount === 0n) {
      throw new TransactionError("TRANSACTION_INVALID_AMOUNT", {
        field: "withdrawal amount",
        value: "0",
      });
    }
    if (target.kind === "spl" && asset === ZERO_ADDRESS) {
      throw new TransactionError("TRANSACTION_WITHDRAWAL_ASSET_MISMATCH");
    }
    if (target.kind === "sol" && asset !== ZERO_ADDRESS) {
      throw new TransactionError("TRANSACTION_WITHDRAWAL_ASSET_MISMATCH");
    }
    this.#withdrawal = { asset, amount, target };
  }

  prepare(): PreparedTransfer {
    const splAssets = new Set(
      [
        ...this.#inputs.map((input) => input.utxo.asset),
        ...this.#recipients.map((recipient) => recipient.asset),
        ...(this.#withdrawal ? [this.#withdrawal.asset] : []),
      ].filter((asset) => asset !== ZERO_ADDRESS),
    );
    if (splAssets.size > 1) throw new TransactionError("TRANSACTION_MULTIPLE_PUBLIC_SPL_ASSETS");
    const splAsset = [...splAssets][0];
    const publicSol = this.#withdrawal?.asset === ZERO_ADDRESS ? -this.#withdrawal.amount : 0n;
    const publicSpl =
      this.#withdrawal && this.#withdrawal.asset !== ZERO_ADDRESS ? -this.#withdrawal.amount : 0n;
    const change = (asset: Address, publicAmount: bigint): bigint => {
      const inputs = this.#inputs
        .filter((input) => input.utxo.asset === asset)
        .reduce((sum, input) => sum + input.utxo.amount, 0n);
      const sent = this.#recipients
        .filter((recipient) => recipient.asset === asset)
        .reduce((sum, recipient) => sum + recipient.amount, 0n);
      const result = inputs + publicAmount - sent;
      if (result < 0n) {
        throw new TransactionError("TRANSACTION_INSUFFICIENT_BALANCE", {
          asset,
          requested: (-result).toString(),
          available: inputs.toString(),
        });
      }
      return result;
    };
    const splChange = splAsset ? change(splAsset, publicSpl) : 0n;
    const solChange = change(ZERO_ADDRESS, publicSol);
    const firstInput = this.#inputs[0];
    if (!firstInput) throw new TransactionError("TRANSACTION_NO_INPUTS");
    const firstNullifier = firstInput.nullifier();
    const splChangeAsset = splAsset !== undefined && splChange > 0n ? splAsset : undefined;
    // Every dummy slot's published tag must name a participant the circuit
    // already sees. A self-paid transfer that keeps no change and pays no
    // shielded recipient has none, so it emits its SOL change slot as a real
    // zero-amount output owned by the sender rather than as padding: the
    // sender then names itself, exactly like an ordinary change output.
    const namesAParticipant =
      namedInputOwnerTag(this.#inputs, this.#payer) !== undefined ||
      splChangeAsset !== undefined ||
      this.#recipients.length > 0;
    const hasSolChange = solChange > 0n || !namesAParticipant;
    const ring = this.#ringProgramId === undefined ? {} : { ringProgramId: this.#ringProgramId };
    const layouts: ProofOutputInit[] = [];
    if (splChangeAsset !== undefined) {
      layouts.push({
        ownerAddress: this.#owner,
        asset: splChangeAsset,
        amount: splChange,
        ...ring,
      });
    } else if (this.#changeLayout === "padded") {
      layouts.push({
        asset: ZERO_ADDRESS,
        amount: 0n,
        ownerTag: this.#owner.confidentialViewTag(),
      });
    }
    if (hasSolChange) {
      layouts.push({ ownerAddress: this.#owner, asset: ZERO_ADDRESS, amount: solChange, ...ring });
    } else if (this.#changeLayout === "padded") {
      layouts.push({
        asset: ZERO_ADDRESS,
        amount: 0n,
        ownerTag: this.#owner.confidentialViewTag(),
      });
    }
    const senderOutputCount = layouts.length;
    layouts.push(
      ...this.#recipients.map((recipient): ProofOutputInit => ({
        ownerAddress: recipient.address,
        asset: recipient.asset,
        amount: recipient.amount,
        ...(recipient.ring === "transfer"
          ? ring
          : recipient.ring === "default"
            ? {}
            : { ringProgramId: recipient.ring.programId }),
      })),
    );
    // The circuit recomputes every output blinding from the first nullifier,
    // the derived seed, and the slot's final physical index, so a compact
    // transfer's change blindings differ from a padded one's.
    const outputSeed = outputBlindingSeed(firstNullifier, this.#blindingSeed);
    const outputs = layouts.map((layout, index) =>
      createProofOutput({
        ...layout,
        blinding: transactOutputBlinding(firstNullifier, outputSeed, index),
      }),
    );
    const shape = resolveShape(this.#inputs.length, outputs.length, this.#shape);
    // Padding belongs to `finalize`, where Rust does it: the slots handed to an
    // authority for encryption are the real outputs only.
    const inputs = [...this.#inputs];
    const target = this.#withdrawal?.target;
    const interfaceTransfers: SettlementTransfer[] =
      this.#withdrawal === undefined || target === undefined
        ? []
        : target.kind === "sol"
          ? [
              {
                kind: "sol",
                isDeposit: false,
                amount: this.#withdrawal.amount,
                userSolAccount: target.recipient,
              },
            ]
          : [
              {
                kind: "spl",
                mint: this.#withdrawal.asset,
                isDeposit: false,
                amount: this.#withdrawal.amount,
                tokenAccount: target.recipientTokenAccount,
                splTokenInterface: target.splTokenInterface,
                splInterfaceBump: target.splInterfaceBump,
              },
            ];
    return preparedTransfer({
      owner: this.#owner,
      inputs: Object.freeze(inputs),
      outputs: Object.freeze(outputs),
      firstNullifier,
      blindingSeed: copy(this.#blindingSeed),
      inputTreeId: this.#inputTreeId,
      outputTreeId: this.#outputTreeId,
      shape,
      payer: this.#payer,
      interfaceTransfers: Object.freeze(interfaceTransfers),
      senderOutputCount,
      changeLayout: this.#changeLayout,
    });
  }

  /**
   * Keypair rail: encrypt every real slot with the owner's own viewing key and
   * sign in place. The authority rail is `prepare` plus `PreparedTransfer.finalize`,
   * with encryption and signing delegated to a `WalletAuthority`.
   */
  sign(keypair: ShieldedKeypair, assets: AssetRegistry): SppProofInputs {
    const prepared = this.prepare();
    const viewingKey = keypair.viewingKey();
    const tx = viewingKey.transactionViewingKey(prepared.firstNullifier);
    try {
      const salt = randomSalt();
      return prepared.finalize({
        txViewingPublicKey: tx.publicKey(),
        salt,
        payload: encodeConfidentialSlots(prepared.outputs, assets, tx, salt),
      });
    } finally {
      tx.destroy();
      viewingKey.destroy();
    }
  }
}

type PreparedTransferFields = Omit<PreparedTransfer, "finalize" | "outputBlindingSeed">;

function preparedTransfer(fields: PreparedTransferFields): PreparedTransfer {
  return Object.freeze({
    ...fields,
    outputBlindingSeed: (): Bytes32 =>
      outputBlindingSeed(fields.firstNullifier, fields.blindingSeed),
    finalize: (encrypted: Parameters<PreparedTransfer["finalize"]>[0]): SppProofInputs =>
      finalizeTransfer(fields, encrypted),
  });
}

/**
 * View tag of the first real input owner that is not the fee payer, if any.
 * A fee sponsor signs without taking part in the shielded transfer, so the
 * circuit refuses to let a padding slot name it. Mirrors Rust
 * `named_input_owner_tag`.
 */
function namedInputOwnerTag(
  inputs: readonly ProofInputUtxo[],
  payer: Address,
): Bytes32 | undefined {
  const payerBytes = decodeAddress(payer);
  for (const spend of inputs) {
    if (spend.isDummy()) continue;
    const tag = spend.utxo.owner.confidentialViewTag();
    if (!equal(tag, payerBytes)) return tag;
  }
  return undefined;
}

/**
 * The published owner tag of every padding slot. A pad must be
 * indistinguishable from a real slot, so the circuit lets it name any
 * participant it already sees, an owner signer other than the fee payer or a
 * real output's owner, and nothing else, so a pad can never attribute the
 * transaction to a third party. Self-attribution is always available, which is
 * why `ConfidentialTransfer.prepare` keeps a real zero-amount change output for
 * a self-paid transfer that would otherwise name nobody. Mirrors Rust
 * `dummy_owner_tag`.
 */
function dummyOwnerTag(
  inputs: readonly ProofInputUtxo[],
  outputs: readonly ProofOutputUtxo[],
  payer: Address,
): Bytes32 {
  const named = namedInputOwnerTag(inputs, payer);
  if (named !== undefined) return named;
  for (const output of outputs) {
    if (output.ownerAddress !== undefined) {
      return output.ownerAddress.signingPublicKey.confidentialViewTag();
    }
  }
  throw new TransactionError("TRANSACTION_NO_DUMMY_OWNER_TAG_PARTICIPANT");
}

function finalizeTransfer(
  prepared: PreparedTransferFields,
  encrypted: Parameters<PreparedTransfer["finalize"]>[0],
): SppProofInputs {
  // Slots are read by output position, so a longer list would be dropped
  // without a trace rather than encrypted into the transaction.
  if (encrypted.payload.length > prepared.outputs.length) {
    throw new TransactionError("TRANSACTION_EXCESS_OUTPUT_SLOTS", {
      got: encrypted.payload.length,
      outputs: prepared.outputs.length,
    });
  }
  // An owner who is also the fee payer is already account index 0, so the tag
  // costs 2 bytes instead of the 33 an inline owner needs.
  const senderResolved = prepared.owner.confidentialViewTag();
  const senderTag: OwnerTag = equal(senderResolved, decodeAddress(prepared.payer))
    ? { kind: "account", index: 0 }
    : { kind: "inline", value: senderResolved };

  const padTag = dummyOwnerTag(prepared.inputs, prepared.outputs, prepared.payer);
  const outputSeed = outputBlindingSeed(prepared.firstNullifier, prepared.blindingSeed);
  const padCount = Math.max(prepared.shape.outputs - prepared.outputs.length, 0);
  const outputUtxos = [
    ...prepared.outputs,
    ...Array.from({ length: padCount }, (_, offset) =>
      createProofOutput({
        asset: ZERO_ADDRESS,
        amount: 0n,
        blinding: transactOutputBlinding(
          prepared.firstNullifier,
          outputSeed,
          prepared.outputs.length + offset,
        ),
        ownerTag: padTag,
      }),
    ),
  ];
  // Every dummy is hashed under the input tree's id, both here for the
  // nullifier the client requests a non-inclusion witness for and in the
  // prover, which rehashes the slot under the single input tree.
  const inputUtxos = prepared.inputs.map((input) =>
    input.isDummy() && input.treeId !== prepared.inputTreeId
      ? input.withTreeId(prepared.inputTreeId)
      : input,
  );
  while (inputUtxos.length < prepared.shape.inputs) {
    inputUtxos.push(ProofInputUtxo.dummy(undefined, prepared.inputTreeId));
  }

  // Length-matched random ciphertext for every position without a real encoding:
  // padded slots and zero-value change slots.
  const needsDummyCiphertext =
    padCount > 0 || prepared.outputs.some((_, index) => encrypted.payload[index] === undefined);
  const dummyLength = needsDummyCiphertext ? dummyCiphertextLength(encrypted.salt) : 0;

  // 1:1 output assembly. Every published slot carries its own ciphertext.
  // Change positions keep the compact sender tag; recipient positions take
  // the inline tag of their ciphertext; padded and zero-value positions carry a
  // length-matched random ciphertext under the pad tag.
  const outputs: TransactOutput[] = [];
  const resolved: Bytes32[] = [];
  for (let index = 0; index < outputUtxos.length; index++) {
    const output = outputUtxos[index];
    if (!output) throw new TransactionError("TRANSACTION_MISSING_OUTPUT", { index });
    const slot = encrypted.payload[index];
    const utxoHash = output.hash(prepared.outputTreeId);
    if (output.isDummy()) {
      outputs.push({
        utxoHash,
        ownerTag: { kind: "inline", value: padTag },
        data: randomBytes(dummyLength),
      });
      resolved.push(padTag);
    } else if (index < prepared.senderOutputCount) {
      outputs.push({
        utxoHash,
        ownerTag: senderTag,
        data: slot?.data ?? randomBytes(dummyLength),
      });
      resolved.push(senderResolved);
    } else {
      const tag = slot?.viewTag ?? output.ownerTag;
      if (!tag) throw new TransactionError("TRANSACTION_MISSING_OUTPUT");
      outputs.push({
        utxoHash,
        ownerTag: { kind: "inline", value: tag },
        data: slot?.data ?? randomBytes(dummyLength),
      });
      resolved.push(tag);
    }
  }
  const externalData = createExternalData({
    instructionDiscriminator: encrypted.instructionDiscriminator ?? InstructionTag.transact,
    expiryUnixTs: 0xffff_ffff_ffff_ffffn,
    interfaceTransfers: prepared.interfaceTransfers,
    txViewingPublicKey: encrypted.txViewingPublicKey,
    salt: encrypted.salt,
    outputs,
    resolvedOwnerTags: resolved,
    messages: encrypted.messages ?? [],
  });
  return new SppProofInputs({
    payer: prepared.payer,
    inputUtxos,
    outputs: outputUtxos,
    externalData,
    blindingSeed: prepared.blindingSeed,
    outputTreeId: prepared.outputTreeId,
  });
}

function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

/**
 * Encode each real output as its own confidential ciphertext, keyed to that
 * output's owner viewing key, at `slotIndex == output position`. Dummy outputs
 * yield `undefined`; the transfer builder fills those positions with a
 * length-matched random ciphertext under the sender's tag.
 */
export function encodeConfidentialSlots(
  outputs: readonly ProofOutputUtxo[],
  assets: AssetRegistry,
  tx: ViewingKey,
  salt: Bytes16,
): readonly (Readonly<{ viewTag: Bytes32; data: Uint8Array }> | undefined)[] {
  return outputs.map((output, slotIndex) => {
    const address = output.ownerAddress;
    if (output.isDummy() || address === undefined) return undefined;
    return {
      viewTag: address.signingPublicKey.confidentialViewTag(),
      data: encodeOutputData(
        output.ringProgramId === undefined
          ? EncryptedScheme.confidential
          : EncryptedScheme.ringConfidential,
        encryptConfidential(
          tx,
          address.viewingPublicKey,
          {
            assetId: assets.assetId(output.asset),
            amount: output.amount,
            blinding: output.blinding,
            ...(output.ringProgramId === undefined ? {} : { ringProgramId: output.ringProgramId }),
            data: output.data,
          },
          salt,
          slotOrdinal(slotIndex),
        ),
        "encrypted",
      ),
    };
  });
}

/**
 * The exact ciphertext byte length of a real confidential slot, derived by
 * encoding a throwaway output through the same path. This keeps dummy slots
 * byte-length-indistinguishable from real ones without pinning a brittle constant.
 */
function dummyCiphertextLength(salt: Bytes16): number {
  const throwaway = ViewingKey.generate();
  try {
    return encodeOutputData(
      EncryptedScheme.confidential,
      encryptConfidential(
        throwaway,
        throwaway.publicKey(),
        { assetId: SOL_ASSET_ID, amount: 0n, blinding: randomBlinding(), data: new Data() },
        salt,
        0,
      ),
      "encrypted",
    ).length;
  } finally {
    throwaway.destroy();
  }
}

export interface OutputContext {
  readonly hash: Bytes32;
  readonly tree: Address;
  readonly leafIndex: bigint;
}

export interface OutputSlot {
  readonly viewTag: Bytes32;
  readonly outputContext: OutputContext;
  readonly payload: Uint8Array;
}

export interface IndexedShieldedTransaction {
  readonly slot: bigint;
  readonly txSignature: Signature;
  readonly txViewingPublicKey?: P256PublicKey;
  readonly salt?: Bytes16;
  readonly outputSlots: readonly OutputSlot[];
  readonly messages: readonly Readonly<{ viewTag: Bytes32; data: Uint8Array }>[];
  readonly nullifiers: readonly Bytes32[];
  readonly proofless: boolean;
}
