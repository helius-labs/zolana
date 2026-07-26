import {
  SPP_SUPPORTED_SHAPES as INTERFACE_SUPPORTED_SHAPES,
  externalDataHash as interfaceExternalDataHash,
  selectSppShape,
  validateSppShape,
  type Address,
  type Bytes16,
  type Bytes32,
  type OwnerTag,
  type Shape,
  type TransactOutput,
} from "@zolana/interface";
import {
  P256PublicKey,
  ShieldedKeypair,
  SigningKey,
  ViewingKey,
  randomSalt,
  type ShieldedAddress,
  type SignatureType,
} from "@zolana/keypair";

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
  hashField,
  poseidon,
  random31,
  sha256Be,
  sha256Bytes,
} from "../internal.js";
import { EncryptedScheme, encodeOutputData, encryptConfidential } from "../serialization/codecs.js";
import {
  ProofInputUtxo,
  Utxo,
  createProofOutput,
  deriveBlinding,
  type ProofOutputUtxo,
} from "../utxo.js";
import { SOL_ASSET_ID, SOL_MINT, type AssetRegistry } from "../wallet/asset.js";

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
  return hashField(decodeAddress(asset));
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

/**
 * The public leg as the three field elements a proof commits to. Rust hands
 * back the same encoding rather than the raw amounts, so every rail derives the
 * fields once here instead of each caller re-deriving them.
 */
export interface PublicAmounts {
  readonly sol: Bytes32;
  readonly spl: Bytes32;
  readonly asset: Bytes32;
}

export interface P256Signature {
  readonly publicKey: P256PublicKey;
  readonly r: Bytes32;
  readonly s: Bytes32;
}

export interface InputUtxoContext {
  readonly index: number;
  readonly utxoHash: Bytes32;
  readonly nullifier: Bytes32;
}

export interface ExternalData {
  readonly instructionDiscriminator: number;
  readonly expiryUnixTs: bigint;
  readonly relayerFee: number;
  readonly publicSolAmount?: bigint;
  readonly publicSplAmount?: bigint;
  readonly userSolAccount: Address;
  readonly userSplToken: Address;
  readonly splTokenInterface: Address;
  readonly dataHash?: Bytes32;
  readonly zoneDataHash?: Bytes32;
  readonly txViewingPublicKey: P256PublicKey;
  readonly salt: Bytes16;
  readonly outputs: readonly TransactOutput[];
  readonly resolvedOwnerTags: readonly Bytes32[];
  readonly messages: readonly Readonly<{ viewTag: Bytes32; data: Uint8Array }>[];
  hash(): Bytes32;
  /** Rust `ExternalData::with_public_sol`. A leg may be set once. */
  withPublicSol(amount: bigint, userSolAccount: Address): ExternalData;
  /** Rust `ExternalData::with_public_spl`. A leg may be set once. */
  withPublicSpl(amount: bigint, userSplToken: Address, splTokenInterface: Address): ExternalData;
  /** Rust `ExternalData::with_zone_hashes`. Both hashes are set together, once. */
  withZoneHashes(dataHash: Bytes32, zoneDataHash: Bytes32): ExternalData;
}

/**
 * What a caller must supply, the counterpart of Rust `ExternalData::new`. The
 * public legs, the zone hashes, the expiry, the relayer fee, and the three
 * accounts carry Rust's defaults, so a confidential transfer names only the
 * fields it actually has.
 */
export interface ExternalDataInit {
  readonly instructionDiscriminator?: number;
  readonly expiryUnixTs?: bigint;
  readonly relayerFee?: number;
  readonly publicSolAmount?: bigint;
  readonly publicSplAmount?: bigint;
  readonly userSolAccount?: Address;
  readonly userSplToken?: Address;
  readonly splTokenInterface?: Address;
  readonly dataHash?: Bytes32;
  readonly zoneDataHash?: Bytes32;
  readonly txViewingPublicKey: P256PublicKey;
  readonly salt: Bytes16;
  readonly outputs: readonly TransactOutput[];
  readonly resolvedOwnerTags: readonly Bytes32[];
  readonly messages: readonly Readonly<{ viewTag: Bytes32; data: Uint8Array }>[];
}

/** The `transact` tag, which Rust `ExternalData::new` takes from `tag::TRANSACT`. */
const TRANSACT_DISCRIMINATOR = 0;
/** Rust's default expiry: `u64::MAX`, meaning no expiry. */
const NO_EXPIRY = 0xffff_ffff_ffff_ffffn;
/** The all-zero address Rust defaults the three accounts to. */
const UNSET_ACCOUNT = "11111111111111111111111111111111" as Address;

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
  checkedInteger(BigInt(data.relayerFee), 2);
  checkedInteger(data.publicSolAmount ?? 0n, 8, true);
  checkedInteger(data.publicSplAmount ?? 0n, 8, true);
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
    relayerFee: data.relayerFee,
    ...(data.publicSolAmount === undefined ? {} : { publicSolAmount: data.publicSolAmount }),
    ...(data.publicSplAmount === undefined ? {} : { publicSplAmount: data.publicSplAmount }),
    userSolAccount: data.userSolAccount,
    userSplTokenAccount: data.userSplToken,
    splTokenInterface: data.splTokenInterface,
    ...(data.dataHash === undefined ? {} : { dataHash: data.dataHash }),
    ...(data.zoneDataHash === undefined ? {} : { zoneDataHash: data.zoneDataHash }),
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
  "hash" | "withPublicSol" | "withPublicSpl" | "withZoneHashes"
>;

export function createExternalData(input: ExternalDataInit): ExternalData {
  // Settlement accounts travel with their public amounts. Rust's Transfer
  // finalize only calls `with_public_sol` / `with_public_spl` when the amount is
  // `Some`, so a flat object that names a recipient without an amount must not
  // hash that recipient — the preimage keeps the unset defaults instead.
  const hasSol = input.publicSolAmount !== undefined;
  const hasSpl = input.publicSplAmount !== undefined;
  const snapshot: ExternalDataFields = {
    ...input,
    instructionDiscriminator: input.instructionDiscriminator ?? TRANSACT_DISCRIMINATOR,
    expiryUnixTs: input.expiryUnixTs ?? NO_EXPIRY,
    relayerFee: input.relayerFee ?? 0,
    userSolAccount: hasSol ? (input.userSolAccount ?? UNSET_ACCOUNT) : UNSET_ACCOUNT,
    userSplToken: hasSpl ? (input.userSplToken ?? UNSET_ACCOUNT) : UNSET_ACCOUNT,
    splTokenInterface: hasSpl ? (input.splTokenInterface ?? UNSET_ACCOUNT) : UNSET_ACCOUNT,
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
    withPublicSol: (amount: bigint, userSolAccount: Address): ExternalData => {
      if (fields.publicSolAmount !== undefined) {
        throw new TransactionError("TRANSACTION_PUBLIC_SOL_ALREADY_SET");
      }
      return set({ publicSolAmount: amount, userSolAccount });
    },
    withPublicSpl: (
      amount: bigint,
      userSplToken: Address,
      splTokenInterface: Address,
    ): ExternalData => {
      if (fields.publicSplAmount !== undefined) {
        throw new TransactionError("TRANSACTION_PUBLIC_SPL_ALREADY_SET");
      }
      return set({ publicSplAmount: amount, userSplToken, splTokenInterface });
    },
    withZoneHashes: (dataHash: Bytes32, zoneDataHash: Bytes32): ExternalData => {
      if (fields.dataHash !== undefined || fields.zoneDataHash !== undefined) {
        throw new TransactionError("TRANSACTION_ZONE_HASHES_ALREADY_SET");
      }
      return set({
        dataHash: checked<Bytes32>(dataHash, 32, "data hash"),
        zoneDataHash: checked<Bytes32>(zoneDataHash, 32, "zone data hash"),
      });
    },
  });
}

/**
 * A spent UTXO carrying the nullifier public key rather than the secret, for
 * callers that hash a transaction they cannot sign.
 */
export interface InputUtxo {
  readonly utxo: Utxo;
  readonly nullifierPublicKey: Bytes32;
  readonly zoneDataHash?: Bytes32;
  readonly dataHash?: Bytes32;
  hash(): Bytes32;
  isDummy(): boolean;
}

export function createInputUtxo(
  input: Readonly<{
    utxo: Utxo;
    nullifierPublicKey: Bytes32;
    zoneDataHash?: Bytes32;
    dataHash?: Bytes32;
  }>,
): InputUtxo {
  const nullifierPublicKey = checked<Bytes32>(input.nullifierPublicKey, 32, "nullifier public key");
  const utxo = new Utxo(input.utxo);
  return Object.freeze({
    ...input,
    utxo,
    nullifierPublicKey,
    hash(): Bytes32 {
      return utxo.hash(nullifierPublicKey, input.dataHash, input.zoneDataHash);
    },
    isDummy(): boolean {
      return utxo.owner.isZero();
    },
  });
}

export interface PrivateTxHashInput {
  readonly inputHashes: readonly Bytes32[];
  readonly outputHashes: readonly Bytes32[];
  /** One per input slot; omitted means a chain of zeros of the same length. */
  readonly addressHashes?: readonly Bytes32[];
  readonly externalDataHash: Bytes32;
}

/**
 * The circuit reads one address hash per input slot, so a set of a different
 * length would silently shift the address chain rather than fail.
 */
export function privateTxHash(input: PrivateTxHashInput): Bytes32 {
  if (
    input.addressHashes !== undefined &&
    input.addressHashes.length !== input.inputHashes.length
  ) {
    throw new TransactionError("TRANSACTION_ADDRESS_HASH_COUNT_MISMATCH", {
      expected: input.inputHashes.length,
      actual: input.addressHashes.length,
    });
  }
  const addressHashes = input.addressHashes ?? input.inputHashes.map(() => copy(ZERO_32));
  return poseidon([
    hashChain(input.inputHashes),
    hashChain(input.outputHashes),
    hashChain(addressHashes),
    input.externalDataHash,
  ]);
}

export interface EncryptedTransaction {
  readonly inputs: readonly InputUtxo[];
  readonly outputs: readonly ProofOutputUtxo[];
  readonly externalData: ExternalData;
  hash(): Bytes32;
}

export function createEncryptedTransaction(
  input: Readonly<{
    inputs: readonly InputUtxo[];
    outputs: readonly ProofOutputUtxo[];
    externalData: ExternalData;
  }>,
): EncryptedTransaction {
  const inputs = Object.freeze([...input.inputs]);
  const outputs = Object.freeze([...input.outputs]);
  return Object.freeze({
    ...input,
    inputs,
    outputs,
    // An unused slot contributes a zero hash, matching the circuit and
    // `SppProofInputs.messageHash`.
    hash(): Bytes32 {
      return privateTxHash({
        inputHashes: inputs.map((entry) => (entry.isDummy() ? copy(ZERO_32) : entry.hash())),
        outputHashes: outputs.map((entry) => (entry.isDummy() ? copy(ZERO_32) : entry.hash())),
        externalDataHash: input.externalData.hash(),
      });
    },
  });
}

export class SppProofInputs {
  readonly payerPublicKeyHash: Bytes32;
  readonly inputUtxos: readonly ProofInputUtxo[];
  readonly outputs: readonly ProofOutputUtxo[];
  readonly externalData: ExternalData;
  #p256Signature?: P256Signature;

  constructor(
    input: Readonly<{
      payerPublicKeyHash: Bytes32;
      inputUtxos: readonly ProofInputUtxo[];
      outputs: readonly ProofOutputUtxo[];
      externalData: ExternalData;
    }>,
  ) {
    this.payerPublicKeyHash = checked<Bytes32>(
      input.payerPublicKeyHash,
      32,
      "payer public key hash",
    );
    this.inputUtxos = Object.freeze([...input.inputUtxos]);
    this.outputs = Object.freeze([...input.outputs]);
    this.externalData = input.externalData;
  }

  /**
   * Deliberate, never implicit: a caller assembling a proof asks for the shape,
   * and one that only wants the message hash builds and hashes an unsupported
   * shape without complaint. Construction validating this would refuse inputs
   * Rust accepts.
   */
  checkShape(): Shape {
    return exactShape(this.inputUtxos.length, this.outputs.length);
  }

  publicAmounts(): PublicAmounts {
    const spl = this.externalData.publicSplAmount ?? 0n;
    return Object.freeze({
      sol: signedToField(this.externalData.publicSolAmount ?? 0n),
      spl: signedToField(spl),
      asset: spl === 0n ? copy(ZERO_32) : assetField(this.#publicSplAsset()),
    });
  }

  /**
   * The mint the public SPL leg settles in, read off the notes rather than
   * named by the caller: the circuit binds the asset field to the UTXOs, so a
   * leg over notes of two mints, or over none, has no asset to commit to.
   */
  #publicSplAsset(): Address {
    let found: Address | undefined;
    const assets = [
      ...this.inputUtxos.map((input) => input.utxo.asset),
      ...this.outputs.map((output) => output.asset),
    ];
    for (const asset of assets) {
      if (asset === SOL_MINT) continue;
      if (found !== undefined && found !== asset) {
        throw new TransactionError("TRANSACTION_MULTIPLE_PUBLIC_SPL_ASSETS");
      }
      found = asset;
    }
    if (found === undefined) {
      throw new TransactionError("TRANSACTION_MISSING_PUBLIC_SPL_ASSET");
    }
    return found;
  }

  /**
   * The real inputs' commitments and nullifiers, indexed over the real inputs
   * alone so a padded slot does not shift the index a Merkle proof is fetched
   * against. A dummy cannot reach this point non-canonical: `ProofInputUtxo`
   * copies its fields and refuses one at construction, where Rust's public
   * struct has to re-check each slot here.
   */
  inputUtxoHashes(): readonly InputUtxoContext[] {
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

  messageHash(): Bytes32 {
    const inputHashes = this.inputUtxos.map((input) =>
      input.isDummy() ? copy(ZERO_32) : input.hash(),
    );
    const outputHashes = this.outputs.map((output) =>
      output.isDummy() ? copy(ZERO_32) : output.hash(),
    );
    return sha256Bytes(
      privateTxHash({
        inputHashes,
        outputHashes,
        externalDataHash: this.externalData.hash(),
      }),
    );
  }

  /**
   * The keypair's own rail decides whether it may sign, not the inputs it is
   * signing over: an owner-signature mismatch is the circuit's to catch, and
   * refusing one here would reject transactions the prover and the chain
   * accept.
   */
  signP256(keypair: ShieldedKeypair): void {
    if (keypair.signingPublicKey().signatureType() !== "p256") {
      throw new TransactionError("TRANSACTION_SIGNER_NOT_P256");
    }
    this.applyP256Signature(keypair.signP256(this.messageHash()));
  }

  /** The remote-authority half of `signP256`: a signature produced elsewhere. */
  applyP256Signature(signature: P256Signature): void {
    this.#p256Signature = Object.freeze({
      publicKey: signature.publicKey,
      r: checked<Bytes32>(signature.r, 32, "signature r"),
      s: checked<Bytes32>(signature.s, 32, "signature s"),
    });
  }

  p256Signature(): P256Signature | undefined {
    return this.#p256Signature;
  }
}

export type WithdrawalTarget =
  | Readonly<{ kind: "sol"; recipient: Address }>
  | Readonly<{
      kind: "spl";
      userTokenAccount: Address;
      splTokenInterface: Address;
    }>;

export interface PreparedTransfer {
  readonly owner: ShieldedAddress;
  readonly inputs: readonly ProofInputUtxo[];
  readonly outputs: readonly ProofOutputUtxo[];
  readonly firstNullifier: Bytes32;
  readonly shape: Shape;
  readonly payerPublicKeyHash: Bytes32;
  readonly publicSolAmount?: bigint;
  readonly publicSplAmount?: bigint;
  readonly userSolAccount: Address;
  readonly userSplToken: Address;
  readonly splTokenInterface: Address;
  finalize(
    input: Readonly<{
      txViewingPublicKey: P256PublicKey;
      salt: Bytes16;
      payload: readonly (Readonly<{ viewTag: Bytes32; data: Uint8Array }> | undefined)[];
    }>,
  ): SppProofInputs;
}

interface Recipient {
  readonly address: ShieldedAddress;
  readonly asset: Address;
  readonly amount: bigint;
}

const ZERO_ADDRESS = "11111111111111111111111111111111" as Address;

export class ConfidentialTransfer {
  readonly #owner: ShieldedAddress;
  readonly #inputs: readonly ProofInputUtxo[];
  readonly #payerPublicKeyHash: Bytes32;
  readonly #recipients: Recipient[] = [];
  readonly #blindingSeed = random31();
  #withdrawal?: Readonly<{ asset: Address; amount: bigint; target: WithdrawalTarget }>;
  #shape?: Shape;

  // Rust `ConfidentialTransfer::new` stores the fields and returns; empty,
  // dummy, and foreign-owned inputs are refused later or not at all.
  constructor(owner: ShieldedAddress, inputs: readonly ProofInputUtxo[], payer: Address) {
    this.#owner = owner;
    this.#inputs = [...inputs];
    this.#payerPublicKeyHash = sha256Be(decodeAddress(payer));
  }

  withShape(shape: Shape): this {
    this.#shape = resolveShape(
      this.#inputs.length,
      SENDER_SLOT_COUNT + this.#recipients.length,
      shape,
    );
    return this;
  }

  requiresP256Owner(): boolean {
    return this.#inputs.some(
      (input) => !input.isDummy() && input.utxo.owner.signatureType() === "p256",
    );
  }

  // Rust `send` performs no amount check; `checkU64` stands in for its `u64`
  // parameter and nothing more. A zero-amount recipient is a slot Rust builds.
  send(recipient: ShieldedAddress, asset: Address, amount: bigint): void {
    checkU64(amount, "recipient amount");
    this.#recipients.push({ address: recipient, asset, amount });
  }

  withdraw(asset: Address, amount: bigint, target: WithdrawalTarget): void {
    if (this.#withdrawal) throw new TransactionError("TRANSACTION_WITHDRAWAL_ALREADY_SET");
    checkU64(amount, "withdrawal amount");
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
    const outputs: ProofOutputUtxo[] = [
      splAsset && change(splAsset, publicSpl) > 0n
        ? createProofOutput({
            ownerAddress: this.#owner,
            asset: splAsset,
            amount: change(splAsset, publicSpl),
            blinding: deriveBlinding(this.#blindingSeed, 0),
          })
        : createProofOutput({
            asset: ZERO_ADDRESS,
            amount: 0n,
            blinding: deriveBlinding(this.#blindingSeed, 0),
            ownerTag: this.#owner.confidentialViewTag(),
          }),
      change(ZERO_ADDRESS, publicSol) > 0n
        ? createProofOutput({
            ownerAddress: this.#owner,
            asset: ZERO_ADDRESS,
            amount: change(ZERO_ADDRESS, publicSol),
            blinding: deriveBlinding(this.#blindingSeed, 1),
          })
        : createProofOutput({
            asset: ZERO_ADDRESS,
            amount: 0n,
            blinding: deriveBlinding(this.#blindingSeed, 1),
            ownerTag: this.#owner.confidentialViewTag(),
          }),
      ...this.#recipients.map((recipient, index) =>
        createProofOutput({
          ownerAddress: recipient.address,
          asset: recipient.asset,
          amount: recipient.amount,
          blinding: deriveBlinding(this.#blindingSeed, index + SENDER_SLOT_COUNT),
        }),
      ),
    ];
    const shape = resolveShape(this.#inputs.length, outputs.length, this.#shape);
    // Padding belongs to `finalize`, where Rust does it: the slots handed to an
    // authority for encryption are the real outputs only.
    const inputs = [...this.#inputs];
    const target = this.#withdrawal?.target;
    const firstInput = this.#inputs[0];
    if (!firstInput) throw new TransactionError("TRANSACTION_NO_INPUTS");
    const preparedBase = {
      owner: this.#owner,
      inputs: Object.freeze(inputs),
      outputs: Object.freeze(outputs),
      firstNullifier: firstInput.nullifier(),
      shape,
      payerPublicKeyHash: copy(this.#payerPublicKeyHash),
      ...(publicSol === 0n ? {} : { publicSolAmount: publicSol }),
      ...(publicSpl === 0n ? {} : { publicSplAmount: publicSpl }),
      userSolAccount: target?.kind === "sol" ? target.recipient : ZERO_ADDRESS,
      userSplToken: target?.kind === "spl" ? target.userTokenAccount : ZERO_ADDRESS,
      splTokenInterface: target?.kind === "spl" ? target.splTokenInterface : ZERO_ADDRESS,
    };
    return Object.freeze({
      ...preparedBase,
      finalize: (encrypted: Parameters<PreparedTransfer["finalize"]>[0]): SppProofInputs =>
        finalizeTransfer(preparedBase, encrypted),
    });
  }

  /**
   * Keypair rail: encrypt every real slot with the owner's own viewing key and
   * sign in place. The authority rail is `prepare` plus `PreparedTransfer.finalize`,
   * with encryption and signing delegated to a `WalletAuthority`.
   */
  sign(keypair: ShieldedKeypair, assets: AssetRegistry): SppProofInputs {
    const prepared = this.prepare();
    const tx = keypair.transactionViewingKey(prepared.firstNullifier);
    const salt = randomSalt();
    const signed = prepared.finalize({
      txViewingPublicKey: tx.publicKey(),
      salt,
      payload: encodeConfidentialSlots(prepared.outputs, assets, tx, salt),
    });
    if (keypair.signingPublicKey().signatureType() === "p256") {
      signed.signP256(keypair);
    }
    return signed;
  }
}

function finalizeTransfer(
  prepared: Omit<PreparedTransfer, "finalize">,
  encrypted: Readonly<{
    txViewingPublicKey: P256PublicKey;
    salt: Bytes16;
    payload: readonly (Readonly<{ viewTag: Bytes32; data: Uint8Array }> | undefined)[];
  }>,
): SppProofInputs {
  // Slots are read by output position, so a longer list would be dropped
  // without a trace rather than encrypted into the transaction.
  if (encrypted.payload.length > prepared.outputs.length) {
    throw new TransactionError("TRANSACTION_EXCESS_OUTPUT_SLOTS", {
      got: encrypted.payload.length,
      outputs: prepared.outputs.length,
    });
  }
  const senderResolved = prepared.owner.confidentialViewTag();
  const senderTag: OwnerTag =
    prepared.owner.signingPublicKey.signatureType() === "p256"
      ? { kind: "p256SigningKey" }
      : equal(sha256Be(senderResolved), prepared.payerPublicKeyHash)
        ? { kind: "account", index: 0 }
        : { kind: "inline", value: senderResolved };

  // Each padded slot gets one throwaway-key view tag, shared between its dummy
  // output and its dummy ciphertext. The tag's rail is sampled from this
  // transaction's real recipients so a curve-membership test on the published
  // tag cannot single out a dummy. Real recipients occupy the slots past the two
  // sender change positions.
  const recipientRails = prepared.outputs
    .slice(SENDER_SLOT_COUNT)
    .flatMap((output) =>
      output.ownerAddress ? [output.ownerAddress.signingPublicKey.signatureType()] : [],
    );
  const senderRail = prepared.owner.signingPublicKey.signatureType();
  const padCount = Math.max(prepared.shape.outputs - prepared.outputs.length, 0);
  const outputUtxos = [
    ...prepared.outputs,
    ...Array.from({ length: padCount }, () =>
      createProofOutput({
        asset: ZERO_ADDRESS,
        amount: 0n,
        ownerTag: dummyViewTag(dummyRail(recipientRails, senderRail)),
      }),
    ),
  ];
  const inputUtxos = [...prepared.inputs];
  while (inputUtxos.length < prepared.shape.inputs) inputUtxos.push(ProofInputUtxo.dummy());

  // Length-matched random ciphertext for every position without a real encoding:
  // padded slots and zero-value change slots.
  const needsDummyCiphertext =
    padCount > 0 || prepared.outputs.some((_, index) => encrypted.payload[index] === undefined);
  const dummyLength = needsDummyCiphertext ? dummyCiphertextLength(encrypted.salt) : 0;

  const outputs: TransactOutput[] = [];
  const resolved: Bytes32[] = [];
  for (let index = 0; index < outputUtxos.length; index++) {
    const output = outputUtxos[index];
    if (!output) throw new TransactionError("TRANSACTION_MISSING_OUTPUT", { index });
    const slot = encrypted.payload[index];
    if (index < SENDER_SLOT_COUNT) {
      outputs.push({
        utxoHash: output.hash(),
        ownerTag: senderTag,
        data: slot?.data ?? randomBytes(dummyLength),
      });
      resolved.push(senderResolved);
    } else {
      const tag = slot?.viewTag ?? output.ownerTag;
      if (!tag) throw new TransactionError("TRANSACTION_MISSING_OUTPUT");
      outputs.push({
        utxoHash: output.hash(),
        ownerTag: { kind: "inline", value: tag },
        data: slot?.data ?? randomBytes(dummyLength),
      });
      resolved.push(tag);
    }
  }
  // Same gating as Rust `PreparedTransfer::finalize`: start from `ExternalData::new`
  // defaults, then bind each settlement leg only when its public amount is set.
  let externalData = createExternalData({
    instructionDiscriminator: 0,
    expiryUnixTs: 0xffff_ffff_ffff_ffffn,
    relayerFee: 0,
    txViewingPublicKey: encrypted.txViewingPublicKey,
    salt: encrypted.salt,
    outputs,
    resolvedOwnerTags: resolved,
    messages: [],
  });
  if (prepared.publicSolAmount !== undefined) {
    externalData = externalData.withPublicSol(
      prepared.publicSolAmount,
      prepared.userSolAccount,
    );
  }
  if (prepared.publicSplAmount !== undefined) {
    externalData = externalData.withPublicSpl(
      prepared.publicSplAmount,
      prepared.userSplToken,
      prepared.splTokenInterface,
    );
  }
  return new SppProofInputs({
    payerPublicKeyHash: prepared.payerPublicKeyHash,
    inputUtxos,
    outputs: outputUtxos,
    externalData,
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
 * length-matched random ciphertext under the padded tag.
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
        EncryptedScheme.confidential,
        encryptConfidential(
          tx,
          address.viewingPublicKey,
          {
            assetId: assets.assetId(output.asset),
            amount: output.amount,
            blinding: output.blinding,
            ...(output.zoneProgramId === undefined ? {} : { zoneProgramId: output.zoneProgramId }),
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

function dummyViewTag(rail: SignatureType): Bytes32 {
  return SigningKey.generate(rail).publicKey().confidentialViewTag();
}

/**
 * The rail for a padded slot's dummy tag: a random draw from this transaction's
 * real recipient rails, so each dummy is distributed identically to a real
 * recipient. With no real recipients (a change-only transfer) there is no
 * distribution to match, so the dummy takes the sender's rail -- the only identity
 * in play. Drawing a rail the recipients do not use would let an observer flag the
 * off-distribution slots as dummies and recover the recipient count.
 */
function dummyRail(
  recipientRails: readonly SignatureType[],
  senderRail: SignatureType,
): SignatureType {
  if (recipientRails.length === 0) return senderRail;
  return recipientRails[randomIndex(recipientRails.length)] ?? senderRail;
}

/** A uniform index below `bound`, rejection-sampled so no value is favoured. */
function randomIndex(bound: number): number {
  const limit = Math.floor(0x1_0000_0000 / bound) * bound;
  const draw = new Uint32Array(1);
  do {
    globalThis.crypto.getRandomValues(draw);
  } while ((draw[0] ?? 0) >= limit);
  return (draw[0] ?? 0) % bound;
}

/**
 * The exact ciphertext byte length of a real confidential slot, derived by
 * encoding a throwaway output through the same path. This keeps dummy slots
 * byte-length-indistinguishable from real ones without pinning a brittle constant.
 */
function dummyCiphertextLength(salt: Bytes16): number {
  const throwaway = ViewingKey.generate();
  return encodeOutputData(
    EncryptedScheme.confidential,
    encryptConfidential(
      throwaway,
      throwaway.publicKey(),
      { assetId: SOL_ASSET_ID, amount: 0n, blinding: random31(), data: new Data() },
      salt,
      0,
    ),
    "encrypted",
  ).length;
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
  readonly txSignature: string;
  readonly txViewingPublicKey?: P256PublicKey;
  readonly salt?: Bytes16;
  readonly outputSlots: readonly OutputSlot[];
  readonly messages: readonly Readonly<{ viewTag: Bytes32; data: Uint8Array }>[];
  readonly nullifiers: readonly Bytes32[];
  readonly proofless: boolean;
}
