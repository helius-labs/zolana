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
import { P256PublicKey, SigningKey, type ShieldedAddress } from "@zolana/keypair";

import { TransactionError } from "../error.js";
import {
  ZERO_32,
  checkU64,
  checked,
  copy,
  decodeAddress,
  equal,
  hashChain,
  poseidon,
  random31,
  sha256Be,
  sha256Bytes,
} from "../internal.js";
import {
  ProofInputUtxo,
  createProofOutput,
  deriveBlinding,
  type ProofOutputUtxo,
} from "../utxo.js";

export type { Shape };
export const SPP_SUPPORTED_SHAPES = INTERFACE_SUPPORTED_SHAPES;

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
}

function externalDataHash(data: Omit<ExternalData, "hash">): Bytes32 {
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

export function createExternalData(input: Omit<ExternalData, "hash">): ExternalData {
  const snapshot = {
    ...input,
    salt: checked<Bytes16>(input.salt, 16, "salt"),
    outputs: input.outputs.map((output) =>
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
    resolvedOwnerTags: input.resolvedOwnerTags.map((tag) =>
      checked<Bytes32>(tag, 32, "resolved owner tag"),
    ),
    messages: input.messages.map((message) =>
      Object.freeze({
        viewTag: checked<Bytes32>(message.viewTag, 32, "message view tag"),
        data: new Uint8Array(message.data),
      }),
    ),
  };
  return Object.freeze({ ...snapshot, hash: (): Bytes32 => externalDataHash(snapshot) });
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
    this.checkShape();
  }

  checkShape(): Shape {
    const exact = SPP_SUPPORTED_SHAPES.find(
      (shape) => shape.inputs === this.inputUtxos.length && shape.outputs === this.outputs.length,
    );
    if (!exact) {
      throw new TransactionError("TRANSACTION_UNSUPPORTED_SHAPE", {
        inputs: this.inputUtxos.length,
        outputs: this.outputs.length,
      });
    }
    return Object.freeze({ ...exact });
  }

  publicAmounts(): PublicAmounts {
    return Object.freeze({
      ...(this.externalData.publicSolAmount === undefined
        ? {}
        : { sol: this.externalData.publicSolAmount }),
      ...(this.externalData.publicSplAmount === undefined
        ? {}
        : { spl: this.externalData.publicSplAmount }),
    });
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

  messageHash(): Bytes32 {
    const inputHashes = this.inputUtxos.map((input) =>
      input.isDummy() ? copy(ZERO_32) : input.hash(),
    );
    const outputHashes = this.outputs.map((output) =>
      output.isDummy() ? copy(ZERO_32) : output.hash(),
    );
    const privateHash = poseidon([
      hashChain(inputHashes),
      hashChain(outputHashes),
      hashChain(inputHashes.map(() => copy(ZERO_32))),
      this.externalData.hash(),
    ]);
    return sha256Bytes(privateHash);
  }

  applyP256Signature(signature: P256Signature): void {
    const real = this.inputUtxos.filter((input) => !input.isDummy());
    const p256 = real.filter((input) => input.utxo.owner.signatureType() === "p256");
    if (p256.length === 0) {
      throw new TransactionError("TRANSACTION_SIGNER_NOT_P256");
    }
    if (
      p256.some((input) => !equal(input.utxo.owner.confidentialViewTag(), signature.publicKey.x()))
    ) {
      throw new TransactionError("TRANSACTION_SIGNATURE_OWNER_MISMATCH");
    }
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

  constructor(owner: ShieldedAddress, inputs: readonly ProofInputUtxo[], payer: Address) {
    if (inputs.length === 0) throw new TransactionError("TRANSACTION_NO_INPUTS");
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
    this.#owner = owner;
    this.#inputs = [...inputs];
    this.#payerPublicKeyHash = sha256Be(decodeAddress(payer));
  }

  withShape(shape: Shape): this {
    this.#shape = resolveShape(this.#inputs.length, 2 + this.#recipients.length, shape);
    return this;
  }

  requiresP256Owner(): boolean {
    return this.#inputs.some(
      (input) => !input.isDummy() && input.utxo.owner.signatureType() === "p256",
    );
  }

  send(recipient: ShieldedAddress, asset: Address, amount: bigint): void {
    checkU64(amount, "recipient amount");
    if (amount === 0n) throw new TransactionError("TRANSACTION_INVALID_AMOUNT", { amount: "0" });
    this.#recipients.push({ address: recipient, asset, amount });
  }

  withdraw(asset: Address, amount: bigint, target: WithdrawalTarget): void {
    if (this.#withdrawal) throw new TransactionError("TRANSACTION_WITHDRAWAL_ALREADY_SET");
    checkU64(amount, "withdrawal amount");
    if (amount === 0n) throw new TransactionError("TRANSACTION_INVALID_AMOUNT", { amount: "0" });
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
          blinding: deriveBlinding(this.#blindingSeed, index + 2),
        }),
      ),
    ];
    const shape = resolveShape(this.#inputs.length, outputs.length, this.#shape);
    while (outputs.length < shape.outputs) {
      const signing = SigningKey.generate(this.#owner.signingPublicKey.signatureType());
      outputs.push(
        createProofOutput({
          asset: ZERO_ADDRESS,
          amount: 0n,
          ownerTag: signing.publicKey().confidentialViewTag(),
        }),
      );
    }
    const inputs = [...this.#inputs];
    while (inputs.length < shape.inputs) inputs.push(ProofInputUtxo.dummy());
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
  // Dummy slots match the default confidential envelope: 5 + 1 + 33 + 49.
  const dummyLength = 88;
  const outputs: TransactOutput[] = [];
  const resolved: Bytes32[] = [];
  for (let index = 0; index < prepared.outputs.length; index++) {
    const output = prepared.outputs[index];
    if (!output) throw new TransactionError("TRANSACTION_MISSING_OUTPUT", { index });
    const slot = encrypted.payload[index];
    if (index < 2) {
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
  const externalData = createExternalData({
    instructionDiscriminator: 0,
    expiryUnixTs: 0xffff_ffff_ffff_ffffn,
    relayerFee: 0,
    ...(prepared.publicSolAmount === undefined
      ? {}
      : { publicSolAmount: prepared.publicSolAmount }),
    ...(prepared.publicSplAmount === undefined
      ? {}
      : { publicSplAmount: prepared.publicSplAmount }),
    userSolAccount: prepared.userSolAccount,
    userSplToken: prepared.userSplToken,
    splTokenInterface: prepared.splTokenInterface,
    txViewingPublicKey: encrypted.txViewingPublicKey,
    salt: encrypted.salt,
    outputs,
    resolvedOwnerTags: resolved,
    messages: [],
  });
  return new SppProofInputs({
    payerPublicKeyHash: prepared.payerPublicKeyHash,
    inputUtxos: prepared.inputs,
    outputs: prepared.outputs,
    externalData,
  });
}

function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
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
