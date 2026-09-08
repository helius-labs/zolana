import type { Address, Bytes16, Bytes32 } from "../../interface/types.js";
import { randomBlinding, randomSalt } from "../../keypair/bytes.js";
import { mergeDummyNullifier, mergeOutputBlinding } from "../../keypair/merge/index.js";
import type { P256PublicKey, ShieldedPublicKey } from "../../keypair/public-key.js";
import type { ShieldedAddress, ShieldedKeypair } from "../../keypair/shielded.js";

import { Data } from "../data.js";
import { MERGE_INPUT_COUNT } from "../../interface/constants.js";
import { TransactionError } from "../error.js";
import { checked, equal } from "../internal.js";
import { encodeSplitBundle, encryptSplit } from "../serialization/codecs.js";
import {
  ProofInputUtxo,
  createProofOutput,
  deriveBlinding,
  type ProofOutputUtxo,
} from "../utxo.js";
import { type AssetRegistry } from "../asset.js";
import { SppProofInputs, createExternalData, type InputUtxoContext } from "./transact.js";

/** Padded input count of the merge circuit, the counterpart of Rust `MERGE_INPUTS`. */
export const MERGE_INPUTS = MERGE_INPUT_COUNT;
const U64_MAX = 0xffff_ffff_ffff_ffffn;

function checkedU64(value: bigint, field: string): bigint {
  if (typeof value !== "bigint" || value < 0n || value > U64_MAX) {
    throw new TransactionError("TRANSACTION_INVALID_AMOUNT", {
      field,
      value: String(value),
    });
  }
  return value;
}

export class PreparedMerge {
  readonly inputs: readonly ProofInputUtxo[];
  readonly output: ProofOutputUtxo;
  readonly expiryUnixTs: bigint;
  readonly signingPublicKey: ShieldedPublicKey;
  readonly nullifierPublicKey: Bytes32;
  readonly #dummyNullifiers: readonly Bytes32[];

  constructor(
    input: Readonly<{
      inputs: readonly ProofInputUtxo[];
      output: ProofOutputUtxo;
      expiryUnixTs: bigint;
      signingPublicKey: ShieldedPublicKey;
      nullifierPublicKey: Bytes32;
      /** One per padded slot, in slot order: `mergeDummyNullifier(firstNullifier, slot)`. */
      dummyNullifiers: readonly Bytes32[];
    }>,
  ) {
    if (input.inputs.length !== MERGE_INPUTS) {
      throw new TransactionError("TRANSACTION_INVALID_OUTPUT_COUNT", {
        expected: MERGE_INPUTS,
        actual: input.inputs.length,
      });
    }
    let sawDummy = false;
    let dummies = 0;
    input.inputs.forEach((spend, index) => {
      if (spend.isDummy()) {
        sawDummy = true;
        dummies++;
      } else if (sawDummy) {
        throw new TransactionError("TRANSACTION_DUMMY_INPUT_NOT_ALLOWED", { index });
      }
    });
    if (input.dummyNullifiers.length !== dummies) {
      throw new TransactionError("TRANSACTION_INVALID_LENGTH", {
        field: "dummyNullifiers",
        expected: dummies,
        actual: input.dummyNullifiers.length,
      });
    }
    this.inputs = Object.freeze([...input.inputs]);
    this.output = input.output;
    this.expiryUnixTs = checkedU64(input.expiryUnixTs, "expiryUnixTs");
    this.signingPublicKey = input.signingPublicKey;
    this.nullifierPublicKey = checked<Bytes32>(
      input.nullifierPublicKey,
      32,
      "nullifier public key",
    );
    this.#dummyNullifiers = Object.freeze(
      input.dummyNullifiers.map((nullifier, index) =>
        checked<Bytes32>(nullifier, 32, `dummy nullifier ${String(index)}`),
      ),
    );
  }

  inputUtxoHashes(): readonly InputUtxoContext[] {
    return realInputContexts(this.inputs, hasData);
  }

  dummyNullifiers(): readonly Bytes32[] {
    return this.#dummyNullifiers;
  }

  /** The slots the padding fills, in order; what `dummyNullifiers` was derived for. */
  static dummySlots(realInputs: number): readonly number[] {
    return Array.from({ length: MERGE_INPUTS - realInputs }, (_, offset) => realInputs + offset);
  }
}

/** An input carrying program or ring data, which the plain merge rail never consolidates. */
function hasData(input: ProofInputUtxo): boolean {
  return (
    input.dataHash !== undefined || input.ringDataHash !== undefined || !input.utxo.data.isEmpty()
  );
}

/**
 * Commitments for the real inputs only. The rail's data policy is re-checked here
 * because the prepared value is publicly constructible, so the builder's check is
 * not the only way in.
 */
function realInputContexts(
  inputs: readonly ProofInputUtxo[],
  disqualifying: (input: ProofInputUtxo) => boolean,
): readonly InputUtxoContext[] {
  return inputs
    .filter((input) => !input.isDummy())
    .map((input, index) => {
      if (disqualifying(input)) {
        throw new TransactionError("TRANSACTION_MERGE_INPUT_HAS_DATA", { index });
      }
      return Object.freeze({
        index,
        utxoHash: input.hash(),
        nullifier: input.nullifier(),
      });
    });
}

/**
 * Consolidates up to `MERGE_INPUTS` plain UTXOs of one owner and asset into one.
 * The output blinding and the padded slots' nullifiers derive from the
 * nullifier secret; the builder receives them derived (`ShieldedKeys.derive`,
 * or `fromKeypair` for keys held in-process).
 */
export class Merge {
  #prepared: PreparedMerge;

  constructor(
    input: Readonly<{
      address: ShieldedAddress;
      inputs: readonly ProofInputUtxo[];
      /** `mergeOutputBlinding(firstNullifier)`. */
      outputBlinding: Bytes32;
      /** `mergeDummyNullifier(firstNullifier, slot)` for each of `PreparedMerge.dummySlots(inputs.length)`. */
      dummyNullifiers: readonly Bytes32[];
    }>,
  ) {
    const inputs = input.inputs;
    if (inputs.length === 0) throw new TransactionError("TRANSACTION_NO_INPUTS");
    if (inputs.length > MERGE_INPUTS) {
      throw new TransactionError("TRANSACTION_TOO_MANY_INPUTS", {
        got: inputs.length,
        max: MERGE_INPUTS,
      });
    }
    const address = input.address;
    const owner = address.signingPublicKey;
    const firstInput = inputs[0];
    if (!firstInput) throw new TransactionError("TRANSACTION_NO_INPUTS");
    const asset = firstInput.utxo.asset;
    let amount = 0n;
    inputs.forEach((spend, index) => {
      if (spend.utxo.owner.signatureType() !== owner.signatureType()) {
        throw new TransactionError("TRANSACTION_MERGE_INPUT_RAIL_MISMATCH", { index });
      }
      if (!equal(spend.utxo.owner.toBytes(), owner.toBytes())) {
        throw new TransactionError("TRANSACTION_MERGE_INPUT_OWNER_MISMATCH", { index });
      }
      if (!equal(spend.nullifierPublicKey, address.nullifierPublicKey)) {
        throw new TransactionError("TRANSACTION_MERGE_INPUT_NULLIFIER_KEY_MISMATCH", { index });
      }
      if (spend.utxo.asset !== asset) {
        throw new TransactionError("TRANSACTION_MERGE_INPUT_ASSET_MISMATCH", { index });
      }
      if (spend.utxo.ringProgramId !== undefined) {
        throw new TransactionError("TRANSACTION_MERGE_INPUT_RING_MISMATCH", { index });
      }
      if (!spend.utxo.data.isEmpty() || spend.dataHash || spend.ringDataHash) {
        throw new TransactionError("TRANSACTION_MERGE_INPUT_HAS_DATA", { index });
      }
      amount += spend.utxo.amount;
      if (amount > 0xffff_ffff_ffff_ffffn) {
        throw new TransactionError("TRANSACTION_SELECTED_BALANCE_OVERFLOW");
      }
    });
    const padded = [...inputs];
    while (padded.length < MERGE_INPUTS) padded.push(ProofInputUtxo.dummy());
    this.#prepared = new PreparedMerge({
      inputs: padded,
      output: createProofOutput({
        ownerAddress: address,
        asset,
        amount,
        blinding: checked<Bytes32>(input.outputBlinding, 32, "merge output blinding"),
      }),
      expiryUnixTs: 0xffff_ffff_ffff_ffffn,
      signingPublicKey: owner,
      nullifierPublicKey: address.nullifierPublicKey,
      dummyNullifiers: input.dummyNullifiers,
    });
  }

  /** Keypair rail: derives the blinding and padded nullifiers here; the key never leaves this call. */
  static fromKeypair(keypair: ShieldedKeypair, inputs: readonly ProofInputUtxo[]): Merge {
    const first = inputs[0];
    if (!first) throw new TransactionError("TRANSACTION_NO_INPUTS");
    const firstNullifier = first.nullifier();
    const nullifierKey = keypair.nullifierKey();
    try {
      return new Merge({
        address: keypair.shieldedAddress(),
        inputs,
        outputBlinding: mergeOutputBlinding(nullifierKey, firstNullifier),
        dummyNullifiers: PreparedMerge.dummySlots(inputs.length).map((slot) =>
          mergeDummyNullifier(nullifierKey, firstNullifier, slot),
        ),
      });
    } finally {
      nullifierKey.destroy();
    }
  }

  prepare(): PreparedMerge {
    return this.#prepared;
  }

  withExpiry(expiryUnixTs: bigint): this {
    this.#prepared = new PreparedMerge({
      inputs: this.#prepared.inputs,
      output: this.#prepared.output,
      expiryUnixTs: checkedU64(expiryUnixTs, "expiryUnixTs"),
      signingPublicKey: this.#prepared.signingPublicKey,
      nullifierPublicKey: this.#prepared.nullifierPublicKey,
      dummyNullifiers: this.#prepared.dummyNullifiers(),
    });
    return this;
  }
}

export class ConfidentialSplit {
  readonly #owner: ShieldedAddress;
  readonly #input: ProofInputUtxo;
  readonly #asset: Address;
  readonly #numOutputs: number;
  readonly #perOutputAmount: bigint;
  readonly #payer: Address;
  readonly #seed = randomBlinding();

  constructor(
    input: Readonly<{
      owner: ShieldedAddress;
      input: ProofInputUtxo;
      asset: Address;
      numOutputs: number;
      perOutputAmount: bigint;
      payer: Address;
    }>,
  ) {
    if (!Number.isInteger(input.numOutputs) || input.numOutputs < 2 || input.numOutputs > 8) {
      throw new TransactionError("TRANSACTION_SPLIT_INVALID_PART_COUNT", {
        numOutputs: input.numOutputs,
      });
    }
    if (input.owner.signingPublicKey.signatureType() === "p256") {
      throw new TransactionError("TRANSACTION_P256_TRANSACT_UNSUPPORTED");
    }
    // The builders collect no signature but the payer's, a UTXO owned by
    // anyone else cannot be authorized here.
    if (input.owner.solanaAddress() !== input.payer) {
      throw new TransactionError("TRANSACTION_ED25519_PAYER_MISMATCH", {
        owner: input.owner.solanaAddress(),
        payer: input.payer,
      });
    }
    // Ownership is proven from the nullifier secret behind `ownerHash`, so an
    // input the splitter cannot open is unprovable. A zero-owner slot has no
    // openable owner hash at all.
    if (input.input.isDummy()) {
      throw new TransactionError("TRANSACTION_SPLIT_INPUT_IS_DUMMY");
    }
    if (!equal(input.input.utxo.owner.toBytes(), input.owner.signingPublicKey.toBytes())) {
      throw new TransactionError("TRANSACTION_SPLIT_INPUT_OWNER_MISMATCH");
    }
    if (!equal(input.input.nullifierPublicKey, input.owner.nullifierPublicKey)) {
      throw new TransactionError("TRANSACTION_SPLIT_INPUT_NULLIFIER_KEY_MISMATCH");
    }
    if (input.input.utxo.asset !== input.asset) {
      throw new TransactionError("TRANSACTION_SPLIT_INPUT_ASSET_MISMATCH");
    }
    if (input.input.utxo.ringProgramId !== undefined) {
      throw new TransactionError("TRANSACTION_SPLIT_INPUT_RING_MISMATCH");
    }
    if (
      input.input.dataHash !== undefined ||
      input.input.ringDataHash !== undefined ||
      !input.input.utxo.data.isEmpty()
    ) {
      throw new TransactionError("TRANSACTION_SPLIT_INPUT_HAS_DATA");
    }
    const perOutputAmount = checkedU64(input.perOutputAmount, "perOutputAmount");
    if (perOutputAmount * BigInt(input.numOutputs) !== input.input.utxo.amount) {
      throw new TransactionError("TRANSACTION_SPLIT_AMOUNT_MISMATCH", {
        input: input.input.utxo.amount.toString(),
        numOutputs: input.numOutputs,
        perOutput: perOutputAmount.toString(),
      });
    }
    this.#owner = input.owner;
    this.#input = input.input;
    this.#asset = input.asset;
    this.#numOutputs = input.numOutputs;
    this.#perOutputAmount = perOutputAmount;
    this.#payer = input.payer;
  }

  prepare(): PreparedSplit {
    const outputs = Array.from({ length: 8 }, (_, index) =>
      createProofOutput({
        ownerAddress: this.#owner,
        asset: this.#asset,
        amount: index < this.#numOutputs ? this.#perOutputAmount : 0n,
        blinding: deriveBlinding(this.#seed, index),
      }),
    );
    return new PreparedSplit({
      owner: this.#owner,
      input: this.#input,
      outputs,
      numOutputs: this.#numOutputs,
      perOutputAmount: this.#perOutputAmount,
      blindingSeed: this.#seed,
      payer: this.#payer,
    });
  }

  /**
   * Keypair shortcut: seal the bundle at slot 0 under the owner's own viewing
   * key in one step. The keys rail is `prepare`, `encryptSplit` over the key
   * `ShieldedKeys.transactionKeys` returns, then `PreparedSplit.finalize`.
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
        payload: {
          viewTag: prepared.ownerViewTag(),
          data: encryptSplit(
            tx,
            prepared.owner.viewingPublicKey,
            encodeSplitBundle(prepared.bundlePlaintext(assets)),
            salt,
            0,
          ),
        },
      });
    } finally {
      tx.destroy();
      viewingKey.destroy();
    }
  }
}

export class PreparedSplit {
  readonly owner: ShieldedAddress;
  readonly input: ProofInputUtxo;
  readonly asset: Address;
  readonly outputs: readonly ProofOutputUtxo[];
  readonly firstNullifier: Bytes32;
  readonly numOutputs: number;
  readonly perOutputAmount: bigint;
  readonly blindingSeed: Bytes32;
  readonly payer: Address;

  constructor(
    input: Readonly<{
      owner: ShieldedAddress;
      input: ProofInputUtxo;
      outputs: readonly ProofOutputUtxo[];
      numOutputs: number;
      perOutputAmount: bigint;
      blindingSeed: Bytes32;
      payer: Address;
    }>,
  ) {
    if (!Number.isInteger(input.numOutputs) || input.numOutputs < 2 || input.numOutputs > 8) {
      throw new TransactionError("TRANSACTION_SPLIT_INVALID_PART_COUNT", {
        numOutputs: input.numOutputs,
      });
    }
    if (input.outputs.length !== 8) {
      throw new TransactionError("TRANSACTION_INVALID_OUTPUT_COUNT", {
        expected: 8,
        actual: input.outputs.length,
      });
    }
    const perOutputAmount = checkedU64(input.perOutputAmount, "perOutputAmount");
    const blindingSeed = checked<Bytes32>(input.blindingSeed, 32, "blinding seed");
    input.outputs.forEach((output, index) => {
      const expectedAmount = index < input.numOutputs ? perOutputAmount : 0n;
      if (
        !equal(output.ownerHash(), input.owner.ownerHash()) ||
        output.asset !== input.input.utxo.asset ||
        output.amount !== expectedAmount ||
        !equal(output.blinding, deriveBlinding(blindingSeed, index)) ||
        output.ringProgramId !== undefined ||
        output.ringDataHash !== undefined ||
        output.dataHash !== undefined ||
        !output.data.isEmpty()
      ) {
        throw new TransactionError("TRANSACTION_OUTPUT_DATA_MISMATCH", { index });
      }
    });
    this.owner = input.owner;
    this.input = input.input;
    this.asset = input.input.utxo.asset;
    this.outputs = Object.freeze([...input.outputs]);
    this.firstNullifier = input.input.nullifier();
    this.numOutputs = input.numOutputs;
    this.perOutputAmount = perOutputAmount;
    this.blindingSeed = blindingSeed;
    this.payer = input.payer;
  }

  bundlePlaintext(
    assets: AssetRegistry,
  ): import("../serialization/codecs.js").SplitBundlePlaintext {
    return {
      ownerPublicKey: this.owner.signingPublicKey,
      numOutputs: this.numOutputs,
      assetId: assets.assetId(this.input.utxo.asset),
      assetAmount: this.perOutputAmount,
      blindingSeed: this.blindingSeed,
      data: new Data(),
    };
  }

  /**
   * The owner's confidential view tag. It tags the bundle at slot 0 and every
   * covered real output, and equals the bundle view tag because the split is
   * self-owned.
   */
  ownerViewTag(): Bytes32 {
    return this.owner.confidentialViewTag();
  }

  finalize(
    input: Readonly<{
      txViewingPublicKey: P256PublicKey;
      salt: Bytes16;
      payload: Readonly<{ viewTag: Bytes32; data: Uint8Array }>;
    }>,
  ): SppProofInputs {
    const tag = this.ownerViewTag();
    const outputs = this.outputs.map((output, index) => ({
      utxoHash: output.hash(),
      ownerTag: { kind: "inline" as const, value: tag },
      ...(index === 0 ? { data: new Uint8Array(input.payload.data) } : {}),
    }));
    return new SppProofInputs({
      payer: this.payer,
      inputUtxos: [this.input],
      outputs: this.outputs,
      externalData: createExternalData({
        txViewingPublicKey: input.txViewingPublicKey,
        salt: input.salt,
        outputs,
        resolvedOwnerTags: this.outputs.map(() => tag),
        messages: [],
      }),
    });
  }
}
