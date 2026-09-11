import type { Address, Bytes16, Bytes32 } from "../../interface/types.js";
import { randomBlinding, randomSalt } from "../../keypair/bytes.js";
import type { NullifierKey } from "../../keypair/nullifier-key.js";
import { mergeDummyNullifier, mergeOutputBlinding } from "../../keypair/merge/index.js";
import type { P256PublicKey, ShieldedPublicKey } from "../../keypair/public-key.js";
import { ShieldedKeypair, type ShieldedAddress } from "../../keypair/shielded.js";

import { Data } from "../data.js";
import { MERGE_INPUT_COUNT } from "../../interface/constants.js";
import { TransactionError } from "../error.js";
import { checked, equal } from "../internal.js";
import { DEFAULT_TREE_ID } from "../../interface/tree-slot.js";
import { encodeSplitBundle, encryptSplit } from "../serialization/codecs.js";
import {
  ProofInputUtxo,
  checkedTreeId,
  createProofOutput,
  outputBlindingSeed,
  transactOutputBlinding,
  type ProofOutputUtxo,
  type TreeId,
} from "../utxo.js";
import { type AssetRegistry } from "../asset.js";
import {
  SppProofInputs,
  createExternalData,
  singleInputTreeId,
  type InputUtxoContext,
} from "./transact.js";

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
  /** The tree every input is spent from. */
  readonly inputTreeId: TreeId;
  /** The tree the merged output is appended to. */
  readonly outputTreeId: TreeId;

  constructor(
    input: Readonly<{
      inputs: readonly ProofInputUtxo[];
      output: ProofOutputUtxo;
      expiryUnixTs: bigint;
      signingPublicKey: ShieldedPublicKey;
      outputTreeId: TreeId;
    }>,
  ) {
    if (input.inputs.length !== MERGE_INPUTS) {
      throw new TransactionError("TRANSACTION_INVALID_OUTPUT_COUNT", {
        expected: MERGE_INPUTS,
        actual: input.inputs.length,
      });
    }
    let sawDummy = false;
    input.inputs.forEach((spend, index) => {
      if (spend.isDummy()) {
        sawDummy = true;
      } else if (sawDummy) {
        throw new TransactionError("TRANSACTION_DUMMY_INPUT_NOT_ALLOWED", { index });
      }
    });
    this.inputTreeId = singleInputTreeId(input.inputs);
    this.inputs = Object.freeze([...input.inputs]);
    this.output = input.output;
    this.expiryUnixTs = checkedU64(input.expiryUnixTs, "expiryUnixTs");
    this.signingPublicKey = input.signingPublicKey;
    this.outputTreeId = checkedTreeId(input.outputTreeId);
  }

  /** The merged output's commitment in `outputTreeId`. */
  outputHash(): Bytes32 {
    return this.output.hash(this.outputTreeId);
  }

  inputUtxoHashes(): readonly InputUtxoContext[] {
    return realInputContexts(this.inputs, hasData);
  }

  dummyNullifiers(nullifierKey: NullifierKey): readonly Bytes32[] {
    const first = this.inputs.find((input) => !input.isDummy());
    if (!first) throw new TransactionError("TRANSACTION_NO_INPUTS");
    const firstNullifier = first.nullifier();
    return this.inputs.flatMap((input, index) =>
      input.isDummy() ? [mergeDummyNullifier(nullifierKey, firstNullifier, index)] : [],
    );
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

export class Merge {
  #prepared: PreparedMerge;

  /**
   * Consolidates up to eight inputs of one asset into one output. The output
   * lands in `outputTreeId`, `DEFAULT_TREE_ID` unless given; mirrors Rust
   * `Merge::new(.., output_tree_id)`.
   */
  constructor(
    identity: ShieldedKeypair | Readonly<{ address: ShieldedAddress; nullifierKey: NullifierKey }>,
    inputs: readonly ProofInputUtxo[],
    outputTreeId: TreeId = DEFAULT_TREE_ID,
  ) {
    if (inputs.length === 0) throw new TransactionError("TRANSACTION_NO_INPUTS");
    if (inputs.length > MERGE_INPUTS) {
      throw new TransactionError("TRANSACTION_TOO_MANY_INPUTS", {
        got: inputs.length,
        max: MERGE_INPUTS,
      });
    }
    const address =
      identity instanceof ShieldedKeypair ? identity.shieldedAddress() : identity.address;
    const nullifierKey =
      identity instanceof ShieldedKeypair ? identity.nullifierKey() : identity.nullifierKey;
    try {
      const owner = address.signingPublicKey;
      const firstInput = inputs[0];
      if (!firstInput) throw new TransactionError("TRANSACTION_NO_INPUTS");
      const asset = firstInput.utxo.asset;
      const nullifierPublicKey = nullifierKey.publicKey();
      const firstNullifier = firstInput.nullifier();
      let amount = 0n;
      inputs.forEach((input, index) => {
        if (input.utxo.owner.signatureType() !== owner.signatureType()) {
          throw new TransactionError("TRANSACTION_MERGE_INPUT_RAIL_MISMATCH", { index });
        }
        if (!equal(input.utxo.owner.toBytes(), owner.toBytes())) {
          throw new TransactionError("TRANSACTION_MERGE_INPUT_OWNER_MISMATCH", { index });
        }
        if (!equal(input.nullifierKey.publicKey(), nullifierPublicKey)) {
          throw new TransactionError("TRANSACTION_MERGE_INPUT_NULLIFIER_KEY_MISMATCH", { index });
        }
        if (input.utxo.asset !== asset) {
          throw new TransactionError("TRANSACTION_MERGE_INPUT_ASSET_MISMATCH", { index });
        }
        if (input.utxo.ringProgramId !== undefined) {
          throw new TransactionError("TRANSACTION_MERGE_INPUT_RING_MISMATCH", { index });
        }
        if (!input.utxo.data.isEmpty() || input.dataHash || input.ringDataHash) {
          throw new TransactionError("TRANSACTION_MERGE_INPUT_HAS_DATA", { index });
        }
        amount += input.utxo.amount;
        if (amount > 0xffff_ffff_ffff_ffffn) {
          throw new TransactionError("TRANSACTION_SELECTED_BALANCE_OVERFLOW");
        }
      });
      // Dummies are hashed under the input tree like every real input.
      const treeId = singleInputTreeId(inputs);
      const padded = [...inputs];
      while (padded.length < MERGE_INPUTS) padded.push(ProofInputUtxo.dummy(undefined, treeId));
      this.#prepared = new PreparedMerge({
        inputs: padded,
        output: createProofOutput({
          ownerAddress: address,
          asset,
          amount,
          blinding: mergeOutputBlinding(nullifierKey, firstNullifier),
        }),
        expiryUnixTs: 0xffff_ffff_ffff_ffffn,
        signingPublicKey: owner,
        outputTreeId: checkedTreeId(outputTreeId),
      });
    } finally {
      // Destroy only the fresh copy, a caller-held key stays the caller's.
      if (identity instanceof ShieldedKeypair) nullifierKey.destroy();
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
      outputTreeId: this.#prepared.outputTreeId,
    });
    return this;
  }

  /** Mirrors Rust `with_output_tree_id`. */
  withOutputTreeId(outputTreeId: TreeId): this {
    this.#prepared = new PreparedMerge({
      inputs: this.#prepared.inputs,
      output: this.#prepared.output,
      expiryUnixTs: this.#prepared.expiryUnixTs,
      signingPublicKey: this.#prepared.signingPublicKey,
      outputTreeId: checkedTreeId(outputTreeId),
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
  readonly #blindingSeed = randomBlinding();
  #outputTreeId: TreeId = DEFAULT_TREE_ID;

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
    if (!equal(input.input.nullifierKey.publicKey(), input.owner.nullifierPublicKey)) {
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

  /** Mirrors Rust `with_output_tree_id`; `DEFAULT_TREE_ID` unless set. */
  withOutputTreeId(outputTreeId: TreeId): this {
    this.#outputTreeId = checkedTreeId(outputTreeId);
    return this;
  }

  prepare(): PreparedSplit {
    // All eight slots are self-owned real outputs, the unused ones at amount
    // zero; every blinding derives from the first nullifier and the slot index.
    const firstNullifier = this.#input.nullifier();
    const outputSeed = outputBlindingSeed(firstNullifier, this.#blindingSeed);
    const outputs = Array.from({ length: SPLIT_OUTPUT_SLOTS }, (_, index) =>
      createProofOutput({
        ownerAddress: this.#owner,
        asset: this.#asset,
        amount: index < this.#numOutputs ? this.#perOutputAmount : 0n,
        blinding: transactOutputBlinding(firstNullifier, outputSeed, index),
      }),
    );
    return new PreparedSplit({
      owner: this.#owner,
      input: this.#input,
      outputs,
      numOutputs: this.#numOutputs,
      perOutputAmount: this.#perOutputAmount,
      blindingSeed: this.#blindingSeed,
      outputTreeId: this.#outputTreeId,
      payer: this.#payer,
    });
  }

  /**
   * Keypair rail: assemble with the owner's own viewing key, seal the bundle at
   * slot 0, and sign in place. The authority rail is `prepare` plus
   * `PreparedSplit.finalize`, with encryption and signing delegated to a
   * `WalletAuthority`.
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

/** Output slots of the split circuit shape (1 in, 8 out). Mirrors Rust `SPLIT_OUTPUT_SLOTS`. */
export const SPLIT_OUTPUT_SLOTS = 8;

export class PreparedSplit {
  readonly owner: ShieldedAddress;
  readonly input: ProofInputUtxo;
  readonly asset: Address;
  readonly outputs: readonly ProofOutputUtxo[];
  readonly firstNullifier: Bytes32;
  readonly numOutputs: number;
  readonly perOutputAmount: bigint;
  /** The private root seed; only the prover request may carry it. */
  readonly blindingSeed: Bytes32;
  /** The tree the input is spent from. */
  readonly inputTreeId: TreeId;
  /** The tree the eight outputs are appended to. */
  readonly outputTreeId: TreeId;
  readonly payer: Address;

  constructor(
    input: Readonly<{
      owner: ShieldedAddress;
      input: ProofInputUtxo;
      outputs: readonly ProofOutputUtxo[];
      numOutputs: number;
      perOutputAmount: bigint;
      blindingSeed: Bytes32;
      outputTreeId: TreeId;
      payer: Address;
    }>,
  ) {
    if (
      !Number.isInteger(input.numOutputs) ||
      input.numOutputs < 2 ||
      input.numOutputs > SPLIT_OUTPUT_SLOTS
    ) {
      throw new TransactionError("TRANSACTION_SPLIT_INVALID_PART_COUNT", {
        numOutputs: input.numOutputs,
      });
    }
    if (input.outputs.length !== SPLIT_OUTPUT_SLOTS) {
      throw new TransactionError("TRANSACTION_INVALID_OUTPUT_COUNT", {
        expected: SPLIT_OUTPUT_SLOTS,
        actual: input.outputs.length,
      });
    }
    const perOutputAmount = checkedU64(input.perOutputAmount, "perOutputAmount");
    const blindingSeed = checked<Bytes32>(input.blindingSeed, 32, "blinding seed");
    const firstNullifier = input.input.nullifier();
    const outputSeed = outputBlindingSeed(firstNullifier, blindingSeed);
    input.outputs.forEach((output, index) => {
      const expectedAmount = index < input.numOutputs ? perOutputAmount : 0n;
      if (
        !equal(output.ownerHash(), input.owner.ownerHash()) ||
        output.asset !== input.input.utxo.asset ||
        output.amount !== expectedAmount ||
        !equal(output.blinding, transactOutputBlinding(firstNullifier, outputSeed, index)) ||
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
    this.firstNullifier = firstNullifier;
    this.numOutputs = input.numOutputs;
    this.perOutputAmount = perOutputAmount;
    this.blindingSeed = blindingSeed;
    this.inputTreeId = input.input.treeId;
    this.outputTreeId = checkedTreeId(input.outputTreeId);
    this.payer = input.payer;
  }

  /** The derived seed the bundle discloses; the root `blindingSeed` never leaves the prover path. */
  outputBlindingSeed(): Bytes32 {
    return outputBlindingSeed(this.firstNullifier, this.blindingSeed);
  }

  /**
   * The bundle carries the derived output seed, never the root: all eight
   * outputs are self-owned, and a reader recovers every blinding from the seed
   * and the first nullifier.
   */
  bundlePlaintext(
    assets: AssetRegistry,
  ): import("../serialization/codecs.js").SplitBundlePlaintext {
    return {
      ownerPublicKey: this.owner.signingPublicKey,
      numOutputs: this.numOutputs,
      assetId: assets.assetId(this.input.utxo.asset),
      assetAmount: this.perOutputAmount,
      blindingSeed: this.outputBlindingSeed(),
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
      utxoHash: output.hash(this.outputTreeId),
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
      blindingSeed: this.blindingSeed,
      outputTreeId: this.outputTreeId,
    });
  }
}
