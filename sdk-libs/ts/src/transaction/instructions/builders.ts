import { equalBytes } from "../../interface/bytes.js";
import type { Address, Bytes16, Bytes32 } from "../../interface/types.js";
import { randomSalt } from "../../keypair/bytes.js";
import {
  mergeDummyNullifier,
  mergeOutputBlinding,
  mergeOutputKey,
  mergePrivateTxBlinding,
} from "../../keypair/merge/index.js";
import type { ShieldedPublicKey } from "../../keypair/public-key.js";
import type { ShieldedAddress, ShieldedKeypair } from "../../keypair/shielded.js";

import {
  MAX_MERGE_INPUTS,
  MERGE_SUPPORTED_INPUT_COUNTS,
  mergePaddedInputCount,
} from "../../interface/constants.js";
import { TransactionError } from "../error.js";
import { checked } from "../internal.js";
import { DEFAULT_TREE_ID } from "../../interface/tree-slot.js";
import { encryptMergeOutput, type MergeOutputCiphertext } from "../serialization/merge.js";
import {
  ProofInputUtxo,
  checkedTreeId,
  createProofOutput,
  type ProofOutputUtxo,
  type TreeId,
} from "../utxo.js";
import { singleInputTreeId, type InputUtxoContext } from "./transact.js";

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
  /** The tree every input is spent from. */
  readonly inputTreeId: TreeId;
  /** The tree the merged output is appended to. */
  readonly outputTreeId: TreeId;
  readonly #dummyNullifiers: readonly Bytes32[];
  readonly #privateTxBlinding: Bytes32;
  readonly #outputCiphertextSalt: Bytes16;
  readonly #outputCiphertext: MergeOutputCiphertext;

  constructor(
    input: Readonly<{
      inputs: readonly ProofInputUtxo[];
      output: ProofOutputUtxo;
      expiryUnixTs: bigint;
      signingPublicKey: ShieldedPublicKey;
      nullifierPublicKey: Bytes32;
      /**
       * One per padded slot, compact padding included, in slot order:
       * `mergeDummyNullifier(firstNullifier, slot)`. Compact padding publishes
       * 0 in its place but proves non-inclusion of it.
       */
      dummyNullifiers: readonly Bytes32[];
      /** `mergePrivateTxBlinding(firstNullifier)`. */
      privateTxBlinding: Bytes32;
      /** Fresh per proof; the pad nonce of `outputCiphertext`. */
      outputCiphertextSalt: Bytes16;
      /**
       * `encryptMergeOutput` of the output's amount and mint under
       * `mergeOutputKey(firstNullifier)`. The proof binds it, so the owner
       * rebuilds the output from the merge transaction alone.
       */
      outputCiphertext: MergeOutputCiphertext;
      outputTreeId: TreeId;
    }>,
  ) {
    if (!MERGE_SUPPORTED_INPUT_COUNTS.includes(input.inputs.length)) {
      throw new TransactionError("TRANSACTION_INVALID_OUTPUT_COUNT", {
        expected: paddedInputCount(input.inputs.length),
        actual: input.inputs.length,
      });
    }
    let sawDummy = false;
    let sawCompact = false;
    let dummies = 0;
    let sent = 0;
    input.inputs.forEach((spend, index) => {
      if (spend.isCompact()) {
        sawCompact = true;
        dummies++;
        return;
      }
      // SPP appends the zeros after the sent nullifiers, so compact padding
      // anywhere else proves a different chain than SPP rebuilds.
      if (sawCompact) {
        throw new TransactionError("TRANSACTION_SLOT_AFTER_COMPACT_PADDING", {
          side: "input",
          index,
        });
      }
      sent++;
      if (spend.isDummy()) {
        sawDummy = true;
        dummies++;
      } else if (sawDummy) {
        throw new TransactionError("TRANSACTION_DUMMY_INPUT_NOT_ALLOWED", { index });
      }
    });
    // SPP picks the merge circuit from the sent count, so compact padding must
    // fill exactly the narrowest circuit that holds the sent inputs.
    if (sawCompact && mergePaddedInputCount(sent) !== input.inputs.length) {
      throw new TransactionError("TRANSACTION_UNSUPPORTED_SHAPE", {
        inputs: input.inputs.length,
        sent,
      });
    }
    if (input.dummyNullifiers.length !== dummies) {
      throw new TransactionError("TRANSACTION_INVALID_LENGTH", {
        field: "dummyNullifiers",
        expected: dummies,
        actual: input.dummyNullifiers.length,
      });
    }
    this.inputTreeId = singleInputTreeId(input.inputs);
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
    this.#privateTxBlinding = checked<Bytes32>(
      input.privateTxBlinding,
      32,
      "merge private tx blinding",
    );
    this.#outputCiphertextSalt = checked<Bytes16>(
      input.outputCiphertextSalt,
      16,
      "merge output ciphertext salt",
    );
    if (input.outputCiphertext.length !== 3) {
      throw new TransactionError("TRANSACTION_INVALID_LENGTH", {
        field: "outputCiphertext",
        expected: 3,
        actual: input.outputCiphertext.length,
      });
    }
    const [ciphertext0, ciphertext1, ciphertext2] = input.outputCiphertext.map((element) =>
      checked<Bytes32>(element, 32, "merge output ciphertext"),
    );
    if (ciphertext0 === undefined || ciphertext1 === undefined || ciphertext2 === undefined) {
      throw new TransactionError("TRANSACTION_INVALID_LENGTH", { field: "outputCiphertext" });
    }
    this.#outputCiphertext = Object.freeze([ciphertext0, ciphertext1, ciphertext2] as const);
    this.outputTreeId = checkedTreeId(input.outputTreeId);
  }

  /** The merged output's commitment in `outputTreeId`. */
  outputHash(): Bytes32 {
    return this.output.hash(this.outputTreeId);
  }

  inputUtxoHashes(): readonly InputUtxoContext[] {
    return realInputContexts(
      this.inputs,
      this.output.ringProgramId === undefined ? hasData : hasUtxoData,
    );
  }

  dummyNullifiers(): readonly Bytes32[] {
    return Object.freeze(this.#dummyNullifiers.map((value) => new Uint8Array(value) as Bytes32));
  }

  privateTxBlinding(): Bytes32 {
    return new Uint8Array(this.#privateTxBlinding) as Bytes32;
  }

  outputCiphertextSalt(): Bytes16 {
    return new Uint8Array(this.#outputCiphertextSalt) as Bytes16;
  }

  outputCiphertext(): MergeOutputCiphertext {
    const [ciphertext0, ciphertext1, ciphertext2] = this.#outputCiphertext;
    return Object.freeze([
      new Uint8Array(ciphertext0) as Bytes32,
      new Uint8Array(ciphertext1) as Bytes32,
      new Uint8Array(ciphertext2) as Bytes32,
    ] as const);
  }

  /** The slots the padding fills, in order; what `dummyNullifiers` was derived for. */
  static dummySlots(realInputs: number): readonly number[] {
    return Array.from(
      { length: paddedInputCount(realInputs) - realInputs },
      (_, offset) => realInputs + offset,
    );
  }
}

function paddedInputCount(realInputs: number): number {
  const count = mergePaddedInputCount(realInputs);
  if (count === undefined) {
    throw new TransactionError("TRANSACTION_TOO_MANY_INPUTS", {
      got: realInputs,
      max: MAX_MERGE_INPUTS,
    });
  }
  return count;
}

/** An input carrying program or ring data, which the plain merge rail never consolidates. */
function hasData(input: ProofInputUtxo): boolean {
  return (
    input.dataHash !== undefined || input.ringDataHash !== undefined || !input.utxo.data.isEmpty()
  );
}

function hasUtxoData(input: ProofInputUtxo): boolean {
  return (
    input.dataHash !== undefined ||
    input.utxo.data.records().some((record) => record.kind === "utxoData")
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
 * Consolidates up to `MAX_MERGE_INPUTS` plain UTXOs of one owner and asset into one.
 * The output blinding, private-transaction blinding, and padded slots'
 * nullifiers derive from the nullifier secret; the builder receives them
 * derived by `ShieldedKeys.derive`. The circuit's unused slots are compact
 * padding: each publishes 0 in place of its derived dummy nullifier, which it
 * still proves absent, and the instruction leaves it out, so the merge reveals
 * its real input count. Mirrors Rust `MergeTransaction::new`.
 */
export class Merge {
  #prepared: PreparedMerge;

  constructor(
    input: Readonly<{
      address: ShieldedAddress;
      inputs: readonly ProofInputUtxo[];
      /** `mergeOutputBlinding(firstNullifier)`. */
      outputBlinding: Bytes32;
      /** `mergePrivateTxBlinding(firstNullifier)`. */
      privateTxBlinding: Bytes32;
      /** `mergeDummyNullifier(firstNullifier, slot)` for each padded slot. */
      dummyNullifiers: readonly Bytes32[];
      /** `mergeOutputKey(firstNullifier)`, the key of the output ciphertext. */
      outputKey: Bytes32;
      /** The pad nonce of the output ciphertext; a fresh random salt by default. */
      outputCiphertextSalt?: Bytes16;
      outputTreeId?: TreeId;
      ring?: Readonly<{ programId: Address; outputDataHash?: Bytes32 }>;
    }>,
  ) {
    const inputs = input.inputs;
    if (inputs.length === 0) throw new TransactionError("TRANSACTION_NO_INPUTS");
    const width = paddedInputCount(inputs.length);
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
      if (!equalBytes(spend.utxo.owner.toBytes(), owner.toBytes())) {
        throw new TransactionError("TRANSACTION_MERGE_INPUT_OWNER_MISMATCH", { index });
      }
      if (!equalBytes(spend.nullifierPublicKey, address.nullifierPublicKey)) {
        throw new TransactionError("TRANSACTION_MERGE_INPUT_NULLIFIER_KEY_MISMATCH", { index });
      }
      if (spend.utxo.asset !== asset) {
        throw new TransactionError("TRANSACTION_MERGE_INPUT_ASSET_MISMATCH", { index });
      }
      if (spend.utxo.ringProgramId !== input.ring?.programId) {
        throw new TransactionError("TRANSACTION_MERGE_INPUT_RING_MISMATCH", { index });
      }
      if (input.ring === undefined ? hasData(spend) : hasUtxoData(spend)) {
        throw new TransactionError("TRANSACTION_MERGE_INPUT_HAS_DATA", { index });
      }
      amount += spend.utxo.amount;
      if (amount > 0xffff_ffff_ffff_ffffn) {
        throw new TransactionError("TRANSACTION_SELECTED_BALANCE_OVERFLOW");
      }
    });
    const inputTreeId = singleInputTreeId(inputs);
    const padded = [...inputs];
    while (padded.length < width) padded.push(ProofInputUtxo.compact(inputTreeId));
    const outputCiphertextSalt = checked<Bytes16>(
      input.outputCiphertextSalt ?? randomSalt(),
      16,
      "merge output ciphertext salt",
    );
    const outputKey = checked<Bytes32>(input.outputKey, 32, "merge output key");
    let outputCiphertext: MergeOutputCiphertext;
    try {
      outputCiphertext = encryptMergeOutput(
        { amount, mint: asset },
        outputKey,
        outputCiphertextSalt,
      );
    } finally {
      outputKey.fill(0);
    }
    this.#prepared = new PreparedMerge({
      inputs: padded,
      output: createProofOutput({
        ownerAddress: address,
        asset,
        amount,
        blinding: checked<Bytes32>(input.outputBlinding, 32, "merge output blinding"),
        ...(input.ring === undefined
          ? {}
          : {
              ringProgramId: input.ring.programId,
              ...(input.ring.outputDataHash === undefined
                ? {}
                : { ringDataHash: input.ring.outputDataHash }),
            }),
      }),
      expiryUnixTs: U64_MAX,
      signingPublicKey: owner,
      nullifierPublicKey: address.nullifierPublicKey,
      dummyNullifiers: input.dummyNullifiers,
      privateTxBlinding: input.privateTxBlinding,
      outputCiphertextSalt,
      outputCiphertext,
      outputTreeId: checkedTreeId(input.outputTreeId ?? DEFAULT_TREE_ID),
    });
  }

  /** Keypair rail: derives all nullifier-key values here; the key never leaves this call. */
  static fromKeypair(
    keypair: ShieldedKeypair,
    inputs: readonly ProofInputUtxo[],
    outputTreeId: TreeId = DEFAULT_TREE_ID,
  ): Merge {
    const first = inputs[0];
    if (!first) throw new TransactionError("TRANSACTION_NO_INPUTS");
    const firstNullifier = first.nullifier();
    const nullifierKey = keypair.nullifierKey();
    let outputKey: Bytes32 | undefined;
    try {
      outputKey = mergeOutputKey(nullifierKey, firstNullifier);
      return new Merge({
        address: keypair.shieldedAddress(),
        inputs,
        outputBlinding: mergeOutputBlinding(nullifierKey, firstNullifier),
        privateTxBlinding: mergePrivateTxBlinding(nullifierKey, firstNullifier),
        dummyNullifiers: PreparedMerge.dummySlots(inputs.length).map((slot) =>
          mergeDummyNullifier(nullifierKey, firstNullifier, slot),
        ),
        outputKey,
        outputTreeId,
      });
    } finally {
      outputKey?.fill(0);
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
      privateTxBlinding: this.#prepared.privateTxBlinding(),
      outputCiphertextSalt: this.#prepared.outputCiphertextSalt(),
      outputCiphertext: this.#prepared.outputCiphertext(),
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
      nullifierPublicKey: this.#prepared.nullifierPublicKey,
      dummyNullifiers: this.#prepared.dummyNullifiers(),
      privateTxBlinding: this.#prepared.privateTxBlinding(),
      outputCiphertextSalt: this.#prepared.outputCiphertextSalt(),
      outputCiphertext: this.#prepared.outputCiphertext(),
      outputTreeId: checkedTreeId(outputTreeId),
    });
    return this;
  }
}
