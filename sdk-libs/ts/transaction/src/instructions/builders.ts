import type { Address, Bytes31, Bytes32 } from "@zolana/interface";
import {
  ShieldedKeypair,
  randomSalt,
  type P256PublicKey,
  type ShieldedAddress,
  type ShieldedPublicKey,
} from "@zolana/keypair";

import { Data } from "../data.js";
import { TransactionError } from "../error.js";
import { checked, decodeAddress, equal, random31, sha256Be } from "../internal.js";
import { encodeSplitBundle, encryptSplit } from "../serialization/codecs.js";
import {
  ProofInputUtxo,
  createProofOutput,
  deriveBlinding,
  type ProofOutputUtxo,
} from "../utxo.js";
import { SOL_MINT, type AssetRegistry } from "../wallet/asset.js";
import {
  SppProofInputs,
  createExternalData,
  exactShape,
  type InputUtxoContext,
  type Shape,
} from "./transact.js";

/** Padded input count of both merge rails, the counterpart of Rust `MERGE_INPUTS`. */
export const MERGE_INPUTS = 8;
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
  readonly userViewingPublicKey: P256PublicKey;
  readonly #txViewingSecret: Bytes32;

  constructor(
    input: Readonly<{
      inputs: readonly ProofInputUtxo[];
      output: ProofOutputUtxo;
      expiryUnixTs: bigint;
      signingPublicKey: ShieldedPublicKey;
      userViewingPublicKey: P256PublicKey;
      txViewingSecret: Bytes32;
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
    this.inputs = Object.freeze([...input.inputs]);
    this.output = input.output;
    this.expiryUnixTs = checkedU64(input.expiryUnixTs, "expiryUnixTs");
    this.signingPublicKey = input.signingPublicKey;
    this.userViewingPublicKey = input.userViewingPublicKey;
    this.#txViewingSecret = checked<Bytes32>(
      input.txViewingSecret,
      32,
      "transaction viewing secret",
    );
  }

  get txViewingSecret(): Bytes32 {
    return checked<Bytes32>(this.#txViewingSecret, 32, "transaction viewing secret");
  }

  inputUtxoHashes(): readonly InputUtxoContext[] {
    return realInputContexts(this.inputs, hasData);
  }
}

/** An input carrying program or zone data, which the plain merge rail never consolidates. */
function hasData(input: ProofInputUtxo): boolean {
  return (
    input.dataHash !== undefined ||
    input.zoneDataHash !== undefined ||
    !input.utxo.data.isEmpty()
  );
}

/**
 * An input carrying program-controlled UTXO data. A policy zone authorizes its own
 * data's transition before the merge, so `zoneDataHash` stays consumable there
 * while `utxoData` never is.
 */
function hasUtxoData(input: ProofInputUtxo): boolean {
  return input.dataHash !== undefined || input.utxo.data.utxoData() !== undefined;
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

  constructor(keypair: ShieldedKeypair, inputs: readonly ProofInputUtxo[]) {
    if (inputs.length === 0) throw new TransactionError("TRANSACTION_NO_INPUTS");
    if (inputs.length > MERGE_INPUTS) {
      throw new TransactionError("TRANSACTION_TOO_MANY_INPUTS", {
        got: inputs.length,
        max: MERGE_INPUTS,
      });
    }
    const owner = keypair.signingPublicKey();
    const firstInput = inputs[0];
    if (!firstInput) throw new TransactionError("TRANSACTION_NO_INPUTS");
    const asset = firstInput.utxo.asset;
    const nullifierPublicKey = keypair.nullifierKey().publicKey();
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
      if (input.utxo.zoneProgramId) {
        throw new TransactionError("TRANSACTION_MERGE_INPUT_ZONE_MISMATCH", { index });
      }
      if (!input.utxo.data.isEmpty() || input.dataHash || input.zoneDataHash) {
        throw new TransactionError("TRANSACTION_MERGE_INPUT_HAS_DATA", { index });
      }
      amount += input.utxo.amount;
      if (amount > 0xffff_ffff_ffff_ffffn) {
        throw new TransactionError("TRANSACTION_SELECTED_BALANCE_OVERFLOW");
      }
    });
    const padded = [...inputs];
    while (padded.length < MERGE_INPUTS) padded.push(ProofInputUtxo.dummy());
    const secret = new Uint8Array(32);
    secret.set(random31(), 1);
    this.#prepared = new PreparedMerge({
      inputs: padded,
      output: createProofOutput({
        ownerAddress: keypair.shieldedAddress(),
        asset,
        amount,
      }),
      expiryUnixTs: 0xffff_ffff_ffff_ffffn,
      signingPublicKey: owner,
      userViewingPublicKey: keypair.viewingPublicKey(),
      txViewingSecret: secret as Bytes32,
    });
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
      userViewingPublicKey: this.#prepared.userViewingPublicKey,
      txViewingSecret: this.#prepared.txViewingSecret,
    });
    return this;
  }
}

export class PreparedMergeZone extends PreparedMerge {
  readonly zoneProgramId: Address;

  constructor(
    input: ConstructorParameters<typeof PreparedMerge>[0] & Readonly<{ zoneProgramId: Address }>,
  ) {
    super(input);
    this.zoneProgramId = input.zoneProgramId;
  }

  // Rust re-checks only the data policy here; the zone binding is the builder's
  // rule, and `validateMergeZoneInputs` stays available for callers that want it.
  override inputUtxoHashes(): readonly InputUtxoContext[] {
    return realInputContexts(this.inputs, hasUtxoData);
  }
}

export class MergeZone {
  #prepared: PreparedMergeZone;

  constructor(
    keypair: ShieldedKeypair,
    inputs: readonly ProofInputUtxo[],
    zoneProgramId: Address,
    outputZoneDataHash?: Bytes32,
  ) {
    if (inputs.length === 0) throw new TransactionError("TRANSACTION_NO_INPUTS");
    if (inputs.length > MERGE_INPUTS) {
      throw new TransactionError("TRANSACTION_TOO_MANY_INPUTS", {
        got: inputs.length,
        max: MERGE_INPUTS,
      });
    }
    const owner = keypair.signingPublicKey();
    const asset = inputs[0]?.utxo.asset;
    if (asset === undefined) throw new TransactionError("TRANSACTION_NO_INPUTS");
    const expectedNullifierKey = keypair.nullifierKey().publicKey();
    let amount = 0n;
    inputs.forEach((input, index) => {
      if (input.utxo.owner.signatureType() !== owner.signatureType()) {
        throw new TransactionError("TRANSACTION_MERGE_INPUT_RAIL_MISMATCH", { index });
      }
      if (!equal(input.utxo.owner.toBytes(), owner.toBytes())) {
        throw new TransactionError("TRANSACTION_MERGE_INPUT_OWNER_MISMATCH", { index });
      }
      if (!equal(input.nullifierKey.publicKey(), expectedNullifierKey)) {
        throw new TransactionError("TRANSACTION_MERGE_INPUT_NULLIFIER_KEY_MISMATCH", { index });
      }
      if (input.utxo.asset !== asset) {
        throw new TransactionError("TRANSACTION_MERGE_INPUT_ASSET_MISMATCH", { index });
      }
      if (input.utxo.zoneProgramId !== zoneProgramId) {
        throw new TransactionError("TRANSACTION_MERGE_INPUT_ZONE_MISMATCH", { index });
      }
      if (input.dataHash !== undefined || input.utxo.data.utxoData() !== undefined) {
        throw new TransactionError("TRANSACTION_MERGE_INPUT_HAS_DATA", { index });
      }
      amount += input.utxo.amount;
      if (amount > 0xffff_ffff_ffff_ffffn) {
        throw new TransactionError("TRANSACTION_SELECTED_BALANCE_OVERFLOW");
      }
    });
    const padded = [...inputs];
    while (padded.length < MERGE_INPUTS) padded.push(ProofInputUtxo.dummy());
    const secret = new Uint8Array(32);
    secret.set(random31(), 1);
    this.#prepared = new PreparedMergeZone({
      inputs: padded,
      output: createProofOutput({
        ownerAddress: keypair.shieldedAddress(),
        asset,
        amount,
        zoneProgramId,
        ...(outputZoneDataHash === undefined ? {} : { zoneDataHash: outputZoneDataHash }),
      }),
      expiryUnixTs: 0xffff_ffff_ffff_ffffn,
      signingPublicKey: owner,
      userViewingPublicKey: keypair.viewingPublicKey(),
      txViewingSecret: secret as Bytes32,
      zoneProgramId,
    });
  }

  prepare(): PreparedMergeZone {
    return this.#prepared;
  }

  withExpiry(expiryUnixTs: bigint): this {
    this.#prepared = new PreparedMergeZone({
      inputs: this.#prepared.inputs,
      output: this.#prepared.output,
      expiryUnixTs: checkedU64(expiryUnixTs, "expiryUnixTs"),
      signingPublicKey: this.#prepared.signingPublicKey,
      userViewingPublicKey: this.#prepared.userViewingPublicKey,
      txViewingSecret: this.#prepared.txViewingSecret,
      zoneProgramId: this.#prepared.zoneProgramId,
    });
    return this;
  }
}

export function validateMergeZoneInputs(
  inputs: readonly ProofInputUtxo[],
  zoneProgramId: Address,
): void {
  inputs.forEach((input, index) => {
    if (!input.isDummy() && input.utxo.zoneProgramId !== zoneProgramId) {
      throw new TransactionError("TRANSACTION_MERGE_INPUT_ZONE_MISMATCH", { index });
    }
  });
}

export class ConfidentialSplit {
  readonly #owner: ShieldedAddress;
  readonly #input: ProofInputUtxo;
  readonly #asset: Address;
  readonly #numOutputs: number;
  readonly #perOutputAmount: bigint;
  readonly #payerHash: Bytes32;
  readonly #seed = random31();

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
    // Split proves ownership in-circuit from the nullifier secret behind
    // `ownerHash`, so an input the splitter cannot open is unprovable. A
    // zero-owner slot has no openable owner hash at all.
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
    if (input.input.utxo.zoneProgramId !== undefined) {
      throw new TransactionError("TRANSACTION_SPLIT_INPUT_ZONE_MISMATCH");
    }
    if (
      input.input.dataHash !== undefined ||
      input.input.zoneDataHash !== undefined ||
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
    this.#payerHash = sha256Be(decodeAddress(input.payer));
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
      payerPublicKeyHash: this.#payerHash,
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
    const tx = keypair.viewingKey().transactionViewingKey(prepared.firstNullifier);
    const salt = randomSalt();
    const signed = prepared.finalize({
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
    if (keypair.signingPublicKey().signatureType() === "p256") {
      signed.applyP256Signature(keypair.signP256(signed.messageHash()));
    }
    return signed;
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
  readonly blindingSeed: Bytes31;
  readonly payerPublicKeyHash: Bytes32;

  constructor(
    input: Readonly<{
      owner: ShieldedAddress;
      input: ProofInputUtxo;
      outputs: readonly ProofOutputUtxo[];
      numOutputs: number;
      perOutputAmount: bigint;
      blindingSeed: Bytes31;
      payerPublicKeyHash: Bytes32;
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
    const blindingSeed = checked<Bytes31>(input.blindingSeed, 31, "blinding seed");
    input.outputs.forEach((output, index) => {
      const expectedAmount = index < input.numOutputs ? perOutputAmount : 0n;
      if (
        !equal(output.ownerHash(), input.owner.ownerHash()) ||
        output.asset !== input.input.utxo.asset ||
        output.amount !== expectedAmount ||
        !equal(output.blinding, deriveBlinding(blindingSeed, index)) ||
        output.zoneProgramId !== undefined ||
        output.zoneDataHash !== undefined ||
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
    this.payerPublicKeyHash = checked<Bytes32>(
      input.payerPublicKeyHash,
      32,
      "payer public key hash",
    );
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
      salt: import("@zolana/interface").Bytes16;
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
      payerPublicKeyHash: this.payerPublicKeyHash,
      inputUtxos: [this.input],
      outputs: this.outputs,
      externalData: createExternalData({
        instructionDiscriminator: 0,
        expiryUnixTs: 0xffff_ffff_ffff_ffffn,
        relayerFee: 0,
        userSolAccount: SOL_MINT,
        userSplToken: SOL_MINT,
        splTokenInterface: SOL_MINT,
        txViewingPublicKey: input.txViewingPublicKey,
        salt: input.salt,
        outputs,
        resolvedOwnerTags: this.outputs.map(() => tag),
        messages: [],
      }),
    });
  }
}

// The all-zero address: no zone at all, never a zone the authority may act for.
const UNPINNED_ZONE = "11111111111111111111111111111111" as Address;

export interface PreparedZoneAuthority {
  readonly inputs: readonly ProofInputUtxo[];
  readonly outputs: readonly ProofOutputUtxo[];
  readonly publicAmounts: Readonly<{ sol?: bigint; spl?: bigint }>;
  readonly zoneProgramId: Address;
  readonly payerPublicKeyHash: Bytes32;
  readonly shape: Shape;
  inputUtxoHashes(): readonly InputUtxoContext[];
}

export function prepareZoneAuthority(
  input: Readonly<{
    inputs: readonly ProofInputUtxo[];
    outputs: readonly ProofOutputUtxo[];
    zoneProgramId: Address;
    payerPublicKeyHash: Bytes32;
    publicAmounts?: Readonly<{ sol?: bigint; spl?: bigint }>;
  }>,
): PreparedZoneAuthority {
  // The UTXO owners do not authorize this spend; the zone's `zone_config` PDA
  // does, and only the zone program can sign for it. The zone binding is what
  // keeps the authority inside its own policy zone, so the zone is pinned
  // nonzero and every real UTXO carries exactly it, with no exemption for the
  // default zone. The public leg is not bound: settlement and nullification
  // share one instruction, so a leg in either direction is safe and allowed.
  if (input.zoneProgramId === UNPINNED_ZONE) {
    throw new TransactionError("TRANSACTION_MISSING_ZONE_AUTHORITY_PROGRAM_ID");
  }
  for (const [index, spend] of input.inputs.entries()) {
    if (!spend.isDummy() && spend.utxo.zoneProgramId !== input.zoneProgramId) {
      throw new TransactionError("TRANSACTION_ZONE_AUTHORITY_INPUT_ZONE_MISMATCH", { index });
    }
  }
  for (const [index, output] of input.outputs.entries()) {
    if (!output.isDummy() && output.zoneProgramId !== input.zoneProgramId) {
      throw new TransactionError("TRANSACTION_ZONE_AUTHORITY_OUTPUT_ZONE_MISMATCH", { index });
    }
  }
  // The padded slot counts must name a proving system that exists, exactly as
  // `SppProofInputs` requires of an owner-signed transact.
  const shape = exactShape(input.inputs.length, input.outputs.length);
  return Object.freeze({
    ...input,
    shape,
    publicAmounts: input.publicAmounts ?? {},
    inputUtxoHashes: (): readonly InputUtxoContext[] =>
      input.inputs
        .filter((spend) => !spend.isDummy())
        .map((spend, index) =>
          Object.freeze({
            index,
            utxoHash: spend.hash(),
            nullifier: spend.nullifier(),
          }),
        ),
  });
}
