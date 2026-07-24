import type { Address, Bytes31, Bytes32 } from "@zolana/interface";
import {
  ShieldedKeypair,
  type P256PublicKey,
  type ShieldedAddress,
  type ShieldedPublicKey,
} from "@zolana/keypair";

import { Data } from "../data.js";
import { TransactionError } from "../error.js";
import { checked, decodeAddress, equal, random31, sha256Be } from "../internal.js";
import {
  ProofInputUtxo,
  createProofOutput,
  deriveBlinding,
  type ProofOutputUtxo,
} from "../utxo.js";
import { SOL_MINT, type AssetRegistry } from "../wallet/asset.js";
import { SppProofInputs, createExternalData, type InputUtxoContext } from "./transact.js";

const MERGE_INPUTS = 8;

export class PreparedMerge {
  readonly inputs: readonly ProofInputUtxo[];
  readonly output: ProofOutputUtxo;
  readonly expiryUnixTs: bigint;
  readonly signingPublicKey: ShieldedPublicKey;
  readonly userViewingPublicKey: P256PublicKey;
  readonly txViewingSecret: Bytes32;

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
    this.inputs = Object.freeze([...input.inputs]);
    this.output = input.output;
    this.expiryUnixTs = input.expiryUnixTs;
    this.signingPublicKey = input.signingPublicKey;
    this.userViewingPublicKey = input.userViewingPublicKey;
    this.txViewingSecret = checked<Bytes32>(
      input.txViewingSecret,
      32,
      "transaction viewing secret",
    );
  }

  inputUtxoHashes(): readonly InputUtxoContext[] {
    return this.inputs
      .filter((input) => !input.isDummy())
      .map((input, index) =>
        Object.freeze({
          index,
          utxoHash: input.hash(),
          nullifier: input.nullifier(),
        }),
      );
  }
}

export class Merge {
  readonly #prepared: PreparedMerge;

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
    const nullifierPublicKey = firstInput.nullifierKey.publicKey();
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
      if (
        input.utxo.zoneProgramId ||
        !input.utxo.data.isEmpty() ||
        input.dataHash ||
        input.zoneDataHash
      ) {
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
    if (input.input.utxo.asset !== input.asset) {
      throw new TransactionError("TRANSACTION_SPLIT_INPUT_ASSET_MISMATCH");
    }
    if (
      input.input.isDummy() ||
      !equal(input.input.utxo.owner.toBytes(), input.owner.signingPublicKey.toBytes()) ||
      !equal(input.input.nullifierKey.publicKey(), input.owner.nullifierPublicKey)
    ) {
      throw new TransactionError("TRANSACTION_INPUT_OWNER_MISMATCH");
    }
    if (
      input.input.utxo.zoneProgramId ||
      !input.input.utxo.data.isEmpty() ||
      input.input.dataHash ||
      input.input.zoneDataHash
    ) {
      throw new TransactionError("TRANSACTION_SPLIT_INPUT_HAS_DATA");
    }
    if (input.perOutputAmount * BigInt(input.numOutputs) !== input.input.utxo.amount) {
      throw new TransactionError("TRANSACTION_SPLIT_AMOUNT_MISMATCH");
    }
    this.#owner = input.owner;
    this.#input = input.input;
    this.#asset = input.asset;
    this.#numOutputs = input.numOutputs;
    this.#perOutputAmount = input.perOutputAmount;
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
}

export class PreparedSplit {
  readonly owner: ShieldedAddress;
  readonly input: ProofInputUtxo;
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
    this.owner = input.owner;
    this.input = input.input;
    this.outputs = Object.freeze([...input.outputs]);
    this.firstNullifier = input.input.nullifier();
    this.numOutputs = input.numOutputs;
    this.perOutputAmount = input.perOutputAmount;
    this.blindingSeed = input.blindingSeed;
    this.payerPublicKeyHash = input.payerPublicKeyHash;
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

  finalize(
    input: Readonly<{
      txViewingPublicKey: P256PublicKey;
      salt: import("@zolana/interface").Bytes16;
      payload: Readonly<{ viewTag: Bytes32; data: Uint8Array }>;
    }>,
  ): SppProofInputs {
    const tag = this.owner.confidentialViewTag();
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

export interface PreparedZoneAuthority {
  readonly inputs: readonly ProofInputUtxo[];
  readonly outputs: readonly ProofOutputUtxo[];
  readonly publicAmounts: Readonly<{ sol?: bigint; spl?: bigint }>;
  readonly zoneProgramId: Address;
  readonly payerPublicKeyHash: Bytes32;
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
  for (const [index, spend] of input.inputs.entries()) {
    if (!spend.isDummy() && spend.utxo.zoneProgramId !== input.zoneProgramId) {
      throw new TransactionError("TRANSACTION_MERGE_INPUT_ZONE_MISMATCH", { index });
    }
  }
  for (const [index, output] of input.outputs.entries()) {
    if (!output.isDummy() && output.zoneProgramId !== input.zoneProgramId) {
      throw new TransactionError("TRANSACTION_OUTPUT_ZONE_MISMATCH", { index });
    }
  }
  return Object.freeze({
    ...input,
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
