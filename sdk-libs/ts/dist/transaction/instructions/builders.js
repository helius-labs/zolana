import { randomBlinding, randomSalt } from "../../keypair/bytes.js";
import { mergeDummyNullifier, mergeOutputBlinding } from "../../keypair/merge/index.js";
import { ShieldedKeypair } from "../../keypair/shielded.js";
import { Data } from "../data.js";
import { TransactionError } from "../error.js";
import { checked, decodeAddress, equal, hashField } from "../internal.js";
import { encodeSplitBundle, encryptSplit } from "../serialization/codecs.js";
import { ProofInputUtxo, createProofOutput, deriveBlinding, } from "../utxo.js";
import {} from "../wallet/asset.js";
import { SppProofInputs, createExternalData } from "./transact.js";
/** Padded input count of the merge circuit, the counterpart of Rust `MERGE_INPUTS`. */
export const MERGE_INPUTS = 8;
const U64_MAX = 0xffffffffffffffffn;
function checkedU64(value, field) {
    if (typeof value !== "bigint" || value < 0n || value > U64_MAX) {
        throw new TransactionError("TRANSACTION_INVALID_AMOUNT", {
            field,
            value: String(value),
        });
    }
    return value;
}
export class PreparedMerge {
    inputs;
    output;
    expiryUnixTs;
    signingPublicKey;
    constructor(input) {
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
            }
            else if (sawDummy) {
                throw new TransactionError("TRANSACTION_DUMMY_INPUT_NOT_ALLOWED", { index });
            }
        });
        this.inputs = Object.freeze([...input.inputs]);
        this.output = input.output;
        this.expiryUnixTs = checkedU64(input.expiryUnixTs, "expiryUnixTs");
        this.signingPublicKey = input.signingPublicKey;
    }
    inputUtxoHashes() {
        return realInputContexts(this.inputs, hasData);
    }
    dummyNullifiers(nullifierKey) {
        const first = this.inputs.find((input) => !input.isDummy());
        if (!first)
            throw new TransactionError("TRANSACTION_NO_INPUTS");
        const firstNullifier = first.nullifier();
        return this.inputs.flatMap((input, index) => input.isDummy() ? [mergeDummyNullifier(nullifierKey, firstNullifier, index)] : []);
    }
}
/** An input carrying program or zone data, which the plain merge rail never consolidates. */
function hasData(input) {
    return (input.dataHash !== undefined || input.zoneDataHash !== undefined || !input.utxo.data.isEmpty());
}
/**
 * Commitments for the real inputs only. The rail's data policy is re-checked here
 * because the prepared value is publicly constructible, so the builder's check is
 * not the only way in.
 */
function realInputContexts(inputs, disqualifying) {
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
    #prepared;
    constructor(identity, inputs) {
        if (inputs.length === 0)
            throw new TransactionError("TRANSACTION_NO_INPUTS");
        if (inputs.length > MERGE_INPUTS) {
            throw new TransactionError("TRANSACTION_TOO_MANY_INPUTS", {
                got: inputs.length,
                max: MERGE_INPUTS,
            });
        }
        const address = identity instanceof ShieldedKeypair ? identity.shieldedAddress() : identity.address;
        const nullifierKey = identity instanceof ShieldedKeypair ? identity.nullifierKey() : identity.nullifierKey;
        const owner = address.signingPublicKey;
        const firstInput = inputs[0];
        if (!firstInput)
            throw new TransactionError("TRANSACTION_NO_INPUTS");
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
            if (input.utxo.zoneProgramId !== undefined) {
                throw new TransactionError("TRANSACTION_MERGE_INPUT_ZONE_MISMATCH", { index });
            }
            if (!input.utxo.data.isEmpty() || input.dataHash || input.zoneDataHash) {
                throw new TransactionError("TRANSACTION_MERGE_INPUT_HAS_DATA", { index });
            }
            amount += input.utxo.amount;
            if (amount > 0xffffffffffffffffn) {
                throw new TransactionError("TRANSACTION_SELECTED_BALANCE_OVERFLOW");
            }
        });
        const padded = [...inputs];
        while (padded.length < MERGE_INPUTS)
            padded.push(ProofInputUtxo.dummy());
        this.#prepared = new PreparedMerge({
            inputs: padded,
            output: createProofOutput({
                ownerAddress: address,
                asset,
                amount,
                blinding: mergeOutputBlinding(nullifierKey, firstNullifier),
            }),
            expiryUnixTs: 0xffffffffffffffffn,
            signingPublicKey: owner,
        });
    }
    prepare() {
        return this.#prepared;
    }
    withExpiry(expiryUnixTs) {
        this.#prepared = new PreparedMerge({
            inputs: this.#prepared.inputs,
            output: this.#prepared.output,
            expiryUnixTs: checkedU64(expiryUnixTs, "expiryUnixTs"),
            signingPublicKey: this.#prepared.signingPublicKey,
        });
        return this;
    }
}
export class ConfidentialSplit {
    #owner;
    #input;
    #asset;
    #numOutputs;
    #perOutputAmount;
    #payerHash;
    #seed = randomBlinding();
    constructor(input) {
        if (!Number.isInteger(input.numOutputs) || input.numOutputs < 2 || input.numOutputs > 8) {
            throw new TransactionError("TRANSACTION_SPLIT_INVALID_PART_COUNT", {
                numOutputs: input.numOutputs,
            });
        }
        if (input.owner.signingPublicKey.signatureType() === "p256") {
            throw new TransactionError("TRANSACTION_P256_TRANSACT_UNSUPPORTED");
        }
        if (input.owner.solanaAddress() !== input.payer) {
            throw new TransactionError("TRANSACTION_ED25519_PAYER_MISMATCH", {
                owner: input.owner.solanaAddress(),
                payer: input.payer,
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
        if (input.input.dataHash !== undefined ||
            input.input.zoneDataHash !== undefined ||
            !input.input.utxo.data.isEmpty()) {
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
        this.#payerHash = hashField(decodeAddress(input.payer));
    }
    prepare() {
        const outputs = Array.from({ length: 8 }, (_, index) => createProofOutput({
            ownerAddress: this.#owner,
            asset: this.#asset,
            amount: index < this.#numOutputs ? this.#perOutputAmount : 0n,
            blinding: deriveBlinding(this.#seed, index),
        }));
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
    sign(keypair, assets) {
        const prepared = this.prepare();
        const tx = keypair.viewingKey().transactionViewingKey(prepared.firstNullifier);
        const salt = randomSalt();
        return prepared.finalize({
            txViewingPublicKey: tx.publicKey(),
            salt,
            payload: {
                viewTag: prepared.ownerViewTag(),
                data: encryptSplit(tx, prepared.owner.viewingPublicKey, encodeSplitBundle(prepared.bundlePlaintext(assets)), salt, 0),
            },
        });
    }
}
export class PreparedSplit {
    owner;
    input;
    asset;
    outputs;
    firstNullifier;
    numOutputs;
    perOutputAmount;
    blindingSeed;
    payerPublicKeyHash;
    constructor(input) {
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
        const blindingSeed = checked(input.blindingSeed, 32, "blinding seed");
        input.outputs.forEach((output, index) => {
            const expectedAmount = index < input.numOutputs ? perOutputAmount : 0n;
            if (!equal(output.ownerHash(), input.owner.ownerHash()) ||
                output.asset !== input.input.utxo.asset ||
                output.amount !== expectedAmount ||
                !equal(output.blinding, deriveBlinding(blindingSeed, index)) ||
                output.zoneProgramId !== undefined ||
                output.zoneDataHash !== undefined ||
                output.dataHash !== undefined ||
                !output.data.isEmpty()) {
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
        this.payerPublicKeyHash = checked(input.payerPublicKeyHash, 32, "payer public key hash");
    }
    bundlePlaintext(assets) {
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
    ownerViewTag() {
        return this.owner.confidentialViewTag();
    }
    finalize(input) {
        const tag = this.ownerViewTag();
        const outputs = this.outputs.map((output, index) => ({
            utxoHash: output.hash(),
            ownerTag: { kind: "inline", value: tag },
            ...(index === 0 ? { data: new Uint8Array(input.payload.data) } : {}),
        }));
        return new SppProofInputs({
            payerPublicKeyHash: this.payerPublicKeyHash,
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
