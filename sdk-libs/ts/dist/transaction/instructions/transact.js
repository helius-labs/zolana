import { address } from "@solana/kit";
import { externalDataHash as interfaceExternalDataHash } from "../../interface/external-data-hash.js";
import { SPP_SUPPORTED_SHAPES as INTERFACE_SUPPORTED_SHAPES, selectSppShape, validateSppShape, } from "../../interface/shape.js";
import {} from "../../interface/types.js";
import { randomBlinding, randomSalt } from "../../keypair/bytes.js";
import { P256PublicKey } from "../../keypair/public-key.js";
import { ShieldedKeypair } from "../../keypair/shielded.js";
import { ViewingKey } from "../../keypair/viewing-key.js";
import { Data } from "../data.js";
import { TransactionError } from "../error.js";
import { ZERO_32, bigIntBytes, checkU64, checked, copy, decodeAddress, equal, hashChain, hashField, poseidon, sha256Bytes, } from "../internal.js";
import { EncryptedScheme, encodeOutputData, encryptConfidential } from "../serialization/codecs.js";
import { ProofInputUtxo, Utxo, createProofOutput, deriveBlinding, } from "../utxo.js";
import { SOL_ASSET_ID } from "../wallet/asset.js";
export const SPP_SUPPORTED_SHAPES = INTERFACE_SUPPORTED_SHAPES;
/**
 * Fixed number of leading sender-owned output slots in a transfer: SPL change at
 * slot 0, SOL change at slot 1. Recipients always start at slot 2.
 */
export const SENDER_SLOT_COUNT = 2;
/** The BN254 scalar modulus, as the decimal literal Rust pins. */
export const BN254_MODULUS_DEC = "21888242871839275222246405745257275088548364400416034343698204186575808495617";
const BN254_MODULUS = BigInt(BN254_MODULUS_DEC);
const I64_MIN = -(2n ** 63n);
const I64_MAX = 2n ** 63n - 1n;
/**
 * A signed public amount as the field element a proof's public inputs carry: a
 * negative amount wraps around the BN254 modulus. Rust takes an `i64`, so the
 * range check here stands in for the type.
 */
export function signedToField(value) {
    if (typeof value !== "bigint" || value < I64_MIN || value > I64_MAX) {
        throw new TransactionError("TRANSACTION_INVALID_AMOUNT", {
            name: "signed amount",
            minimum: I64_MIN.toString(),
            maximum: I64_MAX.toString(),
            actual: String(value),
        });
    }
    return bigIntBytes(value < 0n ? BN254_MODULUS + value : value);
}
/** The field element an asset mint contributes to a proof's public inputs. */
export function assetField(asset) {
    return hashField(decodeAddress(asset));
}
function checkedCount(value, name) {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new TransactionError("TRANSACTION_UNSUPPORTED_SHAPE", { [name]: value });
    }
    return value;
}
export function canonicalShape(inputs, outputs) {
    checkedCount(inputs, "inputs");
    checkedCount(outputs, "outputs");
    try {
        return selectSppShape(inputs, outputs);
    }
    catch (error) {
        throw new TransactionError("TRANSACTION_UNSUPPORTED_SHAPE", { inputs, outputs }, error);
    }
}
/**
 * The proving system whose slot counts the padded transaction already matches.
 * Unlike `canonicalShape` this rounds nothing up: the counts are final by the
 * time a proof is assembled.
 */
export function exactShape(inputs, outputs) {
    const exact = SPP_SUPPORTED_SHAPES.find((shape) => shape.inputs === inputs && shape.outputs === outputs);
    if (!exact) {
        throw new TransactionError("TRANSACTION_UNSUPPORTED_SHAPE", { inputs, outputs });
    }
    return Object.freeze({ ...exact });
}
export function resolveShape(inputs, outputs, declared) {
    if (declared === undefined)
        return canonicalShape(inputs, outputs);
    checkedCount(inputs, "inputs");
    checkedCount(outputs, "outputs");
    const candidate = declared;
    if (typeof candidate !== "object" || candidate === null) {
        throw new TransactionError("TRANSACTION_UNSUPPORTED_SHAPE", {
            declared: String(candidate),
        });
    }
    const shape = candidate;
    checkedCount(shape.inputs, "declaredInputs");
    checkedCount(shape.outputs, "declaredOutputs");
    const supported = SPP_SUPPORTED_SHAPES.some((supportedShape) => supportedShape.inputs === shape.inputs && supportedShape.outputs === shape.outputs);
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
export function slotOrdinal(position) {
    if (!Number.isInteger(position) || position < 0 || position > 0xffff_ffff) {
        throw new TransactionError("TRANSACTION_OUTPUT_SLOT_OVERFLOW", { position });
    }
    return position;
}
/** The `transact` tag, which Rust `ExternalData::new` takes from `tag::TRANSACT`. */
const TRANSACT_DISCRIMINATOR = 12;
/** Rust's default expiry: `u64::MAX`, meaning no expiry. */
const NO_EXPIRY = 0xffffffffffffffffn;
function externalDataHash(data) {
    if (data.outputs.length !== data.resolvedOwnerTags.length) {
        throw new TransactionError("TRANSACTION_OUTPUT_TAG_MISMATCH");
    }
    if (data.outputs.length > 0xffff || data.messages.length > 0xffff) {
        throw new TransactionError("TRANSACTION_TOO_MANY_OUTPUTS");
    }
    const checkedInteger = (value, byteLength, signed = false) => {
        const bits = byteLength * 8;
        if ((!signed && (value < 0n || value >= 1n << BigInt(bits))) ||
            (signed && BigInt.asIntN(bits, value) !== value)) {
            throw new TransactionError("TRANSACTION_INVALID_AMOUNT", {
                value: value.toString(),
                byteLength,
                signed,
            });
        }
    };
    const checkedLength = (bytes) => {
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
        if (output.data !== undefined)
            checkedLength(output.data);
    });
    data.messages.forEach((message) => {
        checkedLength(message.data);
    });
    return interfaceExternalDataHash({
        instructionDiscriminator: data.instructionDiscriminator,
        expiryUnixTs: data.expiryUnixTs,
        interfaceTransfers: data.interfaceTransfers.map((transfer) => transfer.kind === "sol"
            ? {
                kind: transfer.isDeposit ? "solDeposit" : "solWithdrawal",
                amount: transfer.amount,
                recipient: transfer.userSolAccount,
            }
            : {
                kind: transfer.isDeposit ? "splDeposit" : "splWithdrawal",
                amount: transfer.amount,
                userTokenAccount: transfer.userSplToken,
                vault: transfer.splTokenInterface,
            }),
        ...(data.dataHash === undefined ? {} : { dataHash: data.dataHash }),
        ...(data.zoneDataHash === undefined ? {} : { zoneDataHash: data.zoneDataHash }),
        txViewingPk: data.txViewingPublicKey.toBytes(),
        salt: data.salt,
        outputs: data.outputs.map((output, index) => ({
            utxoHash: output.utxoHash,
            ownerTag: data.resolvedOwnerTags[index],
            ...(output.data === undefined ? {} : { data: output.data }),
        })),
        messages: data.messages,
    });
}
export function createExternalData(input) {
    const snapshot = {
        ...input,
        instructionDiscriminator: input.instructionDiscriminator ?? TRANSACT_DISCRIMINATOR,
        expiryUnixTs: input.expiryUnixTs ?? NO_EXPIRY,
        interfaceTransfers: Object.freeze((input.interfaceTransfers ?? []).map((transfer) => Object.freeze({ ...transfer }))),
        salt: checked(input.salt, 16, "salt"),
        // The hash closes over these arrays, so freezing them is what keeps a
        // holder of the returned value from changing the preimage under it.
        outputs: Object.freeze(input.outputs.map((output) => Object.freeze({
            ...output,
            utxoHash: checked(output.utxoHash, 32, "output hash"),
            ownerTag: output.ownerTag.kind === "inline"
                ? Object.freeze({
                    kind: "inline",
                    value: checked(output.ownerTag.value, 32, "output owner tag"),
                })
                : Object.freeze({ ...output.ownerTag }),
            ...(output.data === undefined ? {} : { data: new Uint8Array(output.data) }),
        }))),
        resolvedOwnerTags: Object.freeze(input.resolvedOwnerTags.map((tag) => checked(tag, 32, "resolved owner tag"))),
        messages: Object.freeze(input.messages.map((message) => Object.freeze({
            viewTag: checked(message.viewTag, 32, "message view tag"),
            data: new Uint8Array(message.data),
        }))),
    };
    return sealExternalData(snapshot);
}
/// The builders re-enter through `createExternalData` so a derived value is
/// copied and frozen exactly like the original; a caller keeping the value it
/// passed cannot reach into either.
function sealExternalData(fields) {
    const set = (changed) => createExternalData({ ...fields, ...changed });
    return Object.freeze({
        ...fields,
        hash: () => externalDataHash(fields),
        withInterfaceTransfer: (transfer) => set({ interfaceTransfers: [...fields.interfaceTransfers, transfer] }),
        withInterfaceTransfers: (transfers) => set({ interfaceTransfers: [...transfers] }),
    });
}
export function createInputUtxo(input) {
    const nullifierPublicKey = checked(input.nullifierPublicKey, 32, "nullifier public key");
    const utxo = new Utxo(input.utxo);
    return Object.freeze({
        ...input,
        utxo,
        nullifierPublicKey,
        hash() {
            return utxo.hash(nullifierPublicKey, input.dataHash, input.zoneDataHash);
        },
        isDummy() {
            return utxo.owner.isZero();
        },
    });
}
/**
 * The circuit reads one address hash per input slot, so a set of a different
 * length would silently shift the address chain rather than fail.
 */
export function privateTxHash(input) {
    if (input.addressHashes !== undefined &&
        input.addressHashes.length !== input.inputHashes.length) {
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
export function createEncryptedTransaction(input) {
    const inputs = Object.freeze([...input.inputs]);
    const outputs = Object.freeze([...input.outputs]);
    return Object.freeze({
        ...input,
        inputs,
        outputs,
        // An unused slot contributes a zero hash, matching the circuit and
        // `SppProofInputs.messageHash`.
        hash() {
            return privateTxHash({
                inputHashes: inputs.map((entry) => (entry.isDummy() ? copy(ZERO_32) : entry.hash())),
                outputHashes: outputs.map((entry) => (entry.isDummy() ? copy(ZERO_32) : entry.hash())),
                externalDataHash: input.externalData.hash(),
            });
        },
    });
}
export class SppProofInputs {
    payerPublicKeyHash;
    inputUtxos;
    outputs;
    externalData;
    constructor(input) {
        this.payerPublicKeyHash = checked(input.payerPublicKeyHash, 32, "payer public key hash");
        this.inputUtxos = Object.freeze([...input.inputUtxos]);
        if (this.inputUtxos.some((entry) => !entry.isDummy() && entry.utxo.owner.signatureType() === "p256")) {
            throw new TransactionError("TRANSACTION_P256_TRANSACT_UNSUPPORTED");
        }
        this.outputs = Object.freeze([...input.outputs]);
        this.externalData = input.externalData;
        this.checkShape();
    }
    checkShape() {
        return exactShape(this.inputUtxos.length, this.outputs.length);
    }
    inputUtxoHashes() {
        return this.inputUtxos.filter((input) => !input.isDummy()).map((input) => input.hash());
    }
    inputContexts() {
        return this.inputUtxos
            .filter((input) => !input.isDummy())
            .map((input, index) => Object.freeze({
            index,
            utxoHash: input.hash(),
            nullifier: input.nullifier(),
        }));
    }
    dummyNullifiers() {
        return this.inputUtxos
            .filter((input) => input.isDummy())
            .map((input) => new Uint8Array(input.nullifier()));
    }
    messageHash() {
        const inputHashes = this.inputUtxos.map((input) => input.isDummy() ? copy(ZERO_32) : input.hash());
        const outputHashes = this.outputs.map((output) => output.isDummy() ? copy(ZERO_32) : output.hash());
        return sha256Bytes(privateTxHash({
            inputHashes,
            outputHashes,
            externalDataHash: this.externalData.hash(),
        }));
    }
}
const ZERO_ADDRESS = address("11111111111111111111111111111111");
export class ConfidentialTransfer {
    #owner;
    #inputs;
    #payerPublicKeyHash;
    #recipients = [];
    #blindingSeed = randomBlinding();
    #withdrawal;
    #shape;
    constructor(owner, inputs, payer) {
        if (inputs.length === 0)
            throw new TransactionError("TRANSACTION_NO_INPUTS");
        if (owner.signingPublicKey.signatureType() === "p256") {
            throw new TransactionError("TRANSACTION_P256_TRANSACT_UNSUPPORTED");
        }
        if (owner.solanaAddress() !== payer) {
            throw new TransactionError("TRANSACTION_ED25519_PAYER_MISMATCH", {
                owner: owner.solanaAddress(),
                payer,
            });
        }
        inputs.forEach((input, index) => {
            if (input.isDummy()) {
                throw new TransactionError("TRANSACTION_DUMMY_INPUT_NOT_ALLOWED", { index });
            }
            if (!equal(input.utxo.owner.toBytes(), owner.signingPublicKey.toBytes()) ||
                !equal(input.nullifierKey.publicKey(), owner.nullifierPublicKey)) {
                throw new TransactionError("TRANSACTION_INPUT_OWNER_MISMATCH", { index });
            }
        });
        this.#owner = owner;
        this.#inputs = [...inputs];
        this.#payerPublicKeyHash = hashField(decodeAddress(payer));
    }
    withShape(shape) {
        this.#shape = resolveShape(this.#inputs.length, SENDER_SLOT_COUNT + this.#recipients.length, shape);
        return this;
    }
    requiresP256Owner() {
        return false;
    }
    // Rust `send` performs no amount check; `checkU64` stands in for its `u64`
    // parameter and nothing more. A zero-amount recipient is a slot Rust builds.
    send(recipient, asset, amount) {
        checkU64(amount, "recipient amount");
        this.#recipients.push({ address: recipient, asset, amount });
    }
    withdraw(asset, amount, target) {
        if (this.#withdrawal)
            throw new TransactionError("TRANSACTION_WITHDRAWAL_ALREADY_SET");
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
    prepare() {
        const splAssets = new Set([
            ...this.#inputs.map((input) => input.utxo.asset),
            ...this.#recipients.map((recipient) => recipient.asset),
            ...(this.#withdrawal ? [this.#withdrawal.asset] : []),
        ].filter((asset) => asset !== ZERO_ADDRESS));
        if (splAssets.size > 1)
            throw new TransactionError("TRANSACTION_MULTIPLE_PUBLIC_SPL_ASSETS");
        const splAsset = [...splAssets][0];
        const publicSol = this.#withdrawal?.asset === ZERO_ADDRESS ? -this.#withdrawal.amount : 0n;
        const publicSpl = this.#withdrawal && this.#withdrawal.asset !== ZERO_ADDRESS ? -this.#withdrawal.amount : 0n;
        const change = (asset, publicAmount) => {
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
        const outputs = [
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
            ...this.#recipients.map((recipient, index) => createProofOutput({
                ownerAddress: recipient.address,
                asset: recipient.asset,
                amount: recipient.amount,
                blinding: deriveBlinding(this.#blindingSeed, index + SENDER_SLOT_COUNT),
            })),
        ];
        const shape = resolveShape(this.#inputs.length, outputs.length, this.#shape);
        // Padding belongs to `finalize`, where Rust does it: the slots handed to an
        // authority for encryption are the real outputs only.
        const inputs = [...this.#inputs];
        const target = this.#withdrawal?.target;
        const interfaceTransfers = this.#withdrawal === undefined || target === undefined
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
                        userSplToken: target.userTokenAccount,
                        splTokenInterface: target.splTokenInterface,
                        vaultBump: target.vaultBump,
                    },
                ];
        const firstInput = this.#inputs[0];
        if (!firstInput)
            throw new TransactionError("TRANSACTION_NO_INPUTS");
        const preparedBase = {
            owner: this.#owner,
            inputs: Object.freeze(inputs),
            outputs: Object.freeze(outputs),
            firstNullifier: firstInput.nullifier(),
            shape,
            payerPublicKeyHash: copy(this.#payerPublicKeyHash),
            interfaceTransfers: Object.freeze(interfaceTransfers),
        };
        return Object.freeze({
            ...preparedBase,
            finalize: (encrypted) => finalizeTransfer(preparedBase, encrypted),
        });
    }
    /**
     * Keypair rail: encrypt every real slot with the owner's own viewing key and
     * sign in place. The authority rail is `prepare` plus `PreparedTransfer.finalize`,
     * with encryption and signing delegated to a `WalletAuthority`.
     */
    sign(keypair, assets) {
        const prepared = this.prepare();
        const tx = keypair.viewingKey().transactionViewingKey(prepared.firstNullifier);
        const salt = randomSalt();
        const signed = prepared.finalize({
            txViewingPublicKey: tx.publicKey(),
            salt,
            payload: encodeConfidentialSlots(prepared.outputs, assets, tx, salt),
        });
        return signed;
    }
}
function finalizeTransfer(prepared, encrypted) {
    // Slots are read by output position, so a longer list would be dropped
    // without a trace rather than encrypted into the transaction.
    if (encrypted.payload.length > prepared.outputs.length) {
        throw new TransactionError("TRANSACTION_EXCESS_OUTPUT_SLOTS", {
            got: encrypted.payload.length,
            outputs: prepared.outputs.length,
        });
    }
    const senderResolved = prepared.owner.confidentialViewTag();
    const senderTag = equal(hashField(senderResolved), prepared.payerPublicKeyHash)
        ? { kind: "account", index: 0 }
        : { kind: "inline", value: senderResolved };
    // The circuit requires every dummy output tag to identify a real participant.
    // Rust uses the first real input signer, which is this transfer's owner.
    const padCount = Math.max(prepared.shape.outputs - prepared.outputs.length, 0);
    const outputUtxos = [
        ...prepared.outputs,
        ...Array.from({ length: padCount }, () => createProofOutput({
            asset: ZERO_ADDRESS,
            amount: 0n,
            ownerTag: senderResolved,
        })),
    ];
    const inputUtxos = [...prepared.inputs];
    while (inputUtxos.length < prepared.shape.inputs)
        inputUtxos.push(ProofInputUtxo.dummy());
    // Length-matched random ciphertext for every position without a real encoding:
    // padded slots and zero-value change slots.
    const needsDummyCiphertext = padCount > 0 || prepared.outputs.some((_, index) => encrypted.payload[index] === undefined);
    const dummyLength = needsDummyCiphertext ? dummyCiphertextLength(encrypted.salt) : 0;
    const outputs = [];
    const resolved = [];
    for (let index = 0; index < outputUtxos.length; index++) {
        const output = outputUtxos[index];
        if (!output)
            throw new TransactionError("TRANSACTION_MISSING_OUTPUT", { index });
        const slot = encrypted.payload[index];
        if (index < SENDER_SLOT_COUNT) {
            outputs.push({
                utxoHash: output.hash(),
                ownerTag: senderTag,
                data: slot?.data ?? randomBytes(dummyLength),
            });
            resolved.push(senderResolved);
        }
        else {
            const tag = slot?.viewTag ?? output.ownerTag;
            if (!tag)
                throw new TransactionError("TRANSACTION_MISSING_OUTPUT");
            outputs.push({
                utxoHash: output.hash(),
                ownerTag: { kind: "inline", value: tag },
                data: slot?.data ?? randomBytes(dummyLength),
            });
            resolved.push(tag);
        }
    }
    const externalData = createExternalData({
        instructionDiscriminator: TRANSACT_DISCRIMINATOR,
        expiryUnixTs: 0xffffffffffffffffn,
        interfaceTransfers: prepared.interfaceTransfers,
        txViewingPublicKey: encrypted.txViewingPublicKey,
        salt: encrypted.salt,
        outputs,
        resolvedOwnerTags: resolved,
        messages: [],
    });
    return new SppProofInputs({
        payerPublicKeyHash: prepared.payerPublicKeyHash,
        inputUtxos,
        outputs: outputUtxos,
        externalData,
    });
}
function randomBytes(length) {
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
export function encodeConfidentialSlots(outputs, assets, tx, salt) {
    return outputs.map((output, slotIndex) => {
        const address = output.ownerAddress;
        if (output.isDummy() || address === undefined)
            return undefined;
        return {
            viewTag: address.signingPublicKey.confidentialViewTag(),
            data: encodeOutputData(EncryptedScheme.confidential, encryptConfidential(tx, address.viewingPublicKey, {
                assetId: assets.assetId(output.asset),
                amount: output.amount,
                blinding: output.blinding,
                ...(output.zoneProgramId === undefined ? {} : { zoneProgramId: output.zoneProgramId }),
                data: output.data,
            }, salt, slotOrdinal(slotIndex)), "encrypted"),
        };
    });
}
/**
 * The exact ciphertext byte length of a real confidential slot, derived by
 * encoding a throwaway output through the same path. This keeps dummy slots
 * byte-length-indistinguishable from real ones without pinning a brittle constant.
 */
function dummyCiphertextLength(salt) {
    const throwaway = ViewingKey.generate();
    return encodeOutputData(EncryptedScheme.confidential, encryptConfidential(throwaway, throwaway.publicKey(), { assetId: SOL_ASSET_ID, amount: 0n, blinding: randomBlinding(), data: new Data() }, salt, 0), "encrypted").length;
}
