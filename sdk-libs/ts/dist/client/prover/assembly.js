import { DUMMY_DOMAIN, UTXO_DOMAIN } from "../../interface/program.js";
import { SppProofInputs } from "../../transaction/instructions/transact.js";
import { ProofInputUtxo } from "../../transaction/utxo.js";
import { SOL_MINT } from "../../transaction/wallet/asset.js";
import { ClientError, fromClientCause } from "../error.js";
import { BN254_MODULUS, addressBytes, bigintToBytes, bytesField, bytesToBigInt, field, hashChain, hashField, poseidon, rightHashChain, } from "../internal.js";
const STATE_TREE_HEIGHT = 32;
const NULLIFIER_TREE_HEIGHT = 40;
const ZERO_PROOF = Object.freeze({
    a: new Uint8Array(32),
    b: new Uint8Array(64),
    c: new Uint8Array(32),
});
const CIRCUIT_UTXOS = new WeakMap();
export function circuitUtxo(value) {
    const result = CIRCUIT_UTXOS.get(value);
    if (!result)
        throw new ClientError("CLIENT_PROVER_INPUT");
    return result;
}
export function intoProver(proofInputs, spendProofs, dummyNullifierProofs = []) {
    return assemble(proofInputs, spendProofs, dummyNullifierProofs).proverInputs;
}
export function assemble(proofInputs, spendProofs, dummyNullifierProofs = []) {
    try {
        return assembleUnchecked(proofInputs, spendProofs, dummyNullifierProofs);
    }
    catch (cause) {
        throw fromClientCause(cause);
    }
}
function assembleUnchecked(proofInputs, spendProofs, dummyNullifierProofs) {
    if (!(proofInputs instanceof SppProofInputs)) {
        throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
    }
    proofInputs.checkShape();
    const realInputs = proofInputs.inputUtxos.filter((input) => !input.isDummy());
    if (realInputs.length === 0)
        throw new ClientError("CLIENT_NO_INPUTS");
    const { transferInputs, inputHashes, nullifiers, utxoRoots, nullifierRoots, rootIndexes } = assembleSlots(proofInputs, spendProofs, dummyNullifierProofs, (input) => bytesField(input.utxo.owner.ownerPublicKeyField(), "owner public key"));
    const transferOutputs = proofInputs.outputs.map(createOutput);
    const outputHashes = proofInputs.outputs.map((output) => bytesToBigInt(output.hash()));
    const privateOutputHashes = proofInputs.outputs.map((output) => output.isDummy() ? 0n : bytesToBigInt(output.hash()));
    const outputOwnerFields = transferOutputs.map((output) => output.ownerPublicKeyHash);
    const externalDataHash = bytesField(proofInputs.externalData.hash(), "external data hash");
    const privateTxHash = poseidon([
        hashChain(inputHashes),
        hashChain(privateOutputHashes),
        hashChain(Array.from({ length: inputHashes.length }, () => 0n)),
        externalDataHash,
    ]);
    const movements = publicMovements(proofInputs);
    const publicSlots = movements.assets.flatMap((asset, index) => [
        asset,
        movements.amounts[index] ?? 0n,
    ]);
    const payerPublicKeyHash = bytesField(proofInputs.payerPublicKeyHash, "payer public key hash");
    const signerPublicKeyHashes = [
        payerPublicKeyHash,
        ...Array.from({ length: inputHashes.length }, () => 0n),
    ];
    const allowDummyInputs = 1n;
    const publicInputHash = hashChain([
        hashChain(nullifiers.map(bytesToBigInt)),
        hashChain(outputHashes),
        hashChain(utxoRoots),
        hashChain(nullifierRoots),
        privateTxHash,
        externalDataHash,
        ...publicSlots,
        0n,
        rightHashChain(signerPublicKeyHashes),
        allowDummyInputs,
        hashChain(outputOwnerFields),
    ]);
    const common = Object.freeze({
        inputs: Object.freeze(transferInputs),
        outputs: Object.freeze(transferOutputs),
        externalDataHash: asField(externalDataHash),
        privateTxHash: asField(privateTxHash),
        publicAssets: Object.freeze(movements.assets.map(asField)),
        publicAmounts: Object.freeze(movements.amounts.map(asField)),
        zoneProgramId: asField(0n),
        signerPublicKeyHashes: Object.freeze(signerPublicKeyHashes.map(asField)),
        allowDummyInputs: asField(allowDummyInputs),
        publishedOutputOwnerPublicKeyHashes: Object.freeze(outputOwnerFields.map(asField)),
        publicInputHash: asField(publicInputHash),
    });
    const proverInputs = Object.freeze({ circuit: "transfer", payload: common });
    const instructionData = Object.freeze({
        expiryUnixTs: proofInputs.externalData.expiryUnixTs,
        privateTxHash: bigintToBytes(privateTxHash),
        circuit: Object.freeze({
            kind: "confidentialEddsa",
            inputs: proofInputs.inputUtxos.length,
            outputs: proofInputs.outputs.length,
            publicAssetSlots: 3,
        }),
        txViewingPk: proofInputs.externalData.txViewingPublicKey.toBytes(),
        salt: new Uint8Array(proofInputs.externalData.salt),
        proof: ZERO_PROOF,
        inputs: Object.freeze(proofInputs.inputUtxos.map((_input, index) => {
            const roots = rootIndexes[index];
            const nullifier = nullifiers[index];
            if (!roots || !nullifier) {
                throw new ClientError("CLIENT_PROOF_INPUT_COUNT_MISMATCH", {
                    details: {
                        got: Math.min(rootIndexes.length, nullifiers.length),
                        expected: proofInputs.inputUtxos.length,
                    },
                });
            }
            return Object.freeze({
                nullifierHash: nullifier,
                nullifierTreeRootIndex: roots[1],
                utxoTreeRootIndex: roots[0],
            });
        })),
        interfaceTransfers: Object.freeze(proofInputs.externalData.interfaceTransfers.map((transfer) => transfer.kind === "sol"
            ? Object.freeze({
                kind: transfer.isDeposit ? "solDeposit" : "solWithdrawal",
                amount: transfer.amount,
            })
            : Object.freeze({
                kind: transfer.isDeposit ? "splDeposit" : "splWithdrawal",
                amount: transfer.amount,
                vaultBump: transfer.vaultBump,
            }))),
        ...(proofInputs.externalData.dataHash === undefined
            ? {}
            : { dataHash: new Uint8Array(proofInputs.externalData.dataHash) }),
        ...(proofInputs.externalData.zoneDataHash === undefined
            ? {}
            : { zoneDataHash: new Uint8Array(proofInputs.externalData.zoneDataHash) }),
        outputs: Object.freeze(proofInputs.externalData.outputs.map((output) => Object.freeze({
            ...output,
            utxoHash: new Uint8Array(output.utxoHash),
            ...(output.data === undefined ? {} : { data: new Uint8Array(output.data) }),
        }))),
        messages: Object.freeze(proofInputs.externalData.messages.map((message) => Object.freeze({
            viewTag: new Uint8Array(message.viewTag),
            data: new Uint8Array(message.data),
        }))),
    });
    return Object.freeze({
        instructionData,
        proverInputs,
        publicInputHash: bigintToBytes(publicInputHash),
        nullifiers: Object.freeze(nullifiers.map((nullifier) => new Uint8Array(nullifier))),
        outputHashes: Object.freeze(outputHashes.map((hash) => bigintToBytes(hash))),
        privateTxHash: bigintToBytes(privateTxHash),
        inputRootIndexes: Object.freeze(rootIndexes),
        withProof(proof) {
            return Object.freeze({ ...instructionData, proof: copyProof(proof) });
        },
    });
}
/// Mirrors Rust `assemble_inputs`. Padding is not decided here: a slot with a
/// spend proof is a real spend, a slot without one is a dummy that copies the
/// first real input's roots, root indexes, and owner field so the public-input
/// chain and the on-chain root lookup agree. `ownerField` is the caller's rail:
/// it is the one thing Rust's `OwnerMode` varies, and every rail shares the rest
/// of this loop.
export function assembleSlots(proofInputs, spendProofs, dummyNullifierProofs, ownerField) {
    const transferInputs = [];
    const inputHashes = [];
    const nullifiers = [];
    const utxoRoots = [];
    const nullifierRoots = [];
    const inputOwnerFields = [];
    const rootIndexes = [];
    let proofIndex = 0;
    let dummyProofIndex = 0;
    for (let index = 0; index < proofInputs.inputUtxos.length; index++) {
        const input = proofInputs.inputUtxos[index];
        if (!input) {
            throw new ClientError("CLIENT_PROOF_INPUT_COUNT_MISMATCH", {
                details: { got: index, expected: proofInputs.inputUtxos.length },
            });
        }
        if (input.isDummy()) {
            const first = transferInputs[0];
            const roots = rootIndexes[0];
            if (!first || !roots)
                throw new ClientError("CLIENT_NO_INPUTS");
            const proof = dummyNullifierProofs[dummyProofIndex++];
            if (!proof) {
                throw new ClientError("CLIENT_MISSING_INPUT_MERKLE_PROOF", {
                    details: { index },
                });
            }
            validateDummyNullifierProof(input, proof, index);
            const converted = createDummyTransferInput(input, first.utxoTreeRoot, proof);
            transferInputs.push(converted);
            inputHashes.push(0n);
            nullifiers.push(bigintToBytes(converted.nullifier));
            utxoRoots.push(converted.utxoTreeRoot);
            nullifierRoots.push(converted.nullifierTreeRoot);
            inputOwnerFields.push(converted.ownerPublicKeyHash);
            rootIndexes.push([roots[0], proof.rootIndex]);
            continue;
        }
        const proof = spendProofs[proofIndex++];
        if (!proof) {
            throw new ClientError("CLIENT_MISSING_INPUT_MERKLE_PROOF", {
                details: { index: proofIndex - 1 },
            });
        }
        validateSpendProof(input, proof, proofIndex - 1);
        const owner = ownerField(input, index);
        const converted = createRealInput(input, proof, owner);
        transferInputs.push(converted);
        inputHashes.push(bytesToBigInt(input.hash()));
        nullifiers.push(new Uint8Array(input.nullifier()));
        utxoRoots.push(converted.utxoTreeRoot);
        nullifierRoots.push(converted.nullifierTreeRoot);
        inputOwnerFields.push(owner);
        rootIndexes.push([proof.state.rootIndex, proof.nullifier.rootIndex]);
    }
    return Object.freeze({
        transferInputs: Object.freeze(transferInputs),
        inputHashes: Object.freeze(inputHashes),
        nullifiers: Object.freeze(nullifiers),
        utxoRoots: Object.freeze(utxoRoots),
        nullifierRoots: Object.freeze(nullifierRoots),
        inputOwnerFields: Object.freeze(inputOwnerFields),
        rootIndexes: Object.freeze(rootIndexes),
    });
}
export function createRealInput(input, proof, ownerPublicKeyHash) {
    const value = Object.freeze({
        utxo: input,
        isDummy: asField(0n),
        statePathElements: Object.freeze(proof.state.path.map((item) => asField(bytesField(item, "state path element")))),
        statePathIndex: asField(proof.state.leafIndex),
        nullifierLowValue: asField(bytesField(proof.nullifier.lowElement, "low element")),
        nullifierNextValue: asField(bytesField(proof.nullifier.highElement, "high element")),
        nullifierLowPathElements: Object.freeze(proof.nullifier.path.map((item) => asField(bytesField(item, "nullifier path element")))),
        nullifierLowPathIndex: asField(proof.nullifier.lowElementIndex),
        utxoTreeRoot: asField(bytesField(proof.state.root, "state root")),
        nullifierTreeRoot: asField(bytesField(proof.nullifier.root, "nullifier root")),
        nullifier: asField(bytesField(input.nullifier(), "nullifier")),
        ownerPublicKeyHash: asField(ownerPublicKeyHash),
        nullifierSecret: asField(bytesField(input.nullifierKey.secretBytes(), "nullifier secret")),
    });
    CIRCUIT_UTXOS.set(value, inputCircuitUtxo(input));
    return value;
}
export function createDummyTransferInput(input, utxoRoot, proof, nullifier = input.nullifier()) {
    const value = Object.freeze({
        utxo: input,
        isDummy: asField(1n),
        statePathElements: Object.freeze(Array.from({ length: STATE_TREE_HEIGHT }, () => asField(0n))),
        statePathIndex: asField(0n),
        nullifierLowValue: asField(bytesField(proof.lowElement, "dummy low element")),
        nullifierNextValue: asField(bytesField(proof.highElement, "dummy high element")),
        nullifierLowPathElements: Object.freeze(proof.path.map((item) => asField(bytesField(item, "dummy nullifier path element")))),
        nullifierLowPathIndex: asField(proof.lowElementIndex),
        utxoTreeRoot: asField(utxoRoot),
        nullifierTreeRoot: asField(bytesField(proof.root, "dummy nullifier root")),
        nullifier: asField(bytesField(nullifier, "dummy nullifier")),
        ownerPublicKeyHash: asField(0n),
        nullifierSecret: asField(0n),
    });
    CIRCUIT_UTXOS.set(value, inputCircuitUtxo(input, true));
    return value;
}
export function createOutput(output) {
    const ownerPublicKeyHash = output.ownerAddress
        ? bytesField(output.ownerAddress.signingPublicKey.ownerPublicKeyField(), "output owner public key")
        : hashField(output.ownerTag ?? new Uint8Array(32));
    const value = Object.freeze({
        utxo: output,
        isDummy: asField(output.isDummy() ? 1n : 0n),
        hash: asField(bytesField(output.hash(), "output hash")),
        ownerPublicKeyHash: asField(ownerPublicKeyHash),
        nullifierPublicKey: asField(output.ownerAddress
            ? bytesField(output.ownerAddress.nullifierPublicKey, "output nullifier public key")
            : 0n),
    });
    CIRCUIT_UTXOS.set(value, outputCircuitUtxo(output));
    return value;
}
function inputCircuitUtxo(input, dummy = false) {
    const owner = dummy
        ? 0n
        : poseidon([
            bytesField(input.utxo.owner.ownerPublicKeyField(), "owner public key"),
            bytesField(input.nullifierKey.publicKey(), "nullifier public key"),
        ]);
    return Object.freeze({
        domain: asField(BigInt(dummy ? DUMMY_DOMAIN : UTXO_DOMAIN)),
        owner: asField(owner),
        asset: asField(dummy ? 0n : hashField(addressBytes(input.utxo.asset))),
        amount: asField(dummy ? 0n : input.utxo.amount),
        blinding: asField(bytesToBigInt(input.utxo.blinding)),
        dataHash: asField(dummy ? 0n : input.dataHash ? bytesField(input.dataHash, "data hash") : 0n),
        zoneDataHash: asField(dummy ? 0n : input.zoneDataHash ? bytesField(input.zoneDataHash, "zone data hash") : 0n),
        zoneProgramId: asField(dummy
            ? 0n
            : input.utxo.zoneProgramId
                ? hashField(addressBytes(input.utxo.zoneProgramId))
                : 0n),
    });
}
function outputCircuitUtxo(output) {
    const dummy = output.isDummy();
    return Object.freeze({
        domain: asField(BigInt(dummy ? DUMMY_DOMAIN : UTXO_DOMAIN)),
        owner: asField(dummy ? 0n : bytesField(output.ownerHash(), "output owner")),
        asset: asField(dummy ? 0n : hashField(addressBytes(output.asset))),
        amount: asField(dummy ? 0n : output.amount),
        blinding: asField(bytesToBigInt(output.blinding)),
        dataHash: asField(dummy ? 0n : output.dataHash ? bytesField(output.dataHash, "output data hash") : 0n),
        zoneDataHash: asField(dummy
            ? 0n
            : output.zoneDataHash
                ? bytesField(output.zoneDataHash, "output zone data hash")
                : 0n),
        zoneProgramId: asField(dummy ? 0n : output.zoneProgramId ? hashField(addressBytes(output.zoneProgramId)) : 0n),
    });
}
export function validateSpendProof(input, proof, index) {
    if (!equal(input.hash(), proof.state.leaf)) {
        throw new ClientError("CLIENT_STATE_PROOF_LEAF_MISMATCH", { details: { index } });
    }
    if (!equal(input.nullifier(), proof.nullifier.leaf)) {
        throw new ClientError("CLIENT_NULLIFIER_PROOF_LEAF_MISMATCH", {
            details: { index },
        });
    }
    if (proof.state.merkleContext.tree !== proof.nullifier.merkleContext.tree) {
        throw new ClientError("CLIENT_PROOF_TREE_MISMATCH", { details: { index } });
    }
    if (proof.state.path.length !== STATE_TREE_HEIGHT) {
        throw new ClientError("CLIENT_PROOF_PATH_LENGTH", {
            details: { index, kind: "state", expected: STATE_TREE_HEIGHT, got: proof.state.path.length },
        });
    }
    if (proof.nullifier.path.length !== NULLIFIER_TREE_HEIGHT) {
        throw new ClientError("CLIENT_PROOF_PATH_LENGTH", {
            details: {
                index,
                kind: "nullifier",
                expected: NULLIFIER_TREE_HEIGHT,
                got: proof.nullifier.path.length,
            },
        });
    }
}
function validateDummyNullifierProof(input, proof, index) {
    if (!equal(input.nullifier(), proof.leaf)) {
        throw new ClientError("CLIENT_NULLIFIER_PROOF_LEAF_MISMATCH", { details: { index } });
    }
    if (proof.path.length !== NULLIFIER_TREE_HEIGHT) {
        throw new ClientError("CLIENT_PROOF_PATH_LENGTH", {
            details: {
                index,
                kind: "nullifier",
                expected: NULLIFIER_TREE_HEIGHT,
                got: proof.path.length,
            },
        });
    }
}
function publicMovements(proofInputs) {
    const aggregated = new Map();
    for (const transfer of proofInputs.externalData.interfaceTransfers) {
        const asset = transfer.kind === "sol" ? SOL_MINT : transfer.mint;
        const signed = transfer.isDeposit ? transfer.amount : -transfer.amount;
        aggregated.set(asset, (aggregated.get(asset) ?? 0n) + signed);
    }
    if (aggregated.size > 3) {
        throw new ClientError("CLIENT_PROVER_INPUT");
    }
    const assets = [...aggregated.keys()].map((asset) => hashField(addressBytes(asset)));
    const amounts = [...aggregated.values()].map((amount) => signedField(amount, "public amount"));
    while (assets.length < 3)
        assets.push(0n);
    while (amounts.length < 3)
        amounts.push(0n);
    return Object.freeze({ assets: Object.freeze(assets), amounts: Object.freeze(amounts) });
}
export function signedField(value, name) {
    const result = ((value % BN254_MODULUS) + BN254_MODULUS) % BN254_MODULUS;
    return field(result, name);
}
export function asField(value) {
    return field(value, "field");
}
export function asInteger(value) {
    return value;
}
function equal(left, right) {
    if (left.length !== right.length)
        return false;
    let difference = 0;
    for (let index = 0; index < left.length; index++) {
        difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
    }
    return difference === 0;
}
function copyProof(proof) {
    return Object.freeze({
        a: new Uint8Array(proof.a),
        b: new Uint8Array(proof.b),
        c: new Uint8Array(proof.c),
    });
}
