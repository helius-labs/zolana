import { getAddressEncoder } from "@solana/kit";
import { ShieldedAddress } from "../keypair/shielded.js";
import { Merge } from "../transaction/instructions/builders.js";
import { ProofInputUtxo } from "../transaction/utxo.js";
import { SOL_MINT } from "../transaction/wallet/asset.js";
import { WalletError, wrapWalletError } from "./error.js";
import { bytesKey, equalBytes } from "./internal.js";
import { internalMergeRecord } from "./registry.js";
const addressEncoder = getAddressEncoder();
/** @internal */
export function createMerge(params) {
    const eligible = params.wallet
        .utxos()
        .filter((entry) => !entry.spent && entry.utxo.asset === params.asset);
    const selected = selectMergeEntries(eligible, params.inputs);
    const tree = selected[0]?.outputContext.tree;
    if (tree === undefined)
        throw new WalletError("WALLET_NOTHING_TO_MERGE");
    if (selected.some((entry) => entry.outputContext.tree !== tree)) {
        throw new WalletError("WALLET_INPUT_UTXO_TREE_MISMATCH");
    }
    const nullifierKey = params.material.nullifierKey;
    const inputs = selected.map((entry) => new ProofInputUtxo({
        utxo: entry.utxo,
        nullifierKey,
        ...(entry.dataHash === undefined ? {} : { dataHash: entry.dataHash }),
        ...(entry.zoneDataHash === undefined ? {} : { zoneDataHash: entry.zoneDataHash }),
    }));
    const prepared = new Merge({
        address: ShieldedAddress.fromPublicKeys(params.material.signingPublicKey, params.material.nullifierKey.publicKey(), params.material.viewingPublicKey),
        nullifierKey,
    }, inputs).prepare();
    return Object.freeze({
        prepared,
        numInputs: selected.length,
        mergedAmount: prepared.output.amount,
        tree,
    });
}
function isPlain(entry) {
    return (entry.utxo.zoneProgramId === undefined &&
        entry.dataHash === undefined &&
        entry.zoneDataHash === undefined &&
        entry.utxo.data.isEmpty());
}
function selectMergeEntries(entries, hashes) {
    if (hashes !== undefined) {
        if (hashes.length < 2)
            throw new WalletError("WALLET_NOTHING_TO_MERGE");
        if (hashes.length > 8) {
            throw new WalletError("WALLET_TOO_MANY_INPUTS", {
                details: { got: hashes.length, max: 8 },
            });
        }
        const seen = new Set();
        return hashes.map((hash) => {
            const key = bytesKey(hash);
            if (seen.has(key))
                throw new WalletError("WALLET_DUPLICATE_INPUT_UTXO");
            seen.add(key);
            const entry = entries.find((candidate) => equalBytes(candidate.outputContext.hash, hash));
            if (entry === undefined)
                throw new WalletError("WALLET_INPUT_UTXO_UNAVAILABLE");
            return entry;
        });
    }
    const plain = entries.filter(isPlain);
    const trees = new Set(plain.map((entry) => entry.outputContext.tree));
    if (trees.size > 1)
        throw new WalletError("WALLET_MULTIPLE_INPUT_TREES");
    const selected = [...plain]
        .sort((left, right) => left.utxo.amount < right.utxo.amount ? -1 : left.utxo.amount > right.utxo.amount ? 1 : 0)
        .slice(0, 8);
    if (selected.length < 2)
        throw new WalletError("WALLET_NOTHING_TO_MERGE");
    return selected;
}
/** @internal */
export class MergeMaterial {
    signingPublicKey;
    viewingPublicKey;
    nullifierKey;
    constructor(input) {
        this.signingPublicKey = input.signingPublicKey;
        this.viewingPublicKey = input.viewingPublicKey;
        this.nullifierKey = input.nullifierKey;
    }
    static fromKeypair(keypair) {
        return new MergeMaterial({
            signingPublicKey: keypair.signingPublicKey(),
            viewingPublicKey: keypair.viewingPublicKey(),
            nullifierKey: keypair.nullifierKey(),
        });
    }
    static fromSyncMaterial(material) {
        return new MergeMaterial({
            signingPublicKey: material.identity.signingPublicKey,
            viewingPublicKey: material.identity.viewingPublicKey,
            nullifierKey: material.nullifierKey,
        });
    }
}
export async function buildMergeTransaction(input, context) {
    try {
        const owner = input.authority.solanaPublicKey();
        const material = MergeMaterial.fromSyncMaterial(await input.authority.syncMaterial());
        const created = createMerge({
            wallet: input.wallet,
            material,
            asset: input.asset ?? SOL_MINT,
            ...(input.inputs === undefined ? {} : { inputs: input.inputs }),
        });
        await input.authority.requestUserApproval({
            solanaPublicKey: owner,
            summary: `merge ${String(created.numInputs)} private inputs`,
        });
        const record = await internalMergeRecord({ rpc: input.client, owner }, context);
        validateMergeBuild(record, owner, material);
        if (input.client.tree !== created.tree) {
            throw new WalletError("WALLET_MERGE_TREE_MISMATCH", {
                details: { proofTree: input.client.tree, submitTree: created.tree },
            });
        }
        const proved = await input.client.proveMerge({
            prepared: created.prepared,
            material,
            indexer: treeCheckedIndexer(input.client, created.tree),
        }, context);
        return await input.client.assembleAuthorizedMergeTransaction({
            proved,
            feePayer: input.feePayer,
            userRecord: record.recordAddress,
        }, context);
    }
    catch (cause) {
        throw wrapWalletError("WALLET_BUILD_MERGE", cause);
    }
}
function validateMergeBuild(record, owner, material) {
    if (!record.mergingEnabled) {
        throw new WalletError("WALLET_MERGE_DISABLED", { details: { owner } });
    }
    const signingPublicKey = material.signingPublicKey;
    if (signingPublicKey.signatureType() === "p256") {
        if (record.ownerP256 === undefined ||
            !equalBytes(record.ownerP256, signingPublicKey.p256().toBytes())) {
            throw new WalletError("WALLET_MERGE_SIGNING_KEY_MISMATCH");
        }
    }
    else if (record.ownerP256 !== undefined ||
        !equalBytes(signingPublicKey.ed25519(), new Uint8Array(addressEncoder.encode(owner)))) {
        throw new WalletError("WALLET_MERGE_SIGNING_KEY_MISMATCH");
    }
    if (!equalBytes(record.nullifierPublicKey, material.nullifierKey.publicKey())) {
        throw new WalletError("WALLET_MERGE_NULLIFIER_KEY_MISMATCH");
    }
    if (!equalBytes(record.viewingPublicKey, material.viewingPublicKey.toBytes())) {
        throw new WalletError("WALLET_MERGE_VIEWING_KEY_MISMATCH", { details: { owner } });
    }
}
function treeCheckedIndexer(indexer, submitTree) {
    return {
        getInputMerkleProofs: async (commitments, config, context) => {
            const proofs = await indexer.getInputMerkleProofs(commitments, config, context);
            for (const proof of proofs) {
                for (const proofTree of [
                    proof.state.merkleContext.tree,
                    proof.nullifier.merkleContext.tree,
                ]) {
                    if (proofTree !== submitTree) {
                        throw new WalletError("WALLET_MERGE_TREE_MISMATCH", {
                            details: { proofTree, submitTree },
                        });
                    }
                }
            }
            return proofs;
        },
        getNonInclusionProofs: async (tree, leaves, config, context) => {
            const response = await indexer.getNonInclusionProofs(tree, leaves, config, context);
            for (const proof of response.proofs) {
                if (proof.merkleContext.tree !== submitTree) {
                    throw new WalletError("WALLET_MERGE_TREE_MISMATCH", {
                        details: { proofTree: proof.merkleContext.tree, submitTree },
                    });
                }
            }
            return response;
        },
    };
}
