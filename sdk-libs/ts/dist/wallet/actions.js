import { SPL_TOKEN_PROGRAM_ID } from "../interface/program.js";
import {} from "../interface/types.js";
import { associatedTokenAddress, splAssetVaultPda } from "../interface/pda/index.js";
import { ShieldedAddress } from "../keypair/shielded.js";
import { SOL_MINT } from "../transaction/wallet/asset.js";
import { WalletError, wrapWalletError } from "./error.js";
import { equalBytes } from "./internal.js";
import { resolveRegisteredAddress } from "./registry.js";
export class UnsignedPrivateTransaction {
    #payer;
    #tree;
    #inputs;
    #action;
    #withdrawal;
    #summary;
    constructor(input) {
        this.#payer = input.payer;
        this.#tree = input.tree;
        this.#inputs = Object.freeze([...input.inputs]);
        this.#action = input.action;
        if (input.withdrawal !== undefined)
            this.#withdrawal = input.withdrawal;
        this.#summary = input.summary;
    }
    payer() {
        return this.#payer;
    }
    tree() {
        return this.#tree;
    }
    inputCount() {
        return this.#inputs.length;
    }
    /** @internal */
    _inputs() {
        return this.#inputs;
    }
    /** @internal */
    _action() {
        return this.#action;
    }
    /** @internal */
    _withdrawal() {
        return this.#withdrawal;
    }
    /** @internal */
    _summary() {
        return this.#summary;
    }
}
/** Rust takes a `u64`, so only a value outside that range is refused. */
function u64Amount(amount) {
    if (amount < 0n || amount > 0xffffffffffffffffn) {
        throw new WalletError("WALLET_INVALID_AMOUNT", {
            details: { amount: amount.toString() },
        });
    }
}
function plain(entry) {
    return (entry.utxo.zoneProgramId === undefined &&
        entry.zoneDataHash === undefined &&
        entry.dataHash === undefined &&
        entry.utxo.data.isEmpty());
}
function spendTree(wallet, asset, eligible) {
    const trees = new Set(wallet
        .utxos()
        .filter((entry) => !entry.spent && entry.utxo.asset === asset && eligible(entry))
        .map((entry) => entry.outputContext.tree));
    const first = trees.values().next();
    if (first.done) {
        throw new WalletError("WALLET_INSUFFICIENT_BALANCE", {
            details: { requested: "1", available: "0" },
        });
    }
    if (trees.size !== 1) {
        throw new WalletError("WALLET_MULTIPLE_INPUT_TREES", {
            details: { asset, treeCount: trees.size },
        });
    }
    return first.value;
}
function selectInputs(wallet, tree, asset, amount, eligible) {
    const selected = [];
    let available = 0n;
    for (const entry of wallet.utxos()) {
        if (entry.spent ||
            entry.utxo.asset !== asset ||
            entry.outputContext.tree !== tree ||
            !eligible(entry)) {
            continue;
        }
        selected.push({ entry });
        available += entry.utxo.amount;
        // Rust sums into a `u64`, so a running total past that ceiling is a
        // rejection there rather than a wider number.
        if (available > 0xffffffffffffffffn) {
            throw new WalletError("WALLET_SELECTED_BALANCE_OVERFLOW", {
                details: { available: available.toString() },
            });
        }
        if (available >= amount)
            return Object.freeze(selected);
    }
    throw new WalletError("WALLET_INSUFFICIENT_BALANCE", {
        details: { requested: amount.toString(), available: available.toString() },
    });
}
async function withdrawal(recipient, asset, splTokenProgram) {
    if (asset === SOL_MINT) {
        return {
            target: { kind: "sol", recipient },
            accounts: { kind: "sol", recipient },
        };
    }
    const tokenProgram = splTokenProgram ?? SPL_TOKEN_PROGRAM_ID;
    const [userTokenAccount, [splTokenInterface, vaultBump]] = await Promise.all([
        associatedTokenAddress(recipient, asset, tokenProgram),
        splAssetVaultPda(asset),
    ]);
    return {
        target: { kind: "spl", userTokenAccount, splTokenInterface, vaultBump },
        accounts: {
            kind: "spl",
            mint: asset,
            splTokenInterface,
            userTokenAccount,
            tokenProgram,
        },
    };
}
export async function createWithdrawal(params) {
    u64Amount(params.amount);
    if (params.amount === 0n) {
        throw new WalletError("WALLET_INVALID_AMOUNT", { details: { amount: "0" } });
    }
    const tree = spendTree(params.wallet, params.asset, plain);
    const inputs = selectInputs(params.wallet, tree, params.asset, params.amount, plain);
    const resolved = await withdrawal(params.recipient, params.asset, params.splTokenProgram);
    return Object.freeze({
        transaction: new UnsignedPrivateTransaction({
            payer: params.payer,
            tree,
            inputs,
            action: {
                kind: "withdrawal",
                asset: params.asset,
                amount: params.amount,
                target: resolved.target,
            },
            withdrawal: resolved.accounts,
            summary: `private transaction withdrawal of ${String(params.amount)} to ${params.recipient}`,
        }),
        withdrawal: resolved.accounts,
    });
}
export async function createTransfer(params, context) {
    u64Amount(params.amount);
    try {
        const recipient = params.recipient;
        if (recipient instanceof ShieldedAddress) {
            const tree = spendTree(params.wallet, params.asset, plain);
            const inputs = selectInputs(params.wallet, tree, params.asset, params.amount, plain);
            return Object.freeze({
                transaction: new UnsignedPrivateTransaction({
                    payer: params.payer,
                    tree,
                    inputs,
                    action: {
                        kind: "transfer",
                        recipient,
                        asset: params.asset,
                        amount: params.amount,
                    },
                    summary: `private transaction transfer of ${String(params.amount)} to a shielded address`,
                }),
                recipient: {
                    kind: "shielded",
                    address: recipient,
                    viewTag: recipient.confidentialViewTag(),
                },
            });
        }
        if (params.client === undefined) {
            throw new WalletError("WALLET_RECIPIENT_CLIENT_REQUIRED");
        }
        const registered = await resolveRegisteredAddress({ rpc: params.client, owner: recipient }, context);
        if (registered === undefined) {
            throw new WalletError("WALLET_RECIPIENT_NOT_REGISTERED", {
                details: { recipient },
            });
        }
        const tree = spendTree(params.wallet, params.asset, plain);
        const inputs = selectInputs(params.wallet, tree, params.asset, params.amount, plain);
        return Object.freeze({
            transaction: new UnsignedPrivateTransaction({
                payer: params.payer,
                tree,
                inputs,
                action: {
                    kind: "transfer",
                    recipient: registered.address,
                    asset: params.asset,
                    amount: params.amount,
                },
                summary: `private transaction transfer of ${String(params.amount)} to ${recipient}`,
            }),
            recipient: { kind: "registered", ...registered },
        });
    }
    catch (cause) {
        throw wrapWalletError("WALLET_CREATE_TRANSFER", cause);
    }
}
export function createSplit(params) {
    if (!Number.isInteger(params.parts) || params.parts < 2 || params.parts > 8) {
        throw new WalletError("WALLET_SPLIT_INVALID_PART_COUNT", {
            details: { parts: params.parts },
        });
    }
    const entries = params.wallet
        .utxos()
        .filter((entry) => !entry.spent && entry.utxo.asset === params.asset);
    const named = params.input
        ? entries.find((entry) => equalBytes(entry.outputContext.hash, params.input))
        : undefined;
    if (params.input !== undefined && named === undefined) {
        throw new WalletError("WALLET_INPUT_UTXO_UNAVAILABLE");
    }
    const tree = named ? named.outputContext.tree : spendTree(params.wallet, params.asset, plain);
    const candidates = entries.filter((entry) => entry.outputContext.tree === tree && plain(entry));
    const selected = named ??
        [...candidates]
            .filter((entry) => entry.utxo.amount % BigInt(params.parts) === 0n)
            .sort((left, right) => left.utxo.amount > right.utxo.amount ? -1 : left.utxo.amount < right.utxo.amount ? 1 : 0)[0];
    if (selected === undefined) {
        const largest = [...candidates].sort((left, right) => left.utxo.amount > right.utxo.amount ? -1 : 1)[0];
        if (largest !== undefined) {
            throw new WalletError("WALLET_SPLIT_NOT_DIVISIBLE", {
                details: { amount: largest.utxo.amount.toString(), parts: params.parts },
            });
        }
        throw new WalletError("WALLET_INSUFFICIENT_BALANCE");
    }
    const hash = selected.outputContext.hash;
    if (selected.utxo.zoneProgramId !== undefined) {
        throw new WalletError("WALLET_SPLIT_INPUT_ZONE_MISMATCH", { details: { hash } });
    }
    if (!plain(selected))
        throw new WalletError("WALLET_SPLIT_INPUT_HAS_DATA", { details: { hash } });
    if (selected.utxo.amount % BigInt(params.parts) !== 0n) {
        throw new WalletError("WALLET_SPLIT_NOT_DIVISIBLE", {
            details: { amount: selected.utxo.amount.toString(), parts: params.parts },
        });
    }
    const perOutputAmount = selected.utxo.amount / BigInt(params.parts);
    return Object.freeze({
        transaction: new UnsignedPrivateTransaction({
            payer: params.payer,
            tree,
            inputs: [{ entry: selected }],
            action: {
                kind: "split",
                asset: params.asset,
                numOutputs: params.parts,
                perOutputAmount,
            },
            summary: `private transaction split into ${String(params.parts)} utxos of ${String(perOutputAmount)}`,
        }),
        numOutputs: params.parts,
        perOutputAmount,
    });
}
