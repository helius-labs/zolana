import { buildUnsignedTransaction } from "../client/kit.js";
import { SPL_TOKEN_PROGRAM_ID } from "../interface/program.js";
import { checkedTransactionSize } from "../interface/transaction-size.js";
import {} from "../interface/types.js";
import { associatedTokenAddress } from "../interface/pda/index.js";
import { depositInstruction } from "../interface/instructions/index.js";
import { randomBlinding } from "../keypair/bytes.js";
import { ShieldedAddress } from "../keypair/shielded.js";
import { ownerUtxoHash } from "../transaction/utxo.js";
import { SOL_MINT } from "../transaction/wallet/asset.js";
import { WalletError, wrapWalletError } from "./error.js";
import { resolveRegisteredAddress } from "./registry.js";
/** @internal */
export class Deposit {
    data;
    utxoHash;
    asset;
    settlement;
    constructor(input) {
        this.data = Object.freeze({
            ...input.data,
            viewTag: new Uint8Array(input.data.viewTag),
            owner: new Uint8Array(input.data.owner),
            blinding: new Uint8Array(input.data.blinding),
            ...(input.data.memo === undefined ? {} : { memo: new Uint8Array(input.data.memo) }),
        });
        this.utxoHash = new Uint8Array(input.utxoHash);
        this.asset = input.asset;
        this.settlement = input.settlement;
    }
    instruction(tree, depositor) {
        return depositInstruction({
            tree,
            depositor,
            deposits: [{ ...this.data, asset: this.settlement }],
        });
    }
    viewTag() {
        return new Uint8Array(this.data.viewTag);
    }
}
/** @internal */
export async function createDeposit(params) {
    try {
        if (params.amount <= 0n || params.amount > 0xffffffffffffffffn) {
            throw new WalletError("WALLET_INVALID_AMOUNT", {
                details: { amount: params.amount.toString() },
            });
        }
        const owner = params.recipient.ownerHash();
        const blinding = randomBlinding();
        const data = {
            viewTag: params.recipient.viewingPublicKey.x(),
            owner,
            blinding,
            amount: params.amount,
            ...(params.memo === undefined ? {} : { memo: new Uint8Array(params.memo) }),
        };
        // A SOL deposit needs no token accounts, so one supplied alongside it is
        // ignored rather than rejected.
        let settlement = { kind: "sol" };
        if (params.asset !== SOL_MINT) {
            if (params.splTokenAccount === undefined) {
                throw new WalletError("WALLET_MISSING_SPL_TOKEN_ACCOUNT", {
                    details: { mint: params.asset },
                });
            }
            settlement = {
                kind: "spl",
                accounts: {
                    mint: params.asset,
                    userToken: params.splTokenAccount,
                    tokenProgram: params.splTokenProgram ?? SPL_TOKEN_PROGRAM_ID,
                },
            };
        }
        return new Deposit({
            data,
            utxoHash: ownerUtxoHash({
                owner,
                asset: params.asset,
                amount: params.amount,
                blinding,
            }),
            asset: params.asset,
            settlement,
        });
    }
    catch (cause) {
        throw wrapWalletError("WALLET_CREATE_DEPOSIT", cause);
    }
}
export async function buildDepositTransaction(input, context) {
    try {
        let recipient;
        if (input.recipient instanceof ShieldedAddress) {
            recipient = input.recipient;
        }
        else {
            const registered = await resolveRegisteredAddress({ rpc: input.client, owner: input.recipient }, context);
            if (registered === undefined) {
                throw new WalletError("WALLET_RECIPIENT_NOT_REGISTERED", {
                    details: { recipient: input.recipient },
                });
            }
            recipient = registered.address;
        }
        const depositor = input.depositor ?? input.feePayer;
        const tree = input.tree ?? input.client.tree;
        const asset = input.asset ?? SOL_MINT;
        const splTokenAccount = asset === SOL_MINT
            ? undefined
            : (input.splTokenAccount ??
                (await associatedTokenAddress(depositor, asset, input.splTokenProgram)));
        const deposit = await createDeposit({
            recipient,
            asset,
            amount: input.amount,
            ...(splTokenAccount === undefined ? {} : { splTokenAccount }),
            ...(input.splTokenProgram === undefined ? {} : { splTokenProgram: input.splTokenProgram }),
            ...(input.memo === undefined ? {} : { memo: input.memo }),
        });
        const lifetime = await input.client.getLatestBlockhash(context);
        return checkedTransactionSize(buildUnsignedTransaction({
            feePayer: input.feePayer,
            lifetime,
            instructions: [await deposit.instruction(tree, depositor)],
        }));
    }
    catch (cause) {
        throw wrapWalletError("WALLET_BUILD_DEPOSIT", cause);
    }
}
