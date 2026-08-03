import { createAssociatedTokenAccountInstruction } from "../interface/instructions/index.js";
import { SOL_MINT } from "../transaction/wallet/asset.js";
import { createSplit, createTransfer, createWithdrawal, } from "./actions.js";
import { wrapWalletError } from "./error.js";
import { authorizePrivateTransaction } from "./private-transaction.js";
export async function buildTransferTransaction(input, context) {
    try {
        const created = await createTransfer({
            client: input.client,
            wallet: input.wallet,
            payer: input.feePayer,
            recipient: input.recipient,
            asset: input.asset ?? SOL_MINT,
            amount: input.amount,
        }, context);
        return await buildAuthorizedTransaction(input, created.transaction, [], context);
    }
    catch (cause) {
        throw wrapWalletError("WALLET_BUILD_TRANSFER", cause);
    }
}
export async function buildWithdrawalTransaction(input, context) {
    try {
        const asset = input.asset ?? SOL_MINT;
        const created = await createWithdrawal({
            wallet: input.wallet,
            payer: input.feePayer,
            recipient: input.recipient,
            asset,
            amount: input.amount,
            ...(input.splTokenProgram === undefined ? {} : { splTokenProgram: input.splTokenProgram }),
        });
        const setupInstructions = asset === SOL_MINT
            ? []
            : [
                await createAssociatedTokenAccountInstruction({
                    payer: input.feePayer,
                    owner: input.recipient,
                    mint: asset,
                    ...(input.splTokenProgram === undefined
                        ? {}
                        : { tokenProgram: input.splTokenProgram }),
                }),
            ];
        return await buildAuthorizedTransaction(input, created.transaction, setupInstructions, context);
    }
    catch (cause) {
        throw wrapWalletError("WALLET_BUILD_WITHDRAWAL", cause);
    }
}
export async function buildSplitTransaction(input, context) {
    try {
        const created = createSplit({
            wallet: input.wallet,
            payer: input.feePayer,
            asset: input.asset ?? SOL_MINT,
            parts: input.parts ?? 2,
            ...(input.input === undefined ? {} : { input: input.input }),
        });
        return await buildAuthorizedTransaction(input, created.transaction, [], context);
    }
    catch (cause) {
        throw wrapWalletError("WALLET_BUILD_SPLIT", cause);
    }
}
async function buildAuthorizedTransaction(input, transaction, setupInstructions, context) {
    const authorized = await authorizePrivateTransaction(transaction, input.wallet, input.authority);
    return input.client.assembleAuthorizedPrivateTransaction({
        authorized,
        feePayer: input.feePayer,
        ...(setupInstructions === undefined || setupInstructions.length === 0
            ? {}
            : { setupInstructions }),
    }, context);
}
