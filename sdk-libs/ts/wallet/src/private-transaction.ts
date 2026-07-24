import { type SignedPrivateTransaction, type ZolanaClient } from "@zolana/client";
import type { Address, Bytes32, RequestContext, Transaction } from "@zolana/interface";
import {
  ConfidentialTransfer,
  ProofInputUtxo,
  type SppProofInputs,
  type Wallet,
} from "@zolana/transaction";
import { ConfidentialSplit } from "@zolana/transaction/instructions";

import { UnsignedPrivateTransaction } from "./actions.js";
import { WalletError, wrapWalletError } from "./error.js";
import { equalBytes } from "./internal.js";
import type { TransactionSigner } from "./submit.js";
import type { WalletAuthority } from "./wallet-authority.js";

function matchingInput(
  wallet: Wallet,
  tree: Address,
  expected: ReturnType<UnsignedPrivateTransaction["_inputs"]>[number]["entry"],
): boolean {
  return wallet
    .utxos()
    .some(
      (entry) =>
        !entry.spent &&
        entry.outputContext.tree === tree &&
        equalBytes(entry.outputContext.hash, expected.outputContext.hash) &&
        equalBytes(entry.nullifier, expected.nullifier) &&
        entry.utxo.asset === expected.utxo.asset &&
        entry.utxo.amount === expected.utxo.amount &&
        equalBytes(entry.utxo.blinding, expected.utxo.blinding),
    );
}

async function applyP256Signature(
  proofInputs: SppProofInputs,
  authority: WalletAuthority,
): Promise<void> {
  const requiresP256 = proofInputs.inputUtxos.some(
    (input) => !input.isDummy() && input.utxo.owner.signatureType() === "p256",
  );
  if (requiresP256) {
    proofInputs.applyP256Signature(await authority.signP256(proofInputs.messageHash()));
  }
}

async function prepareShielded(
  transaction: UnsignedPrivateTransaction,
  wallet: Wallet,
  authority: WalletAuthority,
): Promise<SignedPrivateTransaction> {
  const unsignedInputs = transaction._inputs();
  unsignedInputs.forEach((input, index) => {
    if (!matchingInput(wallet, transaction.tree(), input.entry)) {
      throw new WalletError("WALLET_UNSIGNED_INPUT_UNAVAILABLE", {
        details: { index },
      });
    }
  });
  const [address, nullifierKey] = await Promise.all([
    authority.shieldedAddress(),
    authority.spendNullifierKey(),
  ]);
  const inputs = unsignedInputs.map(
    ({ entry }) =>
      new ProofInputUtxo({
        utxo: entry.utxo,
        nullifierKey,
        ...(entry.dataHash === undefined ? {} : { dataHash: entry.dataHash }),
        ...(entry.zoneDataHash === undefined ? {} : { zoneDataHash: entry.zoneDataHash }),
      }),
  );
  const action = transaction._action();
  let proofInputs: SppProofInputs;
  if (action.kind === "split") {
    const input = inputs[0];
    if (input === undefined) throw new WalletError("WALLET_NO_INPUTS");
    const prepared = new ConfidentialSplit({
      owner: address,
      input,
      asset: action.asset,
      numOutputs: action.numOutputs,
      perOutputAmount: action.perOutputAmount,
      payer: transaction.payer(),
    }).prepare();
    const encrypted = await authority.encryptSplit({
      firstNullifier: prepared.firstNullifier,
      viewTag: prepared.owner.confidentialViewTag(),
      bundle: prepared.bundlePlaintext(wallet.registry),
    });
    await authority.requestUserApproval({
      solanaPublicKey: authority.solanaPublicKey(),
      summary: transaction._summary(),
    });
    proofInputs = prepared.finalize({
      txViewingPublicKey: encrypted.txViewingPublicKey,
      salt: encrypted.salt,
      payload: encrypted.payload,
    });
  } else {
    const transfer = new ConfidentialTransfer(address, inputs, transaction.payer());
    if (action.kind === "transfer") {
      transfer.send(action.recipient, action.asset, action.amount);
    } else {
      transfer.withdraw(action.asset, action.amount, action.target);
    }
    const prepared = transfer.prepare();
    const encrypted = await authority.encryptConfidentialTransfer({
      firstNullifier: prepared.firstNullifier,
      outputs: prepared.outputs,
      assets: wallet.registry,
    });
    await authority.requestUserApproval({
      solanaPublicKey: authority.solanaPublicKey(),
      summary: transaction._summary(),
    });
    proofInputs = prepared.finalize({
      txViewingPublicKey: encrypted.txViewingPublicKey,
      salt: encrypted.salt,
      payload: encrypted.payload,
    });
  }
  await applyP256Signature(proofInputs, authority);
  const withdrawal = transaction._withdrawal();
  return Object.freeze({
    transaction: proofInputs,
    tree: transaction.tree(),
    ...(withdrawal === undefined ? {} : { withdrawal }),
  });
}

export async function buildPrivateTransaction(
  input: Readonly<{
    transaction: UnsignedPrivateTransaction;
    wallet: Wallet;
    authority: WalletAuthority;
    client: ZolanaClient;
    feePayer: Address;
  }>,
  context?: RequestContext,
): Promise<Transaction> {
  try {
    const signed = await prepareShielded(input.transaction, input.wallet, input.authority);
    const latest = await input.client.rpc.getLatestBlockhash(context);
    return await input.client.finishSubmissionUnsigned(
      { signed, feePayer: input.feePayer, recentBlockhash: latest.blockhash },
      context,
    );
  } catch (cause) {
    throw wrapWalletError("WALLET_BUILD_PRIVATE_TRANSACTION", cause);
  }
}

export async function signPrivateTransaction(
  input: Readonly<{
    transaction: UnsignedPrivateTransaction;
    wallet: Wallet;
    authority: WalletAuthority;
    client: ZolanaClient;
    feePayer: TransactionSigner;
  }>,
  context?: RequestContext,
): Promise<Transaction> {
  try {
    const transaction = await buildPrivateTransaction(
      { ...input, feePayer: input.feePayer.address },
      context,
    );
    return await input.feePayer.signNativeTransaction(transaction);
  } catch (cause) {
    throw wrapWalletError("WALLET_SIGN_PRIVATE_TRANSACTION", cause);
  }
}

export function p256SignatureBytes(signature: Readonly<{ r: Bytes32; s: Bytes32 }>): Uint8Array {
  const bytes = new Uint8Array(64);
  bytes.set(signature.r);
  bytes.set(signature.s, 32);
  return bytes;
}
