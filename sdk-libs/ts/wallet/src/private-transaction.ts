import { ClientError, type SignedPrivateTransaction, type ZolanaClient } from "@zolana/client";
import type {
  Address,
  Bytes32,
  RequestContext,
  Transaction,
  TransactionSigner,
} from "@zolana/interface";
import type { ShieldedAddress } from "@zolana/keypair";
import {
  ConfidentialTransfer,
  SppProofInputUtxo,
  type Data,
  type SppProofInputs,
  type Utxo,
  type Wallet,
} from "@zolana/transaction";
import { ConfidentialSplit } from "@zolana/transaction/instructions";

import { UnsignedPrivateTransaction } from "./actions.js";
import { WalletError, wrapWalletError } from "./error.js";
import { equalBytes } from "./internal.js";
import type { WalletAuthority } from "./wallet-authority.js";

function sameOptionalHash(left: Bytes32 | undefined, right: Bytes32 | undefined): boolean {
  if (left === undefined || right === undefined) return left === right;
  return equalBytes(left, right);
}

function sameData(left: Data, right: Data): boolean {
  const records = left.records();
  const other = right.records();
  return (
    records.length === other.length &&
    records.every((record, index) => {
      const candidate = other[index];
      return (
        candidate !== undefined &&
        record.kind === candidate.kind &&
        equalBytes(record.bytes, candidate.bytes)
      );
    })
  );
}

function sameUtxo(left: Utxo, right: Utxo): boolean {
  return (
    equalBytes(left.owner.toBytes(), right.owner.toBytes()) &&
    left.asset === right.asset &&
    left.amount === right.amount &&
    equalBytes(left.blinding, right.blinding) &&
    left.zoneProgramId === right.zoneProgramId &&
    sameData(left.data, right.data)
  );
}

/**
 * The note the signer is about to spend must still be the exact note the
 * unsigned transaction was built from. Matching on the commitment alone would
 * let a note swapped between build and sign pass, so every field that feeds the
 * commitment is compared.
 */
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
        sameOptionalHash(entry.dataHash, expected.dataHash) &&
        sameOptionalHash(entry.zoneDataHash, expected.zoneDataHash) &&
        sameUtxo(entry.utxo, expected.utxo),
    );
}

/**
 * The P256 rail is a property of the signing authority, not of the notes being
 * spent: a P256 owner must sign even when every input note carries a different
 * rail, and a Solana owner never signs.
 */
async function applyP256Signature(
  proofInputs: SppProofInputs,
  address: ShieldedAddress,
  authority: WalletAuthority,
): Promise<void> {
  if (address.signingPublicKey.signatureType() !== "p256") return;
  proofInputs.applyP256Signature(await authority.signP256(proofInputs.messageHash()));
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
      new SppProofInputUtxo({
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
  await applyP256Signature(proofInputs, address, authority);
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
    try {
      return await input.feePayer.signNativeTransaction(transaction);
    } catch (signingCause) {
      // The signer stands in for `Transaction::try_sign`, whose failure Rust
      // reports as `ClientError::SolanaTransactionSigning`. Naming the same
      // error here keeps a fee payer that cannot sign identifiable across both
      // SDKs instead of arriving as whatever the caller's signer threw.
      throw new ClientError("CLIENT_SOLANA_TRANSACTION_SIGNING", {
        details: { reason: reasonOf(signingCause) },
        cause: signingCause,
      });
    }
  } catch (cause) {
    throw wrapWalletError("WALLET_SIGN_PRIVATE_TRANSACTION", cause);
  }
}

function reasonOf(cause: unknown): string {
  return cause instanceof Error ? cause.message : String(cause);
}

export function p256SignatureBytes(signature: Readonly<{ r: Bytes32; s: Bytes32 }>): Uint8Array {
  const bytes = new Uint8Array(64);
  bytes.set(signature.r);
  bytes.set(signature.s, 32);
  return bytes;
}
