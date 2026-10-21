import {
  mintAuthorizedPrivateTransaction,
  type AuthorizedPrivateTransaction,
} from "../client/ports.js";
import { initializePoseidon } from "../hasher/index.js";
import type { Address, Bytes32, Instruction, RequestContext } from "../interface/types.js";
import { treeAddress } from "../interface/pda/index.js";
import { selectConfidentialEddsaShape } from "../interface/shape.js";
import { randomBlinding } from "../keypair/bytes.js";
import { DEFAULT_TREE_ID } from "../interface/tree-slot.js";
import type { ShieldedAddress } from "../keypair/shielded.js";
import type { ViewingKey } from "../keypair/viewing-key.js";
import type { Data } from "../transaction/data.js";
import { ConfidentialSplit } from "../transaction/instructions/builders.js";
import { ConfidentialTransfer, SppProofInputs } from "../transaction/instructions/transact.js";
import { TransactionError } from "../transaction/error.js";
import { ProofInputUtxo, type Utxo } from "../transaction/utxo.js";
import {
  approveUnattended,
  checkAuthorizedBinding,
  checkIntentApproval,
  checkPreparedTransfer,
  withdrawalIntentRecipient,
  type ApprovalHandler,
  type TransactionIntent,
} from "../transaction/wallet/intent.js";
import type { ShieldedKeys } from "../transaction/wallet/keys.js";
import { destroyTransactionKeys, transactionKeyAnswers } from "../transaction/wallet/key-batch.js";
import { encryptConfidentialTransfer, encryptSplit } from "../transaction/wallet/encrypt-rails.js";
import type { Wallet, WalletUtxo } from "../transaction/wallet/state.js";

import { UnsignedPrivateTransaction } from "./actions.js";
import { WalletError } from "./error.js";
import { equalBytes } from "./internal.js";

function intentMismatch(field: string): WalletError {
  return new WalletError("WALLET_INTENT_MISMATCH", { details: { field } });
}

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
    left.ringProgramId === right.ringProgramId &&
    sameData(left.data, right.data)
  );
}

/**
 * The UTXO the private authority is about to authorize must still be the exact
 * UTXO selected for this intent. Matching on the commitment alone would allow
 * a UTXO swap before authorization, so every field that feeds the
 * commitment is compared.
 */
function matchingInput(
  wallet: Wallet,
  tree: Address,
  expected: ReturnType<UnsignedPrivateTransaction["_inputs"]>[number]["entry"],
): boolean {
  return wallet
    ._state()
    .utxos.some(
      (entry) =>
        !entry.spent &&
        entry.outputContext.tree === tree &&
        equalBytes(entry.outputContext.hash, expected.outputContext.hash) &&
        equalBytes(entry.nullifier, expected.nullifier) &&
        sameOptionalHash(entry.dataHash, expected.dataHash) &&
        sameOptionalHash(entry.ringDataHash, expected.ringDataHash) &&
        sameUtxo(entry.utxo, expected.utxo),
    );
}

/** @internal */
export async function authorizePrivateTransaction(
  transaction: UnsignedPrivateTransaction,
  wallet: Wallet,
  keys: ShieldedKeys,
  setupInstructions: readonly Instruction[] = [],
  approve: ApprovalHandler = approveUnattended,
  context?: RequestContext,
  inCircuitOwner = false,
): Promise<AuthorizedPrivateTransaction> {
  await initializePoseidon();
  const unsignedInputs = transaction._inputs();
  unsignedInputs.forEach((input, index) => {
    if (!matchingInput(wallet, transaction.tree(), input.entry)) {
      throw new WalletError("WALLET_UNSIGNED_INPUT_UNAVAILABLE", {
        details: { index },
      });
    }
  });
  // A payer other than the owner sponsors the fee; the transact then lists
  // the owner as an owner signer, so the owner still signs the spend.
  const address = keys.address();
  const inputs = unsignedInputs.map(({ entry }) => proofInputFromEntry(entry, address));
  return authorizeWithInputs(
    transaction,
    wallet,
    keys,
    approve,
    address,
    inputs,
    setupInstructions,
    context,
    inCircuitOwner,
  );
}

/** A stored UTXO already carries the nullifier its sync derived. */
export function proofInputFromEntry(entry: WalletUtxo, address: ShieldedAddress): ProofInputUtxo {
  // Wallet conversion currently opens commitments in the default tree only.
  // A stored nullifier from another tree cannot be reused for that opening.
  if (entry.outputContext.tree !== treeAddress(DEFAULT_TREE_ID)) {
    throw new WalletError("WALLET_INPUT_UTXO_TREE_MISMATCH");
  }
  return new ProofInputUtxo({
    utxo: entry.utxo,
    nullifierPublicKey: address.nullifierPublicKey,
    nullifier: entry.nullifier,
    treeId: DEFAULT_TREE_ID,
    ...(entry.dataHash === undefined ? {} : { dataHash: entry.dataHash }),
    ...(entry.ringDataHash === undefined ? {} : { ringDataHash: entry.ringDataHash }),
  });
}

async function authorizeWithInputs(
  transaction: UnsignedPrivateTransaction,
  wallet: Wallet,
  keys: ShieldedKeys,
  approve: ApprovalHandler,
  address: ShieldedAddress,
  inputs: readonly ProofInputUtxo[],
  setupInstructions: readonly Instruction[],
  context: RequestContext | undefined,
  inCircuitOwner: boolean,
): Promise<AuthorizedPrivateTransaction> {
  const action = transaction._action();
  let proofInputs: SppProofInputs;
  let intent: TransactionIntent;
  let senderOutputCount: number;
  let approvedIntentHash: Bytes32;
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
    const encrypted = await withTransactionKey(
      keys,
      prepared.firstNullifier,
      (tx) =>
        encryptSplit(tx, {
          viewingPublicKey: address.viewingPublicKey,
          viewTag: prepared.owner.confidentialViewTag(),
          bundle: prepared.bundlePlaintext(wallet.registry),
        }),
      context,
    );
    intent = {
      kind: "split",
      asset: action.asset,
      numOutputs: action.numOutputs,
      perOutputAmount: action.perOutputAmount,
    };
    const approval = await approve({
      solanaPublicKey: address.solanaAddress(),
      intent,
      summary: transaction._summary(),
    });
    checkIntentApproval(approval, intent, intentMismatch);
    approvedIntentHash = approval.intentHash;
    senderOutputCount = 0;
    proofInputs = prepared.finalize({
      txViewingPublicKey: encrypted.txViewingPublicKey,
      salt: encrypted.salt,
      payload: encrypted.payload,
    });
  } else {
    const transfer = new ConfidentialTransfer(address, inputs, transaction.payer());
    if (action.kind === "transfer") {
      for (const payment of action.payments) {
        transfer.send(payment.recipient, action.asset, payment.amount);
      }
    } else {
      transfer.withdraw(action.asset, action.amount, action.target);
    }
    if (inCircuitOwner) transfer.withConfidentialEddsaShape();
    const prepared = transfer.prepare();
    const encrypted = await withTransactionKey(
      keys,
      prepared.firstNullifier,
      (tx) =>
        encryptConfidentialTransfer(tx, { outputs: prepared.outputs, assets: wallet.registry }),
      context,
    );
    intent =
      action.kind === "transfer"
        ? transferIntent(action.asset, action.payments)
        : {
            kind: "withdrawal",
            asset: action.asset,
            amount: action.amount,
            recipient: withdrawalIntentRecipient(action.target),
          };
    const approval = await approve({
      solanaPublicKey: address.solanaAddress(),
      intent,
      summary: transaction._summary(),
    });
    checkIntentApproval(approval, intent, intentMismatch);
    approvedIntentHash = approval.intentHash;
    checkPreparedTransfer(prepared, intent, intentMismatch);
    senderOutputCount = prepared.senderOutputCount;
    proofInputs = prepared.finalize({
      txViewingPublicKey: encrypted.txViewingPublicKey,
      salt: encrypted.salt,
      payload: encrypted.payload,
    });
  }
  if (inCircuitOwner && action.kind === "split") {
    const shape = selectConfidentialEddsaShape(
      proofInputs.inputUtxos.length,
      proofInputs.outputs.length,
    );
    const padded = [...proofInputs.inputUtxos];
    while (padded.length < shape.inputs) padded.push(ProofInputUtxo.dummy(randomBlinding()));
    proofInputs = new SppProofInputs({ ...proofInputs, inputUtxos: padded });
  }
  const withdrawal = transaction._withdrawal();
  const material = Object.freeze({
    proofInputs,
    tree: transaction.tree(),
    intent,
    senderOutputCount,
    owner: address,
    setupInstructions,
    ...(withdrawal === undefined ? {} : { withdrawal }),
  });
  checkAuthorizedBinding(material, intentMismatch);
  return mintAuthorizedPrivateTransaction(material, approvedIntentHash);
}

/** One payment is a `transfer` intent, so a single-recipient approval keeps its hash. */
function transferIntent(
  asset: Address,
  payments: readonly Readonly<{ recipient: ShieldedAddress; amount: bigint }>[],
): TransactionIntent {
  const [only] = payments;
  if (payments.length === 1 && only !== undefined) {
    return { kind: "transfer", asset, amount: only.amount, recipient: only.recipient };
  }
  return Object.freeze({
    kind: "multiTransfer",
    asset,
    payments: Object.freeze(
      payments.map((payment) =>
        Object.freeze({ recipient: payment.recipient, amount: payment.amount }),
      ),
    ),
  });
}

/**
 * The per-transaction key exists for the one synchronous sealing step and is
 * destroyed with it, whether `use` returns or throws. `use` is synchronous so
 * the key cannot outlive the call.
 * @internal
 */
export async function withTransactionKey<T>(
  keys: ShieldedKeys,
  firstNullifier: Bytes32,
  use: (tx: ViewingKey) => T extends Promise<unknown> ? never : T,
  context?: RequestContext,
): Promise<T> {
  const minted = await keys.transactionKeys(
    [{ viewingPublicKey: keys.address().viewingPublicKey, firstNullifier }],
    context,
  );
  try {
    const [tx] = transactionKeyAnswers(
      minted,
      1,
      () => new TransactionError("TRANSACTION_KEYS_BATCH_MISMATCH"),
    );
    if (tx === undefined) throw new TransactionError("TRANSACTION_KEYS_BATCH_MISMATCH");
    return use(tx);
  } finally {
    destroyTransactionKeys(minted);
  }
}
