import type { AuthorizedPrivateTransaction } from "../client/client.js";
import type { Address, Bytes32 } from "../interface/types.js";
import type { Data } from "../transaction/data.js";
import { ConfidentialSplit } from "../transaction/instructions/builders.js";
import { ConfidentialTransfer, type SppProofInputs } from "../transaction/instructions/transact.js";
import { ProofInputUtxo, type Utxo } from "../transaction/utxo.js";
import type { Wallet } from "../transaction/wallet/state.js";

import { UnsignedPrivateTransaction } from "./actions.js";
import { WalletError } from "./error.js";
import { equalBytes } from "./internal.js";
import type { WalletAuthority } from "../transaction/wallet/authority.js";

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
 * The note the private authority is about to authorize must still be the exact
 * note selected for this intent. Matching on the commitment alone would let a
 * note swapped before authorization pass, so every field that feeds the
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
        sameOptionalHash(entry.zoneDataHash, expected.zoneDataHash) &&
        sameUtxo(entry.utxo, expected.utxo),
    );
}

/** @internal */
export async function authorizePrivateTransaction(
  transaction: UnsignedPrivateTransaction,
  wallet: Wallet,
  authority: WalletAuthority,
): Promise<AuthorizedPrivateTransaction> {
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
  const withdrawal = transaction._withdrawal();
  return Object.freeze({
    proofInputs,
    tree: transaction.tree(),
    ...(withdrawal === undefined ? {} : { withdrawal }),
  });
}
