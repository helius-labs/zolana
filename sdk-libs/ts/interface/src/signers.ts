import { InterfaceError } from "./errors.js";
import type { Address, Signature, Transaction } from "./index.js";
import { addressBytes } from "./internal.js";

/**
 * Position of `address` in a compiled message's signer list, which is also its
 * slot in `Transaction.signatures`.
 *
 * A legacy message begins with the three privilege counts, the first of which
 * is the number of required signatures, followed by a compact-u16 account count
 * and the account keys themselves. The required signers are the leading entries
 * of that list, so the slot is found by scanning only those keys.
 */
export function signerIndex(transaction: Transaction, address: Address): number {
  const message = transaction.messageBytes;
  const requiredSignatures = message[0];
  if (requiredSignatures === undefined) {
    throw new InterfaceError("INTERFACE_INVALID_TRANSACTION", { field: "messageBytes" });
  }
  // The high bit of the first byte marks a versioned message, whose account
  // keys sit behind an address-table section this does not parse.
  if ((requiredSignatures & 0x80) !== 0) {
    throw new InterfaceError("INTERFACE_INVALID_TRANSACTION", { field: "messageVersion" });
  }
  const { value: accountCount, length: countLength } = decodeCompactU16(message, 3);
  if (accountCount < requiredSignatures) {
    throw new InterfaceError("INTERFACE_INVALID_TRANSACTION", { field: "accountCount" });
  }
  const keys = 3 + countLength;
  if (message.length < keys + accountCount * 32) {
    throw new InterfaceError("INTERFACE_INVALID_TRANSACTION", { field: "accountKeys" });
  }
  const wanted = addressBytes(address);
  for (let index = 0; index < requiredSignatures; index++) {
    const offset = keys + index * 32;
    if (equal(message.subarray(offset, offset + 32), wanted)) return index;
  }
  throw new InterfaceError("INTERFACE_SIGNER_NOT_REQUIRED", { address });
}

/**
 * Write `signature` into `address`'s slot and leave every other slot as it was,
 * so a transaction needing several signers can be passed from one to the next.
 */
export function withSignature(
  transaction: Transaction,
  address: Address,
  signature: Signature,
): Transaction {
  const index = signerIndex(transaction, address);
  const signatures = [...transaction.signatures];
  signatures[index] = signature;
  return Object.freeze({
    messageBytes: new Uint8Array(transaction.messageBytes),
    signatures: Object.freeze(signatures),
  });
}

function decodeCompactU16(
  bytes: Uint8Array,
  offset: number,
): Readonly<{ value: number; length: number }> {
  let value = 0;
  for (let index = 0; index < 3; index++) {
    const byte = bytes[offset + index];
    if (byte === undefined) {
      throw new InterfaceError("INTERFACE_INVALID_TRANSACTION", { field: "compactU16" });
    }
    value |= (byte & 0x7f) << (index * 7);
    if ((byte & 0x80) === 0) return { value, length: index + 1 };
  }
  throw new InterfaceError("INTERFACE_INVALID_TRANSACTION", { field: "compactU16" });
}

function equal(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index++) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}
