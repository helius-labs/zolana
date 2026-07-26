import type {
  Address as KitAddress,
  SignatureBytes,
  Transaction as KitTransaction,
  TransactionMessageBytes,
} from "@solana/kit";
import {
  decodeBase58,
  decodeCompactU16,
  encodeBase58,
  type Address,
  type Signature,
  type Transaction,
} from "@zolana/interface";

import { toKitAddress } from "./address.js";
import { KitError } from "./error.js";

const ADDRESS_LENGTH = 32;
const SIGNATURE_LENGTH = 64;
const HEADER_LENGTH = 3;

/**
 * Required signer addresses from a compiled legacy message, in message order.
 *
 * Kit's signature map is keyed by address and uses insertion order for the
 * serialized signature list, so the map must be built in message order. Offsets
 * match `signerIndex` in `@zolana/interface`; the parse lives here because Kit
 * needs this shape.
 */
function signerAddresses(messageBytes: Uint8Array): readonly Address[] {
  const requiredSignatures = messageBytes[0];
  if (requiredSignatures === undefined) throw invalidTransaction("messageBytes");
  // The high bit of the first byte marks a versioned message, whose account
  // keys sit behind an address-table section this does not parse.
  if ((requiredSignatures & 0x80) !== 0) throw invalidTransaction("messageVersion");
  const { value: accountCount, length: countLength } = decodeCompactU16(
    messageBytes,
    HEADER_LENGTH,
  );
  if (accountCount < requiredSignatures) throw invalidTransaction("accountCount");
  const keysOffset = HEADER_LENGTH + countLength;
  if (messageBytes.length < keysOffset + accountCount * ADDRESS_LENGTH) {
    throw invalidTransaction("accountKeys");
  }
  const addresses: Address[] = [];
  for (let index = 0; index < requiredSignatures; index++) {
    const offset = keysOffset + index * ADDRESS_LENGTH;
    addresses.push(encodeBase58(messageBytes.subarray(offset, offset + ADDRESS_LENGTH)) as Address);
  }
  return addresses;
}

export function toKitTransaction(transaction: Transaction): KitTransaction {
  const addresses = signerAddresses(transaction.messageBytes);
  if (transaction.signatures.length !== addresses.length) {
    throw new KitError("KIT_SIGNATURE_COUNT", "transaction has one slot per required signer", {
      details: { expected: addresses.length, actual: transaction.signatures.length },
    });
  }
  const signatures: Record<KitAddress, SignatureBytes | null> = {};
  for (let index = 0; index < addresses.length; index++) {
    const address = addresses[index] as Address;
    const signature = transaction.signatures[index];
    signatures[toKitAddress(address)] =
      signature === undefined ? null : toSignatureBytes(signature);
  }
  return {
    messageBytes: Uint8Array.from(transaction.messageBytes) as unknown as TransactionMessageBytes,
    signatures,
  };
}

export function fromKitTransaction(transaction: KitTransaction): Transaction {
  const messageBytes = Uint8Array.from(transaction.messageBytes);
  const addresses = signerAddresses(messageBytes);
  const keys = Object.keys(transaction.signatures);
  if (keys.length !== addresses.length) {
    throw new KitError("KIT_SIGNATURE_COUNT", "signature map has one entry per required signer", {
      details: { expected: addresses.length, actual: keys.length },
    });
  }
  const signatures = addresses.map((address, index) => {
    // Kit serializes signatures in map insertion order; key set alone is not enough.
    if (keys[index] !== (address as string)) {
      throw new KitError("KIT_SIGNATURE_ORDER", "signature map is not in signer order", {
        details: { index, expected: address, actual: keys[index] },
      });
    }
    const value = signatureEntry(transaction.signatures, address);
    return value === null || value === undefined ? undefined : fromSignatureBytes(value);
  });
  return Object.freeze({ messageBytes, signatures: Object.freeze(signatures) });
}

export function toSignatureBytes(signature: Signature): SignatureBytes {
  let decoded: Uint8Array;
  try {
    decoded = decodeBase58(signature);
  } catch (cause) {
    throw invalidSignature(signature, cause);
  }
  if (decoded.length !== SIGNATURE_LENGTH) throw invalidSignature(signature);
  return decoded as SignatureBytes;
}

export function fromSignatureBytes(bytes: SignatureBytes): Signature {
  if (bytes.length !== SIGNATURE_LENGTH) throw invalidSignature(bytes);
  return encodeBase58(Uint8Array.from(bytes)) as Signature;
}

function signatureEntry(
  signatures: KitTransaction["signatures"],
  address: Address,
): SignatureBytes | null | undefined {
  return signatures[address as string as KitAddress];
}

function invalidSignature(value: unknown, cause?: unknown): KitError {
  return new KitError("KIT_INVALID_SIGNATURE", "signature must be 64 bytes", {
    details: { value: typeof value === "string" ? value : typeof value },
    ...(cause === undefined ? {} : { cause }),
  });
}

function invalidTransaction(field: string): KitError {
  return new KitError("KIT_INVALID_TRANSACTION", "compiled message is malformed", {
    details: { field },
  });
}
