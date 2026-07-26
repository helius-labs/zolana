import type { Address } from "@zolana/interface";
import bs58 from "bs58";

import { SmartAccountClientError } from "./error.js";

const ADDRESS_LENGTH = 32;

export function decodeAddress(address: Address): Uint8Array {
  if (typeof address !== "string" || address.length === 0) {
    throw invalidAddress(address);
  }
  let decoded: Uint8Array;
  try {
    decoded = bs58.decode(address);
  } catch {
    throw invalidAddress(address);
  }
  if (decoded.length !== ADDRESS_LENGTH || encodeAddress(decoded) !== address) {
    throw invalidAddress(address);
  }
  return decoded;
}

export function encodeAddress(bytes: Uint8Array): Address {
  if (bytes.length !== ADDRESS_LENGTH) {
    throw new SmartAccountClientError(
      "SMART_ACCOUNT_INVALID_ADDRESS",
      "address bytes must contain 32 bytes",
      { details: { actualLength: bytes.length, expectedLength: ADDRESS_LENGTH } },
    );
  }
  return bs58.encode(bytes) as Address;
}

function invalidAddress(value: unknown): SmartAccountClientError {
  return new SmartAccountClientError("SMART_ACCOUNT_INVALID_ADDRESS", "invalid Solana address", {
    details: { value: typeof value === "string" ? value : typeof value },
  });
}
