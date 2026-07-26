import { address as toKitAddressChecked, type Address as KitAddress } from "@solana/kit";
import { decodeBase58, encodeBase58, type Address } from "@zolana/interface";

import { KitError } from "./error.js";

const ADDRESS_LENGTH = 32;

/**
 * Validates a Zolana `Address` and brands it as a Kit address.
 */
export function toKitAddress(address: Address): KitAddress {
  if (typeof address !== "string") throw invalidAddress(address);
  try {
    return toKitAddressChecked(address);
  } catch (cause) {
    throw invalidAddress(address, cause);
  }
}

/**
 * Converts a Kit address to a Zolana `Address` after re-checking base58 form.
 * Kit values are usually already valid; this still checks in case the brand was
 * asserted onto untrusted input.
 */
export function fromKitAddress(address: KitAddress): Address {
  if (typeof address !== "string" || address.length === 0) throw invalidAddress(address);
  let decoded: Uint8Array;
  try {
    decoded = decodeBase58(address);
  } catch (cause) {
    throw invalidAddress(address, cause);
  }
  if (decoded.length !== ADDRESS_LENGTH || encodeBase58(decoded) !== address) {
    throw invalidAddress(address);
  }
  return address as string as Address;
}

function invalidAddress(value: unknown, cause?: unknown): KitError {
  return new KitError("KIT_INVALID_ADDRESS", "not a Solana address", {
    details: { value: typeof value === "string" ? value : typeof value },
    ...(cause === undefined ? {} : { cause }),
  });
}
