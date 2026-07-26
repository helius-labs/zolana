import { encodeCompactU16 } from "@zolana/interface";

import { ClientError } from "./error.js";

/** Solana's compact-u16: seven bits per byte, high bit marking continuation. */
export function compactU16(value: number): Uint8Array {
  try {
    return encodeCompactU16(value);
  } catch {
    throw new ClientError("CLIENT_INVALID_INTEGER");
  }
}
