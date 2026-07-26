import { ClientError } from "./error.js";

/** Solana's compact-u16: seven bits per byte, high bit marking continuation. */
export function compactU16(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff) {
    throw new ClientError("CLIENT_INVALID_INTEGER");
  }
  const bytes: number[] = [];
  let remaining = value;
  do {
    let byte = remaining & 0x7f;
    remaining >>>= 7;
    if (remaining !== 0) byte |= 0x80;
    bytes.push(byte);
  } while (remaining !== 0);
  return Uint8Array.from(bytes);
}
