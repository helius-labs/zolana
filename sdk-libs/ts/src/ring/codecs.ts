import { CUSTOM_RING_PROOF_LENGTH } from "../client/prover/proof.js";
import type { Address, Bytes33 } from "../interface/types.js";
import { Reader, encodeBase58 } from "../interface/internal.js";
import { P256PublicKey } from "../keypair/public-key.js";

import { RingError } from "./error.js";

export interface RingProgramConfig {
  readonly authority: Address;
  readonly auditorPublicKey: P256PublicKey;
  readonly bump: number;
}

const RING_PROGRAM_CONFIG_DISCRIMINATOR = 1;
const RING_PROGRAM_CONFIG_SIZE = 67;

export function decodeRingProgramConfig(data: Uint8Array): RingProgramConfig {
  if (data.length !== RING_PROGRAM_CONFIG_SIZE || data[0] !== RING_PROGRAM_CONFIG_DISCRIMINATOR) {
    throw new RingError("RING_CONFIG_INVALID", {
      details: { length: data.length, discriminator: data[0] },
    });
  }
  const reader = new Reader(data);
  reader.u8("discriminator");
  const authority = encodeBase58(reader.bytes(32, "authority"));
  const auditorPublicKey = P256PublicKey.fromBytes(reader.bytes(33, "auditorPublicKey") as Bytes33);
  const bump = reader.u8("bump");
  reader.done();
  return Object.freeze({ authority, auditorPublicKey, bump });
}

export { CUSTOM_RING_PROOF_LENGTH };

export function checkedCustomRingProof(proof: Uint8Array): Uint8Array {
  if (proof.length !== CUSTOM_RING_PROOF_LENGTH) {
    throw new RingError("RING_PROOF_LENGTH", {
      details: { expected: CUSTOM_RING_PROOF_LENGTH, actual: proof.length },
    });
  }
  return new Uint8Array(proof);
}
