import { AUDIT_PROOF_LENGTH } from "../client/prover/proof.js";
import type { Address, Bytes32, Bytes33 } from "../interface/types.js";
import { Reader, encodeBase58 } from "../interface/internal.js";
import { P256PublicKey } from "../keypair/public-key.js";

import { RingError } from "./error.js";

export interface RingProgramConfig {
  readonly authority: Address;
  readonly auditorPublicKey: P256PublicKey;
  readonly bump: number;
}

/** Mirrors Rust `PolicyConfig`. */
export interface RingPolicyConfig {
  readonly policyHash: Bytes32;
  readonly recordsTree: Address;
  readonly recordsBump: number;
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

/** Rust `POLICY_CONFIG` and `PolicyConfig::SIZE`. */
const RING_POLICY_CONFIG_DISCRIMINATOR = 3;
const RING_POLICY_CONFIG_SIZE = 67;

export function decodeRingPolicyConfig(data: Uint8Array): RingPolicyConfig {
  if (data.length !== RING_POLICY_CONFIG_SIZE || data[0] !== RING_POLICY_CONFIG_DISCRIMINATOR) {
    throw new RingError("RING_POLICY_CONFIG_INVALID", {
      details: { length: data.length, discriminator: data[0] },
    });
  }
  const reader = new Reader(data);
  reader.u8("discriminator");
  const policyHash = reader.bytes(32, "policyHash") as Bytes32;
  const recordsTree = encodeBase58(reader.bytes(32, "recordsTree"));
  const recordsBump = reader.u8("recordsBump");
  const bump = reader.u8("bump");
  reader.done();
  return Object.freeze({ policyHash, recordsTree, recordsBump, bump });
}

export { AUDIT_PROOF_LENGTH };

export function checkedAuditProof(proof: Uint8Array): Uint8Array {
  if (proof.length !== AUDIT_PROOF_LENGTH) {
    throw new RingError("RING_AUDIT_PROOF_LENGTH", {
      details: { expected: AUDIT_PROOF_LENGTH, actual: proof.length },
    });
  }
  return new Uint8Array(proof);
}
