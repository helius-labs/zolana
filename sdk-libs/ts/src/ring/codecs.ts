import { CUSTOM_RING_PROOF_LENGTH } from "../client/prover/proof.js";
import {
  RING_INLINE_ASSET_SLOTS,
  RING_RULE_SLOTS,
  RING_SOURCE_SLOTS,
} from "../client/prover/types.js";
import type { Address, Bytes32, Bytes33 } from "../interface/types.js";
import { Reader, encodeBase58 } from "../interface/internal.js";
import { P256PublicKey } from "../keypair/public-key.js";
import { bytesToBigInt } from "../transaction/internal.js";

import { RingError } from "./error.js";

export interface RingProgramConfig {
  readonly authority: Address;
  readonly auditorPublicKey: P256PublicKey;
  readonly bump: number;
  readonly hasPolicy: boolean;
}

/** Mirrors Rust `SourceSlot`, slot `i` is empty (`listId === 0`) or serves list `i + 1`. */
export interface RingPolicySource {
  readonly listId: number;
  readonly namespace: Address;
}

/** Mirrors Rust `PolicyConfig`. */
export interface RingPolicyConfig {
  readonly policyHash: Bytes32;
  readonly entriesTree: Address;
  readonly namespaceBump: number;
  readonly bump: number;
  readonly sources: readonly RingPolicySource[];
  /** Counted arrays exclude zero padding. */
  readonly ruleCount: number;
  readonly rules: readonly Bytes32[];
  readonly inlineCount: number;
  readonly inlineAssets: readonly Bytes32[];
  readonly inlineLimits: readonly bigint[];
  readonly generation: number;
  readonly generationSlot: bigint;
}

const RING_PROGRAM_CONFIG_DISCRIMINATOR = 1;
const RING_PROGRAM_CONFIG_SIZE = 68;

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
  const hasPolicy = reader.u8("hasPolicy") !== 0;
  reader.done();
  return Object.freeze({ authority, auditorPublicKey, bump, hasPolicy });
}

/** Rust `POLICY_CONFIG` and `PolicyConfig::SIZE`. */
const RING_POLICY_CONFIG_DISCRIMINATOR = 3;
const RING_POLICY_CONFIG_SIZE = 1177;

export function decodeRingPolicyConfig(data: Uint8Array): RingPolicyConfig {
  if (data.length !== RING_POLICY_CONFIG_SIZE || data[0] !== RING_POLICY_CONFIG_DISCRIMINATOR) {
    throw new RingError("RING_POLICY_CONFIG_INVALID", {
      details: { length: data.length, discriminator: data[0] },
    });
  }
  const reader = new Reader(data);
  reader.u8("discriminator");
  const policyHash = reader.bytes(32, "policyHash") as Bytes32;
  const entriesTree = encodeBase58(reader.bytes(32, "entriesTree"));
  const namespaceBump = reader.u8("namespaceBump");
  const bump = reader.u8("bump");
  const sources = Object.freeze(
    Array.from({ length: RING_SOURCE_SLOTS }, () =>
      Object.freeze({
        listId: reader.u8("listId"),
        namespace: encodeBase58(reader.bytes(32, "namespace")),
      }),
    ),
  );
  const rules = countedRows(reader, RING_RULE_SLOTS, "rules");
  const inlineAssets = countedRows(reader, RING_INLINE_ASSET_SLOTS, "inlineAssets");
  const inlineLimits = countedLimits(reader, inlineAssets.length);
  const generation = reader.u32("generation");
  const generationSlot = reader.u64("generationSlot");
  reader.done();
  return Object.freeze({
    policyHash,
    entriesTree,
    namespaceBump,
    bump,
    sources,
    ruleCount: rules.length,
    rules,
    inlineCount: inlineAssets.length,
    inlineAssets,
    inlineLimits,
    generation,
    generationSlot,
  });
}

function countedLimits(reader: Reader, count: number): readonly bigint[] {
  const limits: bigint[] = [];
  for (let index = 0; index < RING_INLINE_ASSET_SLOTS; index += 1) {
    const limit = bytesToBigInt(reader.bytes(8, "inlineLimits"));
    if (index < count) limits.push(limit);
    else if (limit !== 0n) {
      throw new RingError("RING_POLICY_CONFIG_INVALID", {
        details: { field: "inlineLimits", index },
      });
    }
  }
  return Object.freeze(limits);
}

/** Mirrors Rust `EncodedRuleTable::decode`. */
function countedRows(reader: Reader, slots: number, field: string): readonly Bytes32[] {
  const count = reader.u8(field);
  if (count > slots) {
    throw new RingError("RING_POLICY_CONFIG_INVALID", { details: { field, count, slots } });
  }
  const rows: Bytes32[] = [];
  for (let index = 0; index < slots; index += 1) {
    const row = reader.bytes(32, field) as Bytes32;
    if (index < count) rows.push(row);
    else if (row.some((byte) => byte !== 0)) {
      throw new RingError("RING_POLICY_CONFIG_INVALID", { details: { field, index } });
    }
  }
  return Object.freeze(rows);
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
