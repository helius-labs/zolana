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
  /** Raw id of `entriesTree`, every entry leaf and address hashes under it. */
  readonly entriesTreeId: number;
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

/** Mirrors Rust `CoSigner`, `scope` is a subset of the `RING_COSIGN_*` bits. */
export interface RingCoSigner {
  readonly signer: Address;
  readonly scope: number;
  readonly bump: number;
  /** Per mint, SOL under the zero address, a withdrawn mint without a row always needs the co-signer. */
  readonly thresholds: readonly { readonly mint: Address; readonly above: bigint }[];
}

export const RING_COSIGN_TRANSFERS = 1;
export const RING_COSIGN_DEPOSITS = 2;
export const RING_COSIGN_WITHDRAWALS = 4;
export const RING_COSIGN_SCOPE_MASK = 7;
/** Rust `MAX_CO_SIGNER_THRESHOLDS`. */
export const RING_COSIGN_THRESHOLD_SLOTS = 8;

const RING_PROGRAM_CONFIG_DISCRIMINATOR = 1;
const RING_PROGRAM_CONFIG_SIZE = 68;
/** Rust `CO_SIGNER` and `CoSigner::SIZE`. */
const RING_CO_SIGNER_DISCRIMINATOR = 4;
const RING_CO_SIGNER_SIZE = 356;

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

export function decodeRingCoSigner(data: Uint8Array): RingCoSigner {
  if (data.length !== RING_CO_SIGNER_SIZE || data[0] !== RING_CO_SIGNER_DISCRIMINATOR) {
    throw new RingError("RING_CO_SIGNER_INVALID", {
      details: { length: data.length, discriminator: data[0] },
    });
  }
  const reader = new Reader(data);
  reader.u8("discriminator");
  const signer = encodeBase58(reader.bytes(32, "signer"));
  const scope = reader.u8("scope");
  const count = reader.u8("thresholdCount");
  if (
    scope === 0 ||
    (scope & ~RING_COSIGN_SCOPE_MASK) !== 0 ||
    count > RING_COSIGN_THRESHOLD_SLOTS
  ) {
    throw new RingError("RING_CO_SIGNER_INVALID", { details: { scope, count } });
  }
  const thresholds = [];
  for (let slot = 0; slot < RING_COSIGN_THRESHOLD_SLOTS; slot += 1) {
    const mint = encodeBase58(reader.bytes(32, "mint"));
    const above = reader.u64("above");
    if (slot < count) thresholds.push(Object.freeze({ mint, above }));
  }
  const bump = reader.u8("bump");
  reader.done();
  return Object.freeze({ signer, scope, bump, thresholds: Object.freeze(thresholds) });
}

/** Mirrors Rust `Delegate`, the key that moves notes between members on the authority rail. */
export interface RingDelegate {
  readonly delegate: Address;
  readonly bump: number;
}

/** Rust `DELEGATE` and `Delegate::SIZE`. */
const RING_DELEGATE_DISCRIMINATOR = 6;
const RING_DELEGATE_SIZE = 34;

export function decodeRingDelegate(data: Uint8Array): RingDelegate {
  if (data.length !== RING_DELEGATE_SIZE || data[0] !== RING_DELEGATE_DISCRIMINATOR) {
    throw new RingError("RING_DELEGATE_INVALID", {
      details: { length: data.length, discriminator: data[0] },
    });
  }
  const reader = new Reader(data);
  reader.u8("discriminator");
  const key = reader.bytes(32, "delegate");
  const bump = reader.u8("bump");
  reader.done();
  if (key.every((byte) => byte === 0)) {
    throw new RingError("RING_DELEGATE_INVALID", { details: { delegate: "zero" } });
  }
  return Object.freeze({ delegate: encodeBase58(key), bump });
}

/** Mirrors Rust `SpendWindow`, a mint's public-leg caps over fixed windows, zero caps do not bind. */
export interface RingSpendWindow {
  readonly mint: Address;
  readonly windowSlots: bigint;
  readonly depositCap: bigint;
  readonly withdrawalCap: bigint;
  readonly windowStartSlot: bigint;
  readonly deposited: bigint;
  readonly withdrawn: bigint;
  readonly bump: number;
}

/** Rust `SPEND_WINDOW` and `SpendWindow::SIZE`. */
const RING_SPEND_WINDOW_DISCRIMINATOR = 5;
const RING_SPEND_WINDOW_SIZE = 82;

export function decodeRingSpendWindow(data: Uint8Array): RingSpendWindow {
  if (data.length !== RING_SPEND_WINDOW_SIZE || data[0] !== RING_SPEND_WINDOW_DISCRIMINATOR) {
    throw new RingError("RING_SPEND_WINDOW_INVALID", {
      details: { length: data.length, discriminator: data[0] },
    });
  }
  const reader = new Reader(data);
  reader.u8("discriminator");
  const mint = encodeBase58(reader.bytes(32, "mint"));
  const windowSlots = reader.u64("windowSlots");
  const depositCap = reader.u64("depositCap");
  const withdrawalCap = reader.u64("withdrawalCap");
  const windowStartSlot = reader.u64("windowStartSlot");
  const deposited = reader.u64("deposited");
  const withdrawn = reader.u64("withdrawn");
  const bump = reader.u8("bump");
  reader.done();
  if (windowSlots === 0n) {
    throw new RingError("RING_SPEND_WINDOW_INVALID", { details: { mint, windowSlots } });
  }
  return Object.freeze({
    mint,
    windowSlots,
    depositCap,
    withdrawalCap,
    windowStartSlot,
    deposited,
    withdrawn,
    bump,
  });
}

/** Rust `POLICY_CONFIG` and `PolicyConfig::SIZE`. */
const RING_POLICY_CONFIG_DISCRIMINATOR = 3;
const RING_POLICY_CONFIG_SIZE = 1179;

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
  const entriesTreeId = reader.u16("entriesTreeId");
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
    entriesTreeId,
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
