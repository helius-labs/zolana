import { CUSTOM_RING_PROOF_LENGTH } from "../client/prover/proof.js";
import {
  RING_INLINE_ASSET_SLOTS,
  RING_RULE_SLOTS,
  RING_SOURCE_SLOTS,
  RING_VELOCITY_SLOTS,
  type CustomRingVelocityRow,
} from "../client/prover/types.js";
import type { Address, Bytes32, Bytes33 } from "../interface/types.js";
import { Reader, addressBytes, encodeBase58 } from "../interface/internal.js";
import { P256PublicKey } from "../keypair/public-key.js";
import { ZERO_32, bytesToBigInt } from "../transaction/internal.js";
import { equalBytes } from "../wallet/internal.js";

import { RingError } from "./error.js";
import { checkedRegistryField, KEY_REGISTRY_CAPACITY } from "./key-registry-tree.js";

export interface RingProgramConfig {
  readonly authority: Address;
  readonly auditorPublicKey: P256PublicKey;
  readonly bump: number;
  readonly hasPolicy: boolean;
  /** Mirrors Rust `KeyEscrow::Registry`, set once with the delegate and never cleared. */
  readonly keyEscrow: boolean;
}

/** Pins whether deposits must disclose their openings to the auditor. */
export interface RingDepositAudit {
  readonly required: boolean;
  readonly bump: number;
}

export function decodeRingDepositAudit(data: Uint8Array): RingDepositAudit {
  if (data.length !== 3 || data[0] !== 10 || (data[1] !== 0 && data[1] !== 1))
    throw new RingError("RING_DEPOSIT_AUDIT_INVALID");
  const bump = data[2];
  if (bump === undefined) throw new RingError("RING_DEPOSIT_AUDIT_INVALID");
  return Object.freeze({ required: data[1] === 1, bump });
}

/** Mirrors Rust `SourceSlot`, slot `i` is empty (`listId === 0`) or serves list `i + 1`. */
export interface RingPolicySource {
  readonly listId: number;
  readonly namespace: Address;
}

/** Mirrors Rust `PolicyConfig`. */
export interface RingPolicyConfig {
  readonly policyHash: Bytes32;
  /** Every entry and spend record address is claimed in this tree. */
  readonly addressTree: Address;
  /** Raw id of `addressTree`, every entry and spend record address hashes under it. */
  readonly addressTreeId: number;
  readonly namespaceBump: number;
  readonly bump: number;
  readonly namespaceOwnerHash: Bytes32;
  readonly sources: readonly RingPolicySource[];
  /** Counted arrays exclude zero padding. */
  readonly ruleCount: number;
  readonly rules: readonly Bytes32[];
  readonly inlineCount: number;
  readonly inlineAssets: readonly Bytes32[];
  readonly inlineLimits: readonly bigint[];
  readonly windowSlots: bigint;
  readonly velocityCount: number;
  readonly velocity: readonly CustomRingVelocityRow[];
  readonly generation: number;
  readonly generationSlot: bigint;
}

/** Pins the Solana signature required by scope or amount. */
export interface RingCoSigner {
  readonly signer: Address;
  readonly scope: number;
  readonly bump: number;
  /** A withdrawn mint without a row always needs the co-signer. */
  readonly thresholds: readonly { readonly mint: Address; readonly above: bigint }[];
}

export const RING_COSIGN_TRANSFERS = 1;
export const RING_COSIGN_DEPOSITS = 2;
export const RING_COSIGN_WITHDRAWALS = 4;
export const RING_COSIGN_SCOPE_MASK = 7;
/** Rust `MAX_CO_SIGNER_THRESHOLDS`. */
export const RING_COSIGN_THRESHOLD_SLOTS = 8;

const RING_PROGRAM_CONFIG_DISCRIMINATOR = 1;
const RING_PROGRAM_CONFIG_SIZE = 69;
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
  // Any nonzero byte reads as on, escrow fails closed.
  const keyEscrow = reader.u8("keyEscrow") !== 0;
  reader.done();
  return Object.freeze({ authority, auditorPublicKey, bump, hasPolicy, keyEscrow });
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
  if (count > RING_COSIGN_THRESHOLD_SLOTS) {
    throw new RingError("RING_CO_SIGNER_INVALID", { details: { count } });
  }
  const thresholds = [];
  for (let slot = 0; slot < RING_COSIGN_THRESHOLD_SLOTS; slot += 1) {
    const mintBytes = reader.bytes(32, "mint");
    const above = reader.u64("above");
    if (slot < count) {
      thresholds.push(Object.freeze({ mint: encodeBase58(mintBytes), above }));
    } else if (!equalBytes(mintBytes, ZERO_32) || above !== 0n) {
      throw new RingError("RING_CO_SIGNER_INVALID", { details: { slot } });
    }
  }
  const bump = reader.u8("bump");
  reader.done();
  checkRingCoSignerConfig({ signer, scope, thresholds });
  return Object.freeze({ signer, scope, bump, thresholds: Object.freeze(thresholds) });
}

export function checkRingCoSignerConfig(
  config: Pick<RingCoSigner, "signer" | "scope" | "thresholds">,
): void {
  if (
    equalBytes(addressBytes(config.signer, "signer"), ZERO_32) ||
    !Number.isInteger(config.scope) ||
    config.scope < 1 ||
    config.scope > RING_COSIGN_SCOPE_MASK ||
    config.thresholds.length > RING_COSIGN_THRESHOLD_SLOTS ||
    new Set(config.thresholds.map((row) => row.mint)).size !== config.thresholds.length
  ) {
    throw new RingError("RING_CO_SIGNER_INVALID");
  }
}

/** Pins the signer for moves without member signatures. */
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
  if (equalBytes(key, ZERO_32)) {
    throw new RingError("RING_DELEGATE_INVALID", { details: { delegate: "zero" } });
  }
  return Object.freeze({ delegate: encodeBase58(key), bump });
}

/** Tracks each mint's public deposits and withdrawals per window. */
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

/** Rust `KeyRegistryRoot`. */
export interface RingKeyRegistryRoot {
  readonly root: Bytes32;
  readonly nextIndex: bigint;
  readonly bump: number;
  /** Slot of `root` in `history`. */
  readonly historyCursor: number;
  /** Every root stays sound, an enrolled leaf never changes. */
  readonly history: readonly Bytes32[];
}

/** Rust `KEY_REGISTRY_ROOT`, `KEY_REGISTRY_ROOT_HISTORY` and `KeyRegistryRoot::SIZE`. */
const RING_KEY_REGISTRY_ROOT_DISCRIMINATOR = 9;
export const RING_KEY_REGISTRY_ROOT_HISTORY = 32;
const RING_KEY_REGISTRY_ROOT_SIZE = 42 + 1 + 32 * RING_KEY_REGISTRY_ROOT_HISTORY;

export function decodeRingKeyRegistryRoot(data: Uint8Array): RingKeyRegistryRoot {
  if (
    data.length !== RING_KEY_REGISTRY_ROOT_SIZE ||
    data[0] !== RING_KEY_REGISTRY_ROOT_DISCRIMINATOR
  ) {
    throw new RingError("RING_KEY_REGISTRY_INVALID", {
      details: { length: data.length, discriminator: data[0] },
    });
  }
  const reader = new Reader(data);
  reader.u8("discriminator");
  const root = checkedRegistryField(reader.bytes(32, "root"));
  const nextIndex = reader.u64("nextIndex");
  const bump = reader.u8("bump");
  const historyCursor = reader.u8("historyCursor");
  const history = Object.freeze(
    Array.from(
      { length: RING_KEY_REGISTRY_ROOT_HISTORY },
      () => reader.bytes(32, "history") as Bytes32,
    ),
  );
  reader.done();
  if (nextIndex < 1n || nextIndex > KEY_REGISTRY_CAPACITY) {
    throw new RingError("RING_KEY_REGISTRY_INVALID", { details: { nextIndex } });
  }
  // Rust `advance_to` keeps `history[history_cursor] == root`.
  if (!equalBytes(history[historyCursor] ?? ZERO_32, root)) {
    throw new RingError("RING_KEY_REGISTRY_INVALID", { details: { historyCursor } });
  }
  return Object.freeze({ root, nextIndex, bump, historyCursor, history });
}

/** Rust `POLICY_CONFIG` and `PolicyConfig::SIZE`. */
const RING_POLICY_CONFIG_DISCRIMINATOR = 3;
export const RING_POLICY_CONFIG_SIZE = 1604;

export function decodeRingPolicyConfig(data: Uint8Array): RingPolicyConfig {
  if (data.length !== RING_POLICY_CONFIG_SIZE || data[0] !== RING_POLICY_CONFIG_DISCRIMINATOR) {
    throw new RingError("RING_POLICY_CONFIG_INVALID", {
      details: { length: data.length, discriminator: data[0] },
    });
  }
  const reader = new Reader(data);
  reader.u8("discriminator");
  const policyHash = reader.bytes(32, "policyHash") as Bytes32;
  const addressTree = encodeBase58(reader.bytes(32, "addressTree"));
  const addressTreeId = reader.u16("addressTreeId");
  const namespaceBump = reader.u8("namespaceBump");
  const bump = reader.u8("bump");
  const namespaceOwnerHash = reader.bytes(32, "namespaceOwnerHash") as Bytes32;
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
  const inlineLimits = countedLimits(reader, {
    count: inlineAssets.length,
    slots: RING_INLINE_ASSET_SLOTS,
    field: "inlineLimits",
  });
  const windowSlots = bytesToBigInt(reader.bytes(8, "windowSlots"));
  const velocityAssets = countedRows(reader, RING_VELOCITY_SLOTS, "velocityAssets");
  const velocityLimits = { count: velocityAssets.length, slots: RING_VELOCITY_SLOTS };
  const velocityCaps = countedLimits(reader, { ...velocityLimits, field: "velocityCaps" });
  const velocityCosign = countedLimits(reader, { ...velocityLimits, field: "velocityCosign" });
  const generation = reader.u32("generation");
  const generationSlot = reader.u64("generationSlot");
  reader.done();
  const velocity = Object.freeze(
    velocityAssets.map((asset, index) =>
      Object.freeze({
        asset,
        cap: velocityCaps[index] ?? 0n,
        cosignAbove: velocityCosign[index] ?? 0n,
      }),
    ),
  );
  return Object.freeze({
    policyHash,
    addressTree,
    addressTreeId,
    namespaceBump,
    bump,
    namespaceOwnerHash,
    sources,
    ruleCount: rules.length,
    rules,
    inlineCount: inlineAssets.length,
    inlineAssets,
    inlineLimits,
    windowSlots,
    velocityCount: velocity.length,
    velocity,
    generation,
    generationSlot,
  });
}

/** Big endian amounts, one per counted row, zero past the count. */
function countedLimits(
  reader: Reader,
  rows: Readonly<{ count: number; slots: number; field: string }>,
): readonly bigint[] {
  const limits: bigint[] = [];
  for (let index = 0; index < rows.slots; index += 1) {
    const limit = bytesToBigInt(reader.bytes(8, rows.field));
    if (index < rows.count) limits.push(limit);
    else if (limit !== 0n) {
      throw new RingError("RING_POLICY_CONFIG_INVALID", { details: { field: rows.field, index } });
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
