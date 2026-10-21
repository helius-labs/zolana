/** Field layouts of the auditor disclosure, Rust `custom_ring_interface::disclosure`. */
import { InterfaceError } from "./errors.js";

/** Packed audit output capacities, no delivery proof. */
export const PACKED_AUDIT_CAPACITIES: readonly number[] = Object.freeze([2, 4]);
export const DELIVERED_AUDIT_CAPACITIES: readonly number[] = Object.freeze([8, 16]);
/** Input classes of the anonymous commitment keys per output capacity, ascending. */
export const ANONYMOUS_AUDIT_CLASSES: readonly Readonly<{
  outputs: number;
  classes: readonly number[];
}>[] = Object.freeze([
  Object.freeze({ outputs: 2, classes: Object.freeze([4, 8, 12, 16, 24, 28]) }),
  Object.freeze({ outputs: 4, classes: Object.freeze([4, 8, 12, 16, 24]) }),
  Object.freeze({ outputs: 8, classes: Object.freeze([4, 8, 12, 16]) }),
]);
/** Input slots of every anonymous entry key. */
export const ANONYMOUS_ENTRY_CLASS = 8;
/** Output capacities of the anonymous entry keys. */
export const ANONYMOUS_ENTRY_OUTPUTS: readonly number[] = Object.freeze([2, 4, 8]);
/** The widest commitment class, no anonymous key serves more inputs. */
export const ANONYMOUS_MAX_INPUTS = Math.max(
  ...ANONYMOUS_AUDIT_CLASSES.flatMap((entry) => entry.classes),
);
/** A delivered slot of a transfer with an exit, ring `owner_key ‖ 0^8`, exit `asset ‖ u64be(amount)`. */
export const DELIVERED_SLOT_BYTES = 40;
/** A delivered ring slot of an exit-free transfer, `owner_key`. */
export const DENSE_DELIVERED_SLOT_BYTES = 32;
/** A ring slot `owner_key ‖ u`, an exit `asset ‖ u64be(amount) ‖ 0^24`. */
export const ANONYMOUS_SLOT_BYTES = 64;
/** The hidden sender's key ahead of the anonymous output slots. */
export const DISCLOSURE_SENDER_KEY_BYTES = 32;
/** One `u64be(amount)` per input slot of the entry class. */
export const DISCLOSURE_INPUT_AMOUNT_BYTES = 8;
/** Rust `PACK_BE_CHUNK_BYTES`, the bytes of one disclosure field. */
export const DISCLOSURE_CHUNK_BYTES = 31;

/** The audit statement's layout element, Rust `AuditLayout`. */
export interface AuditLayout {
  /** A published output exits, `SeedOut` opens the disclosure. */
  readonly exits: boolean;
  /** The policy proof escrows every output nullifier key the disclosure leaves out. */
  readonly keyEscrow: boolean;
  /** No published output carries a data hash. */
  readonly dataFree: boolean;
  /** The anonymous entry key, every spent UTXO opens in full. */
  readonly fullOpenings: boolean;
}

/** `exits | key_escrow << 1 | data_free << 2 | full_openings << 3`. */
export function auditLayoutValue(layout: AuditLayout): number {
  const flags = [layout.exits, layout.keyEscrow, layout.dataFree, layout.fullOpenings];
  if (flags.some((flag) => typeof flag !== "boolean"))
    throw new InterfaceError("INTERFACE_INVALID_SHAPE", { name: "layout" });
  return flags.reduce((value, flag, bit) => (flag ? value | (1 << bit) : value), 0);
}

/** The key of an anonymous transfer's audit proof, Rust `AnonymousAuditKey`. */
export type AnonymousAuditKey =
  /** Publishes each spent UTXO's hash, every spent UTXO a note of the ring. */
  | Readonly<{ kind: "commitment"; class: number }>
  /** Opens every spent UTXO, the key of a transfer that spends a default-ring note. */
  | Readonly<{ kind: "entry" }>;

/** The input slots of the key. */
export function anonymousKeyClass(key: AnonymousAuditKey): number {
  return key.kind === "commitment" ? key.class : ANONYMOUS_ENTRY_CLASS;
}

/** What picks an anonymous transfer's audit key, Rust `AnonymousSpend`. */
export interface AnonymousSpend {
  /** Published inputs. */
  readonly inputs: number;
  readonly outputs: number;
  /** A spent UTXO is a default-ring note, the commitment keys refuse ring id zero. */
  readonly spendsDefaultRing: boolean;
}

/** `undefined` when no key serves the spend, a larger entry spend splits. */
export function anonymousAuditKey(spend: AnonymousSpend): AnonymousAuditKey | undefined {
  if (!spend.spendsDefaultRing) {
    const inputClass = anonymousAuditClass(spend.inputs, spend.outputs);
    return inputClass === undefined
      ? undefined
      : Object.freeze({ kind: "commitment", class: inputClass });
  }
  return ANONYMOUS_ENTRY_OUTPUTS.includes(spend.outputs) && spend.inputs <= ANONYMOUS_ENTRY_CLASS
    ? Object.freeze({ kind: "entry" })
    : undefined;
}

/** The smallest commitment class holding `inputs` for `outputs`, `undefined` when no key serves it. */
export function anonymousAuditClass(inputs: number, outputs: number): number | undefined {
  return ANONYMOUS_AUDIT_CLASSES.find((entry) => entry.outputs === outputs)?.classes.find(
    (inputClass) => inputClass >= inputs,
  );
}

export interface PackedLayout {
  /** The published slots, a prefix of the capacity. */
  readonly outputs: number;
  readonly exits: boolean;
  readonly keyEscrow: boolean;
  readonly dataFree: boolean;
}

export interface DeliveredLayout {
  /** Every slot of the capacity. */
  readonly outputs: number;
  readonly exits: boolean;
  readonly keyEscrow: boolean;
}

export interface AnonymousLayout {
  readonly key: AnonymousAuditKey;
  /** Published inputs. */
  readonly inputs: number;
  readonly outputs: number;
  readonly exits: boolean;
}

/** The published fields of one transfer's disclosure, Rust `DisclosureLayout`. */
export type DisclosureLayout =
  /** Capacity 2 and 4 of the confidential and delegate rails. */
  | (Readonly<{ kind: "packed" }> & PackedLayout)
  /** Capacity 8 and 16 of the confidential and delegate rails. */
  | (Readonly<{ kind: "delivered" }> & DeliveredLayout)
  | (Readonly<{ kind: "anonymous" }> & AnonymousLayout);

/** Field positions `start` up to `end`, exclusive. */
export interface FieldRange {
  readonly start: number;
  readonly end: number;
}

/** Positions in a packed disclosure, slot `k` opens at `firstSlot + k * slotWidth`. */
export interface PackedFields {
  readonly seedOut: number | undefined;
  readonly firstSlot: number;
  readonly slotWidth: number;
  /** Offsets inside a slot from here on. */
  readonly nullifierPk: number | undefined;
  readonly asset: number;
  /** `data_hash` then `ring_data_hash`. */
  readonly dataHashes: number | undefined;
  /** The two fields of `pack_disclosure(owner_key ‖ u64be(amount))`. */
  readonly ownerAndAmount: number;
  readonly fieldCount: number;
}

/** Positions in a delivered disclosure. */
export interface DeliveredFields {
  readonly seedOut: number | undefined;
  /** `nullifier_pk` per slot. */
  readonly nullifierPks: FieldRange | undefined;
  /** `pack_disclosure` of every slot, `slotBytes` each. */
  readonly slots: FieldRange;
  readonly slotBytes: number;
  readonly fieldCount: number;
}

/** Positions in an anonymous disclosure. */
export interface AnonymousFields {
  readonly seedOut: number | undefined;
  /** The entry key's `nullifier_pk` of every spent UTXO. */
  readonly senderNullifierPk: number | undefined;
  /** `nullifier_pk` per output. */
  readonly nullifierPks: FieldRange;
  /** `pack_disclosure(sender_key ‖ slots)`, `ANONYMOUS_SLOT_BYTES` a slot. */
  readonly slots: FieldRange;
  /** The entry key's `pack_disclosure(u64be(amount))` over its class, zero past the inputs. */
  readonly inputAmounts: FieldRange | undefined;
  /** Per published input `inputWidth` fields, the UTXO hash or the entry key's `asset, blinding`. */
  readonly inputs: FieldRange;
  readonly inputWidth: number;
  readonly fieldCount: number;
}

/** Rust `pack_be_chunks`, the fields `length` bytes pack into. */
export function packedChunks(length: number): number {
  return Math.ceil(length / DISCLOSURE_CHUNK_BYTES);
}

const PACKED_OWNER_AND_AMOUNT_FIELDS = packedChunks(32 + 8);

export function packedFields(layout: PackedLayout): PackedFields {
  const next = new Cursor();
  const seedOut = layout.exits ? next.one() : undefined;
  const slot = new Cursor();
  const nullifierPk = layout.keyEscrow ? undefined : slot.one();
  const asset = slot.one();
  const dataHashes = layout.dataFree ? undefined : slot.run(2).start;
  const ownerAndAmount = slot.run(PACKED_OWNER_AND_AMOUNT_FIELDS).start;
  const firstSlot = next.run(layout.outputs * slot.position).start;
  return Object.freeze({
    seedOut,
    firstSlot,
    slotWidth: slot.position,
    nullifierPk,
    asset,
    dataHashes,
    ownerAndAmount,
    fieldCount: next.position,
  });
}

export function deliveredFields(layout: DeliveredLayout): DeliveredFields {
  const next = new Cursor();
  const seedOut = layout.exits ? next.one() : undefined;
  const nullifierPks = layout.keyEscrow ? undefined : next.run(layout.outputs);
  const slotBytes = layout.exits ? DELIVERED_SLOT_BYTES : DENSE_DELIVERED_SLOT_BYTES;
  const slots = next.run(packedChunks(slotBytes * layout.outputs));
  return Object.freeze({ seedOut, nullifierPks, slots, slotBytes, fieldCount: next.position });
}

export function anonymousFields(layout: AnonymousLayout): AnonymousFields {
  const entry = layout.key.kind === "entry";
  const next = new Cursor();
  const seedOut = layout.exits ? next.one() : undefined;
  const senderNullifierPk = entry ? next.one() : undefined;
  const nullifierPks = next.run(layout.outputs);
  const slots = next.run(
    packedChunks(DISCLOSURE_SENDER_KEY_BYTES + ANONYMOUS_SLOT_BYTES * layout.outputs),
  );
  const inputAmounts = entry
    ? next.run(packedChunks(DISCLOSURE_INPUT_AMOUNT_BYTES * ANONYMOUS_ENTRY_CLASS))
    : undefined;
  const inputWidth = entry ? 2 : 1;
  const inputs = next.run(inputWidth * layout.inputs);
  return Object.freeze({
    seedOut,
    senderNullifierPk,
    nullifierPks,
    slots,
    inputAmounts,
    inputs,
    inputWidth,
    fieldCount: next.position,
  });
}

export function disclosureFieldCount(layout: DisclosureLayout): number {
  switch (layout.kind) {
    case "packed":
      return packedFields(layout).fieldCount;
    case "delivered":
      return deliveredFields(layout).fieldCount;
    case "anonymous":
      return anonymousFields(layout).fieldCount;
  }
}

/** Hands out consecutive field positions. */
class Cursor {
  position = 0;

  one(): number {
    return this.run(1).start;
  }

  run(length: number): FieldRange {
    const start = this.position;
    this.position += length;
    return Object.freeze({ start, end: this.position });
  }
}
