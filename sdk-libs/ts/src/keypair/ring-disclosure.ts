import { isCanonicalField } from "../interface/canonical-field.js";
import {
  ANONYMOUS_AUDIT_CLASSES,
  ANONYMOUS_ENTRY_CLASS,
  ANONYMOUS_ENTRY_OUTPUTS,
  ANONYMOUS_SLOT_BYTES,
  DELIVERED_AUDIT_CAPACITIES,
  DELIVERED_SLOT_BYTES,
  DISCLOSURE_INPUT_AMOUNT_BYTES,
  DISCLOSURE_SENDER_KEY_BYTES,
  PACKED_AUDIT_CAPACITIES,
  anonymousFields,
  deliveredFields,
  disclosureFieldCount,
  packedChunks,
  packedFields,
  type AnonymousLayout,
  type DeliveredLayout,
  type DisclosureLayout,
  type FieldRange,
  type PackedFields,
  type PackedLayout,
} from "../interface/ring-disclosure-layout.js";

import { maskDisclosure, packDisclosure, unmaskDisclosure, unpackDisclosure } from "./audit.js";
import {
  type Bytes16,
  type Bytes32,
  bigIntToBytes,
  bytesToBigInt,
  checkedBytes,
  concatBytes,
} from "./bytes.js";
import { KeypairError } from "./error.js";
import { RingDomain } from "./ring-domain.js";

export type DummySlot = Readonly<{ kind: "dummy" }>;

/** One published packed slot, ring output or exit alike, Rust `PackedOutputOpening`. */
export interface PackedOutputOpening {
  readonly ownerKey: Bytes32;
  /** `undefined` under key escrow, the owner's record escrows it. */
  readonly nullifierPk: Bytes32 | undefined;
  /** `hash_bytes(mint)`. */
  readonly asset: Bytes32;
  readonly amount: bigint;
  /** Zero on a data-free transfer. */
  readonly dataHash: Bytes32;
  readonly ringDataHash: Bytes32;
}

/** The recipient rebuilds the rest of a ring output from its body, an exit's owner is its owner tag. */
export type DeliveredOutputOpening =
  /** `nullifierPk` is `undefined` under key escrow. */
  | Readonly<{ kind: "ring"; ownerKey: Bytes32; nullifierPk: Bytes32 | undefined }>
  | Readonly<{ kind: "exit"; nullifierPk: Bytes32 | undefined; asset: Bytes32; amount: bigint }>
  | DummySlot;

/** The published tag hides `recipientU`, only the disclosure names it. */
export type AnonymousOutputOpening =
  | Readonly<{ kind: "ring"; ownerKey: Bytes32; nullifierPk: Bytes32; recipientU: Bytes32 }>
  | Readonly<{ kind: "exit"; nullifierPk: Bytes32; asset: Bytes32; amount: bigint }>
  | DummySlot;

/** A spent UTXO of the hidden sender, its data hashes zero. */
export interface AnonymousInputOpening {
  readonly asset: Bytes32;
  readonly amount: bigint;
  readonly blinding: Bytes32;
}

/** The spent UTXOs as the anonymous audit key discloses them, `undefined` for a dummy. */
export type AnonymousInputs =
  /** Every spent UTXO a ring note, the auditor opens it by its UTXO hash. */
  | Readonly<{ kind: "commitments"; hashes: readonly (Bytes32 | undefined)[] }>
  /** The entry key opens every spent UTXO, all under one nullifier key. */
  | Readonly<{
      kind: "openings";
      senderNullifierPk: Bytes32;
      inputs: readonly (AnonymousInputOpening | undefined)[];
    }>;

/** The plaintext an audit proof publishes under the CROD pad, `seedOut` present exactly when an output exits. */
export type RingDisclosure =
  /** `undefined` for a dummy. */
  | Readonly<{
      kind: "packed";
      layout: PackedLayout;
      seedOut: Bytes32 | undefined;
      outputs: readonly (PackedOutputOpening | undefined)[];
    }>
  | Readonly<{
      kind: "delivered";
      layout: DeliveredLayout;
      seedOut: Bytes32 | undefined;
      outputs: readonly DeliveredOutputOpening[];
    }>
  | Readonly<{
      kind: "anonymous";
      layout: AnonymousLayout;
      seedOut: Bytes32 | undefined;
      senderKey: Bytes32;
      outputs: readonly AnonymousOutputOpening[];
      inputs: AnonymousInputs;
    }>;

/** A ring slot and an exit share a byte width, the exit bitmap tells them apart. */
export interface PublishedOutputs {
  readonly layout: DisclosureLayout;
  /** One per published slot. */
  readonly exits: readonly boolean[];
}

/** Both sides of the disclosure know `tx_sk` and the transfer's salt. */
export interface DisclosureKey {
  readonly txViewingSecret: Bytes32;
  readonly salt: Bytes16;
}

export function disclosureLayout(disclosure: RingDisclosure): DisclosureLayout {
  switch (disclosure.kind) {
    case "packed":
      return checkedLayout({ kind: "packed", ...disclosure.layout });
    case "delivered":
      return checkedLayout({ kind: "delivered", ...disclosure.layout });
    case "anonymous":
      return checkedLayout({ kind: "anonymous", ...disclosure.layout });
  }
}

/** The published fields, `C[j] = P[j] + pad_j`. */
export function sealRingDisclosure(
  key: DisclosureKey,
  disclosure: RingDisclosure,
): readonly Bytes32[] {
  const plaintext = disclosureFields(disclosure);
  try {
    const sealed = maskDisclosure({
      key: key.txViewingSecret,
      salt: key.salt,
      domain: RingDomain.disclosurePad,
      fields: plaintext,
    });
    // The program refuses a zero published field, another salt seals the transfer.
    if (sealed.some((field) => field.every((byte) => byte === 0)))
      throw new KeypairError("KEYPAIR_DISCLOSURE_FIELD", { name: "published" });
    return sealed;
  } finally {
    for (const field of plaintext) field.fill(0);
  }
}

/** Refuses a field at or above the modulus and any nonzero padding. */
export function openRingDisclosure(
  key: DisclosureKey,
  published: PublishedOutputs & Readonly<{ fields: readonly Bytes32[] }>,
): RingDisclosure {
  const layout = checkedLayout(published.layout);
  if (published.fields.length !== disclosureFieldCount(layout)) throw shapeError("fields");
  const plaintext = unmaskDisclosure({
    key: key.txViewingSecret,
    salt: key.salt,
    domain: RingDomain.disclosurePad,
    fields: published.fields,
  });
  try {
    return decodeDisclosure({ layout, exits: published.exits }, plaintext);
  } finally {
    for (const field of plaintext) field.fill(0);
  }
}

/** The plaintext `P`, every field where the layout's fields place it. */
export function disclosureFields(disclosure: RingDisclosure): Bytes32[] {
  const layout = disclosureLayout(disclosure);
  const fields = Array.from(
    { length: disclosureFieldCount(layout) },
    () => new Uint8Array(32) as Bytes32,
  );
  try {
    switch (disclosure.kind) {
      case "packed": {
        const at = packedFields(disclosure.layout);
        checkCount(disclosure.outputs.length, disclosure.layout.outputs);
        placeSeedOut(fields, at.seedOut, disclosure.seedOut);
        disclosure.outputs.forEach((opening, index) => {
          if (opening !== undefined)
            placePacked(fields, at.firstSlot + index * at.slotWidth, at, opening);
        });
        break;
      }
      case "delivered": {
        const at = deliveredFields(disclosure.layout);
        checkCount(disclosure.outputs.length, disclosure.layout.outputs);
        placeSeedOut(fields, at.seedOut, disclosure.seedOut);
        if (at.nullifierPks === undefined) {
          if (disclosure.outputs.some((output) => deliveredNullifierPk(output) !== undefined))
            throw shapeError("nullifierPk");
        } else
          place(fields, at.nullifierPks, disclosure.outputs.map(publishedDeliveredNullifierPk));
        place(
          fields,
          at.slots,
          packParts((parts) => {
            for (const output of disclosure.outputs) pushDeliveredSlot(parts, output, at.slotBytes);
          }),
        );
        break;
      }
      case "anonymous":
        placeAnonymous(fields, disclosure);
        break;
    }
    return fields.map((field, index) => canonical(field, `field${String(index)}`));
  } catch (error) {
    for (const field of fields) field.fill(0);
    throw error;
  }
}

/** Refuses a field at or above the modulus and any nonzero padding, the result shares no bytes with `plaintext`. */
export function decodeDisclosure(
  published: PublishedOutputs,
  plaintext: readonly Bytes32[],
): RingDisclosure {
  const layout = checkedLayout(published.layout);
  const { exits } = published;
  if (plaintext.length !== disclosureFieldCount(layout)) throw shapeError("fields");
  const fields = plaintext.map((value, index) => field(value, `field${String(index)}`));
  checkCount(exits.length, layout.outputs);
  if (!layout.exits && exits.includes(true)) throw shapeError("exits");
  switch (layout.kind) {
    case "packed": {
      const at = packedFields(layout);
      return Object.freeze({
        kind: "packed",
        layout: packedLayout(layout),
        seedOut: fieldAt(fields, at.seedOut),
        outputs: Object.freeze(
          exits.map((_, index) => {
            const start = at.firstSlot + index * at.slotWidth;
            return readPacked(fields.slice(start, start + at.slotWidth), at);
          }),
        ),
      });
    }
    case "delivered": {
      const at = deliveredFields(layout);
      const slots = unpackDisclosure(slice(fields, at.slots), at.slotBytes * layout.outputs);
      try {
        return Object.freeze({
          kind: "delivered",
          layout: deliveredLayout(layout),
          seedOut: fieldAt(fields, at.seedOut),
          outputs: Object.freeze(
            exits.map((exit, index) =>
              readDelivered(
                at.nullifierPks === undefined ? undefined : fields[at.nullifierPks.start + index],
                slots.subarray(index * at.slotBytes, (index + 1) * at.slotBytes),
                exit,
              ),
            ),
          ),
        });
      } finally {
        slots.fill(0);
      }
    }
    case "anonymous":
      return readAnonymous(anonymousLayout(layout), exits, fields);
  }
}

const KEY_BYTES = 32;
const AMOUNT_BYTES = 8;
const KEY_AND_AMOUNT_BYTES = KEY_BYTES + AMOUNT_BYTES;
const OWNER_AND_AMOUNT_FIELDS = packedChunks(KEY_AND_AMOUNT_BYTES);
const U64_MAX = 0xffff_ffff_ffff_ffffn;
const DUMMY: DummySlot = Object.freeze({ kind: "dummy" });

/** A structural layout names one key, its counts within the capacities that key serves. */
function checkedLayout<T extends DisclosureLayout>(layout: T): T {
  const flags = [layout.exits, ...(layout.kind === "anonymous" ? [] : [layout.keyEscrow])];
  const counted = (value: number) => Number.isInteger(value) && value >= 1;
  const valid =
    flags.every((flag) => typeof flag === "boolean") &&
    counted(layout.outputs) &&
    (layout.kind === "packed"
      ? typeof layout.dataFree === "boolean" &&
        layout.outputs <= Math.max(...PACKED_AUDIT_CAPACITIES)
      : layout.kind === "delivered"
        ? DELIVERED_AUDIT_CAPACITIES.includes(layout.outputs)
        : counted(layout.inputs) &&
          (layout.key.kind === "entry"
            ? ANONYMOUS_ENTRY_OUTPUTS.includes(layout.outputs) &&
              layout.inputs <= ANONYMOUS_ENTRY_CLASS
            : (ANONYMOUS_AUDIT_CLASSES.find(
                (entry) => entry.outputs === layout.outputs,
              )?.classes.includes(layout.key.class) ??
                false) &&
              layout.inputs <= layout.key.class));
  if (!valid) throw shapeError("layout");
  return layout;
}

function packedLayout(layout: PackedLayout): PackedLayout {
  return Object.freeze({
    outputs: layout.outputs,
    exits: layout.exits,
    keyEscrow: layout.keyEscrow,
    dataFree: layout.dataFree,
  });
}

function deliveredLayout(layout: DeliveredLayout): DeliveredLayout {
  return Object.freeze({
    outputs: layout.outputs,
    exits: layout.exits,
    keyEscrow: layout.keyEscrow,
  });
}

function anonymousLayout(layout: AnonymousLayout): AnonymousLayout {
  return Object.freeze({
    key: layout.key,
    inputs: layout.inputs,
    outputs: layout.outputs,
    exits: layout.exits,
  });
}

function placePacked(
  fields: Bytes32[],
  start: number,
  at: PackedFields,
  opening: PackedOutputOpening,
): void {
  if ((at.nullifierPk === undefined) !== (opening.nullifierPk === undefined))
    throw shapeError("nullifierPk");
  if (at.nullifierPk !== undefined && opening.nullifierPk !== undefined)
    fields[start + at.nullifierPk] = field(opening.nullifierPk, "nullifierPk");
  fields[start + at.asset] = field(opening.asset, "asset");
  if (at.dataHashes !== undefined) {
    fields[start + at.dataHashes] = field(opening.dataHash, "dataHash");
    fields[start + at.dataHashes + 1] = field(opening.ringDataHash, "ringDataHash");
  } else if (!isZero(opening.dataHash) || !isZero(opening.ringDataHash))
    throw shapeError("dataHash");
  const first = start + at.ownerAndAmount;
  place(
    fields,
    { start: first, end: first + OWNER_AND_AMOUNT_FIELDS },
    packParts((parts) => {
      parts.push(checkedBytes<Bytes32>(opening.ownerKey, 32, "ownerKey"));
      parts.push(amountBytes(opening.amount));
    }),
  );
}

/** `undefined` for a dummy, every field of its slot zero. */
function readPacked(slot: readonly Bytes32[], at: PackedFields): PackedOutputOpening | undefined {
  if (slot.every(isZero)) return undefined;
  const bytes = unpackDisclosure(
    slot.slice(at.ownerAndAmount, at.ownerAndAmount + OWNER_AND_AMOUNT_FIELDS),
    KEY_AND_AMOUNT_BYTES,
  );
  try {
    return Object.freeze({
      ownerKey: key(bytes, 0, "ownerKey"),
      nullifierPk: at.nullifierPk === undefined ? undefined : slot[at.nullifierPk],
      asset: required(slot[at.asset]),
      amount: bytesToBigInt(bytes.subarray(KEY_BYTES)),
      dataHash: at.dataHashes === undefined ? zero() : required(slot[at.dataHashes]),
      ringDataHash: at.dataHashes === undefined ? zero() : required(slot[at.dataHashes + 1]),
    });
  } finally {
    bytes.fill(0);
  }
}

function deliveredNullifierPk(output: DeliveredOutputOpening): Bytes32 | undefined {
  return output.kind === "dummy" ? undefined : output.nullifierPk;
}

/** The disclosed key of a slot, zero for a dummy. */
function publishedDeliveredNullifierPk(output: DeliveredOutputOpening): Bytes32 {
  if (output.kind === "dummy") return zero();
  if (output.nullifierPk === undefined) throw shapeError("nullifierPk");
  return field(output.nullifierPk, "nullifierPk");
}

/** With an exit a slot is `owner_key ‖ 0^8` or `asset ‖ u64be(amount)`, without one `owner_key`. */
function pushDeliveredSlot(
  parts: Uint8Array[],
  output: DeliveredOutputOpening,
  width: number,
): void {
  switch (output.kind) {
    case "ring":
      parts.push(checkedBytes<Bytes32>(output.ownerKey, 32, "ownerKey"));
      parts.push(new Uint8Array(width - KEY_BYTES));
      return;
    case "exit":
      if (width !== DELIVERED_SLOT_BYTES) throw shapeError("exits");
      parts.push(field(output.asset, "asset"));
      parts.push(amountBytes(output.amount));
      return;
    case "dummy":
      parts.push(new Uint8Array(width));
  }
}

function readDelivered(
  nullifierPk: Bytes32 | undefined,
  slot: Uint8Array,
  exit: boolean,
): DeliveredOutputOpening {
  const head = key(slot, 0, "ownerKey");
  const tail = slot.subarray(KEY_BYTES);
  if (exit)
    return Object.freeze({
      kind: "exit",
      nullifierPk,
      asset: field(head, "asset"),
      amount: bytesToBigInt(tail),
    });
  // A disclosed zero key marks a dummy, under key escrow its zero slot does.
  if (isZero(nullifierPk ?? head)) {
    zeroBytes(slot);
    return DUMMY;
  }
  zeroBytes(tail);
  return Object.freeze({ kind: "ring", ownerKey: head, nullifierPk });
}

function anonymousNullifierPk(output: AnonymousOutputOpening): Bytes32 {
  return output.kind === "dummy" ? zero() : field(output.nullifierPk, "nullifierPk");
}

/** A ring slot `owner_key ‖ u`, an exit `asset ‖ u64be(amount) ‖ 0^24`. */
function pushAnonymousSlot(parts: Uint8Array[], output: AnonymousOutputOpening): void {
  switch (output.kind) {
    case "ring":
      parts.push(checkedBytes<Bytes32>(output.ownerKey, 32, "ownerKey"));
      parts.push(checkedBytes<Bytes32>(output.recipientU, 32, "recipientU"));
      return;
    case "exit":
      parts.push(field(output.asset, "asset"));
      parts.push(amountBytes(output.amount));
      parts.push(new Uint8Array(ANONYMOUS_SLOT_BYTES - KEY_AND_AMOUNT_BYTES));
      return;
    case "dummy":
      parts.push(new Uint8Array(ANONYMOUS_SLOT_BYTES));
  }
}

function readAnonymousOutput(
  nullifierPk: Bytes32,
  slot: Uint8Array,
  exit: boolean,
): AnonymousOutputOpening {
  const head = key(slot, 0, "ownerKey");
  const tail = slot.subarray(KEY_BYTES);
  if (exit) {
    zeroBytes(tail.subarray(AMOUNT_BYTES));
    return Object.freeze({
      kind: "exit",
      nullifierPk,
      asset: field(head, "asset"),
      amount: bytesToBigInt(tail.subarray(0, AMOUNT_BYTES)),
    });
  }
  if (isZero(nullifierPk)) {
    zeroBytes(slot);
    return DUMMY;
  }
  return Object.freeze({
    kind: "ring",
    ownerKey: head,
    nullifierPk,
    recipientU: key(tail, 0, "recipientU"),
  });
}

function placeAnonymous(
  fields: Bytes32[],
  disclosure: Extract<RingDisclosure, { kind: "anonymous" }>,
): void {
  const { layout, inputs } = disclosure;
  const at = anonymousFields(layout);
  checkCount(disclosure.outputs.length, layout.outputs);
  placeSeedOut(fields, at.seedOut, disclosure.seedOut);
  place(fields, at.nullifierPks, disclosure.outputs.map(anonymousNullifierPk));
  place(
    fields,
    at.slots,
    packParts((parts) => {
      parts.push(
        checkedBytes<Bytes32>(disclosure.senderKey, DISCLOSURE_SENDER_KEY_BYTES, "senderKey"),
      );
      for (const output of disclosure.outputs) pushAnonymousSlot(parts, output);
    }),
  );
  if (inputs.kind === "commitments") {
    if (layout.key.kind !== "commitment") throw shapeError("inputs");
    checkCount(inputs.hashes.length, layout.inputs);
    place(
      fields,
      at.inputs,
      inputs.hashes.map((hash) => (hash === undefined ? zero() : field(hash, "inputHash"))),
    );
    return;
  }
  if (
    layout.key.kind !== "entry" ||
    at.senderNullifierPk === undefined ||
    at.inputAmounts === undefined
  )
    throw shapeError("inputs");
  checkCount(inputs.inputs.length, layout.inputs);
  const openings = inputs.inputs.map(
    (opening) => opening ?? { asset: zero(), amount: 0n, blinding: zero() },
  );
  openings.forEach((opening, index) => {
    const pair = at.inputs.start + at.inputWidth * index;
    fields[pair] = field(opening.asset, "inputAsset");
    fields[pair + 1] = field(opening.blinding, "inputBlinding");
  });
  place(
    fields,
    at.inputAmounts,
    packParts((parts) => {
      for (const opening of openings) parts.push(amountBytes(opening.amount));
      parts.push(
        new Uint8Array(DISCLOSURE_INPUT_AMOUNT_BYTES * (ANONYMOUS_ENTRY_CLASS - openings.length)),
      );
    }),
  );
  fields[at.senderNullifierPk] = field(inputs.senderNullifierPk, "senderNullifierPk");
}

function readAnonymous(
  layout: AnonymousLayout,
  exits: readonly boolean[],
  fields: readonly Bytes32[],
): RingDisclosure {
  const at = anonymousFields(layout);
  const block = unpackDisclosure(
    slice(fields, at.slots),
    DISCLOSURE_SENDER_KEY_BYTES + ANONYMOUS_SLOT_BYTES * layout.outputs,
  );
  try {
    const outputs = slice(fields, at.nullifierPks).map((nullifierPk, index) => {
      const start = DISCLOSURE_SENDER_KEY_BYTES + index * ANONYMOUS_SLOT_BYTES;
      return readAnonymousOutput(
        nullifierPk,
        block.subarray(start, start + ANONYMOUS_SLOT_BYTES),
        exits[index] === true,
      );
    });
    return Object.freeze({
      kind: "anonymous",
      layout,
      seedOut: fieldAt(fields, at.seedOut),
      senderKey: key(block, 0, "senderKey"),
      outputs: Object.freeze(outputs),
      inputs: readAnonymousInputs(layout, fields),
    });
  } finally {
    block.fill(0);
  }
}

function readAnonymousInputs(layout: AnonymousLayout, fields: readonly Bytes32[]): AnonymousInputs {
  const at = anonymousFields(layout);
  const published = slice(fields, at.inputs);
  if (layout.key.kind === "commitment")
    return Object.freeze({
      kind: "commitments",
      hashes: Object.freeze(published.map((hash) => (isZero(hash) ? undefined : hash))),
    });
  if (at.senderNullifierPk === undefined || at.inputAmounts === undefined)
    throw shapeError("inputs");
  const amounts = unpackDisclosure(
    slice(fields, at.inputAmounts),
    DISCLOSURE_INPUT_AMOUNT_BYTES * ANONYMOUS_ENTRY_CLASS,
  );
  try {
    zeroBytes(amounts.subarray(DISCLOSURE_INPUT_AMOUNT_BYTES * layout.inputs));
    return Object.freeze({
      kind: "openings",
      senderNullifierPk: required(fields[at.senderNullifierPk]),
      inputs: Object.freeze(
        Array.from({ length: layout.inputs }, (_, index) => {
          const asset = required(published[at.inputWidth * index]);
          const blinding = required(published[at.inputWidth * index + 1]);
          const amount = bytesToBigInt(
            amounts.subarray(
              index * DISCLOSURE_INPUT_AMOUNT_BYTES,
              (index + 1) * DISCLOSURE_INPUT_AMOUNT_BYTES,
            ),
          );
          return amount === 0n && isZero(asset) && isZero(blinding)
            ? undefined
            : Object.freeze({ asset, amount, blinding });
        }),
      ),
    });
  } finally {
    amounts.fill(0);
  }
}

/** `SeedOut` is published exactly when the layout names its position. */
function placeSeedOut(
  fields: Bytes32[],
  at: number | undefined,
  seedOut: Bytes32 | undefined,
): void {
  if ((at === undefined) !== (seedOut === undefined)) throw shapeError("seedOut");
  if (at !== undefined && seedOut !== undefined) fields[at] = field(seedOut, "seedOut");
}

function place(fields: Bytes32[], range: FieldRange, values: readonly Bytes32[]): void {
  if (values.length !== range.end - range.start) throw shapeError("fields");
  values.forEach((value, offset) => {
    fields[range.start + offset] = value;
  });
}

function packParts(write: (parts: Uint8Array[]) => void): readonly Bytes32[] {
  const parts: Uint8Array[] = [];
  let block: Uint8Array | undefined;
  try {
    write(parts);
    block = concatBytes(...parts);
    return packDisclosure(block);
  } finally {
    for (const part of parts) part.fill(0);
    block?.fill(0);
  }
}

function slice(fields: readonly Bytes32[], range: FieldRange): readonly Bytes32[] {
  return fields.slice(range.start, range.end);
}

function fieldAt(fields: readonly Bytes32[], at: number | undefined): Bytes32 | undefined {
  return at === undefined ? undefined : required(fields[at]);
}

function required(value: Bytes32 | undefined): Bytes32 {
  if (value === undefined) throw shapeError("fields");
  return value;
}

function checkCount(found: number, expected: number): void {
  if (found !== expected) throw shapeError("count");
}

function amountBytes(amount: bigint): Uint8Array {
  if (typeof amount !== "bigint" || amount < 0n || amount > U64_MAX)
    throw new KeypairError("KEYPAIR_DISCLOSURE_FIELD", { name: "amount" });
  return bigIntToBytes(amount, AMOUNT_BYTES);
}

/** The circuit discloses only canonical field encodings. */
function field(value: Uint8Array, name: string): Bytes32 {
  return canonical(checkedBytes<Bytes32>(value, 32, name), name);
}

function canonical(value: Bytes32, name: string): Bytes32 {
  if (!isCanonicalField(value)) throw new KeypairError("KEYPAIR_DISCLOSURE_FIELD", { name });
  return value;
}

function key(bytes: Uint8Array, at: number, name: string): Bytes32 {
  return checkedBytes<Bytes32>(bytes.subarray(at, at + KEY_BYTES), 32, name);
}

function zeroBytes(bytes: Uint8Array): void {
  if (!isZero(bytes)) throw new KeypairError("KEYPAIR_DISCLOSURE_PADDING", { name: "slot" });
}

function isZero(bytes: Uint8Array): boolean {
  return bytes.every((byte) => byte === 0);
}

function zero(): Bytes32 {
  return new Uint8Array(32) as Bytes32;
}

function shapeError(name: string): KeypairError {
  return new KeypairError("KEYPAIR_DISCLOSURE_SHAPE", { name });
}
