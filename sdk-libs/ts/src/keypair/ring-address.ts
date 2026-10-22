/** Mirrors Rust `zolana_keypair::ring_address`, pinned by `test-vectors/ring_address.json`. */
import { equalBytes } from "@noble/ciphers/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  address,
  getAddressDecoder,
  getAddressEncoder,
  getBase58Decoder,
  getBase58Encoder,
  type Address,
} from "@solana/kit";

import { concatBytes } from "./bytes.js";
import { U64_MAX, checkedCounter } from "./derivation.js";
import { KeypairError } from "./error.js";
import { SHIELDED_ADDRESS_LENGTH, ShieldedAddress } from "./shielded.js";

const addressDecoder = getAddressDecoder();
const addressEncoder = getAddressEncoder();
const base58Decoder = getBase58Decoder();
const base58Encoder = getBase58Encoder();
const encoder = new TextEncoder();

export const RING_ADDRESS_VERSION = 2;

export const RING_ADDRESS_CHECKSUM_DOMAIN = "zolana/ring-addr/v2";

export const RING_PAYMENT_SCHEME = "zolana:";

/** The most rows a sender checks before a pair stream. */
export const MAX_PAIRING_ROWS = 4;

const CHECKSUM_LENGTH = 4;
/** `mint(32) ‖ u64be(min_amount)`. */
const PAIRING_ROW_LENGTH = 40;
/** `version ‖ recipient ‖ ring_program_id ‖ pairing count`. */
const HEADER_LENGTH = 1 + SHIELDED_ADDRESS_LENGTH + 32 + 1;
const PROGRAM_OFFSET = 1 + SHIELDED_ADDRESS_LENGTH;

export const MAX_RING_ADDRESS_PAYLOAD_LENGTH =
  HEADER_LENGTH + MAX_PAIRING_ROWS * PAIRING_ROW_LENGTH + CHECKSUM_LENGTH;

/** A first contact of `mint` worth at least `minAmount` anchors a pair stream, the all-zero mint matches every asset. */
export interface PairingRow {
  readonly mint: Address;
  readonly minAmount: bigint;
}

const ANY_MINT = addressDecoder.decode(new Uint8Array(32));

/** The first contacts a recipient keeps a pair stream for, a note the recipient never scans for is lost. */
export class Pairing {
  readonly rows: readonly PairingRow[];

  private constructor(rows: readonly PairingRow[]) {
    this.rows = Object.freeze(rows.map((row) => Object.freeze({ ...row })));
    Object.freeze(this);
  }

  /** No pair streams, every payment takes the inbox stream. */
  static off(): Pairing {
    return new Pairing([]);
  }

  /** Every asset at any amount, the rows a new address carries. */
  static any(): Pairing {
    return new Pairing([{ mint: ANY_MINT, minAmount: 0n }]);
  }

  static of(rows: readonly PairingRow[]): Pairing {
    if (rows.length > MAX_PAIRING_ROWS)
      throw new KeypairError("KEYPAIR_INVALID_RING_ADDRESS_PAIRING", {
        actual: rows.length,
        maximum: MAX_PAIRING_ROWS,
      });
    return new Pairing(
      rows.map((row) => ({
        mint: pairingMint(row.mint),
        minAmount: checkedCounter(row.minAmount, "minAmount"),
      })),
    );
  }

  isOff(): boolean {
    return this.rows.length === 0;
  }

  /** Whether a first contact of `mint` and `amount` anchors a pair stream. */
  admits(mint: Address, amount: bigint): boolean {
    return this.rows.some(
      (row) => (row.mint === ANY_MINT || row.mint === mint) && amount >= row.minAmount,
    );
  }
}

function pairingMint(value: Address): Address {
  try {
    return address(value);
  } catch (error) {
    throw new KeypairError("KEYPAIR_INVALID_RING_ADDRESS_PAIRING", { reason: "mint" }, error);
  }
}

/** Shared off chain, never published. `recipient.viewingPublicKey` is the per-address key its inbox stream derives from. */
export class RingAddress {
  readonly recipient: ShieldedAddress;
  readonly ringProgramId: Address;
  readonly pairing: Pairing;

  constructor(
    fields: Readonly<{
      recipient: ShieldedAddress;
      ringProgramId: Address;
      pairing: Pairing;
    }>,
  ) {
    this.recipient = fields.recipient;
    this.ringProgramId = fields.ringProgramId;
    this.pairing = fields.pairing;
    Object.freeze(this);
  }

  equals(other: RingAddress): boolean {
    return equalBytes(this.toBytes(), other.toBytes());
  }

  /** `version ‖ recipient ‖ ring_program_id ‖ count ‖ rows ‖ checksum`. */
  toBytes(): Uint8Array {
    const rows = this.pairing.rows.map((row) => {
      const bytes = new Uint8Array(PAIRING_ROW_LENGTH);
      bytes.set(addressEncoder.encode(row.mint));
      new DataView(bytes.buffer).setBigUint64(32, row.minAmount);
      return bytes;
    });
    const body = concatBytes(
      Uint8Array.of(RING_ADDRESS_VERSION),
      this.recipient.toBytes(),
      new Uint8Array(addressEncoder.encode(this.ringProgramId)),
      Uint8Array.of(rows.length),
      ...rows,
    );
    return concatBytes(body, checksum(body));
  }

  static fromBytes(bytes: Uint8Array): RingAddress {
    if (!(bytes instanceof Uint8Array) || bytes.length < HEADER_LENGTH + CHECKSUM_LENGTH)
      throw new KeypairError("KEYPAIR_INVALID_RING_ADDRESS_LENGTH");
    const body = bytes.subarray(0, bytes.length - CHECKSUM_LENGTH);
    const version = body[0] ?? -1;
    if (version !== RING_ADDRESS_VERSION)
      throw new KeypairError("KEYPAIR_UNKNOWN_RING_ADDRESS_VERSION", { actual: version });
    const count = body[HEADER_LENGTH - 1] ?? 0;
    if (count > MAX_PAIRING_ROWS)
      throw new KeypairError("KEYPAIR_INVALID_RING_ADDRESS_PAIRING", {
        actual: count,
        maximum: MAX_PAIRING_ROWS,
      });
    if (body.length !== HEADER_LENGTH + count * PAIRING_ROW_LENGTH)
      throw new KeypairError("KEYPAIR_INVALID_RING_ADDRESS_LENGTH");
    if (!equalBytes(bytes.subarray(body.length), checksum(body)))
      throw new KeypairError("KEYPAIR_INVALID_RING_ADDRESS_CHECKSUM");
    const rows = Array.from({ length: count }, (_, index) => {
      const row = body.subarray(
        HEADER_LENGTH + index * PAIRING_ROW_LENGTH,
        HEADER_LENGTH + (index + 1) * PAIRING_ROW_LENGTH,
      );
      return {
        mint: addressDecoder.decode(row.subarray(0, 32)),
        minAmount: new DataView(row.buffer, row.byteOffset + 32, 8).getBigUint64(0),
      };
    });
    return new RingAddress({
      recipient: ShieldedAddress.fromBytes(body.subarray(1, PROGRAM_OFFSET)),
      ringProgramId: addressDecoder.decode(body.subarray(PROGRAM_OFFSET, HEADER_LENGTH - 1)),
      pairing: Pairing.of(rows),
    });
  }

  toBase58(): string {
    return base58Decoder.decode(this.toBytes());
  }

  static fromBase58(text: string): RingAddress {
    let bytes: Uint8Array;
    try {
      bytes = new Uint8Array(base58Encoder.encode(text));
    } catch (error) {
      throw new KeypairError("KEYPAIR_INVALID_RING_ADDRESS_BASE58", undefined, error);
    }
    if (bytes.length > MAX_RING_ADDRESS_PAYLOAD_LENGTH)
      throw new KeypairError("KEYPAIR_INVALID_RING_ADDRESS_LENGTH");
    return RingAddress.fromBytes(bytes);
  }
}

function checksum(body: Uint8Array): Uint8Array {
  return sha256(concatBytes(encoder.encode(RING_ADDRESS_CHECKSUM_DOMAIN), body)).subarray(
    0,
    CHECKSUM_LENGTH,
  );
}

export type RingPaymentRequestFields = Readonly<{
  address: RingAddress;
  amount?: bigint | undefined;
  mint?: Address | undefined;
  label?: string | undefined;
}>;

/** `zolana:<address>?amount=&mint=&label=`, the query part is unauthenticated. */
export class RingPaymentRequest {
  readonly address: RingAddress;
  readonly amount: bigint | undefined;
  readonly mint: Address | undefined;
  readonly label: string | undefined;

  constructor(fields: RingPaymentRequestFields) {
    this.address = fields.address;
    this.amount = fields.amount === undefined ? undefined : checkedCounter(fields.amount, "amount");
    this.mint = fields.mint;
    this.label = fields.label;
    Object.freeze(this);
  }

  toString(): string {
    const query: string[] = [];
    if (this.amount !== undefined) query.push(`amount=${this.amount}`);
    if (this.mint !== undefined) query.push(`mint=${this.mint}`);
    if (this.label !== undefined) query.push(`label=${encodeLabel(this.label)}`);
    const suffix = query.length === 0 ? "" : `?${query.join("&")}`;
    return `${RING_PAYMENT_SCHEME}${this.address.toBase58()}${suffix}`;
  }

  static parse(text: string): RingPaymentRequest {
    const trimmed = text.trim();
    if (!trimmed.startsWith(RING_PAYMENT_SCHEME)) {
      throw new KeypairError("KEYPAIR_INVALID_RING_ADDRESS_SCHEME");
    }
    const rest = trimmed.slice(RING_PAYMENT_SCHEME.length);
    const separator = rest.indexOf("?");
    const encoded = separator === -1 ? rest : rest.slice(0, separator);
    const query = separator === -1 ? [] : rest.slice(separator + 1).split("&");
    const address = RingAddress.fromBase58(encoded);
    let amount: bigint | undefined;
    let mint: Address | undefined;
    let label: string | undefined;
    for (const part of query) {
      const equals = part.indexOf("=");
      const key = equals === -1 ? part : part.slice(0, equals);
      const value = equals === -1 ? "" : part.slice(equals + 1);
      switch (key) {
        case "amount":
          amount = replaceOnce(amount, parseAmount(value));
          break;
        case "mint":
          mint = replaceOnce(mint, parseMint(value));
          break;
        case "label":
          label = replaceOnce(label, decodeLabel(value));
          break;
        default:
          throw new KeypairError("KEYPAIR_UNKNOWN_RING_PAYMENT_KEY", { name: key });
      }
    }
    return new RingPaymentRequest({ address, amount, mint, label });
  }
}

function replaceOnce<T>(slot: T | undefined, value: T): T {
  if (slot !== undefined) throw new KeypairError("KEYPAIR_DUPLICATE_RING_PAYMENT_KEY");
  return value;
}

function parseAmount(value: string): bigint {
  if (!/^[0-9]+$/.test(value)) throw new KeypairError("KEYPAIR_INVALID_RING_PAYMENT_AMOUNT");
  const amount = BigInt(value);
  if (amount > U64_MAX) throw new KeypairError("KEYPAIR_INVALID_RING_PAYMENT_AMOUNT");
  return amount;
}

function parseMint(value: string): Address {
  try {
    return address(value);
  } catch (error) {
    throw new KeypairError("KEYPAIR_INVALID_RING_PAYMENT_MINT", undefined, error);
  }
}

/** RFC 3986 unreserved characters stay literal, everything else is percent-encoded. */
function encodeLabel(label: string): string {
  return encodeURIComponent(label).replace(
    /[!'()*]/g,
    (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`,
  );
}

/** Every `%` must open a two-digit escape. */
function decodeLabel(value: string): string {
  if (
    !value
      .split("%")
      .slice(1)
      .every((after) => /^[0-9a-fA-F]{2}/.test(after))
  ) {
    throw new KeypairError("KEYPAIR_INVALID_RING_PAYMENT_LABEL");
  }
  try {
    return decodeURIComponent(value);
  } catch (error) {
    throw new KeypairError("KEYPAIR_INVALID_RING_PAYMENT_LABEL", undefined, error);
  }
}
