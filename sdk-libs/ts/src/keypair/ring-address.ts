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

import { checkedBytes, concatBytes } from "./bytes.js";
import { U64_MAX, checkedCounter } from "./derivation.js";
import { KeypairError } from "./error.js";
import { InboxSecret } from "./inbox-secret.js";
import { SHIELDED_ADDRESS_LENGTH, ShieldedAddress } from "./shielded.js";

export { InboxSecret } from "./inbox-secret.js";

const addressDecoder = getAddressDecoder();
const addressEncoder = getAddressEncoder();
const base58Decoder = getBase58Decoder();
const base58Encoder = getBase58Encoder();
const encoder = new TextEncoder();

export const RING_ADDRESS_VERSION = 1;

export const RING_ADDRESS_CHECKSUM_DOMAIN = "zolana/ring-addr/v1";

export const RING_PAYMENT_SCHEME = "zolana:";

const CHECKSUM_LENGTH = 4;

/** `version || recipient || ring_program_id || inbox_secret || checksum`. */
export const RING_ADDRESS_PAYLOAD_LENGTH = 1 + SHIELDED_ADDRESS_LENGTH + 32 + 32 + CHECKSUM_LENGTH;

const PROGRAM_OFFSET = 1 + SHIELDED_ADDRESS_LENGTH;
const INBOX_OFFSET = PROGRAM_OFFSET + 32;
const CHECKSUM_OFFSET = INBOX_OFFSET + 32;

/** Shared off chain, never published. */
export class RingAddress {
  readonly recipient: ShieldedAddress;
  readonly ringProgramId: Address;
  readonly inboxSecret: InboxSecret;

  constructor(
    fields: Readonly<{
      recipient: ShieldedAddress;
      ringProgramId: Address;
      inboxSecret: InboxSecret;
    }>,
  ) {
    this.recipient = fields.recipient;
    this.ringProgramId = fields.ringProgramId;
    this.inboxSecret = fields.inboxSecret;
    Object.freeze(this);
  }

  equals(other: RingAddress): boolean {
    return (
      this.ringProgramId === other.ringProgramId &&
      this.inboxSecret.equals(other.inboxSecret) &&
      equalBytes(this.recipient.toBytes(), other.recipient.toBytes())
    );
  }

  toBytes(): Uint8Array {
    const bytes = new Uint8Array(RING_ADDRESS_PAYLOAD_LENGTH);
    bytes[0] = RING_ADDRESS_VERSION;
    bytes.set(this.recipient.toBytes(), 1);
    bytes.set(addressEncoder.encode(this.ringProgramId), PROGRAM_OFFSET);
    bytes.set(this.inboxSecret.toBytes(), INBOX_OFFSET);
    bytes.set(checksum(bytes.subarray(0, CHECKSUM_OFFSET)), CHECKSUM_OFFSET);
    return bytes;
  }

  static fromBytes(bytes: Uint8Array): RingAddress {
    const payload = checkedBytes<Uint8Array>(bytes, RING_ADDRESS_PAYLOAD_LENGTH, "ring address");
    if (payload[0] !== RING_ADDRESS_VERSION) {
      throw new KeypairError("KEYPAIR_UNKNOWN_RING_ADDRESS_VERSION", { actual: payload[0] ?? -1 });
    }
    if (
      !equalBytes(payload.subarray(CHECKSUM_OFFSET), checksum(payload.subarray(0, CHECKSUM_OFFSET)))
    ) {
      throw new KeypairError("KEYPAIR_INVALID_RING_ADDRESS_CHECKSUM");
    }
    return new RingAddress({
      recipient: ShieldedAddress.fromBytes(payload.subarray(1, PROGRAM_OFFSET)),
      ringProgramId: addressDecoder.decode(payload.subarray(PROGRAM_OFFSET, INBOX_OFFSET)),
      inboxSecret: InboxSecret.fromBytes(payload.subarray(INBOX_OFFSET, CHECKSUM_OFFSET)),
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
    if (bytes.length !== RING_ADDRESS_PAYLOAD_LENGTH) {
      throw new KeypairError("KEYPAIR_INVALID_RING_ADDRESS_LENGTH", {
        expected: RING_ADDRESS_PAYLOAD_LENGTH,
        actual: bytes.length,
      });
    }
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
