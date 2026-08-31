import { ed25519 } from "@noble/curves/ed25519.js";
import {
  createSignableMessage,
  getBase58Decoder,
  getBase64Decoder,
  type MessagePartialSigner,
} from "@solana/kit";

import type {
  Address,
  Bytes32,
  Bytes33,
  Bytes64,
  RequestContext,
  Signature,
} from "../interface/types.js";
import { postJsonRpc } from "../services/jsonrpc.js";
import { TransportFailure, checkedEndpoint, checkedFetch } from "../services/transport.js";
import { wireDecoder } from "../interface/decode.js";
import { addressBytes, copyBytes } from "../interface/internal.js";
import { P256PublicKey } from "../keypair/public-key.js";

import { RingError } from "./error.js";
import { checkedReaderKey, readerKeyBytes, readerKeyFromBytes } from "./reader.js";

const base58Decoder = getBase58Decoder();
const base64Decoder = getBase64Decoder();
const encoder = new TextEncoder();

const RING_RPC_TIMEOUT_MS = 30_000;
const RING_RPC_MAX_REQUEST_BYTES = 1024 * 1024;
const RING_RPC_MAX_RESPONSE_BYTES = 4 * 1024 * 1024;

/** `reader` is the 34-byte scheme-tagged key of `readerKeyBytes`, a P-256 reader signs through WebAuthn only. */
export interface RingReadSigner {
  readonly reader: Uint8Array;
  sign(message: Uint8Array): Promise<Uint8Array | WebAuthnSignature>;
}

/** Mirrors Rust `WebAuthnAssertion` plus the DER signature. */
export interface WebAuthnSignature {
  readonly signature: Uint8Array;
  readonly authenticatorData: Uint8Array;
  readonly clientDataJSON: Uint8Array;
}

const READ_DOMAIN = "zolana/ring-rpc-read/v1";
const AUDITOR_KEY_DOMAIN = "zolana/ring-auditor-key/v1";
const AUDITOR_KEY_REQUEST_DOMAIN = "zolana/ring-rpc-auditor-key-request/v1";
/** Rust `AUDIT_PAGE_LIMIT`. */
export const RING_READ_PAGE_LIMIT = 100n;
/** Rust `AUDIT_CURSOR_LIMIT`. */
export const RING_READ_CURSOR_LIMIT = 256;

/** Mirrors Rust `ReadAttestation::bytes`. */
export function ringReadAttestation(
  input: Readonly<{
    ringProgramId: Address;
    timestamp: bigint;
    nonce: Bytes32;
    cursor?: Uint8Array;
    limit?: bigint;
  }>,
): Uint8Array {
  const cursor = input.cursor === undefined ? "" : base64Decoder.decode(input.cursor);
  return encoder.encode(
    [
      READ_DOMAIN,
      `ring: ${input.ringProgramId}`,
      `timestamp: ${input.timestamp}`,
      `nonce: ${base64Decoder.decode(input.nonce)}`,
      `limit: ${input.limit ?? 0n}`,
      `cursor: ${cursor}`,
    ].join("\n"),
  );
}

/** Mirrors Rust `auditor_key_attestation`. */
export function auditorKeyAttestation(
  ringProgramId: Address,
  auditorPublicKey: P256PublicKey,
): Uint8Array {
  const domain = encoder.encode(AUDITOR_KEY_DOMAIN);
  const ring = addressBytes(ringProgramId, "ringProgramId");
  const key = auditorPublicKey.toBytes();
  const bytes = new Uint8Array(domain.length + ring.length + key.length);
  bytes.set(domain, 0);
  bytes.set(ring, domain.length);
  bytes.set(key, domain.length + ring.length);
  return bytes;
}

/** Mirrors Rust `AuditorKeyAttestation::bytes`, the genesis hash pins the cluster. */
export function auditorKeyRequestAttestation(
  input: Readonly<{
    genesisHash: Bytes32;
    ringProgramId: Address;
    timestamp: bigint;
    nonce: Bytes32;
  }>,
): Uint8Array {
  return encoder.encode(
    [
      AUDITOR_KEY_REQUEST_DOMAIN,
      `genesis: ${base58Decoder.decode(input.genesisHash)}`,
      `ring: ${input.ringProgramId}`,
      `timestamp: ${input.timestamp}`,
      `nonce: ${base64Decoder.decode(input.nonce)}`,
    ].join("\n"),
  );
}

export function messageSignerReader(signer: MessagePartialSigner): RingReadSigner {
  return Object.freeze({
    reader: readerKeyBytes(checkedReaderKey(signer.address)),
    sign: (message: Uint8Array) => signMessage(signer, message),
  });
}

/** Mirrors Rust `GetDecryptedTransactionsRequest` after `ReadRequest::sign`. */
export interface SignedRingRead {
  readonly ringProgramId: Address;
  readonly cursor?: Uint8Array;
  readonly limit?: bigint;
  readonly reader: Uint8Array;
  readonly timestamp: bigint;
  readonly nonce: Bytes32;
  readonly signature: Uint8Array | WebAuthnSignature;
}

/** Mirrors Rust `ReadRequest`. */
export class RingReadRequest {
  readonly #ringProgramId: Address;
  readonly #nonce: Bytes32;
  #cursor?: Uint8Array;
  #limit?: bigint;
  #timestamp?: bigint;

  private constructor(ringProgramId: Address) {
    this.#ringProgramId = ringProgramId;
    this.#nonce = freshNonce();
  }

  static read(ringProgramId: Address): RingReadRequest {
    return new RingReadRequest(ringProgramId);
  }

  withCursor(cursor: Uint8Array): this {
    this.#cursor = new Uint8Array(checkedReadCursor(cursor));
    return this;
  }

  withLimit(limit: bigint): this {
    this.#limit = checkedReadLimit(limit);
    return this;
  }

  /** Unix seconds, the RPC rejects a clock more than its skew away. */
  at(timestamp: bigint): this {
    this.#timestamp = checkedUnixTimestamp(timestamp, "timestamp");
    return this;
  }

  async sign(signer: RingReadSigner): Promise<SignedRingRead> {
    const timestamp = timestampOrNow(this.#timestamp);
    const signature = await signer.sign(
      ringReadAttestation({
        ringProgramId: this.#ringProgramId,
        timestamp,
        nonce: this.#nonce,
        ...(this.#cursor === undefined ? {} : { cursor: this.#cursor }),
        ...(this.#limit === undefined ? {} : { limit: this.#limit }),
      }),
    );
    return Object.freeze({
      ringProgramId: this.#ringProgramId,
      ...(this.#cursor === undefined ? {} : { cursor: this.#cursor }),
      ...(this.#limit === undefined ? {} : { limit: this.#limit }),
      reader: signer.reader,
      timestamp,
      nonce: this.#nonce,
      signature,
    });
  }
}

/** Mirrors Rust `CreateAuditorKeyRequest` after `AuditorKeyRequest::sign`. */
export interface SignedAuditorKeyRequest {
  readonly ringProgramId: Address;
  readonly authority: Address;
  readonly genesisHash: Bytes32;
  readonly timestamp: bigint;
  readonly nonce: Bytes32;
  readonly signature: Bytes64;
}

/** Mirrors Rust `AuditorKeyRequest`. */
export class RingAuditorKeyRequest {
  readonly #ringProgramId: Address;
  readonly #genesisHash: Bytes32;
  readonly #nonce: Bytes32;
  #timestamp?: bigint;

  private constructor(ringProgramId: Address, genesisHash: Bytes32) {
    this.#ringProgramId = ringProgramId;
    this.#genesisHash = genesisHash;
    this.#nonce = freshNonce();
  }

  static forRing(ringProgramId: Address, genesisHash: Bytes32): RingAuditorKeyRequest {
    return new RingAuditorKeyRequest(
      ringProgramId,
      copyBytes(genesisHash, 32, "genesisHash") as Bytes32,
    );
  }

  /** Unix seconds, the RPC rejects a clock more than its skew away. */
  at(timestamp: bigint): this {
    this.#timestamp = checkedUnixTimestamp(timestamp, "timestamp");
    return this;
  }

  async sign(authority: MessagePartialSigner): Promise<SignedAuditorKeyRequest> {
    const timestamp = timestampOrNow(this.#timestamp);
    const signature = await signMessage(
      authority,
      auditorKeyRequestAttestation({
        genesisHash: this.#genesisHash,
        ringProgramId: this.#ringProgramId,
        timestamp,
        nonce: this.#nonce,
      }),
    );
    return Object.freeze({
      ringProgramId: this.#ringProgramId,
      authority: authority.address,
      genesisHash: this.#genesisHash,
      timestamp,
      nonce: this.#nonce,
      signature,
    });
  }
}

export type RingKeyMode = "local" | "derived";

export interface RingRpcHealth {
  readonly mode: RingKeyMode;
  readonly servicePublicKey: Address;
}

/** Mirrors Rust `CreateAuditorKeyResponse`, the signature covers `auditorKeyAttestation`. */
export interface RingAuditorKey {
  readonly ringProgramId: Address;
  readonly auditorPublicKey: P256PublicKey;
  readonly auditorViewTag: Bytes32;
  readonly servicePublicKey: Address;
  readonly signature: Uint8Array;
}

/** Value entering a ring, which carries no auditor message. */
export interface RingDeposit {
  readonly signature: Signature;
  readonly slot: bigint;
  /** The owner tag of the note the deposit created. */
  readonly depositor: Address;
  readonly asset: Address;
  readonly amount: bigint;
}

/** One page of ring deposits. The cursor is opaque, pass it back to reach older history. */
export interface RingDepositsPage {
  readonly deposits: readonly RingDeposit[];
  readonly cursor?: Uint8Array;
  /** The oldest slot this page examined, so a caller can merge the stream with an audit read by slot. */
  readonly oldestSlot?: bigint;
}

/** Mirrors Rust `RingState`. */
export type RingState = "served" | "foreignAuditor" | "uninitialized";

/** Mirrors Rust `RingStatusResponse`. Unsigned, carries only the key the chain publishes. */
export interface RingStatus {
  readonly ringProgramId: Address;
  readonly state: RingState;
  /** The key the ring's config names, absent until the config exists. */
  readonly configAuditorPublicKey?: P256PublicKey;
  readonly servicePublicKey: Address;
}

export interface DecryptedRingOutput {
  readonly slotIndex: number;
  readonly recipientViewingPublicKey: P256PublicKey;
  /** `OutputSlot.viewTag`, the Solana address of an Ed25519 or PDA owner. */
  readonly ownerTag: Bytes32;
  readonly asset: Address;
  readonly amount: bigint;
  readonly ringProgramId?: Address;
}

/** A public settlement leg. Value left the ring to a plain account. */
export interface DecryptedRingWithdrawal {
  /** A token account for an SPL leg, a wallet for a SOL leg. */
  readonly recipient: Address;
  /** The mint of an SPL leg or the native SOL mint. */
  readonly asset: Address;
  readonly amount: bigint;
}

export interface DecryptedRingTransaction {
  readonly slot: bigint;
  readonly signature: Signature;
  readonly txViewingPublicKey: P256PublicKey;
  readonly outputs: readonly DecryptedRingOutput[];
  readonly undecryptableSlots: readonly number[];
  readonly nullifiers: readonly Bytes32[];
  /** Required signers, fee payer first. */
  readonly signers: readonly Address[];
  /** Empty when nothing left the ring. */
  readonly withdrawals: readonly DecryptedRingWithdrawal[];
}

/** Mirrors Rust `SkippedReason`. */
export type SkippedReason = "missingAuditorMessage" | "invalidAuditData";

export interface SkippedRingTransaction {
  readonly slot: bigint;
  readonly signature: Signature;
  readonly reason: SkippedReason;
}

export interface DecryptedRingTransactionsPage {
  readonly slot: bigint;
  readonly blockTime: bigint;
  readonly items: readonly DecryptedRingTransaction[];
  readonly skipped: readonly SkippedRingTransaction[];
  readonly cursor?: Uint8Array;
}

export interface RingRpcOptions {
  readonly fetch?: typeof globalThis.fetch;
  /** Even loopback needs it for plain HTTP. */
  readonly allowInsecureHttp?: boolean;
}

export class RingRpc {
  readonly #url: URL;
  readonly #fetch: typeof globalThis.fetch;

  constructor(url: string | URL, options?: RingRpcOptions) {
    try {
      this.#url = checkedEndpoint(url, {
        field: "url",
        ...(options?.allowInsecureHttp === undefined
          ? {}
          : { allowInsecureHttp: options.allowInsecureHttp }),
      });
      this.#fetch = checkedFetch(options?.fetch);
    } catch (error) {
      if (!(error instanceof TransportFailure)) throw error;
      throw new RingError("RING_RPC_CONFIG", { details: { ...error.facts } });
    }
  }

  get url(): string {
    return this.#url.href;
  }

  async health(context?: RequestContext): Promise<RingRpcHealth> {
    const wire = record(await this.#call("health", undefined, context), "result");
    const mode = wire["mode"];
    if (mode !== "local" && mode !== "derived") throw invalid("result.mode");
    return Object.freeze({
      mode,
      servicePublicKey: address(wire["servicePubkey"], "result.servicePubkey"),
    });
  }

  /** Verified against `servicePubkey` before the key is returned. */
  async createAuditorKey(
    input: Readonly<{
      ringProgramId: Address;
      genesisHash: Bytes32;
      /** The upgrade authority, or the config authority once the config exists. */
      authority: MessagePartialSigner;
      timestamp?: bigint;
    }>,
    context?: RequestContext,
  ): Promise<RingAuditorKey> {
    let request = RingAuditorKeyRequest.forRing(input.ringProgramId, input.genesisHash);
    if (input.timestamp !== undefined) request = request.at(input.timestamp);
    return this.createAuditorKeySigned(await request.sign(input.authority), context);
  }

  async createAuditorKeySigned(
    request: SignedAuditorKeyRequest,
    context?: RequestContext,
  ): Promise<RingAuditorKey> {
    checkedSignedAuditorKeyRequest(request);
    const wire = record(
      await this.#call(
        "createAuditorKey",
        {
          ringProgramId: request.ringProgramId,
          auth: {
            authority: request.authority,
            genesisHash: base58Decoder.decode(request.genesisHash),
            ...authWire(request),
          },
        },
        context,
      ),
      "result",
    );
    const key = base64(wire["auditorPubkey"], "result.auditorPubkey");
    if (key.length !== 33) throw invalid("result.auditorPubkey");
    const auditorPublicKey = P256PublicKey.fromBytes(key as Bytes33);
    const servicePublicKey = address(wire["servicePubkey"], "result.servicePubkey");
    const signature = base58(wire["signature"], "result.signature");
    const ring = address(wire["ringProgramId"], "result.ringProgramId");
    if (ring !== request.ringProgramId) throw invalid("result.ringProgramId");
    const attested = ed25519.verify(
      signature,
      auditorKeyAttestation(ring, auditorPublicKey),
      addressBytes(servicePublicKey, "servicePubkey"),
    );
    if (!attested) {
      throw new RingError("RING_RPC", {
        details: { method: "createAuditorKey", reason: "attestation signature is invalid" },
      });
    }
    return Object.freeze({
      ringProgramId: ring,
      auditorPublicKey,
      auditorViewTag: hash(wire["auditorViewTag"], "result.auditorViewTag"),
      servicePublicKey,
      signature,
    });
  }

  /**
   * Deposits publish their asset and amount, so this read is unsigned.
   * `limit` counts signatures examined, so an empty page can still carry a cursor over older history.
   */
  async ringDeposits(
    input: Readonly<{ ringProgramId: Address; limit?: number; cursor?: Uint8Array }>,
    context?: RequestContext,
  ): Promise<RingDepositsPage> {
    const wire = record(
      await this.#call(
        "ringDeposits",
        {
          ringProgramId: input.ringProgramId,
          ...(input.limit === undefined ? {} : { limit: input.limit }),
          ...(input.cursor === undefined ? {} : { cursor: base64Decoder.decode(input.cursor) }),
        },
        context,
      ),
      "result",
    );
    const cursor = wire["cursor"];
    const oldestSlot = wire["oldestSlot"];
    return Object.freeze({
      deposits: Object.freeze(
        list(wire["deposits"], "result.deposits").map((entry) => {
          const deposit = record(entry, "result.deposits");
          return Object.freeze({
            signature: signature(deposit["signature"], "deposits.signature"),
            slot: integer(deposit["slot"], "deposits.slot"),
            depositor: address(deposit["depositor"], "deposits.depositor"),
            asset: address(deposit["asset"], "deposits.asset"),
            amount: integer(deposit["amount"], "deposits.amount"),
          });
        }),
      ),
      ...(cursor === undefined || cursor === null
        ? {}
        : { cursor: base64(cursor, "result.cursor") }),
      ...(oldestSlot === undefined || oldestSlot === null
        ? {}
        : { oldestSlot: integer(oldestSlot, "result.oldestSlot") }),
    });
  }

  /** Whether this service can open the ring, before a read is attempted. */
  async ringStatus(ringProgramId: Address, context?: RequestContext): Promise<RingStatus> {
    const wire = record(await this.#call("ringStatus", { ringProgramId }, context), "result");
    const state = string(wire["state"], "result.state");
    if (state !== "served" && state !== "foreignAuditor" && state !== "uninitialized") {
      throw invalid("result.state");
    }
    const config = wire["configAuditorPubkey"];
    return Object.freeze({
      ringProgramId: address(wire["ringProgramId"], "result.ringProgramId"),
      state,
      ...(config === undefined || config === null
        ? {}
        : { configAuditorPublicKey: p256Key(config, "result.configAuditorPubkey") }),
      servicePublicKey: address(wire["servicePubkey"], "result.servicePubkey"),
    });
  }

  /** Each page is signed again, the attestation binds the nonce, the cursor and the time. */
  async getDecryptedTransactions(
    input: Readonly<{
      ringProgramId: Address;
      signer: RingReadSigner;
      cursor?: Uint8Array;
      limit?: bigint;
      timestamp?: bigint;
    }>,
    context?: RequestContext,
  ): Promise<DecryptedRingTransactionsPage> {
    let request = RingReadRequest.read(input.ringProgramId);
    if (input.cursor !== undefined) request = request.withCursor(input.cursor);
    if (input.limit !== undefined) request = request.withLimit(input.limit);
    if (input.timestamp !== undefined) request = request.at(input.timestamp);
    return this.readSigned(await request.sign(input.signer), context);
  }

  async readSigned(
    read: SignedRingRead,
    context?: RequestContext,
  ): Promise<DecryptedRingTransactionsPage> {
    checkedSignedRead(read);
    const { signature } = read;
    const wire = record(
      await this.#call(
        "getDecryptedTransactions",
        {
          ringProgramId: read.ringProgramId,
          ...(read.cursor === undefined ? {} : { cursor: base64Decoder.decode(read.cursor) }),
          ...(read.limit === undefined ? {} : { limit: Number(read.limit) }),
          auth: {
            reader: base64Decoder.decode(read.reader),
            ...authWire({
              timestamp: read.timestamp,
              nonce: read.nonce,
              signature: signature instanceof Uint8Array ? signature : signature.signature,
            }),
            ...(signature instanceof Uint8Array
              ? {}
              : {
                  webauthn: {
                    authenticatorData: base64Decoder.decode(signature.authenticatorData),
                    clientDataJson: base64Decoder.decode(signature.clientDataJSON),
                  },
                }),
          },
        },
        context,
      ),
      "result",
    );
    const wireContext = record(wire["context"], "result.context");
    const value = record(wire["value"], "result.value");
    const cursor = value["cursor"];
    return Object.freeze({
      slot: integer(wireContext["slot"], "result.context.slot"),
      blockTime: signedInteger(wireContext["blockTime"], "result.context.blockTime"),
      items: Object.freeze(
        list(value["items"], "result.value.items").map((item, index) =>
          decodeTransaction(record(item, `result.value.items[${index}]`)),
        ),
      ),
      skipped: Object.freeze(
        list(value["skipped"], "result.value.skipped").map((entry, index) =>
          decodeSkipped(record(entry, `result.value.skipped[${index}]`)),
        ),
      ),
      ...(cursor === undefined || cursor === null
        ? {}
        : { cursor: base64(cursor, "result.value.cursor") }),
    });
  }

  // `params` is the request object, not a positional list.
  async #call(
    method: string,
    params: Readonly<Record<string, unknown>> | undefined,
    context: RequestContext | undefined,
  ): Promise<unknown> {
    try {
      return await postJsonRpc(
        {
          fetch: this.#fetch,
          url: new URL(this.#url.href),
          rpcMethod: method,
          params,
          id: 1,
          maxRequestBytes: RING_RPC_MAX_REQUEST_BYTES,
          maxResponseBytes: RING_RPC_MAX_RESPONSE_BYTES,
        },
        { timeoutMs: RING_RPC_TIMEOUT_MS, ...context },
      );
    } catch (error) {
      if (!(error instanceof TransportFailure)) throw error;
      const code =
        error.kind === "envelope" || error.kind === "missingResult" || error.kind === "rpc"
          ? "RING_RPC"
          : error.kind === "context" || error.kind === "config"
            ? "RING_RPC_CONFIG"
            : "RING_RPC_TRANSPORT";
      throw new RingError(code, { details: { method, ...error.facts } });
    }
  }
}

/** Minted once per request. */
function freshNonce(): Bytes32 {
  const nonce = new Uint8Array(32);
  globalThis.crypto.getRandomValues(nonce);
  return nonce as Bytes32;
}

function timestampOrNow(timestamp: bigint | undefined): bigint {
  return timestamp ?? BigInt(Math.floor(Date.now() / 1000));
}

function authWire(
  auth: Readonly<{ timestamp: bigint; nonce: Bytes32; signature: Uint8Array }>,
): Readonly<{ timestamp: number; nonce: string; signature: string }> {
  return {
    timestamp: Number(auth.timestamp),
    nonce: base64Decoder.decode(auth.nonce),
    signature: base64Decoder.decode(auth.signature),
  };
}

async function signMessage(signer: MessagePartialSigner, message: Uint8Array): Promise<Bytes64> {
  const [signatures] = await signer.signMessages([createSignableMessage(message)]);
  const signature = signatures?.[signer.address];
  if (signature === undefined) {
    throw new RingError("RING_RPC", { details: { reason: "signer returned no signature" } });
  }
  return copyBytes(signature, 64, "signature") as Bytes64;
}

function decodeTransaction(wire: Record<string, unknown>): DecryptedRingTransaction {
  return Object.freeze({
    slot: integer(wire["slot"], "slot"),
    signature: signature(wire["txSignature"], "txSignature"),
    txViewingPublicKey: p256Key(wire["txViewingPk"], "txViewingPk"),
    outputs: Object.freeze(
      list(wire["outputs"], "outputs").map((entry, index) =>
        decodeOutput(record(entry, `outputs[${index}]`)),
      ),
    ),
    undecryptableSlots: Object.freeze(
      list(wire["undecryptableSlots"], "undecryptableSlots").map((slot) =>
        Number(integer(slot, "undecryptableSlots")),
      ),
    ),
    nullifiers: Object.freeze(
      list(wire["nullifiers"], "nullifiers").map((nullifier) => hash(nullifier, "nullifiers")),
    ),
    signers: Object.freeze(list(wire["signers"], "signers").map((key) => address(key, "signers"))),
    withdrawals: Object.freeze(
      list(wire["withdrawals"], "withdrawals").map((entry) => {
        const leg = record(entry, "withdrawals");
        return Object.freeze({
          recipient: address(leg["recipient"], "withdrawals.recipient"),
          asset: address(leg["asset"], "withdrawals.asset"),
          amount: integer(leg["amount"], "withdrawals.amount"),
        });
      }),
    ),
  });
}

function decodeOutput(output: Record<string, unknown>): DecryptedRingOutput {
  const ring = output["ringProgramId"];
  return Object.freeze({
    slotIndex: Number(integer(output["slotIndex"], "slotIndex")),
    recipientViewingPublicKey: p256Key(output["recipientViewingPk"], "recipientViewingPk"),
    ownerTag: hash(output["ownerTag"], "ownerTag"),
    asset: address(output["asset"], "asset"),
    amount: integer(output["amount"], "amount"),
    ...(ring === undefined || ring === null
      ? {}
      : { ringProgramId: address(ring, "ringProgramId") }),
  });
}

function decodeSkipped(wire: Record<string, unknown>): SkippedRingTransaction {
  const reason = wire["reason"];
  if (reason !== "missingAuditorMessage" && reason !== "invalidAuditData") {
    throw invalid("reason");
  }
  return Object.freeze({
    slot: integer(wire["slot"], "slot"),
    signature: signature(wire["txSignature"], "txSignature"),
    reason,
  });
}

function invalid(path: string): RingError {
  return new RingError("RING_RPC", { details: { reason: "invalid response", path } });
}

const { record, list, string, address, signature, signedInteger, integer, base64, base58 } =
  wireDecoder(invalid);

function invalidRequest(field: string): RingError {
  return new RingError("RING_RPC", { details: { reason: "invalid request", field } });
}

const { address: requestAddress } = wireDecoder(invalidRequest);

function requestBytes(value: unknown, length: number, field: string): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== length) throw invalidRequest(field);
  return value;
}

function checkedReadCursor(cursor: Uint8Array): Uint8Array {
  if (
    !(cursor instanceof Uint8Array) ||
    cursor.length === 0 ||
    cursor.length > RING_READ_CURSOR_LIMIT
  ) {
    throw new RingError("RING_READ_CURSOR", {
      details: { length: cursor instanceof Uint8Array ? cursor.length : -1 },
    });
  }
  return cursor;
}

function checkedReadLimit(limit: bigint): bigint {
  if (typeof limit !== "bigint" || limit < 1n || limit > RING_READ_PAGE_LIMIT) {
    throw new RingError("RING_READ_LIMIT", { details: { limit: String(limit) } });
  }
  return limit;
}

/** Bounded to the safe integer range, `Number` in the wire encoding stays exact. */
function checkedUnixTimestamp(value: bigint, field: string): bigint {
  if (typeof value !== "bigint" || value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw invalidRequest(field);
  }
  return value;
}

function checkedSignedRead(read: SignedRingRead): void {
  requestAddress(read.ringProgramId, "ringProgramId");
  readerKeyFromBytes(read.reader);
  requestBytes(read.nonce, 32, "nonce");
  if (read.cursor !== undefined) checkedReadCursor(read.cursor);
  if (read.limit !== undefined) checkedReadLimit(read.limit);
  checkedUnixTimestamp(read.timestamp, "timestamp");
  const signature = read.signature;
  if (signature instanceof Uint8Array) {
    requestBytes(signature, 64, "signature");
    return;
  }
  if (!(signature.signature instanceof Uint8Array) || signature.signature.length === 0) {
    throw invalidRequest("signature");
  }
  // rpIdHash(32) + flags(1) + counter(4), the shortest authenticator data WebAuthn emits.
  if (
    !(signature.authenticatorData instanceof Uint8Array) ||
    signature.authenticatorData.length < 37
  ) {
    throw invalidRequest("authenticatorData");
  }
  if (!(signature.clientDataJSON instanceof Uint8Array) || signature.clientDataJSON.length === 0) {
    throw invalidRequest("clientDataJSON");
  }
}

function checkedSignedAuditorKeyRequest(request: SignedAuditorKeyRequest): void {
  requestAddress(request.ringProgramId, "ringProgramId");
  requestAddress(request.authority, "authority");
  requestBytes(request.genesisHash, 32, "genesisHash");
  requestBytes(request.nonce, 32, "nonce");
  requestBytes(request.signature, 64, "signature");
  checkedUnixTimestamp(request.timestamp, "timestamp");
}

function hash(value: unknown, path: string): Bytes32 {
  const bytes = base58(value, path);
  if (bytes.length !== 32) throw invalid(path);
  return bytes as Bytes32;
}

function p256Key(value: unknown, path: string): P256PublicKey {
  const bytes = base64(value, path);
  if (bytes.length !== 33) throw invalid(path);
  return P256PublicKey.fromBytes(bytes as Bytes33);
}
