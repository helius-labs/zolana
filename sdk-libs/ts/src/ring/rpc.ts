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
import { SOLANA_OWNER_TAG, hashBytes, initializePoseidon } from "../hasher/index.js";
import { isCanonicalField } from "../interface/canonical-field.js";
import { postJsonRpc } from "../services/jsonrpc.js";
import { TransportFailure, checkedEndpoint, checkedFetch } from "../services/transport.js";
import { wireDecoder } from "../interface/decode.js";
import { addressBytes, copyBytes } from "../interface/internal.js";
import { MAX_MERGE_INPUTS, mergePaddedInputCount } from "../interface/constants.js";
import { X25519PublicKey } from "../keypair/x25519.js";
import { KeypairError } from "../keypair/error.js";

import {
  OUTPUT_PAYLOAD_ERROR_KINDS,
  auditOpeningHash,
  type DecryptedAnonymousRingTrace,
  type OutputPayloadError,
  type OutputPayloadErrorKind,
} from "./audit.js";
import type { AuditOutputOpening } from "../keypair/audit.js";
import { bytesToBigInt, equal, ZERO_32 } from "../transaction/internal.js";
import { RingError } from "./error.js";
import { checkedReaderKey, readerKeyBytes, readerKeyFromBytes } from "./reader.js";
import { memberOfTag } from "./policy.js";

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
  auditorPublicKey: X25519PublicKey,
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
  readonly auditorPublicKey: X25519PublicKey;
  readonly auditorViewTag: Bytes32;
  readonly servicePublicKey: Address;
  readonly signature: Uint8Array;
}

/** Value entering a ring, which carries no auditor message. */
export interface RingDeposit {
  readonly signature: Signature;
  readonly slot: bigint;
  /** The owner tag of the UTXO the deposit created. */
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
  readonly configAuditorPublicKey?: X25519PublicKey;
  readonly servicePublicKey: Address;
}

export interface DecryptedRingOutput {
  readonly slotIndex: number;
  readonly recipientViewingPublicKey: X25519PublicKey;
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
  /** Ordinal of the confirmed SPP event within this Solana transaction. */
  readonly eventIndex: number;
  readonly txViewingPublicKey: X25519PublicKey;
  /** Optional recipient delivery metadata, never a complete accounting of disclosed notes. */
  readonly outputs: readonly DecryptedRingOutput[];
  /** Authoritative disclosure in published slot order, independent of recipient encryption. */
  readonly outputOpenings: readonly DecryptedRingOpening[];
  readonly anonymous?: DecryptedAnonymousRingTrace;
  readonly payloadErrors: readonly OutputPayloadError[];
  readonly nullifiers: readonly Bytes32[];
  /** Required signers, fee payer first. */
  readonly signers: readonly Address[];
  /** Empty when nothing left the ring. */
  readonly withdrawals: readonly DecryptedRingWithdrawal[];
}

export interface DecryptedRingOpening extends AuditOutputOpening {
  readonly outputContext: Readonly<{ treeId: number; leafIndex: bigint; hash: Bytes32 }>;
}

export type {
  DecryptedAnonymousRingTrace,
  OutputPayloadError,
  OutputPayloadErrorKind,
} from "./audit.js";

/** Mirrors Rust `SkippedReason`. */
export type SkippedReason = "missingAuditorMessage" | "invalidAuditData";

export interface SkippedRingTransaction {
  readonly slot: bigint;
  readonly signature: Signature;
  readonly eventIndex: number;
  readonly reason: SkippedReason;
}

export interface DecryptedRingTransactionsPage {
  readonly slot: bigint;
  readonly blockTime: bigint;
  readonly items: readonly DecryptedRingTransaction[];
  readonly skipped: readonly SkippedRingTransaction[];
  readonly cursor?: Uint8Array;
}

/** A ring merge opened by the service from a registered recovery key. */
export interface AuditedMergeRecord {
  readonly signature: Signature;
  readonly eventIndex: number;
  readonly outputCommitment: Bytes32;
  readonly ownerMember: Bytes32;
  /** Confirmed RegisterKey signer, when the indexer retained that lineage. */
  readonly ownerPubkey?: Address;
  readonly mint: Address;
  readonly amount: bigint;
  readonly blinding: Bytes32;
  readonly ringDataHash: Bytes32;
  readonly inputNullifiers: readonly Bytes32[];
  /** The merged note's nullifier from the escrowed key, absent exactly when `inputCommitments` is set. */
  readonly nullifier?: Bytes32;
  /** The spent commitments an anonymous merge discloses, padding zero, one per circuit slot. */
  readonly inputCommitments?: readonly Bytes32[];
}

export interface UnresolvedMergeRecord {
  readonly signature: Signature;
  readonly eventIndex: number;
  readonly outputCommitment: Bytes32;
}

export interface AuditedMergesPage {
  readonly slot: bigint;
  readonly blockTime: bigint;
  readonly opened: readonly AuditedMergeRecord[];
  readonly unresolved: readonly UnresolvedMergeRecord[];
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
    const checked = checkedSignedAuditorKeyRequest(request);
    const wire = record(
      await this.#call(
        "createAuditorKey",
        {
          ringProgramId: checked.ringProgramId,
          auth: {
            authority: checked.authority,
            genesisHash: base58Decoder.decode(checked.genesisHash),
            ...authWire(checked),
          },
        },
        context,
      ),
      "result",
    );
    const key = base64(wire["auditorPubkey"], "result.auditorPubkey");
    if (key.length !== 33) throw invalid("result.auditorPubkey");
    const auditorPublicKey = X25519PublicKey.fromBytes(key as Bytes33);
    const servicePublicKey = address(wire["servicePubkey"], "result.servicePubkey");
    const signature = base58(wire["signature"], "result.signature");
    const ring = address(wire["ringProgramId"], "result.ringProgramId");
    if (ring !== checked.ringProgramId) throw invalid("result.ringProgramId");
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
        : {
            configAuditorPublicKey: X25519PublicKey.fromBytes(
              base64(config, "result.configAuditorPubkey"),
            ),
          }),
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

  /** The server opens confirmed ring merges with its auditor key. */
  async getAuditedMerges(
    input: Readonly<{
      ringProgramId: Address;
      signer: RingReadSigner;
      cursor?: Uint8Array;
      limit?: bigint;
      timestamp?: bigint;
    }>,
    context?: RequestContext,
  ): Promise<AuditedMergesPage> {
    let request = RingReadRequest.read(input.ringProgramId);
    if (input.cursor !== undefined) request = request.withCursor(input.cursor);
    if (input.limit !== undefined) request = request.withLimit(input.limit);
    if (input.timestamp !== undefined) request = request.at(input.timestamp);
    return this.readSignedMerges(await request.sign(input.signer), context);
  }

  async readSignedMerges(
    read: SignedRingRead,
    context?: RequestContext,
  ): Promise<AuditedMergesPage> {
    await initializePoseidon();
    const checked = checkedSignedRead(read);
    const wire = record(
      await this.#call("getAuditedMerges", signedReadParams(checked), context),
      "result",
    );
    const wireContext = record(wire["context"], "result.context");
    const value = record(wire["value"], "result.value");
    const cursor = readResponseCursor(value["cursor"], checked);
    const field = (input: unknown, path: string): Bytes32 => {
      const bytes = hash(input, path);
      if (!isCanonicalField(bytes)) throw invalid(path);
      return bytes;
    };
    const identity = (item: Record<string, unknown>, path: string) => ({
      signature: signature(item["txSignature"], `${path}.txSignature`),
      eventIndex: u16(item["eventIndex"], `${path}.eventIndex`),
      outputCommitment: field(item["outputCommitment"], `${path}.outputCommitment`),
    });
    const opened = list(value["opened"], "result.value.opened");
    const unresolved = list(value["unresolved"], "result.value.unresolved");
    if (opened.length + unresolved.length > Number(checked.limit ?? RING_READ_PAGE_LIMIT))
      throw invalid("result.value");
    return Object.freeze({
      slot: integer(wireContext["slot"], "result.context.slot"),
      blockTime: signedInteger(wireContext["blockTime"], "result.context.blockTime"),
      opened: Object.freeze(
        opened.map((entry, index) => {
          const path = `result.value.opened[${index}]`;
          const item = record(entry, path);
          const inputNullifiers = list(item["inputNullifiers"], `${path}.inputNullifiers`);
          if (inputNullifiers.length < 2 || inputNullifiers.length > MAX_MERGE_INPUTS)
            throw invalid(`${path}.inputNullifiers`);
          const ownerMember = field(item["ownerMember"], `${path}.ownerMember`);
          const ownerPubkey = item["ownerPubkey"];
          const owner =
            ownerPubkey === undefined || ownerPubkey === null
              ? undefined
              : address(ownerPubkey, `${path}.ownerPubkey`);
          if (owner !== undefined && !equal(memberOfTag(addressBytes(owner)), ownerMember))
            throw invalid(`${path}.ownerPubkey`);
          return Object.freeze({
            ...identity(item, path),
            ownerMember,
            ...(owner === undefined ? {} : { ownerPubkey: owner }),
            mint: address(item["mint"], `${path}.mint`),
            amount: u64(item["amount"], `${path}.amount`),
            blinding: field(item["blinding"], `${path}.blinding`),
            ringDataHash: field(item["ringDataHash"], `${path}.ringDataHash`),
            inputNullifiers: Object.freeze(
              inputNullifiers.map((nullifier) => field(nullifier, `${path}.inputNullifiers`)),
            ),
            ...mergeKeys(item, inputNullifiers.length, path, field),
          });
        }),
      ),
      unresolved: Object.freeze(
        unresolved.map((entry, index) =>
          Object.freeze(
            identity(
              record(entry, `result.value.unresolved[${index}]`),
              `result.value.unresolved[${index}]`,
            ),
          ),
        ),
      ),
      ...(cursor === undefined ? {} : { cursor }),
    });
  }

  async readSigned(
    read: SignedRingRead,
    context?: RequestContext,
  ): Promise<DecryptedRingTransactionsPage> {
    const checked = checkedSignedRead(read);
    const wire = record(
      await this.#call("getDecryptedTransactions", signedReadParams(checked), context),
      "result",
    );
    const wireContext = record(wire["context"], "result.context");
    const value = record(wire["value"], "result.value");
    const cursor = readResponseCursor(value["cursor"], checked);
    const items = list(value["items"], "result.value.items");
    const skipped = list(value["skipped"], "result.value.skipped");
    if (items.length + skipped.length > Number(checked.limit ?? RING_READ_PAGE_LIMIT))
      throw invalid("result.value");
    await initializePoseidon();
    return Object.freeze({
      slot: integer(wireContext["slot"], "result.context.slot"),
      blockTime: signedInteger(wireContext["blockTime"], "result.context.blockTime"),
      items: Object.freeze(
        items.map((item, index) => decodeTransaction(record(item, `result.value.items[${index}]`))),
      ),
      skipped: Object.freeze(
        skipped.map((entry, index) =>
          decodeSkipped(record(entry, `result.value.skipped[${index}]`)),
        ),
      ),
      ...(cursor === undefined ? {} : { cursor }),
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

function signedReadParams(checked: SignedRingRead): Record<string, unknown> {
  const { signature } = checked;
  return {
    ringProgramId: checked.ringProgramId,
    ...(checked.cursor === undefined ? {} : { cursor: base64Decoder.decode(checked.cursor) }),
    ...(checked.limit === undefined ? {} : { limit: Number(checked.limit) }),
    auth: {
      reader: base64Decoder.decode(checked.reader),
      ...authWire({
        timestamp: checked.timestamp,
        nonce: checked.nonce,
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
  };
}

/** A response cursor must be usable for the next signed page. */
function readResponseCursor(value: unknown, request: SignedRingRead): Uint8Array | undefined {
  if (value === null) return undefined;
  if (value === undefined) throw invalid("result.value.cursor");
  const cursor = base64(value, "result.value.cursor");
  if (
    cursor.length === 0 ||
    cursor.length > RING_READ_CURSOR_LIMIT ||
    (request.cursor !== undefined && equal(cursor, request.cursor))
  )
    throw invalid("result.value.cursor");
  return cursor;
}

/** Rust `MergeKeys`, an escrowed merge names its nullifier and an anonymous one its spent commitments. */
function mergeKeys(
  item: Record<string, unknown>,
  published: number,
  path: string,
  field: (input: unknown, path: string) => Bytes32,
): Pick<AuditedMergeRecord, "nullifier" | "inputCommitments"> {
  const absent = (value: unknown): boolean => value === undefined || value === null;
  const nullifier = item["nullifier"];
  const commitments = item["inputCommitments"];
  if (absent(nullifier) === absent(commitments)) throw invalid(`${path}.nullifier`);
  if (!absent(nullifier)) return { nullifier: field(nullifier, `${path}.nullifier`) };
  const disclosed = list(commitments, `${path}.inputCommitments`);
  if (disclosed.length !== mergePaddedInputCount(published))
    throw invalid(`${path}.inputCommitments`);
  return {
    inputCommitments: Object.freeze(
      disclosed.map((commitment) => field(commitment, `${path}.inputCommitments`)),
    ),
  };
}

/** One Ed25519 signature from a kit message signer over the raw bytes. */
export async function signMessage(
  signer: MessagePartialSigner,
  message: Uint8Array,
): Promise<Bytes64> {
  const [signatures] = await signer.signMessages([createSignableMessage(message)]);
  const signature = signatures?.[signer.address];
  if (signature === undefined) {
    throw new RingError("RING_RPC", { details: { reason: "signer returned no signature" } });
  }
  return copyBytes(signature, 64, "signature") as Bytes64;
}

function decodeTransaction(wire: Record<string, unknown>): DecryptedRingTransaction {
  const anonymous = wire["anonymous"] !== undefined && wire["anonymous"] !== null;
  const outputOpenings = Object.freeze(
    list(wire["outputOpenings"], "outputOpenings").map((entry) =>
      decodeOpening(record(entry, "outputOpenings"), anonymous),
    ),
  );
  const outputs = Object.freeze(
    list(wire["outputs"], "outputs").map((entry, index) =>
      decodeOutput(record(entry, `outputs[${index}]`)),
    ),
  );
  const payloadErrors = Object.freeze(
    list(wire["payloadErrors"], "payloadErrors").map((entry) => {
      const error = record(entry, "payloadErrors");
      return Object.freeze({
        slotIndex: u32(error["slotIndex"], "payloadErrors.slotIndex"),
        kind: payloadErrorKind(error["kind"]),
      });
    }),
  );
  const seen = new Set<number>();
  for (const output of outputs) {
    const opening = outputOpenings[output.slotIndex];
    const ring =
      output.ringProgramId === undefined ? ZERO_32 : hashBytes(addressBytes(output.ringProgramId));
    if (
      opening === undefined ||
      seen.has(output.slotIndex) ||
      !equal(hashBytes(addressBytes(output.asset)), opening.asset) ||
      output.amount !== bytesToBigInt(opening.amount) ||
      !equal(ring, opening.ringProgramId)
    )
      throw invalid("outputs.opening");
    seen.add(output.slotIndex);
  }
  // A slot without an output carries at most one error, a stored output only a pair hint.
  const errored = new Set<number>();
  for (const error of payloadErrors) {
    if (outputOpenings[error.slotIndex] === undefined || errored.has(error.slotIndex))
      throw invalid("payloadErrors");
    if (seen.has(error.slotIndex) !== (error.kind === "pairHint")) throw invalid("payloadErrors");
    errored.add(error.slotIndex);
  }
  return Object.freeze({
    slot: integer(wire["slot"], "slot"),
    signature: signature(wire["txSignature"], "txSignature"),
    eventIndex: u16(wire["eventIndex"], "eventIndex"),
    txViewingPublicKey: x25519Key(wire["txViewingPk"], "txViewingPk"),
    ...(anonymous
      ? { anonymous: decodeAnonymousTrace(record(wire["anonymous"], "anonymous")) }
      : {}),
    outputs,
    outputOpenings,
    payloadErrors,
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

function decodeOpening(wire: Record<string, unknown>, anonymous: boolean): DecryptedRingOpening {
  const field = (name: string): Bytes32 => {
    const value = hash(wire[name], `outputOpenings.${name}`);
    if (!isCanonicalField(value)) throw invalid(`outputOpenings.${name}`);
    return value;
  };
  const opening: AuditOutputOpening = {
    domain: field("domain"),
    treeId: field("treeId"),
    ownerHash: field("ownerHash"),
    asset: field("asset"),
    amount: field("amount"),
    blinding: field("blinding"),
    dataHash: field("dataHash"),
    ringDataHash: field("ringDataHash"),
    ringProgramId: field("ringProgramId"),
  };
  const context = record(wire["outputContext"], "outputOpenings.outputContext");
  const treeId = u32(context["treeId"], "outputOpenings.outputContext.treeId");
  if (treeId > 0xffff) throw invalid("outputOpenings.outputContext.treeId");
  const outputContext = Object.freeze({
    treeId,
    leafIndex: u64(context["leafIndex"], "outputOpenings.outputContext.leafIndex"),
    hash: hash(context["hash"], "outputOpenings.outputContext.hash"),
  });
  const dummy = anonymous && Object.values(opening).every((value) => equal(value, ZERO_32));
  if (
    !dummy &&
    (!equal(auditOpeningHash(opening), outputContext.hash) ||
      bytesToBigInt(opening.treeId) !== BigInt(treeId))
  )
    throw invalid("outputOpenings.commitment");
  return Object.freeze({ ...opening, outputContext });
}

/** Checks owner encodings and canonical recipient slot order before exposing a trace. */
function decodeAnonymousTrace(wire: Record<string, unknown>): DecryptedAnonymousRingTrace {
  // Decode bounded input openings without narrowing an unchecked integer.
  const inputs = list(wire["inputs"], "anonymous.inputs").map((entry) => {
    const input = record(entry, "anonymous.inputs");
    const treeId = u32(input["treeId"], "anonymous.inputs.treeId");
    if (treeId > 0xffff) throw invalid("anonymous.inputs.treeId");
    return Object.freeze({
      treeId,
      amount: u64(input["amount"], "anonymous.inputs.amount"),
      asset: hash(input["asset"], "anonymous.inputs.asset"),
    });
  });
  // Real outputs retain their original slot indices after dummy slots are removed.
  let previous = -1;
  const recipients = list(wire["recipients"], "anonymous.recipients").map((entry) => {
    const output = record(entry, "anonymous.recipients");
    const slotIndex = u32(output["slotIndex"], "anonymous.recipients.slotIndex");
    if (slotIndex <= previous) throw invalid("anonymous.recipients.slotIndex");
    const identityTag = output["identityTag"];
    if (identityTag !== SOLANA_OWNER_TAG) throw invalid("anonymous.recipients.identityTag");
    previous = slotIndex;
    return Object.freeze({
      slotIndex,
      identityTag,
      identityKey: hash(output["identityKey"], "anonymous.recipients.identityKey"),
      nullifierPk: hash(output["nullifierPk"], "anonymous.recipients.nullifierPk"),
      amount: u64(output["amount"], "anonymous.recipients.amount"),
      asset: hash(output["asset"], "anonymous.recipients.asset"),
    });
  });
  return Object.freeze({
    sender: address(wire["sender"], "anonymous.sender"),
    inputs: Object.freeze(inputs),
    recipients: Object.freeze(recipients),
  });
}

function payloadErrorKind(value: unknown): OutputPayloadErrorKind {
  const kind = OUTPUT_PAYLOAD_ERROR_KINDS.find((candidate) => candidate === value);
  if (kind === undefined) throw invalid("payloadErrors.kind");
  return kind;
}

/** A slot index, rejected outside the u32 range. */
function u32(value: unknown, path: string): number {
  const decoded = integer(value, path);
  if (decoded < 0n || decoded > 0xffff_ffffn) throw invalid(path);
  return Number(decoded);
}

/** An SPP event ordinal cannot exceed the indexer's u16 wire range. */
function u16(value: unknown, path: string): number {
  const decoded = integer(value, path);
  if (decoded < 0n || decoded > 0xffffn) throw invalid(path);
  return Number(decoded);
}

function u64(value: unknown, path: string): bigint {
  const decoded = integer(value, path);
  if (decoded < 0n || decoded > 0xffff_ffff_ffff_ffffn) throw invalid(path);
  return decoded;
}

function decodeOutput(output: Record<string, unknown>): DecryptedRingOutput {
  const ring = output["ringProgramId"];
  return Object.freeze({
    slotIndex: u32(output["slotIndex"], "slotIndex"),
    recipientViewingPublicKey: x25519Key(output["recipientViewingPk"], "recipientViewingPk"),
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
    eventIndex: u16(wire["eventIndex"], "eventIndex"),
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

const { address: requestAddress, record: requestRecord } = wireDecoder(invalidRequest);

function exactRequestRecord(
  value: unknown,
  allowed: ReadonlySet<string>,
  required: ReadonlySet<string>,
  field: string,
): Record<string, unknown> {
  const candidate = requestRecord(value, field);
  const invalidField = Reflect.ownKeys(candidate).find(
    (key) => typeof key !== "string" || !allowed.has(key),
  );
  if (invalidField !== undefined) throw invalidRequest(`${field}.shape`);
  const missing = [...required].find((key) => !Object.hasOwn(candidate, key));
  if (missing !== undefined) throw invalidRequest(`${field}.${missing}`);
  return candidate;
}

function requestBytes(value: unknown, length: number, field: string): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== length) throw invalidRequest(field);
  return new Uint8Array(value);
}

function checkedReadCursor(cursor: unknown): Uint8Array {
  if (
    !(cursor instanceof Uint8Array) ||
    cursor.length === 0 ||
    cursor.length > RING_READ_CURSOR_LIMIT
  ) {
    throw new RingError("RING_READ_CURSOR", {
      details: { length: cursor instanceof Uint8Array ? cursor.length : -1 },
    });
  }
  return new Uint8Array(cursor);
}

function checkedReadLimit(limit: unknown): bigint {
  if (typeof limit !== "bigint" || limit < 1n || limit > RING_READ_PAGE_LIMIT) {
    throw new RingError("RING_READ_LIMIT", { details: { limit: String(limit) } });
  }
  return limit;
}

/** Bounded to the safe integer range, `Number` in the wire encoding stays exact. */
function checkedUnixTimestamp(value: unknown, field: string): bigint {
  if (typeof value !== "bigint" || value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw invalidRequest(field);
  }
  return value;
}

const SIGNED_READ_FIELDS = new Set([
  "ringProgramId",
  "cursor",
  "limit",
  "reader",
  "timestamp",
  "nonce",
  "signature",
]);
const SIGNED_READ_REQUIRED_FIELDS = new Set([
  "ringProgramId",
  "reader",
  "timestamp",
  "nonce",
  "signature",
]);
const WEBAUTHN_FIELDS = new Set(["signature", "authenticatorData", "clientDataJSON"]);
const SIGNED_AUDITOR_FIELDS = new Set([
  "ringProgramId",
  "authority",
  "genesisHash",
  "timestamp",
  "nonce",
  "signature",
]);

function checkedReaderBytes(value: unknown): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== 34) {
    throw new RingError("RING_READER_KEY", {
      details: { length: value instanceof Uint8Array ? value.length : -1 },
    });
  }
  const reader = new Uint8Array(value);
  try {
    readerKeyFromBytes(reader);
  } catch (cause) {
    if (cause instanceof RingError) throw cause;
    throw new RingError("RING_READER_KEY", { cause });
  }
  return reader;
}

function checkedSignedRead(value: unknown): SignedRingRead {
  const read = exactRequestRecord(
    value,
    SIGNED_READ_FIELDS,
    SIGNED_READ_REQUIRED_FIELDS,
    "request",
  );
  const ringProgramId = requestAddress(read["ringProgramId"], "ringProgramId");
  const reader = checkedReaderBytes(read["reader"]);
  const nonce = requestBytes(read["nonce"], 32, "nonce") as Bytes32;
  const cursor = read["cursor"] === undefined ? undefined : checkedReadCursor(read["cursor"]);
  const limit = read["limit"] === undefined ? undefined : checkedReadLimit(read["limit"]);
  const timestamp = checkedUnixTimestamp(read["timestamp"], "timestamp");
  const signature = read["signature"];
  if (signature instanceof Uint8Array) {
    return Object.freeze({
      ringProgramId,
      reader,
      nonce,
      timestamp,
      signature: requestBytes(signature, 64, "signature"),
      ...(cursor === undefined ? {} : { cursor }),
      ...(limit === undefined ? {} : { limit }),
    });
  }
  const webauthn = exactRequestRecord(signature, WEBAUTHN_FIELDS, WEBAUTHN_FIELDS, "signature");
  if (!(webauthn["signature"] instanceof Uint8Array) || webauthn["signature"].length === 0) {
    throw invalidRequest("signature");
  }
  const authenticatorData = webauthn["authenticatorData"];
  if (!(authenticatorData instanceof Uint8Array) || authenticatorData.length < 37) {
    throw invalidRequest("authenticatorData");
  }
  const clientDataJSON = webauthn["clientDataJSON"];
  if (!(clientDataJSON instanceof Uint8Array) || clientDataJSON.length === 0) {
    throw invalidRequest("clientDataJSON");
  }
  return Object.freeze({
    ringProgramId,
    reader,
    nonce,
    timestamp,
    signature: Object.freeze({
      signature: new Uint8Array(webauthn["signature"]),
      authenticatorData: new Uint8Array(authenticatorData),
      clientDataJSON: new Uint8Array(clientDataJSON),
    }),
    ...(cursor === undefined ? {} : { cursor }),
    ...(limit === undefined ? {} : { limit }),
  });
}

function checkedSignedAuditorKeyRequest(value: unknown): SignedAuditorKeyRequest {
  const request = exactRequestRecord(
    value,
    SIGNED_AUDITOR_FIELDS,
    SIGNED_AUDITOR_FIELDS,
    "request",
  );
  return Object.freeze({
    ringProgramId: requestAddress(request["ringProgramId"], "ringProgramId"),
    authority: requestAddress(request["authority"], "authority"),
    genesisHash: requestBytes(request["genesisHash"], 32, "genesisHash") as Bytes32,
    nonce: requestBytes(request["nonce"], 32, "nonce") as Bytes32,
    signature: requestBytes(request["signature"], 64, "signature") as Bytes64,
    timestamp: checkedUnixTimestamp(request["timestamp"], "timestamp"),
  });
}

function hash(value: unknown, path: string): Bytes32 {
  const bytes = base58(value, path);
  if (bytes.length !== 32) throw invalid(path);
  return bytes as Bytes32;
}

function x25519Key(value: unknown, path: string): X25519PublicKey {
  const bytes = base64(value, path);
  if (bytes.length !== 33) throw invalid(path);
  try {
    return X25519PublicKey.fromBytes(bytes as Bytes33);
  } catch (cause) {
    if (!(cause instanceof KeypairError)) throw cause;
    throw invalid(path);
  }
}
