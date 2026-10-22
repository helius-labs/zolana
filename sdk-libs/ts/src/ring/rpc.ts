import { ed25519 } from "@noble/curves/ed25519.js";
import {
  createSignableMessage,
  getBase58Decoder,
  getBase64Decoder,
  type MessagePartialSigner,
} from "@solana/kit";

import type {
  Address,
  Bytes31,
  Bytes32,
  Bytes33,
  Bytes64,
  RequestContext,
  Signature,
} from "../interface/types.js";
import { initializePoseidon } from "../hasher/index.js";
import { isCanonicalField } from "../interface/canonical-field.js";
import { postJsonRpc } from "../services/jsonrpc.js";
import { TransportFailure, checkedEndpoint, checkedFetch } from "../services/transport.js";
import { wireDecoder } from "../interface/decode.js";
import { addressBytes, copyBytes, sha256 } from "../interface/internal.js";
import { MAX_MERGE_INPUTS, mergePaddedInputCount } from "../interface/constants.js";
import { MEMBER_REGISTRY_ROOT_HISTORY } from "../interface/member-registry.js";
import { TAG_LEN, ringIdField } from "../keypair/ring-stream.js";
import { X25519PublicKey } from "../keypair/x25519.js";
import { KeypairError } from "../keypair/error.js";

import {
  knownUtxoHash,
  type AuditedInput,
  type AuditedInputOpening,
  type AuditedSender,
  type AuditedUtxo,
  type InputRing,
  type KnownUtxo,
  type OutputOpening,
  type OutputPayloadError,
  type OutputPayloadErrorKind,
} from "./audit.js";
import type { AuditedRingMerge, MergeKeys, UnresolvedRingMerge } from "./audit-merge.js";
import type { RingRootEntry } from "./codecs.js";
import { ZERO_32, equal } from "../transaction/internal.js";
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

const READ_DOMAIN = "zolana/ring-rpc-read/v2";
const AUDITOR_KEY_DOMAIN = "zolana/ring-auditor-key/v1";
const AUDITOR_KEY_REQUEST_DOMAIN = "zolana/ring-rpc-auditor-key-request/v1";
const AUDITED_UTXOS_DOMAIN = "zolana/ring-rpc-audited-utxos/v1";
/** Rust `AUDIT_PAGE_LIMIT`. */
export const RING_READ_PAGE_LIMIT = 100n;
/** Rust `AUDITED_UTXOS_LIMIT`, the UTXO hashes one read names. */
export const RING_AUDITED_UTXOS_LIMIT = 100;
/** Rust `AUDIT_CURSOR_LIMIT`. */
export const RING_READ_CURSOR_LIMIT = 256;

/** Rust `PagedRead`, the paged read a reader's signature authorizes. */
export type RingPagedRead = "getDecryptedTransactions" | "getAuditedMerges";

/** Mirrors Rust `ReadAttestation::message`. */
export function ringReadAttestation(
  input: Readonly<{
    method: RingPagedRead;
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
      `method: ${input.method}`,
      `ring: ${input.ringProgramId}`,
      `timestamp: ${input.timestamp}`,
      `nonce: ${base64Decoder.decode(input.nonce)}`,
      `limit: ${input.limit ?? 0n}`,
      `cursor: ${cursor}`,
    ].join("\n"),
  );
}

/** Mirrors Rust `AuditedUtxosAttestation::message`, the digest binds every requested hash in order. */
export function auditedUtxosAttestation(
  input: Readonly<{
    ringProgramId: Address;
    timestamp: bigint;
    nonce: Bytes32;
    utxoHashes: readonly Bytes32[];
  }>,
): Uint8Array {
  const joined = new Uint8Array(32 * input.utxoHashes.length);
  input.utxoHashes.forEach((utxoHash, index) => joined.set(utxoHash, 32 * index));
  return encoder.encode(
    [
      AUDITED_UTXOS_DOMAIN,
      `ring: ${input.ringProgramId}`,
      `timestamp: ${input.timestamp}`,
      `nonce: ${base64Decoder.decode(input.nonce)}`,
      `utxos: ${base64Decoder.decode(sha256(joined))}`,
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
  readonly method: RingPagedRead;
  readonly ringProgramId: Address;
  readonly cursor?: Uint8Array;
  readonly limit?: bigint;
  readonly reader: Uint8Array;
  readonly timestamp: bigint;
  readonly nonce: Bytes32;
  readonly signature: Uint8Array | WebAuthnSignature;
}

/** Mirrors Rust `ReadRequest`, every signature draws its own nonce. */
export class RingReadRequest {
  readonly #method: RingPagedRead;
  readonly #ringProgramId: Address;
  #cursor?: Uint8Array;
  #limit?: bigint;
  #timestamp?: bigint;

  private constructor(method: RingPagedRead, ringProgramId: Address) {
    this.#method = method;
    this.#ringProgramId = ringProgramId;
  }

  static decryptedTransactions(ringProgramId: Address): RingReadRequest {
    return new RingReadRequest("getDecryptedTransactions", ringProgramId);
  }

  static auditedMerges(ringProgramId: Address): RingReadRequest {
    return new RingReadRequest("getAuditedMerges", ringProgramId);
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
    const nonce = freshNonce();
    const signature = await signer.sign(
      ringReadAttestation({
        method: this.#method,
        ringProgramId: this.#ringProgramId,
        timestamp,
        nonce,
        ...(this.#cursor === undefined ? {} : { cursor: this.#cursor }),
        ...(this.#limit === undefined ? {} : { limit: this.#limit }),
      }),
    );
    return Object.freeze({
      method: this.#method,
      ringProgramId: this.#ringProgramId,
      ...(this.#cursor === undefined ? {} : { cursor: this.#cursor }),
      ...(this.#limit === undefined ? {} : { limit: this.#limit }),
      reader: signer.reader,
      timestamp,
      nonce,
      signature,
    });
  }
}

/** Mirrors Rust `GetAuditedUtxosRequest` after `AuditedUtxosRequest::sign`. */
export interface SignedAuditedUtxosRead {
  readonly ringProgramId: Address;
  /** Answers come back in the same order. */
  readonly utxoHashes: readonly Bytes32[];
  readonly reader: Uint8Array;
  readonly timestamp: bigint;
  readonly nonce: Bytes32;
  readonly signature: Uint8Array | WebAuthnSignature;
}

/** Mirrors Rust `AuditedUtxosRequest`, one to `RING_AUDITED_UTXOS_LIMIT` hashes. */
export class RingAuditedUtxosRequest {
  readonly #ringProgramId: Address;
  readonly #utxoHashes: readonly Bytes32[];
  #timestamp?: bigint;

  private constructor(ringProgramId: Address, utxoHashes: readonly Bytes32[]) {
    this.#ringProgramId = ringProgramId;
    this.#utxoHashes = utxoHashes;
  }

  static read(ringProgramId: Address, utxoHashes: readonly Bytes32[]): RingAuditedUtxosRequest {
    return new RingAuditedUtxosRequest(ringProgramId, checkedUtxoHashes(utxoHashes));
  }

  /** Unix seconds, the RPC rejects a clock more than its skew away. */
  at(timestamp: bigint): this {
    this.#timestamp = checkedUnixTimestamp(timestamp, "timestamp");
    return this;
  }

  async sign(signer: RingReadSigner): Promise<SignedAuditedUtxosRead> {
    const timestamp = timestampOrNow(this.#timestamp);
    const nonce = freshNonce();
    const signature = await signer.sign(
      auditedUtxosAttestation({
        ringProgramId: this.#ringProgramId,
        timestamp,
        nonce,
        utxoHashes: this.#utxoHashes,
      }),
    );
    return Object.freeze({
      ringProgramId: this.#ringProgramId,
      utxoHashes: this.#utxoHashes,
      reader: signer.reader,
      timestamp,
      nonce,
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
  #timestamp?: bigint;

  private constructor(ringProgramId: Address, genesisHash: Bytes32) {
    this.#ringProgramId = ringProgramId;
    this.#genesisHash = genesisHash;
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
    const nonce = freshNonce();
    const signature = await signMessage(
      authority,
      auditorKeyRequestAttestation({
        genesisHash: this.#genesisHash,
        ringProgramId: this.#ringProgramId,
        timestamp,
        nonce,
      }),
    );
    return Object.freeze({
      ringProgramId: this.#ringProgramId,
      authority: authority.address,
      genesisHash: this.#genesisHash,
      timestamp,
      nonce,
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

/** Mirrors Rust `RingActivation`, SPP's gate on every operational ring instruction. */
export interface RingActivation {
  readonly activated: boolean;
  readonly paused: boolean;
}

/** Mirrors Rust `RegistryStatus`, the registry's history, floor and queue as the chain holds them. */
export interface RingRegistryStatus {
  /** Entry `i` sits at history slot `i`, `undefined` for a slot never written. */
  readonly history: readonly (RingRootEntry | undefined)[];
  /** The history slot of the newest root. */
  readonly historyCursor: number;
  readonly nextIndex: number;
  /** The applied position every own-ring root must reach. */
  readonly floor: bigint;
  readonly priorFloor: bigint;
  /** The slot of the last floor raise. */
  readonly floorSlot: bigint;
  /** Queue positions `queueHead..queueTail` wait for an application. */
  readonly queueHead: bigint;
  readonly queueTail: bigint;
}

/** Mirrors Rust `RingStatusResponse`, unsigned and only what the chain publishes. */
export interface RingStatus {
  readonly ringProgramId: Address;
  readonly state: RingState;
  /** The key the ring's config names, absent until the config exists. */
  readonly configAuditorPublicKey?: X25519PublicKey;
  readonly servicePublicKey: Address;
  /** Absent until SPP holds a config for the ring. */
  readonly activation?: RingActivation;
  /** Absent until the ring creates its member registry. */
  readonly registry?: RingRegistryStatus;
}

/** Mirrors Rust `DecryptedOutputContext`, the tree is the canonical PDA of `treeId`. */
export interface DecryptedOutputContext {
  readonly treeId: number;
  readonly leafIndex: bigint;
  readonly hash: Bytes32;
}

/** Mirrors Rust `DecryptedOutput`, a slot whose rebuilt opening reaches its published commitment. */
export interface DecryptedRingOutput {
  readonly slotIndex: number;
  readonly outputContext: DecryptedOutputContext;
  readonly opening: OutputOpening;
}

/** A public settlement leg. Value left the ring to a plain account. */
export interface DecryptedRingWithdrawal {
  /** A token account for an SPL leg, a wallet for a SOL leg. */
  readonly recipient: Address;
  /** The mint of an SPL leg or the native SOL mint. */
  readonly asset: Address;
  readonly amount: bigint;
}

/** Mirrors Rust `DecryptedTransaction`. */
export interface DecryptedRingTransaction {
  readonly slot: bigint;
  readonly signature: Signature;
  /** Ordinal of the confirmed SPP event within this Solana transaction. */
  readonly eventIndex: number;
  readonly txViewingPublicKey: X25519PublicKey;
  /** Published order, every slot sits here or in `payloadErrors` exactly once. */
  readonly outputs: readonly DecryptedRingOutput[];
  readonly payloadErrors: readonly OutputPayloadError[];
  /** The hidden sender of an anonymous ring. */
  readonly sender?: AuditedSender;
  /** One per published nullifier of an anonymous ring. */
  readonly inputs: readonly AuditedInput[];
  readonly nullifiers: readonly Bytes32[];
  /** Required signers, fee payer first. */
  readonly signers: readonly Address[];
  /** Empty when nothing left the ring. */
  readonly withdrawals: readonly DecryptedRingWithdrawal[];
}

export type {
  AuditedInput,
  AuditedInputOpening,
  AuditedSender,
  AuditedUtxo,
  InputRing,
  KnownUtxo,
  OutputOpening,
  OutputPayloadError,
  OutputPayloadErrorKind,
} from "./audit.js";

/** Mirrors Rust `SkippedReason`, `unseenInput` an anonymous input naming a UTXO the service has not opened. */
export type SkippedReason = "missingAuditorMessage" | "invalidAuditData" | "unseenInput";

const SKIPPED_REASONS: readonly SkippedReason[] = Object.freeze([
  "missingAuditorMessage",
  "invalidAuditData",
  "unseenInput",
]);

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

/** Mirrors Rust `GetAuditedMergesResponse`, the merges the service opened with its auditor key. */
export interface AuditedMergesPage {
  readonly slot: bigint;
  readonly blockTime: bigint;
  readonly opened: readonly AuditedRingMerge[];
  readonly unresolved: readonly UnresolvedRingMerge[];
  readonly cursor?: Uint8Array;
}

/** Mirrors Rust `AuditedUtxoView`, a UTXO the auditor opened and the slot that created it. */
export interface RingAuditedUtxo {
  readonly utxoHash: Bytes32;
  readonly utxo: KnownUtxo;
  readonly slot: bigint;
  readonly signature: Signature;
  readonly eventIndex: number;
  readonly slotIndex: number;
}

export interface RingAuditedUtxosPage {
  readonly slot: bigint;
  readonly blockTime: bigint;
  /** In request order, `undefined` for a UTXO the service has not opened. */
  readonly utxos: readonly (RingAuditedUtxo | undefined)[];
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
    const ring = address(wire["ringProgramId"], "result.ringProgramId");
    if (ring !== ringProgramId) throw invalid("result.ringProgramId");
    const config = wire["configAuditorPubkey"];
    const activation = wire["activation"];
    const registry = wire["registry"];
    return Object.freeze({
      ringProgramId: ring,
      state,
      ...(absent(config)
        ? {}
        : { configAuditorPublicKey: x25519Key(config, "result.configAuditorPubkey") }),
      servicePublicKey: address(wire["servicePubkey"], "result.servicePubkey"),
      ...(absent(activation) ? {} : { activation: decodeActivation(activation) }),
      ...(absent(registry) ? {} : { registry: decodeRegistryStatus(registry) }),
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
    let request = RingReadRequest.decryptedTransactions(input.ringProgramId);
    if (input.cursor !== undefined) request = request.withCursor(input.cursor);
    if (input.limit !== undefined) request = request.withLimit(input.limit);
    if (input.timestamp !== undefined) request = request.at(input.timestamp);
    return this.readSigned(await request.sign(input.signer), context);
  }

  /** The UTXOs the service opened, signed over the requested hashes. */
  async getAuditedUtxos(
    input: Readonly<{
      ringProgramId: Address;
      utxoHashes: readonly Bytes32[];
      signer: RingReadSigner;
      timestamp?: bigint;
    }>,
    context?: RequestContext,
  ): Promise<RingAuditedUtxosPage> {
    let request = RingAuditedUtxosRequest.read(input.ringProgramId, input.utxoHashes);
    if (input.timestamp !== undefined) request = request.at(input.timestamp);
    return this.readSignedUtxos(await request.sign(input.signer), context);
  }

  /** Rust `GetAuditedUtxosResponse::known_utxos`, an answer is used only where it rebuilds its requested hash. */
  async readSignedUtxos(
    read: SignedAuditedUtxosRead,
    context?: RequestContext,
  ): Promise<RingAuditedUtxosPage> {
    await initializePoseidon();
    const { utxoHashes, ...auth } = exactRequestRecord(
      read,
      SIGNED_UTXOS_FIELDS,
      SIGNED_UTXOS_FIELDS,
      "request",
    );
    const hashes = checkedUtxoHashes(utxoHashes);
    const checked = checkedReadAuth(auth);
    const wire = record(
      await this.#call(
        "getAuditedUtxos",
        {
          ...signedReadParams(checked),
          utxoHashes: hashes.map((utxoHash) => base58Decoder.decode(utxoHash)),
        },
        context,
      ),
      "result",
    );
    const wireContext = record(wire["context"], "result.context");
    const utxos = list(record(wire["value"], "result.value")["utxos"], "result.value.utxos");
    if (utxos.length !== hashes.length) throw invalid("result.value.utxos");
    const ringId = ringIdField(checked.ringProgramId);
    return Object.freeze({
      slot: integer(wireContext["slot"], "result.context.slot"),
      blockTime: signedInteger(wireContext["blockTime"], "result.context.blockTime"),
      utxos: Object.freeze(
        utxos.map((entry, index) => {
          if (entry === null) return undefined;
          const path = `result.value.utxos[${index}]`;
          const item = record(entry, path);
          const utxoHash = hash(item["utxoHash"], `${path}.utxoHash`);
          const utxo = decodeKnownUtxo(record(item["utxo"], `${path}.utxo`), `${path}.utxo`);
          // The ring's UTXO or a default-ring one the ring spent, any other opening is not this hash's.
          if (
            !equal(utxoHash, hashes[index] ?? new Uint8Array()) ||
            ![ringId, ZERO_32].some((ring) => equal(knownUtxoHash(utxo, ring), utxoHash))
          )
            throw invalid(`${path}.utxo`);
          return Object.freeze({
            utxoHash,
            utxo,
            slot: u64(item["slot"], `${path}.slot`),
            signature: signature(item["txSignature"], `${path}.txSignature`),
            eventIndex: u16(item["eventIndex"], `${path}.eventIndex`),
            slotIndex: u32(item["slotIndex"], `${path}.slotIndex`),
          });
        }),
      ),
    });
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
    let request = RingReadRequest.auditedMerges(input.ringProgramId);
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
    const checked = checkedSignedRead(read, "getAuditedMerges");
    const wire = record(
      await this.#call("getAuditedMerges", signedReadParams(checked), context),
      "result",
    );
    const wireContext = record(wire["context"], "result.context");
    const value = record(wire["value"], "result.value");
    const cursor = readResponseCursor(value["cursor"], checked);
    const identity = (item: Record<string, unknown>, path: string) => ({
      signature: signature(item["txSignature"], `${path}.txSignature`),
      eventIndex: u16(item["eventIndex"], `${path}.eventIndex`),
      outputCommitment: canonicalHash(item["outputCommitment"], `${path}.outputCommitment`),
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
          if (inputNullifiers.length === 0 || inputNullifiers.length > MAX_MERGE_INPUTS)
            throw invalid(`${path}.inputNullifiers`);
          const ownerMember = canonicalHash(item["ownerMember"], `${path}.ownerMember`);
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
            ...(owner === undefined ? {} : { ownerPublicKey: owner }),
            mint: address(item["mint"], `${path}.mint`),
            amount: u64(item["amount"], `${path}.amount`),
            blinding: canonicalHash(item["blinding"], `${path}.blinding`),
            ringDataHash: canonicalHash(item["ringDataHash"], `${path}.ringDataHash`),
            inputNullifiers: Object.freeze(
              inputNullifiers.map((nullifier) =>
                canonicalHash(nullifier, `${path}.inputNullifiers`),
              ),
            ),
            keys: mergeKeys(item, inputNullifiers.length, path),
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
    const checked = checkedSignedRead(read, "getDecryptedTransactions");
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

function signedReadParams(
  checked: ReadAuth & Partial<Pick<SignedRingRead, "cursor" | "limit">>,
): Record<string, unknown> {
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
function mergeKeys(item: Record<string, unknown>, published: number, path: string): MergeKeys {
  const nullifier = item["nullifier"];
  const commitments = item["inputCommitments"];
  if (absent(nullifier) === absent(commitments)) throw invalid(`${path}.nullifier`);
  if (!absent(nullifier))
    return Object.freeze({
      kind: "escrowed",
      nullifier: canonicalHash(nullifier, `${path}.nullifier`),
    });
  const disclosed = list(commitments, `${path}.inputCommitments`);
  if (disclosed.length !== mergePaddedInputCount(published))
    throw invalid(`${path}.inputCommitments`);
  return Object.freeze({
    kind: "disclosed",
    inputCommitments: Object.freeze(
      disclosed.map((commitment) => canonicalHash(commitment, `${path}.inputCommitments`)),
    ),
  });
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

/** Structure only, the openings stay as the service rebuilt them. */
function decodeTransaction(wire: Record<string, unknown>): DecryptedRingTransaction {
  const outputs = list(wire["outputs"], "outputs").map((entry, index) =>
    decodeOutput(record(entry, `outputs[${index}]`), `outputs[${index}]`),
  );
  const payloadErrors = list(wire["payloadErrors"], "payloadErrors").map((entry, index) => {
    const error = record(entry, `payloadErrors[${index}]`);
    return Object.freeze({
      slotIndex: u32(error["slotIndex"], `payloadErrors[${index}].slotIndex`),
      kind: payloadErrorKind(error["kind"], `payloadErrors[${index}].kind`),
    });
  });
  checkSlotCoverage([
    ...outputs.map((output) => output.slotIndex),
    ...payloadErrors.map((error) => error.slotIndex),
  ]);
  const nullifiers = list(wire["nullifiers"], "nullifiers").map((nullifier, index) =>
    hash(nullifier, `nullifiers[${index}]`),
  );
  const sender = absent(wire["sender"])
    ? undefined
    : decodeSender(record(wire["sender"], "sender"));
  const inputs = absent(wire["inputs"])
    ? []
    : list(wire["inputs"], "inputs").map((entry, index) =>
        decodeInput(record(entry, `inputs[${index}]`), `inputs[${index}]`),
      );
  // An anonymous ring discloses one input per published nullifier, every other ring none.
  if (
    sender === undefined
      ? inputs.length !== 0
      : inputs.length !== nullifiers.length ||
        inputs.some((input, index) => !equal(input.nullifier, nullifiers[index]!))
  )
    throw invalid("inputs");
  // A tag marks an anonymous ring output, a confidential ring publishes none.
  if (
    outputs.some(
      (output) =>
        output.opening.kind === "ring" &&
        (output.opening.tag !== undefined) !== (sender !== undefined),
    )
  )
    throw invalid("outputs.tag");
  return Object.freeze({
    slot: integer(wire["slot"], "slot"),
    signature: signature(wire["txSignature"], "txSignature"),
    eventIndex: u16(wire["eventIndex"], "eventIndex"),
    txViewingPublicKey: x25519Key(wire["txViewingPk"], "txViewingPk"),
    outputs: Object.freeze(outputs),
    payloadErrors: Object.freeze(payloadErrors),
    ...(sender === undefined ? {} : { sender }),
    inputs: Object.freeze(inputs),
    nullifiers: Object.freeze(nullifiers),
    signers: Object.freeze(
      list(wire["signers"], "signers").map((key, index) => address(key, `signers[${index}]`)),
    ),
    withdrawals: Object.freeze(
      list(wire["withdrawals"], "withdrawals").map((entry, index) => {
        const path = `withdrawals[${index}]`;
        const leg = record(entry, path);
        return Object.freeze({
          recipient: address(leg["recipient"], `${path}.recipient`),
          asset: address(leg["asset"], `${path}.asset`),
          amount: u64(leg["amount"], `${path}.amount`),
        });
      }),
    ),
  });
}

/** Rust `TransactionAudit` records every published slot as an output or as one payload error. */
function checkSlotCoverage(indexes: readonly number[]): void {
  const seen = new Set(indexes);
  if (seen.size !== indexes.length || indexes.some((index) => index >= indexes.length))
    throw invalid("payloadErrors");
}

function decodeOutput(wire: Record<string, unknown>, path: string): DecryptedRingOutput {
  const context = record(wire["outputContext"], `${path}.outputContext`);
  const treeId = u32(context["treeId"], `${path}.outputContext.treeId`);
  if (treeId > 0xffff) throw invalid(`${path}.outputContext.treeId`);
  const kind = wire["kind"];
  const utxo = wire["utxo"];
  const recipientU = wire["recipientU"];
  const tag = wire["tag"];
  let opening: OutputOpening;
  if (kind === "ring" && !absent(utxo) && !absent(recipientU)) {
    opening = Object.freeze({
      kind,
      utxo: decodeDecryptedUtxo(record(utxo, `${path}.utxo`), `${path}.utxo`),
      recipientU: hash(recipientU, `${path}.recipientU`),
      ...(absent(tag) ? {} : { tag: ringTag(tag, `${path}.tag`) }),
    });
  } else if (kind === "exit" && !absent(utxo) && absent(recipientU) && absent(tag)) {
    opening = Object.freeze({
      kind,
      utxo: decodeDecryptedUtxo(record(utxo, `${path}.utxo`), `${path}.utxo`),
    });
  } else if (kind === "dummy" && absent(utxo) && absent(recipientU) && absent(tag)) {
    opening = Object.freeze({ kind });
  } else {
    throw invalid(`${path}.kind`);
  }
  return Object.freeze({
    slotIndex: u32(wire["slotIndex"], `${path}.slotIndex`),
    outputContext: Object.freeze({
      treeId,
      leafIndex: u64(context["leafIndex"], `${path}.outputContext.leafIndex`),
      hash: hash(context["hash"], `${path}.outputContext.hash`),
    }),
    opening,
  });
}

/** Rust `DecryptedUtxo`, a transfer's output names its nullifier key. */
function decodeDecryptedUtxo(wire: Record<string, unknown>, path: string): AuditedUtxo {
  return Object.freeze({
    ...utxoFields(wire, path, hash),
    nullifierPk: hash(wire["nullifierPk"], `${path}.nullifierPk`),
  });
}

/** Rust `DecryptedKnownUtxo`, exactly one of `nullifierPk` and `ownerHash`, the latter for a deposited UTXO. */
function decodeKnownUtxo(wire: Record<string, unknown>, path: string): KnownUtxo {
  const nullifierPk = wire["nullifierPk"];
  const ownerHash = wire["ownerHash"];
  if (absent(nullifierPk) === absent(ownerHash)) throw invalid(`${path}.ownerHash`);
  return Object.freeze({
    ...utxoFields(wire, path, canonicalHash),
    owner: absent(ownerHash)
      ? Object.freeze({
          kind: "keyed",
          nullifierPk: canonicalHash(nullifierPk, `${path}.nullifierPk`),
        })
      : Object.freeze({
          kind: "deposited",
          ownerHash: canonicalHash(ownerHash, `${path}.ownerHash`),
        }),
    treeId: u16(wire["treeId"], `${path}.treeId`),
  });
}

function utxoFields(
  wire: Record<string, unknown>,
  path: string,
  field: (input: unknown, path: string) => Bytes32,
): Omit<AuditedUtxo, "nullifierPk"> {
  const mint = wire["mint"];
  return {
    ownerKey: hash(wire["ownerKey"], `${path}.ownerKey`),
    asset: field(wire["asset"], `${path}.asset`),
    ...(absent(mint) ? {} : { mint: address(mint, `${path}.mint`) }),
    amount: u64(wire["amount"], `${path}.amount`),
    blinding: field(wire["blinding"], `${path}.blinding`),
    dataHash: field(wire["dataHash"], `${path}.dataHash`),
    ringDataHash: field(wire["ringDataHash"], `${path}.ringDataHash`),
  };
}

/** A BN254 scalar the reader hashes, a non-canonical encoding is malformed. */
function canonicalHash(input: unknown, path: string): Bytes32 {
  const bytes = hash(input, path);
  if (!isCanonicalField(bytes)) throw invalid(path);
  return bytes;
}

function decodeSender(wire: Record<string, unknown>): AuditedSender {
  const nullifierPk = wire["nullifierPk"];
  return Object.freeze({
    ownerKey: hash(wire["ownerKey"], "sender.ownerKey"),
    ...(absent(nullifierPk) ? {} : { nullifierPk: hash(nullifierPk, "sender.nullifierPk") }),
  });
}

function decodeInput(wire: Record<string, unknown>, path: string): AuditedInput {
  const nullifier = hash(wire["nullifier"], `${path}.nullifier`);
  if (absent(wire["opening"])) return Object.freeze({ nullifier });
  const opening = record(wire["opening"], `${path}.opening`);
  const mint = opening["mint"];
  const ring = opening["ring"];
  const decoded: AuditedInputOpening = Object.freeze({
    asset: hash(opening["asset"], `${path}.opening.asset`),
    ...(absent(mint) ? {} : { mint: address(mint, `${path}.opening.mint`) }),
    amount: u64(opening["amount"], `${path}.opening.amount`),
    blinding: hash(opening["blinding"], `${path}.opening.blinding`),
    ...(absent(ring) ? {} : { ring: decodeInputRing(record(ring, `${path}.opening.ring`), path) }),
  });
  return Object.freeze({ nullifier, opening: decoded });
}

/** Rust `DecryptedInputRing`, tagged by `kind`. */
function decodeInputRing(wire: Record<string, unknown>, path: string): InputRing {
  switch (wire["kind"]) {
    case "ring":
    case "default":
      return Object.freeze({
        kind: wire["kind"],
        commitment: hash(wire["commitment"], `${path}.opening.ring.commitment`),
      });
    case "unresolved":
      return Object.freeze({
        kind: "unresolved",
        ring: hash(wire["ring"], `${path}.opening.ring.ring`),
        default: hash(wire["default"], `${path}.opening.ring.default`),
      });
    default:
      throw invalid(`${path}.opening.ring.kind`);
  }
}

/** `0x00 ‖ tag`, the owner tag of an anonymous ring output. */
function ringTag(value: unknown, path: string): Bytes31 {
  const field = hash(value, path);
  if (field[0] !== 0) throw invalid(path);
  return field.slice(1, 1 + TAG_LEN) as Bytes31;
}

/** Rust `OutputPayloadErrorKind` as the ring rpc serializes it. */
export const RING_PAYLOAD_ERROR_KINDS: readonly OutputPayloadErrorKind[] = Object.freeze([
  "frame",
  "disclosure",
  "recipientKey",
  "commitment",
  "escrowUnknown",
]);

function payloadErrorKind(value: unknown, path: string): OutputPayloadErrorKind {
  const kind = RING_PAYLOAD_ERROR_KINDS.find((candidate) => candidate === value);
  if (kind === undefined) throw invalid(path);
  return kind;
}

function decodeActivation(value: unknown): RingActivation {
  const wire = record(value, "result.activation");
  const flag = (name: string): boolean => {
    const field = wire[name];
    if (typeof field !== "boolean") throw invalid(`result.activation.${name}`);
    return field;
  };
  return Object.freeze({ activated: flag("activated"), paused: flag("paused") });
}

function decodeRegistryStatus(value: unknown): RingRegistryStatus {
  const wire = record(value, "result.registry");
  const history = list(wire["history"], "result.registry.history");
  if (history.length !== MEMBER_REGISTRY_ROOT_HISTORY) throw invalid("result.registry.history");
  const historyCursor = u32(wire["historyCursor"], "result.registry.historyCursor");
  const queueHead = u64(wire["queueHead"], "result.registry.queueHead");
  const queueTail = u64(wire["queueTail"], "result.registry.queueTail");
  if (historyCursor >= MEMBER_REGISTRY_ROOT_HISTORY || queueHead > queueTail)
    throw invalid("result.registry");
  return Object.freeze({
    history: Object.freeze(
      history.map((entry, index) => {
        if (entry === null) return undefined;
        const path = `result.registry.history[${index}]`;
        const root = record(entry, path);
        return Object.freeze({
          root: hash(root["root"], `${path}.root`),
          applied: u64(root["applied"], `${path}.applied`),
          slot: u64(root["slot"], `${path}.slot`),
        });
      }),
    ),
    historyCursor,
    nextIndex: u32(wire["nextIndex"], "result.registry.nextIndex"),
    floor: u64(wire["floor"], "result.registry.floor"),
    priorFloor: u64(wire["priorFloor"], "result.registry.priorFloor"),
    floorSlot: u64(wire["floorSlot"], "result.registry.floorSlot"),
    queueHead,
    queueTail,
  });
}

function absent(value: unknown): boolean {
  return value === undefined || value === null;
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

function decodeSkipped(wire: Record<string, unknown>): SkippedRingTransaction {
  const reason = SKIPPED_REASONS.find((candidate) => candidate === wire["reason"]);
  if (reason === undefined) throw invalid("reason");
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

/** One to `RING_AUDITED_UTXOS_LIMIT` 32-byte hashes. */
function checkedUtxoHashes(value: unknown): readonly Bytes32[] {
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    value.length > RING_AUDITED_UTXOS_LIMIT ||
    !value.every((entry) => entry instanceof Uint8Array && entry.length === 32)
  )
    throw new RingError("RING_READ_LIMIT", {
      details: { name: "utxoHashes", length: Array.isArray(value) ? value.length : -1 },
    });
  return Object.freeze(value.map((entry: Uint8Array) => new Uint8Array(entry) as Bytes32));
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
  "method",
  "ringProgramId",
  "cursor",
  "limit",
  "reader",
  "timestamp",
  "nonce",
  "signature",
]);
const SIGNED_READ_REQUIRED_FIELDS = new Set([
  "method",
  "ringProgramId",
  "reader",
  "timestamp",
  "nonce",
  "signature",
]);
const SIGNED_UTXOS_FIELDS = new Set([
  "ringProgramId",
  "utxoHashes",
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

function checkedSignedRead(value: unknown, method: RingPagedRead): SignedRingRead {
  const read = exactRequestRecord(
    value,
    SIGNED_READ_FIELDS,
    SIGNED_READ_REQUIRED_FIELDS,
    "request",
  );
  if (read["method"] !== method) throw invalidRequest("method");
  const cursor = read["cursor"] === undefined ? undefined : checkedReadCursor(read["cursor"]);
  const limit = read["limit"] === undefined ? undefined : checkedReadLimit(read["limit"]);
  return Object.freeze({
    method,
    ...checkedReadAuth(read),
    ...(cursor === undefined ? {} : { cursor }),
    ...(limit === undefined ? {} : { limit }),
  });
}

type ReadAuth = Omit<SignedRingRead, "method" | "cursor" | "limit">;

function checkedReadAuth(read: Readonly<Record<string, unknown>>): ReadAuth {
  const ringProgramId = requestAddress(read["ringProgramId"], "ringProgramId");
  const reader = checkedReaderBytes(read["reader"]);
  const nonce = requestBytes(read["nonce"], 32, "nonce") as Bytes32;
  const timestamp = checkedUnixTimestamp(read["timestamp"], "timestamp");
  const signature = read["signature"];
  if (signature instanceof Uint8Array) {
    return Object.freeze({
      ringProgramId,
      reader,
      nonce,
      timestamp,
      signature: requestBytes(signature, 64, "signature"),
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
