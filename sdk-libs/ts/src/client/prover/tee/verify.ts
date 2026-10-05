import { verify as verifyQuote, type Collateral } from "@phala/dcap-qvl";
import { sha256, sha384, sha512 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";

import { wireDecoder } from "../../../interface/decode.js";
import { ClientError } from "../../error.js";
import type { TeePolicy } from "./policy.js";

/** TCG event type of every dstack runtime event in RTMR3. */
const RUNTIME_EVENT_TYPE = 0x0800_0001;
const REPORT_DOMAIN = utf8ToBytes("zolana/prover-tee/v1/report");

/** A prover that passed {@link verifyAttestation} for one session nonce. */
export type AttestedProver = Readonly<{
  hpkePublicKey: Uint8Array;
  tcbStatus: string;
  composeHash: string;
  gpuVerified: boolean;
}>;

type EventLogEntry = Readonly<{
  imr: number;
  eventType: number;
  digest: string;
  event: string;
  eventPayload: Uint8Array;
}>;

/** Binds the session nonce, the sealing key and the NRAS digest into the quote, zeros without a GPU. */
export function reportData(
  nonce: Uint8Array,
  hpkePublicKey: Uint8Array,
  gpuToken: Uint8Array | undefined,
): Uint8Array {
  const gpuDigest = gpuToken === undefined ? new Uint8Array(32) : sha256(gpuToken);
  return sha512(concatBytes(REPORT_DOMAIN, nonce, hpkePublicKey, gpuDigest));
}

/**
 * Accepts the evidence only if Intel signed a TDX quote whose measurements,
 * app identity and report_data all match `policy` and `nonce` at `nowSecs`.
 */
export function verifyAttestation(
  json: unknown,
  policy: TeePolicy,
  nonce: Uint8Array,
  nowSecs: number,
): AttestedProver {
  const evidence = decode.record(json, "evidence");
  const quote = bytesOf(evidence["quote"], "quote");
  const collateral = collateralOf(evidence["collateral"]);
  const hpkePublicKey = bytesOf(evidence["hpke_public_key"], "hpke_public_key", 32);
  const gpu = evidence["gpu"];
  if (gpu !== null && typeof gpu !== "string") throw refused("evidence");
  const events = decode.list(evidence["event_log"], "event_log").map(eventOf);

  let verified;
  try {
    verified = verifyQuote(quote, collateral, nowSecs);
  } catch {
    throw refused("quote");
  }
  if (!policy.tcbStatuses.includes(verified.status)) throw refused("tcb_status");
  const report = verified.report.asTd10();
  if (report === null) throw refused("quote");
  const measured = (field: Uint8Array, expected: string): boolean => bytesToHex(field) === expected;
  if (
    !policy.measurements.some(
      (m) =>
        measured(report.mrTd, m.mrtd) &&
        measured(report.rtMr0, m.rtmr0) &&
        measured(report.rtMr1, m.rtmr1) &&
        measured(report.rtMr2, m.rtmr2),
    )
  ) {
    throw refused("measurement");
  }

  const runtime = runtimeEvents(events, report.rtMr3);
  if (bytesToHex(single(runtime, "app-id")) !== policy.appId) throw refused("app_id");
  const composeHash = bytesToHex(single(runtime, "compose-hash"));
  if (!policy.composeHashes.includes(composeHash)) throw refused("compose_hash");
  if (!policy.osImageHashes.includes(bytesToHex(single(runtime, "os-image-hash")))) {
    throw refused("os_image");
  }
  checkKeyProvider(single(runtime, "key-provider"), policy);

  if (bytesToHex(hpkePublicKey) !== policy.hpkePublicKey) throw refused("hpke_key");
  const gpuToken = gpu === null ? undefined : utf8ToBytes(gpu);
  if (bytesToHex(report.reportData) !== bytesToHex(reportData(nonce, hpkePublicKey, gpuToken))) {
    throw refused("report_data");
  }
  if (policy.gpu === "required" && gpuToken === undefined) throw refused("gpu_missing");
  return Object.freeze({
    hpkePublicKey,
    tcbStatus: verified.status,
    composeHash,
    gpuVerified: gpuToken !== undefined,
  });
}

/** Swapped event content fails even when the stated digests replay to `rtmr3`. */
function runtimeEvents(log: readonly EventLogEntry[], rtmr3: Uint8Array): readonly EventLogEntry[] {
  let replayed = new Uint8Array(48);
  const runtime = log.filter((entry) => entry.imr === 3);
  const eventType = new Uint8Array(4);
  new DataView(eventType.buffer).setUint32(0, RUNTIME_EVENT_TYPE, true);
  const separator = utf8ToBytes(":");
  for (const entry of runtime) {
    if (entry.eventType !== RUNTIME_EVENT_TYPE) throw refused("event_log");
    const digest = sha384(
      concatBytes(eventType, separator, utf8ToBytes(entry.event), separator, entry.eventPayload),
    );
    if (bytesToHex(digest) !== entry.digest) throw refused("event_log");
    replayed = sha384(concatBytes(replayed, digest));
  }
  if (bytesToHex(replayed) !== bytesToHex(rtmr3)) throw refused("event_log");
  return runtime;
}

function single(events: readonly EventLogEntry[], name: string): Uint8Array {
  const matching = events.filter((event) => event.event === name);
  const [event] = matching;
  if (matching.length !== 1 || event === undefined) throw refused("runtime_event");
  return event.eventPayload;
}

function checkKeyProvider(eventPayload: Uint8Array, policy: TeePolicy): void {
  let provider: unknown;
  try {
    provider = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(eventPayload));
  } catch {
    throw refused("runtime_event");
  }
  const record = decode.record(provider, "key-provider");
  const id = bytesToHex(bytesOf(record["id"], "key-provider"));
  if (record["name"] !== "kms" || id !== policy.keyProviderId) {
    throw refused("key_provider");
  }
}

function eventOf(value: unknown): EventLogEntry {
  const entry = decode.record(value, "event_log");
  const imr = entry["imr"];
  const eventType = entry["event_type"];
  if (!Number.isSafeInteger(imr) || !Number.isSafeInteger(eventType)) throw refused("evidence");
  return Object.freeze({
    imr: Number(imr),
    eventType: Number(eventType),
    digest: bytesToHex(bytesOf(entry["digest"], "digest")),
    event: decode.string(entry["event"], "event"),
    eventPayload: bytesOf(entry["event_payload"], "event_payload"),
  });
}

/** dcap-qvl only ever sees checked hex. */
function collateralOf(value: unknown): Collateral {
  const c = decode.record(value, "collateral");
  const text = (field: string): string => decode.string(c[field], field);
  const hex = (field: string): string => bytesToHex(bytesOf(c[field], field));
  return {
    pck_crl_issuer_chain: text("pck_crl_issuer_chain"),
    root_ca_crl: hex("root_ca_crl"),
    pck_crl: hex("pck_crl"),
    tcb_info_issuer_chain: text("tcb_info_issuer_chain"),
    tcb_info: text("tcb_info"),
    tcb_info_signature: hex("tcb_info_signature"),
    qe_identity_issuer_chain: text("qe_identity_issuer_chain"),
    qe_identity: text("qe_identity"),
    qe_identity_signature: hex("qe_identity_signature"),
  };
}

function bytesOf(value: unknown, path: string, length?: number): Uint8Array {
  const hex = decode.string(value, path);
  if (!/^(?:[0-9a-fA-F]{2})*$/u.test(hex)) throw refused("evidence");
  const bytes = hexToBytes(hex);
  if (length !== undefined && bytes.length !== length) throw refused("evidence");
  return bytes;
}

const refused = (check: string): ClientError =>
  new ClientError("CLIENT_PROVER_TEE_ATTESTATION", { details: { check } });
const decode = wireDecoder(() => refused("evidence"));
