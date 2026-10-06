import { verify as verifyQuote, type Collateral } from "@phala/dcap-qvl";
import { sha384 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";

import {
  evidenceBytes,
  evidenceDecode as decode,
  refused,
  type AttestationClaims,
  type GpuRequirement,
  type PlatformModule,
  type PlatformVerdict,
} from "./platform.js";

/** TCG event type of every dstack runtime event in RTMR3. */
const RUNTIME_EVENT_TYPE = 0x0800_0001;

/** The boot measurements of one OS image on one VM shape, lowercase hex. */
export type TdxMeasurement = Readonly<{
  mrtd: string;
  rtmr0: string;
  rtmr1: string;
  rtmr2: string;
}>;

/** Byte fields in lowercase hex. */
export type DstackTdxPolicy = Readonly<{
  platform: "dstack-tdx";
  appId: string;
  hpkePublicKey: string;
  /** The `id` the key-provider event names, the KMS root the app keys derive from. */
  keyProviderId: string;
  osImageHashes: readonly string[];
  measurements: readonly TdxMeasurement[];
  composeHashes: readonly string[];
  tcbStatuses: readonly string[];
  gpu: GpuRequirement;
  maxAgeSecs: number;
}>;

type EventLogEntry = Readonly<{
  imr: number;
  eventType: number;
  digest: string;
  event: string;
  eventPayload: Uint8Array;
}>;

export const DSTACK_TDX: PlatformModule<DstackTdxPolicy> = Object.freeze({
  platform: "dstack-tdx",
  hostsGpu: true,
  keyPerBoot: false,
  anchors: Object.freeze([]),
  policy: (fields, common) =>
    Object.freeze({
      platform: "dstack-tdx",
      appId: fields.hex("app_id", 20),
      hpkePublicKey: fields.hex("hpke_public_key", 32),
      keyProviderId: fields.hex("key_provider_id"),
      osImageHashes: fields.hexList("os_image_hashes", 32),
      measurements: fields.records("measurements", (m) =>
        Object.freeze({
          mrtd: m.hex("mrtd", 48),
          rtmr0: m.hex("rtmr0", 48),
          rtmr1: m.hex("rtmr1", 48),
          rtmr2: m.hex("rtmr2", 48),
        }),
      ),
      composeHashes: fields.hexList("compose_hashes", 32),
      tcbStatuses: fields.strings("tcb_statuses"),
      ...common,
    }),
  pinsJson: (policy) => ({
    app_id: policy.appId,
    hpke_public_key: policy.hpkePublicKey,
    key_provider_id: policy.keyProviderId,
    os_image_hashes: policy.osImageHashes,
    measurements: policy.measurements,
    compose_hashes: policy.composeHashes,
    tcb_statuses: policy.tcbStatuses,
  }),
  verify: verifyDstackTdx,
});

/**
 * Accepts the evidence only if Intel signed a TDX quote whose measurements and
 * app identity match `policy` at `claims.nowSecs`.
 */
function verifyDstackTdx(
  json: unknown,
  policy: DstackTdxPolicy,
  claims: AttestationClaims,
): PlatformVerdict {
  const evidence = decode.record(json, "evidence");
  const quote = evidenceBytes(evidence["quote"], "quote");
  const collateral = collateralOf(evidence["collateral"]);
  const events = decode.list(evidence["event_log"], "event_log").map(eventOf);

  let verified;
  try {
    verified = verifyQuote(quote, collateral, claims.nowSecs);
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
  const composeHash = single(runtime, "compose-hash");
  if (!policy.composeHashes.includes(bytesToHex(composeHash))) throw refused("compose_hash");
  if (!policy.osImageHashes.includes(bytesToHex(single(runtime, "os-image-hash")))) {
    throw refused("os_image");
  }
  checkKeyProvider(single(runtime, "key-provider"), policy);

  if (bytesToHex(claims.hpkePublicKey) !== policy.hpkePublicKey) throw refused("hpke_key");
  return Object.freeze({
    reportData: report.reportData,
    imageId: composeHash,
    tcbStatus: verified.status,
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
    // The guest agent's GetQuote leaves RTMR3 digests empty, a stated one must still match.
    if (entry.digest !== "" && bytesToHex(digest) !== entry.digest) throw refused("event_log");
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

function checkKeyProvider(eventPayload: Uint8Array, policy: DstackTdxPolicy): void {
  let provider: unknown;
  try {
    provider = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(eventPayload));
  } catch {
    throw refused("runtime_event");
  }
  const record = decode.record(provider, "key-provider");
  const id = bytesToHex(evidenceBytes(record["id"], "key-provider"));
  if (record["name"] !== "kms" || id !== policy.keyProviderId) {
    throw refused("key_provider");
  }
}

function eventOf(value: unknown): EventLogEntry {
  const entry = decode.record(value, "event_log");
  const imr = entry["imr"];
  const eventType = entry["event_type"];
  if (!Number.isSafeInteger(imr) || !Number.isSafeInteger(eventType))
    throw refused("malformed_attestation");
  return Object.freeze({
    imr: Number(imr),
    eventType: Number(eventType),
    digest:
      entry["digest"] === undefined ? "" : bytesToHex(evidenceBytes(entry["digest"], "digest")),
    event: decode.string(entry["event"], "event"),
    eventPayload: evidenceBytes(entry["event_payload"], "event_payload"),
  });
}

/** dcap-qvl only ever sees checked hex. */
function collateralOf(value: unknown): Collateral {
  const c = decode.record(value, "collateral");
  const text = (field: string): string => decode.string(c[field], field);
  const hex = (field: string): string => bytesToHex(evidenceBytes(c[field], field));
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
