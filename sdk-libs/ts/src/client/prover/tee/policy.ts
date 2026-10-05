import { wireDecoder } from "../../../interface/decode.js";
import { ClientError } from "../../error.js";
import { PINNED_TEE_POLICY_FILE } from "./pinned.js";

export type GpuRequirement = "optional" | "required";

/** The boot measurements of one OS image on one VM shape, lowercase hex. */
export type TeeMeasurement = Readonly<{
  mrtd: string;
  rtmr0: string;
  rtmr1: string;
  rtmr2: string;
}>;

/** What a prover must prove before it sees a request, byte fields in lowercase hex. */
export type TeePolicy = Readonly<{
  appId: string;
  hpkePublicKey: string;
  /** The `id` the key-provider event names, the KMS root the app keys derive from. */
  keyProviderId: string;
  osImageHashes: readonly string[];
  measurements: readonly TeeMeasurement[];
  composeHashes: readonly string[];
  tcbStatuses: readonly string[];
  gpu: GpuRequirement;
  maxAgeSecs: number;
}>;

/** The deployment pinned in the SDK release, mirroring the Rust SDK `policy.json`. */
export function pinnedTeePolicy(): TeePolicy {
  const deployment = PINNED_TEE_POLICY_FILE.deployment;
  if (deployment === null) {
    throw new ClientError("CLIENT_PROVER_TEE_ATTESTATION", {
      details: { check: "no_pinned_deployment" },
    });
  }
  return teePolicyFromJson(deployment);
}

/** Parses the snake_case JSON form the Rust SDK and the release script share. */
export function teePolicyFromJson(json: unknown): TeePolicy {
  const value = decode.record(json, "tee");
  const hashes = (field: string): readonly string[] =>
    Object.freeze(decode.list(value[field], field).map((hash) => hexOf(hash, field, 32)));
  const measurements = decode.list(value["measurements"], "measurements").map((entry) => {
    const m = decode.record(entry, "measurements");
    return Object.freeze({
      mrtd: hexOf(m["mrtd"], "mrtd", 48),
      rtmr0: hexOf(m["rtmr0"], "rtmr0", 48),
      rtmr1: hexOf(m["rtmr1"], "rtmr1", 48),
      rtmr2: hexOf(m["rtmr2"], "rtmr2", 48),
    });
  });
  const gpu = value["gpu"];
  if (gpu !== "optional" && gpu !== "required") throw invalid("gpu");
  const maxAgeSecs = value["max_age_secs"];
  if (typeof maxAgeSecs !== "number" || !Number.isSafeInteger(maxAgeSecs) || maxAgeSecs <= 0) {
    throw invalid("max_age_secs");
  }
  return Object.freeze({
    appId: hexOf(value["app_id"], "app_id", 20),
    hpkePublicKey: hexOf(value["hpke_public_key"], "hpke_public_key", 32),
    keyProviderId: hexOf(value["key_provider_id"], "key_provider_id"),
    osImageHashes: hashes("os_image_hashes"),
    measurements: Object.freeze(measurements),
    composeHashes: hashes("compose_hashes"),
    tcbStatuses: Object.freeze(
      decode
        .list(value["tcb_statuses"], "tcb_statuses")
        .map((status) => decode.string(status, "tcb_statuses")),
    ),
    gpu,
    maxAgeSecs,
  });
}

/** Revalidates a caller-built policy that skipped {@link teePolicyFromJson}. */
export function checkedTeePolicy(policy: TeePolicy): TeePolicy {
  return teePolicyFromJson({
    app_id: policy.appId,
    hpke_public_key: policy.hpkePublicKey,
    key_provider_id: policy.keyProviderId,
    os_image_hashes: policy.osImageHashes,
    measurements: policy.measurements,
    compose_hashes: policy.composeHashes,
    tcb_statuses: policy.tcbStatuses,
    gpu: policy.gpu,
    max_age_secs: policy.maxAgeSecs,
  });
}

const invalid = (path: string): ClientError =>
  new ClientError("CLIENT_INVALID_CONFIG", { details: { field: `tee.${path}` } });
const decode = wireDecoder(invalid);

/** Lowercase hex, of exactly `bytes` bytes when given. */
function hexOf(value: unknown, path: string, bytes?: number): string {
  const hex = decode.string(value, path);
  if (!/^(?:[0-9a-f]{2})*$/u.test(hex)) throw invalid(path);
  if (bytes !== undefined && hex.length !== bytes * 2) throw invalid(path);
  return hex;
}
