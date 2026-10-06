import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { equalBytes } from "@noble/curves/utils.js";
import { concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";

import {
  evidenceBytes,
  evidenceDecode as decode,
  refused,
  type AttestationClaims,
  type PlatformVerdict,
} from "./platform.js";
import {
  PLATFORMS,
  type PlatformTable,
  type PolicyFor,
  type TeePlatform,
  type TeePolicy,
} from "./registry.js";

const REPORT_DOMAIN = utf8ToBytes("zolana/prover-tee/v1/report");

/** Attestation verified for one session nonce. */
export type AttestedProver = Readonly<{
  platform: TeePlatform;
  hpkePublicKey: Uint8Array;
  /** The dstack compose hash, or the Nitro PCR0. */
  imageId: Uint8Array;
  /** Set by `dstack-tdx` only. */
  tcbStatus?: string;
  gpuVerified: boolean;
}>;

/** Binds the session nonce, the encryption key and the NRAS digest into the evidence, zeros without a GPU. */
export function reportData(
  nonce: Uint8Array,
  hpkePublicKey: Uint8Array,
  gpuToken: Uint8Array | undefined,
): Uint8Array {
  const gpuDigest = gpuToken === undefined ? new Uint8Array(32) : sha256(gpuToken);
  return sha512(concatBytes(REPORT_DOMAIN, nonce, hpkePublicKey, gpuDigest));
}

/**
 * Accepts the attestation only if its platform's evidence matches `policy` at
 * `nowSecs` and binds `nonce`, the HPKE key and the GPU verdict.
 */
export function verifyAttestation(
  json: unknown,
  policy: TeePolicy,
  nonce: Uint8Array,
  nowSecs: number,
  platforms: PlatformTable = PLATFORMS,
): AttestedProver {
  const attestation = decode.record(json, "attestation");
  if (decode.string(attestation["platform"], "platform") !== policy.platform) {
    throw refused("platform");
  }
  const hpkePublicKey = evidenceBytes(attestation["hpke_public_key"], "hpke_public_key", 32);
  const gpu = attestation["gpu"];
  if (gpu !== null && typeof gpu !== "string") throw refused("malformed_attestation");
  if (gpu !== null && !platforms[policy.platform].hostsGpu) throw refused("gpu");
  const claims: AttestationClaims = Object.freeze({ nonce, hpkePublicKey, nowSecs });
  const verdict = platformVerdict(
    platforms,
    policy.platform,
    policy,
    attestation["evidence"],
    claims,
  );

  const gpuToken = gpu === null ? undefined : utf8ToBytes(gpu);
  if (!equalBytes(verdict.reportData, reportData(nonce, hpkePublicKey, gpuToken))) {
    throw refused("report_data");
  }
  if (policy.gpu === "required" && gpuToken === undefined) throw refused("gpu_missing");
  return Object.freeze({
    platform: policy.platform,
    hpkePublicKey,
    imageId: verdict.imageId,
    ...(verdict.tcbStatus === undefined ? {} : { tcbStatus: verdict.tcbStatus }),
    gpuVerified: gpuToken !== undefined,
  });
}

function platformVerdict<K extends TeePlatform>(
  platforms: PlatformTable,
  platform: K,
  policy: PolicyFor<K>,
  evidence: unknown,
  claims: AttestationClaims,
): PlatformVerdict {
  const module = platforms[platform];
  return module.verify(evidence, policy, claims, module.anchors);
}
