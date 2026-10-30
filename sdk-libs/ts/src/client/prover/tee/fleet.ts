import { bytesToHex } from "@noble/hashes/utils.js";

import {
  PolicyFields,
  evidenceBytes,
  evidenceDecode,
  invalidPolicy,
  policyDecode,
  refused,
} from "./platform.js";
import { checkedTeePolicy, teePolicyFromJson, teePolicyJson } from "./policy.js";
import { PLATFORMS, type PlatformTable, type TeePolicy } from "./registry.js";
import { verifyAttestation, type AttestedProver } from "./verify.js";

const MAX_DEPLOYMENTS = 32;
const IDENTIFIER = /^[a-z0-9][a-z0-9-]{0,127}$/u;

/** One approved generation; region is descriptive metadata, not attested geography. */
export type TeeDeployment = Readonly<{
  id: string;
  region: string;
  policy: TeePolicy;
}>;

/** Explicit pins for a fleet. Parsing performs no download or signature verification. */
export type TeeFleetPolicy = Readonly<{
  kind: "fleet";
  schemaVersion: 1;
  network: string;
  revision: number;
  expiresAt: number;
  deployments: readonly TeeDeployment[];
}>;

export type ProverTeePolicy = TeePolicy | TeeFleetPolicy;

/** Parses a reviewed fleet file and requires the caller's intended network. */
export function teeFleetPolicyFromJson(json: unknown, network: string): TeeFleetPolicy {
  const fields = new PolicyFields(json);
  if (fields.get("schema_version") !== 1) throw invalidPolicy("schema_version");
  const expectedNetwork = identifier(network, "network");
  if (identifier(fields.get("network"), "network") !== expectedNetwork) {
    throw invalidPolicy("network");
  }
  const revision = positiveInteger(fields.get("revision"), "revision");
  const expiresAt = positiveInteger(fields.get("expires_at"), "expires_at");
  const rawDeployments = policyDecode.list(fields.get("deployments"), "deployments");
  if (rawDeployments.length === 0 || rawDeployments.length > MAX_DEPLOYMENTS) {
    throw invalidPolicy("deployments");
  }
  const deployments = Object.freeze(
    Array.from(rawDeployments, (json): TeeDeployment => {
      const entry = new PolicyFields(json);
      const id = identifier(entry.get("id"), "id");
      const region = identifier(entry.get("region"), "region");
      const policyJson = policyDecode.record(entry.get("policy"), "policy");
      if (Object.hasOwn(policyJson, "deployment")) throw invalidPolicy("policy");
      const policy = teePolicyFromJson(policyJson);
      if (policy.hpkePublicKey === undefined) throw invalidPolicy("hpke_public_key");
      if (policy.measurements.length === 0) throw invalidPolicy("measurements");
      entry.finish();
      return Object.freeze({ id, region, policy });
    }),
  );
  fields.finish();
  const ids = new Set<string>();
  const keys = new Set<string>();
  for (const entry of deployments) {
    const key = entry.policy.hpkePublicKey;
    if (key === undefined || ids.has(entry.id) || keys.has(key)) {
      throw invalidPolicy("deployments");
    }
    ids.add(entry.id);
    keys.add(key);
  }
  return Object.freeze({
    kind: "fleet",
    schemaVersion: 1,
    network: expectedNetwork,
    revision,
    expiresAt,
    deployments,
  });
}

/** Revalidates caller-constructed objects and takes an immutable copy. */
export function checkedProverTeePolicy(policy: ProverTeePolicy): ProverTeePolicy {
  if (typeof policy !== "object" || policy === null || Array.isArray(policy)) {
    throw invalidPolicy("platform");
  }
  if (!("kind" in policy)) return checkedTeePolicy(policy);
  if (policy.kind !== "fleet") throw invalidPolicy("kind");
  if (policy.schemaVersion !== 1) throw invalidPolicy("schema_version");
  policyDecode.list(policy.deployments, "deployments");
  return teeFleetPolicyFromJson(
    {
      schema_version: policy.schemaVersion,
      network: policy.network,
      revision: policy.revision,
      expires_at: policy.expiresAt,
      deployments: Array.from(policy.deployments, (entry) => {
        if (typeof entry !== "object" || entry === null) throw invalidPolicy("deployments");
        return {
          id: entry.id,
          region: entry.region,
          policy: teePolicyJson(checkedTeePolicy(entry.policy)),
        };
      }),
    },
    policy.network,
  );
}

export function checkFleetTime(policy: TeeFleetPolicy, nowSecs: number): void {
  if (!Number.isSafeInteger(nowSecs) || nowSecs < 0 || nowSecs >= policy.expiresAt) {
    throw refused("policy_expired");
  }
}

/** Select by the offered key only as a hint, then verify all evidence against that entry. */
export function verifyFleetAttestation(
  json: unknown,
  fleet: TeeFleetPolicy,
  nonce: Uint8Array,
  nowSecs: number,
  platforms: PlatformTable = PLATFORMS,
): Readonly<{ prover: AttestedProver; policy: TeePolicy }> {
  checkFleetTime(fleet, nowSecs);
  const attestation = evidenceDecode.record(json, "attestation");
  const key = bytesToHex(evidenceBytes(attestation["hpke_public_key"], "hpke_public_key", 32));
  const deployment = fleet.deployments.find((entry) => entry.policy.hpkePublicKey === key);
  if (deployment === undefined) throw refused("recipient_key");
  return Object.freeze({
    prover: verifyAttestation(json, deployment.policy, nonce, nowSecs, platforms),
    policy: deployment.policy,
  });
}

function positiveInteger(value: unknown, path: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    throw invalidPolicy(path);
  }
  return value;
}

export function identifier(value: unknown, path: string): string {
  const text = policyDecode.string(value, path);
  if (!IDENTIFIER.test(text)) throw invalidPolicy(path);
  return text;
}
