import { ClientError } from "../../error.js";
import { DEFAULT_TEE_POLICY_FILE } from "./default.js";
import { MAINNET_TEE_POLICY_FILE } from "./mainnet.js";
import { isMainnetTeeProver } from "../../../endpoint.js";
import { PolicyFields, invalidPolicy } from "./platform.js";
import {
  PLATFORMS,
  isTeePlatform,
  type PolicyFor,
  type TeePlatform,
  type TeePolicy,
} from "./registry.js";

export type { GpuRequirement } from "./platform.js";

/** Mainnet pins for its exact prover endpoint; devnet pins when omitted or for another URL. */
export function defaultTeePolicy(proverUrl?: URL): TeePolicy {
  const deployment =
    proverUrl !== undefined && isMainnetTeeProver(proverUrl)
      ? MAINNET_TEE_POLICY_FILE.deployment
      : DEFAULT_TEE_POLICY_FILE.deployment;
  if (deployment === null) {
    throw new ClientError("CLIENT_PROVER_TEE_ATTESTATION", {
      details: { check: "no_default_deployment" },
    });
  }
  return teePolicyFromJson(deployment);
}

/** Parses the snake_case JSON form the Rust SDK and the release script share. */
export function teePolicyFromJson(json: unknown): TeePolicy {
  const fields = new PolicyFields(json);
  const gpu = fields.get("gpu");
  if (gpu !== "optional" && gpu !== "required") throw invalidPolicy("gpu");
  const maxAgeSecs = fields.get("max_age_secs");
  if (typeof maxAgeSecs !== "number" || !Number.isSafeInteger(maxAgeSecs) || maxAgeSecs <= 0) {
    throw invalidPolicy("max_age_secs");
  }
  const platform = fields.get("platform");
  if (typeof platform !== "string" || !isTeePlatform(platform)) throw invalidPolicy("platform");
  const module = PLATFORMS[platform];
  if (gpu === "required" && !module.hostsGpu) throw invalidPolicy("gpu");
  const policy = module.policy(fields, { gpu, maxAgeSecs });
  fields.finish();
  return Object.freeze(policy);
}

/** Revalidates a caller-built policy that skipped {@link teePolicyFromJson}. */
export function checkedTeePolicy(policy: TeePolicy): TeePolicy {
  if (!isTeePlatform(policy.platform)) throw invalidPolicy("platform");
  return teePolicyFromJson({
    platform: policy.platform,
    ...pinsJson(policy.platform, policy),
    gpu: policy.gpu,
    max_age_secs: policy.maxAgeSecs,
  });
}

function pinsJson<K extends TeePlatform>(
  platform: K,
  policy: PolicyFor<K>,
): Readonly<Record<string, unknown>> {
  return PLATFORMS[platform].pinsJson(policy);
}
