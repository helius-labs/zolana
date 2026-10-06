import { hexToBytes } from "@noble/hashes/utils.js";

import { wireDecoder } from "../../../interface/decode.js";
import { ClientError } from "../../error.js";

export type GpuRequirement = "optional" | "required";

export type PolicyCommon = Readonly<{ gpu: GpuRequirement; maxAgeSecs: number }>;

export type AttestationClaims = Readonly<{
  nonce: Uint8Array;
  hpkePublicKey: Uint8Array;
  nowSecs: number;
}>;

export type PlatformVerdict = Readonly<{
  reportData: Uint8Array;
  imageId: Uint8Array;
  tcbStatus?: string;
}>;

export type PlatformModule<Policy extends Readonly<{ platform: string }>> = Readonly<{
  platform: Policy["platform"];
  /** False refuses a GPU requirement and any GPU verdict. */
  hostsGpu: boolean;
  keyPerBoot: boolean;
  /** DER roots, empty when the verifier library pins its own. */
  anchors: readonly Uint8Array[];
  policy: (fields: PolicyFields, common: PolicyCommon) => Policy;
  pinsJson: (policy: Policy) => Readonly<Record<string, unknown>>;
  verify: (
    evidence: unknown,
    policy: Policy,
    claims: AttestationClaims,
    anchors: readonly Uint8Array[],
  ) => PlatformVerdict;
}>;

/** Refuses a field no reader asked for. */
export class PolicyFields {
  readonly #record: Readonly<Record<string, unknown>>;
  readonly #read = new Set<string>();

  constructor(json: unknown) {
    this.#record = policyDecode.record(json, "tee");
  }

  get(name: string): unknown {
    this.#read.add(name);
    return Object.hasOwn(this.#record, name) ? this.#record[name] : undefined;
  }

  hex(name: string, bytes?: number): string {
    return policyHex(this.get(name), name, bytes);
  }

  hexList(name: string, bytes: number): readonly string[] {
    return Object.freeze(
      policyDecode.list(this.get(name), name).map((hex) => policyHex(hex, name, bytes)),
    );
  }

  strings(name: string): readonly string[] {
    return Object.freeze(
      policyDecode.list(this.get(name), name).map((text) => policyDecode.string(text, name)),
    );
  }

  records<T>(name: string, decode: (fields: PolicyFields) => T): readonly T[] {
    return Object.freeze(
      policyDecode.list(this.get(name), name).map((entry) => {
        const fields = new PolicyFields(entry);
        const decoded = decode(fields);
        fields.finish();
        return decoded;
      }),
    );
  }

  finish(): void {
    const unread = Object.keys(this.#record).find((key) => !this.#read.has(key));
    if (unread !== undefined) throw invalidPolicy(unread);
  }
}

export const invalidPolicy = (path: string): ClientError =>
  new ClientError("CLIENT_INVALID_CONFIG", { details: { field: `tee.${path}` } });
export const policyDecode = wireDecoder(invalidPolicy);

export const refused = (check: string): ClientError =>
  new ClientError("CLIENT_PROVER_TEE_ATTESTATION", { details: { check } });
export const evidenceDecode = wireDecoder(() => refused("malformed_attestation"));

/** Accepts either hex case. */
export function evidenceBytes(value: unknown, path: string, length?: number): Uint8Array {
  const hex = evidenceDecode.string(value, path);
  if (!/^(?:[0-9a-fA-F]{2})*$/u.test(hex)) throw refused("malformed_attestation");
  const bytes = hexToBytes(hex);
  if (length !== undefined && bytes.length !== length) throw refused("malformed_attestation");
  return bytes;
}

/** Lowercase hex, of exactly `bytes` bytes when given. */
function policyHex(value: unknown, path: string, bytes?: number): string {
  const hex = policyDecode.string(value, path);
  if (!/^(?:[0-9a-f]{2})*$/u.test(hex)) throw invalidPolicy(path);
  if (bytes !== undefined && hex.length !== bytes * 2) throw invalidPolicy(path);
  return hex;
}
