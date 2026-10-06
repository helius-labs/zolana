import { DSTACK_TDX, type DstackTdxPolicy } from "./dstack.js";
import { AWS_NITRO, type AwsNitroPolicy } from "./nitro.js";
import type { PlatformModule } from "./platform.js";

export type { DstackTdxPolicy, TdxMeasurement } from "./dstack.js";
export type { AwsNitroPolicy, NitroMeasurement } from "./nitro.js";

/** What a prover must prove before it sees a request. */
export type TeePolicy = DstackTdxPolicy | AwsNitroPolicy;

export type TeePlatform = TeePolicy["platform"];

export type PolicyFor<K extends TeePlatform> = Extract<TeePolicy, Readonly<{ platform: K }>>;

export type PlatformTable = { readonly [K in TeePlatform]: PlatformModule<PolicyFor<K>> };

export const PLATFORMS: PlatformTable = Object.freeze({
  "dstack-tdx": DSTACK_TDX,
  "aws-nitro": AWS_NITRO,
});

export function isTeePlatform(name: string): name is TeePlatform {
  return Object.hasOwn(PLATFORMS, name);
}
