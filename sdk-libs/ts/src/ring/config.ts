import { getProgramDerivedAddress, type Address, type Instruction } from "@solana/kit";

import type { ChainReader } from "../client/ports.js";
import { SYSTEM_PROGRAM, meta, type SignerAccount } from "../interface/instructions/index.js";
import { Writer, addressBytes } from "../interface/internal.js";
import {
  ringAuthAddress,
  ringCoSignerAddress,
  ringCoSignerPda,
  ringConfigAddress,
  ringConfigPda,
  ringDelegateAddress,
  ringDelegatePda,
  ringDepositAuditAddress,
  ringDepositAuditPda,
  ringKeyRegistryRootPda,
  ringPolicyConfigPda,
  ringSpendWindowAddress,
  ringSpendWindowPda,
} from "../interface/pda/index.js";
import { SHIELDED_POOL_PROGRAM_ID } from "../interface/program.js";
import type { RequestContext } from "../interface/types.js";
import { isDerivationPoint } from "../keypair/derivation.js";

import {
  checkRingCoSignerConfig,
  type RingCoSigner,
  type RingDelegate,
  type RingPolicyConfig,
  type RingProgramConfig,
  type RingSpendWindow,
  decodeRingCoSigner,
  decodeRingDelegate,
  decodeRingDepositAudit,
  decodeRingPolicyConfig,
  decodeRingProgramConfig,
  decodeRingSpendWindow,
  decodeRingKeyRegistryRoot,
  type RingKeyRegistryRoot,
} from "./codecs.js";
import { RingError } from "./error.js";

const encoder = new TextEncoder();
export const BPF_LOADER_UPGRADEABLE_ID = "BPFLoaderUpgradeab1e11111111111111111111111" as Address;
const SET_AUTHORITY_TAG = 6;
const SET_PAUSED_TAG = 11;
const SET_CO_SIGNER_TAG = 28;
const CLEAR_CO_SIGNER_TAG = 21;
const SET_SPEND_WINDOW_TAG = 22;
const CLEAR_SPEND_WINDOW_TAG = 23;
const SET_DELEGATE_TAG = 24;
const CREATE_KEY_REGISTRY_ROOT_TAG = 29;
const SET_DEPOSIT_AUDIT_TAG = 31;

export async function fetchRingDepositAudit(
  client: Pick<ChainReader, "getAccount">,
  ringProgramId: Address,
  context?: RequestContext,
): Promise<boolean> {
  const [address, bump] = await ringDepositAuditPda(ringProgramId);
  const account = await client.getAccount(address, context);
  if (account === undefined || (account.owner === SYSTEM_PROGRAM && account.data.length === 0))
    return false;
  if (account.owner !== ringProgramId) throw new RingError("RING_DEPOSIT_AUDIT_INVALID");
  const setting = decodeRingDepositAudit(account.data);
  if (setting.bump !== bump) throw new RingError("RING_DEPOSIT_AUDIT_INVALID");
  return setting.required;
}

export async function setRingDepositAuditInstruction(
  input: Readonly<{
    ringProgramId: Address;
    payer: SignerAccount;
    authority: SignerAccount;
    required: boolean;
  }>,
): Promise<Instruction> {
  if (typeof input.required !== "boolean") throw new RingError("RING_DEPOSIT_AUDIT_INVALID");
  const [config, setting] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    ringDepositAuditAddress(input.ringProgramId),
  ]);
  return {
    programAddress: input.ringProgramId,
    accounts: [
      meta(input.payer, true, true),
      meta(input.authority, true, false),
      meta(config, false, false),
      meta(setting, false, true),
      meta(SYSTEM_PROGRAM, false, false),
    ],
    data: Uint8Array.of(SET_DEPOSIT_AUDIT_TAG, Number(input.required)),
  };
}

/** The stored bump must be canonical. */
export async function fetchRingKeyRegistryRoot(
  client: Pick<ChainReader, "getAccount">,
  ringProgramId: Address,
  context?: RequestContext,
): Promise<RingKeyRegistryRoot> {
  const [address, bump] = await ringKeyRegistryRootPda(ringProgramId);
  const account = await client.getAccount(address, context);
  if (account === undefined) throw new RingError("RING_KEY_REGISTRY_MISSING");
  if (account.owner !== ringProgramId) throw new RingError("RING_KEY_REGISTRY_INVALID");
  const root = decodeRingKeyRegistryRoot(account.data);
  if (root.bump !== bump) throw new RingError("RING_KEY_REGISTRY_INVALID");
  return root;
}

export async function createRingKeyRegistryRootInstruction(
  input: Readonly<{ ringProgramId: Address; payer: SignerAccount; authority: SignerAccount }>,
): Promise<Instruction> {
  const [config, [root]] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    ringKeyRegistryRootPda(input.ringProgramId),
  ]);
  return {
    programAddress: input.ringProgramId,
    accounts: [
      meta(input.payer, true, true),
      meta(input.authority, true, false),
      meta(config, false, false),
      meta(root, false, true),
      meta(SYSTEM_PROGRAM, false, false),
    ],
    data: Uint8Array.of(CREATE_KEY_REGISTRY_ROOT_TAG),
  };
}

/** Mirrors Rust `CustomRing::namespace_pda`, the shielded owner of every policy entry. */
export async function ringPolicyNamespaceAddress(ringProgramId: Address): Promise<Address> {
  const [address] = await getProgramDerivedAddress({
    programAddress: ringProgramId,
    seeds: [encoder.encode("policy_records")],
  });
  return address;
}

/** Mirrors Rust `CustomRing::program_data_pda`. */
export async function ringProgramDataAddress(ringProgramId: Address): Promise<Address> {
  const [address] = await getProgramDerivedAddress({
    programAddress: BPF_LOADER_UPGRADEABLE_ID,
    seeds: [addressBytes(ringProgramId, "ringProgramId")],
  });
  return address;
}

/** Mirrors Rust `CustomRing::read_config`, a non-canonical bump or a reserved auditor key is invalid. */
export async function fetchRingProgramConfig(
  client: Pick<ChainReader, "getAccount">,
  ringProgramId: Address,
  context?: RequestContext,
): Promise<RingProgramConfig> {
  const [address, bump] = await ringConfigPda(ringProgramId);
  const account = await client.getAccount(address, context);
  if (account === undefined) {
    throw new RingError("RING_CONFIG_NOT_FOUND", { details: { ringProgramId, address } });
  }
  if (account.owner !== ringProgramId) {
    throw new RingError("RING_CONFIG_INVALID", {
      details: { ringProgramId, owner: account.owner },
    });
  }
  const config = decodeRingProgramConfig(account.data);
  if (config.bump !== bump || isDerivationPoint(config.auditorPublicKey)) {
    throw new RingError("RING_CONFIG_INVALID", { details: { ringProgramId, address } });
  }
  return config;
}

/** Mirrors Rust `CustomRing::read_policy_config`, a non-canonical bump is invalid. */
export async function fetchRingPolicyConfig(
  client: Pick<ChainReader, "getAccount">,
  ringProgramId: Address,
  context?: RequestContext,
): Promise<RingPolicyConfig> {
  const [address, bump] = await ringPolicyConfigPda(ringProgramId);
  const account = await client.getAccount(address, context);
  if (account === undefined) {
    throw new RingError("RING_POLICY_CONFIG_NOT_FOUND", { details: { ringProgramId, address } });
  }
  if (account.owner !== ringProgramId) {
    throw new RingError("RING_POLICY_CONFIG_INVALID", {
      details: { ringProgramId, owner: account.owner },
    });
  }
  const config = decodeRingPolicyConfig(account.data);
  if (config.bump !== bump) {
    throw new RingError("RING_POLICY_CONFIG_INVALID", { details: { ringProgramId, address } });
  }
  return config;
}

export type RingConfigs =
  | Readonly<{ hasPolicy: false; config: RingProgramConfig }>
  | Readonly<{ hasPolicy: true; config: RingProgramConfig; policy: RingPolicyConfig }>;

export async function fetchRingConfigs(
  client: Pick<ChainReader, "getAccount">,
  ringProgramId: Address,
  context?: RequestContext,
): Promise<RingConfigs> {
  const config = await fetchRingProgramConfig(client, ringProgramId, context);
  if (!config.hasPolicy) return Object.freeze({ hasPolicy: false, config });
  const policy = await fetchRingPolicyConfig(client, ringProgramId, context);
  return Object.freeze({ hasPolicy: true, config, policy });
}

/** The policy of a ring that keeps per-member spend records, else `undefined`. */
export function windowedPolicy(configs: RingConfigs): RingPolicyConfig | undefined {
  return configs.hasPolicy &&
    configs.policy.windowSlots !== 0n &&
    configs.policy.velocityCount !== 0
    ? configs.policy
    : undefined;
}

export async function fetchRingCoSigner(
  client: Pick<ChainReader, "getAccount">,
  ringProgramId: Address,
  context?: RequestContext,
): Promise<RingCoSigner | undefined> {
  const address = await ringCoSignerAddress(ringProgramId);
  const account = await client.getAccount(address, context);
  if (account === undefined || account.data.length === 0) return undefined;
  if (account.owner !== ringProgramId) {
    throw new RingError("RING_CO_SIGNER_INVALID", {
      details: { ringProgramId, owner: account.owner },
    });
  }
  const [, bump] = await ringCoSignerPda(ringProgramId);
  const cosigner = decodeRingCoSigner(account.data);
  if (cosigner.bump !== bump) {
    throw new RingError("RING_CO_SIGNER_INVALID", { details: { ringProgramId, address } });
  }
  return cosigner;
}

export async function setRingCoSignerInstruction(
  input: Readonly<{
    ringProgramId: Address;
    payer: SignerAccount;
    authority: SignerAccount;
    signer: Address;
    /** A nonzero subset of the `RING_COSIGN_*` bits. */
    scope: number;
    thresholds?: readonly { readonly mint: Address; readonly above: bigint }[];
  }>,
): Promise<Instruction> {
  const thresholds = input.thresholds ?? [];
  checkRingCoSignerConfig({ signer: input.signer, scope: input.scope, thresholds });
  const [config, cosigner] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    ringCoSignerAddress(input.ringProgramId),
  ]);
  const writer = new Writer()
    .u8(SET_CO_SIGNER_TAG, "tag")
    .bytes(addressBytes(input.signer, "signer"), 32, "signer")
    .u8(input.scope, "scope")
    .u8(thresholds.length, "thresholdCount");
  for (const row of thresholds) {
    writer.bytes(addressBytes(row.mint, "mint"), 32, "mint").u64(row.above, "above");
  }
  return {
    programAddress: input.ringProgramId,
    accounts: [
      meta(input.payer, true, true),
      meta(input.authority, true, false),
      meta(config, false, false),
      meta(cosigner, false, true),
      meta(SYSTEM_PROGRAM, false, false),
    ],
    data: writer.finish(),
  };
}

export async function clearRingCoSignerInstruction(
  input: Readonly<{
    ringProgramId: Address;
    authority: SignerAccount;
    rentRecipient: Address;
  }>,
): Promise<Instruction> {
  const [config, cosigner] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    ringCoSignerAddress(input.ringProgramId),
  ]);
  return {
    programAddress: input.ringProgramId,
    accounts: [
      meta(input.authority, true, false),
      meta(config, false, false),
      meta(cosigner, false, true),
      meta(input.rentRecipient, false, true),
    ],
    data: Uint8Array.of(CLEAR_CO_SIGNER_TAG),
  };
}

export async function fetchRingDelegate(
  client: Pick<ChainReader, "getAccount">,
  ringProgramId: Address,
  context?: RequestContext,
): Promise<RingDelegate | undefined> {
  const [address, bump] = await ringDelegatePda(ringProgramId);
  const account = await client.getAccount(address, context);
  if (account === undefined || account.data.length === 0) return undefined;
  if (account.owner !== ringProgramId) {
    throw new RingError("RING_DELEGATE_INVALID", {
      details: { ringProgramId, owner: account.owner },
    });
  }
  const delegate = decodeRingDelegate(account.data);
  if (delegate.bump !== bump) {
    throw new RingError("RING_DELEGATE_INVALID", { details: { ringProgramId, address } });
  }
  return delegate;
}

/** No instruction replaces the delegate. */
export async function setRingDelegateInstruction(
  input: Readonly<{
    ringProgramId: Address;
    payer: SignerAccount;
    authority: SignerAccount;
    delegate: Address;
  }>,
): Promise<Instruction> {
  const [delegatePda, programData] = await Promise.all([
    ringDelegateAddress(input.ringProgramId),
    ringProgramDataAddress(input.ringProgramId),
  ]);
  return {
    programAddress: input.ringProgramId,
    accounts: [
      meta(input.payer, true, true),
      meta(input.authority, true, false),
      meta(delegatePda, false, true),
      meta(SYSTEM_PROGRAM, false, false),
      meta(input.ringProgramId, false, false),
      meta(programData, false, false),
    ],
    data: new Writer()
      .u8(SET_DELEGATE_TAG, "tag")
      .bytes(addressBytes(input.delegate, "delegate"), 32, "delegate")
      .finish(),
  };
}

export async function fetchRingSpendWindow(
  client: Pick<ChainReader, "getAccount">,
  ringProgramId: Address,
  mint: Address,
  context?: RequestContext,
): Promise<RingSpendWindow | undefined> {
  const [address, bump] = await ringSpendWindowPda(ringProgramId, mint);
  const account = await client.getAccount(address, context);
  if (account === undefined || account.data.length === 0) return undefined;
  if (account.owner !== ringProgramId) {
    throw new RingError("RING_SPEND_WINDOW_INVALID", {
      details: { ringProgramId, owner: account.owner },
    });
  }
  const window = decodeRingSpendWindow(account.data);
  if (window.mint !== mint || window.bump !== bump) {
    throw new RingError("RING_SPEND_WINDOW_INVALID", { details: { ringProgramId, address } });
  }
  return window;
}

/** Replacing a window resets its counters. */
export async function setRingSpendWindowInstruction(
  input: Readonly<{
    ringProgramId: Address;
    payer: SignerAccount;
    authority: SignerAccount;
    mint: Address;
    /** Nonzero, windows start at multiples of it. */
    windowSlots: bigint;
    /** Zero leaves the direction uncapped. */
    depositCap?: bigint;
    withdrawalCap?: bigint;
  }>,
): Promise<Instruction> {
  if (input.windowSlots === 0n) {
    throw new RingError("RING_SPEND_WINDOW_INVALID", { details: { mint: input.mint } });
  }
  const [config, window] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    ringSpendWindowAddress(input.ringProgramId, input.mint),
  ]);
  const data = new Writer()
    .u8(SET_SPEND_WINDOW_TAG, "tag")
    .bytes(addressBytes(input.mint, "mint"), 32, "mint")
    .u64(input.windowSlots, "windowSlots")
    .u64(input.depositCap ?? 0n, "depositCap")
    .u64(input.withdrawalCap ?? 0n, "withdrawalCap")
    .finish();
  return {
    programAddress: input.ringProgramId,
    accounts: [
      meta(input.payer, true, true),
      meta(input.authority, true, false),
      meta(config, false, false),
      meta(window, false, true),
      meta(SYSTEM_PROGRAM, false, false),
    ],
    data,
  };
}

export async function clearRingSpendWindowInstruction(
  input: Readonly<{
    ringProgramId: Address;
    authority: SignerAccount;
    mint: Address;
    rentRecipient: Address;
  }>,
): Promise<Instruction> {
  const [config, window] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    ringSpendWindowAddress(input.ringProgramId, input.mint),
  ]);
  return {
    programAddress: input.ringProgramId,
    accounts: [
      meta(input.authority, true, false),
      meta(config, false, false),
      meta(window, false, true),
      meta(input.rentRecipient, false, true),
    ],
    data: new Writer()
      .u8(CLEAR_SPEND_WINDOW_TAG, "tag")
      .bytes(addressBytes(input.mint, "mint"), 32, "mint")
      .finish(),
  };
}

/** Mirrors Rust `SetAuthority`. Both authorities sign, a mistyped address cannot strand the config. */
export async function setRingAuthorityInstruction(
  input: Readonly<{
    ringProgramId: Address;
    authority: SignerAccount;
    newAuthority: SignerAccount;
  }>,
): Promise<Instruction> {
  const config = await ringConfigAddress(input.ringProgramId);
  return {
    programAddress: input.ringProgramId,
    accounts: [
      meta(input.authority, true, false),
      meta(input.newAuthority, true, false),
      meta(config, false, true),
    ],
    data: new Uint8Array([SET_AUTHORITY_TAG]),
  };
}

/** Mirrors Rust `SetPaused`. */
export async function setRingPausedInstruction(
  input: Readonly<{
    ringProgramId: Address;
    authority: SignerAccount;
    paused: boolean;
  }>,
): Promise<Instruction> {
  const [config, ringAuth] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    ringAuthAddress(input.ringProgramId),
  ]);
  return {
    programAddress: input.ringProgramId,
    accounts: [
      meta(input.authority, true, false),
      meta(config, false, false),
      meta(ringAuth, false, true),
      meta(SHIELDED_POOL_PROGRAM_ID, false, false),
    ],
    data: Uint8Array.of(SET_PAUSED_TAG, input.paused ? 1 : 0),
  };
}
