import {
  getProgramDerivedAddress,
  type Address,
  type Instruction,
  type ProgramDerivedAddress,
} from "@solana/kit";

import type { ZolanaClient } from "../client/client.js";
import { meta, type SignerAccount } from "../interface/instructions/index.js";
import { addressBytes } from "../interface/internal.js";
import type { RequestContext } from "../interface/types.js";
import { isDerivationPoint } from "../keypair/derivation.js";

import {
  type RingPolicyConfig,
  type RingProgramConfig,
  decodeRingPolicyConfig,
  decodeRingProgramConfig,
} from "./codecs.js";
import { RingError } from "./error.js";

const encoder = new TextEncoder();
const BPF_LOADER_UPGRADEABLE_ID = "BPFLoaderUpgradeab1e11111111111111111111111" as Address;
const SET_AUTHORITY_TAG = 6;

export async function ringConfigAddress(ringProgramId: Address): Promise<Address> {
  return (await ringConfigPda(ringProgramId))[0];
}

function ringConfigPda(ringProgramId: Address): Promise<ProgramDerivedAddress> {
  return getProgramDerivedAddress({
    programAddress: ringProgramId,
    seeds: [encoder.encode("config")],
  });
}

/** Mirrors Rust `CustomRing::policy_config_pda`. */
export async function ringPolicyConfigAddress(ringProgramId: Address): Promise<Address> {
  return (await ringPolicyConfigPda(ringProgramId))[0];
}

function ringPolicyConfigPda(ringProgramId: Address): Promise<ProgramDerivedAddress> {
  return getProgramDerivedAddress({
    programAddress: ringProgramId,
    seeds: [encoder.encode("policy")],
  });
}

/** Mirrors Rust `CustomRing::records_pda`, the shielded owner of every policy record. */
export async function ringPolicyRecordsAddress(ringProgramId: Address): Promise<Address> {
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
  client: ZolanaClient,
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
  client: ZolanaClient,
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
