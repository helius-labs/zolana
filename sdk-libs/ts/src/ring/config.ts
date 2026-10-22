import { getProgramDerivedAddress, type Address, type ProgramDerivedAddress } from "@solana/kit";

import type { ChainReader } from "../client/ports.js";
import { decodeRingConfig } from "../interface/accounts.js";
import { addressBytes } from "../interface/internal.js";
import {
  ringAuthAddress,
  ringConfigPda,
  ringMemberRegistryPda,
  ringRecordQueuePda,
} from "../interface/pda/index.js";
import { SHIELDED_POOL_PROGRAM_ID } from "../interface/program.js";
import type { RequestContext } from "../interface/types.js";

import {
  decodeRingMemberRegistry,
  decodeRingProgramConfig,
  decodeRingRecordQueue,
  type RingMemberRegistry,
  type RingProgramConfig,
  type RingRecordQueue,
} from "./codecs.js";
import { RingError, type RingErrorCode } from "./error.js";

export const BPF_LOADER_UPGRADEABLE_ID = "BPFLoaderUpgradeab1e11111111111111111111111" as Address;

type AccountReader = Pick<ChainReader, "getAccount">;

/** Mirrors Rust `CustomRing::program_data_pda`. */
export async function ringProgramDataAddress(ringProgramId: Address): Promise<Address> {
  const [address] = await getProgramDerivedAddress({
    programAddress: BPF_LOADER_UPGRADEABLE_ID,
    seeds: [addressBytes(ringProgramId, "ringProgramId")],
  });
  return address;
}

/** Mirrors Rust `CustomRing::require_config`. */
export function fetchRingProgramConfig(
  client: AccountReader,
  ringProgramId: Address,
  context?: RequestContext,
): Promise<RingProgramConfig> {
  return readRingAccount(client, ringProgramId, context, {
    pda: ringConfigPda,
    decode: decodeRingProgramConfig,
    missing: "RING_CONFIG_NOT_FOUND",
    invalid: "RING_CONFIG_INVALID",
  });
}

/** Mirrors Rust `CustomRing::require_registry`. */
export function fetchRingMemberRegistry(
  client: AccountReader,
  ringProgramId: Address,
  context?: RequestContext,
): Promise<RingMemberRegistry> {
  return readRingAccount(client, ringProgramId, context, {
    pda: ringMemberRegistryPda,
    decode: decodeRingMemberRegistry,
    missing: "RING_MEMBER_REGISTRY_MISSING",
    invalid: "RING_MEMBER_REGISTRY_INVALID",
  });
}

/** Mirrors Rust `CustomRing::require_queue`. */
export function fetchRingRecordQueue(
  client: AccountReader,
  ringProgramId: Address,
  context?: RequestContext,
): Promise<RingRecordQueue> {
  return readRingAccount(client, ringProgramId, context, {
    pda: ringRecordQueuePda,
    decode: decodeRingRecordQueue,
    missing: "RING_RECORD_QUEUE_MISSING",
    invalid: "RING_RECORD_QUEUE_INVALID",
  });
}

/** A curator's registry named by account, the canonical registry of the program owning it. */
export async function fetchCuratorRegistry(
  client: AccountReader,
  registry: Address,
  context?: RequestContext,
): Promise<Readonly<{ ringProgramId: Address; registry: RingMemberRegistry }>> {
  const account = await client.getAccount(registry, context);
  if (account === undefined)
    throw new RingError("RING_MEMBER_REGISTRY_MISSING", {
      details: { registry },
    });
  const [expected, bump] = await ringMemberRegistryPda(account.owner);
  const decoded = decodeRingMemberRegistry(account.data);
  if (registry !== expected || decoded.bump !== bump)
    throw new RingError("RING_MEMBER_REGISTRY_INVALID", {
      details: { registry },
    });
  return Object.freeze({ ringProgramId: account.owner, registry: decoded });
}

/** Rust `CustomRing::require_active`, every SPP call through the ring refuses one unregistered, inactive or paused. */
export async function requireActiveRing(
  client: AccountReader,
  ringProgramId: Address,
  context?: RequestContext,
): Promise<void> {
  const address = await ringAuthAddress(ringProgramId);
  const account = await client.getAccount(address, context);
  if (account === undefined)
    throw new RingError("RING_NOT_REGISTERED", { details: { ringProgramId } });
  if (account.owner !== SHIELDED_POOL_PROGRAM_ID)
    throw new RingError("RING_CONFIG_INVALID", { details: { ringProgramId, address } });
  let registration;
  try {
    registration = decodeRingConfig(account.data);
  } catch (cause) {
    throw new RingError("RING_CONFIG_INVALID", { details: { ringProgramId, address }, cause });
  }
  if (registration.programId !== ringProgramId)
    throw new RingError("RING_CONFIG_INVALID", { details: { ringProgramId, address } });
  if (!registration.activated)
    throw new RingError("RING_NOT_ACTIVATED", { details: { ringProgramId } });
  if (registration.paused) throw new RingError("RING_PAUSED", { details: { ringProgramId } });
}

/** Mirrors Rust `CustomRing::read`, a foreign owner or a non-canonical bump is invalid. */
async function readRingAccount<A extends Readonly<{ bump: number }>>(
  client: AccountReader,
  ringProgramId: Address,
  context: RequestContext | undefined,
  account: Readonly<{
    pda: (ringProgramId: Address) => Promise<ProgramDerivedAddress>;
    decode: (data: Uint8Array) => A;
    missing: RingErrorCode;
    invalid: RingErrorCode;
  }>,
): Promise<A> {
  const [address, bump] = await account.pda(ringProgramId);
  const stored = await client.getAccount(address, context);
  if (stored === undefined)
    throw new RingError(account.missing, {
      details: { ringProgramId, address },
    });
  if (stored.owner !== ringProgramId)
    throw new RingError(account.invalid, {
      details: { ringProgramId, owner: stored.owner },
    });
  const decoded = account.decode(stored.data);
  if (decoded.bump !== bump)
    throw new RingError(account.invalid, {
      details: { ringProgramId, address },
    });
  return decoded;
}
