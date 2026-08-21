import { getProgramDerivedAddress, type Address, type ProgramDerivedAddress } from "@solana/kit";

import type { ZolanaClient } from "../client/client.js";
import { addressBytes } from "../interface/internal.js";
import type { RequestContext } from "../interface/types.js";
import { isDerivationPoint } from "../keypair/derivation.js";

import { type RingProgramConfig, decodeRingProgramConfig } from "./codecs.js";
import { RingError } from "./error.js";

const encoder = new TextEncoder();
const BPF_LOADER_UPGRADEABLE_ID = "BPFLoaderUpgradeab1e11111111111111111111111" as Address;

export async function ringConfigAddress(ringProgramId: Address): Promise<Address> {
  return (await ringConfigPda(ringProgramId))[0];
}

function ringConfigPda(ringProgramId: Address): Promise<ProgramDerivedAddress> {
  return getProgramDerivedAddress({
    programAddress: ringProgramId,
    seeds: [encoder.encode("config")],
  });
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
