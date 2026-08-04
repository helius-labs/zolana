import { findAssociatedTokenPda } from "@solana-program/token";
import {
  getAddressEncoder,
  getProgramDerivedAddress,
  type Address,
  type ProgramDerivedAddress,
} from "@solana/kit";

import {
  SHIELDED_POOL_CPI_AUTHORITY,
  SHIELDED_POOL_PROGRAM_ID,
  SOL_INTERFACE,
  SPL_TOKEN_PROGRAM_ID,
} from "../program.js";

const encoder = new TextEncoder();
const addressEncoder = getAddressEncoder();

function derive(seed: string, address?: Address): Promise<ProgramDerivedAddress> {
  return getProgramDerivedAddress({
    programAddress: SHIELDED_POOL_PROGRAM_ID,
    seeds: [
      encoder.encode(seed),
      ...(address === undefined ? [] : [addressEncoder.encode(address)]),
    ],
  });
}

export async function protocolConfigAddress(): Promise<Address> {
  return (await derive("protocol_config"))[0];
}

export function solInterfaceAddress(): Address {
  return SOL_INTERFACE;
}

export function shieldedPoolCpiAuthorityAddress(): Address {
  return SHIELDED_POOL_CPI_AUTHORITY;
}

export async function splAssetCounterAddress(): Promise<Address> {
  return (await derive("spl_asset_counter"))[0];
}

export async function splAssetRegistryAddress(mint: Address): Promise<Address> {
  return (await derive("spl_asset_registry", mint))[0];
}

/**
 * Named for Rust's `pda::spl_interface_with_bump`. The seed stays
 * `spl_asset_vault`, which is the seed Rust pins too.
 */
export function splInterfaceWithBump(mint: Address): Promise<ProgramDerivedAddress> {
  return derive("spl_asset_vault", mint);
}

export async function splAssetVaultAddress(mint: Address): Promise<Address> {
  return (await splInterfaceWithBump(mint))[0];
}

/** Canonical bump of the per-mint SPL interface PDA. Rust: `pda::spl_interface_bump`. */
export async function splInterfaceBump(mint: Address): Promise<number> {
  return (await splInterfaceWithBump(mint))[1];
}

export async function zoneConfigAddress(zoneProgram: Address): Promise<Address> {
  return (
    await getProgramDerivedAddress({
      programAddress: zoneProgram,
      seeds: [encoder.encode("zone_auth")],
    })
  )[0];
}

export async function associatedTokenAddress(
  owner: Address,
  mint: Address,
  tokenProgram?: Address | null,
): Promise<Address> {
  return (
    await findAssociatedTokenPda({
      owner,
      mint,
      tokenProgram: tokenProgram ?? SPL_TOKEN_PROGRAM_ID,
    })
  )[0];
}
