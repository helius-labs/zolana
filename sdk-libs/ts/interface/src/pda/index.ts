import {
  ASSOCIATED_TOKEN_PROGRAM_ID,
  SHIELDED_POOL_CPI_AUTHORITY,
  SHIELDED_POOL_PROGRAM_ID,
  SOL_INTERFACE,
  SPL_TOKEN_PROGRAM_ID,
  type Address,
} from "../index.js";
import { addressBytes, checkedAddress, findProgramAddress, isEd25519Point } from "../internal.js";

export { findProgramAddress, isEd25519Point };

const encoder = new TextEncoder();

function derive(seed: string, address?: Address): Address {
  const seeds: Uint8Array[] = [encoder.encode(seed)];
  if (address !== undefined) seeds.push(addressBytes(address));
  return findProgramAddress(seeds, SHIELDED_POOL_PROGRAM_ID)[0];
}

export function protocolConfigAddress(): Address {
  return derive("protocol_config");
}

export function solInterfaceAddress(): Address {
  const derived = findProgramAddress(
    [encoder.encode("sol_interface"), Uint8Array.of(0)],
    SHIELDED_POOL_PROGRAM_ID,
  )[0];
  if (derived !== SOL_INTERFACE) {
    throw new Error("SOL interface constant does not match its canonical PDA");
  }
  return derived;
}

export function shieldedPoolCpiAuthorityAddress(): Address {
  const derived = derive("cpi_authority");
  if (derived !== SHIELDED_POOL_CPI_AUTHORITY) {
    throw new Error("CPI authority constant does not match its canonical PDA");
  }
  return derived;
}

export function splAssetCounterAddress(): Address {
  return derive("spl_asset_counter");
}

export function splAssetRegistryAddress(mint: Address): Address {
  return derive("spl_asset_registry", checkedAddress(mint, "mint"));
}

export function splAssetVaultAddress(mint: Address): Address {
  return derive("spl_asset_vault", checkedAddress(mint, "mint"));
}

export function zoneConfigAddress(zoneProgram: Address): readonly [Address, number] {
  return findProgramAddress(
    [encoder.encode("spp_zone_config"), addressBytes(zoneProgram, "zoneProgram")],
    SHIELDED_POOL_PROGRAM_ID,
  );
}

export function zoneAuthAddress(zoneProgram: Address): readonly [Address, number] {
  return findProgramAddress([encoder.encode("zone_auth")], checkedAddress(zoneProgram, "zoneProgram"));
}

export function associatedTokenAddress(owner: Address, mint: Address): Address {
  return findProgramAddress(
    [addressBytes(owner, "owner"), addressBytes(SPL_TOKEN_PROGRAM_ID), addressBytes(mint, "mint")],
    ASSOCIATED_TOKEN_PROGRAM_ID,
  )[0];
}
