import { PublicKey } from "@solana/web3.js";
import {
  ASSOCIATED_TOKEN_PROGRAM_ID,
  SHIELDED_POOL_CPI_AUTHORITY,
  SHIELDED_POOL_PROGRAM_ID,
  SOL_INTERFACE,
  SPL_TOKEN_PROGRAM_ID,
} from "./constants.js";

const seed = (value: string) => new TextEncoder().encode(value);

export function shieldedPoolProgramId(): PublicKey {
  return SHIELDED_POOL_PROGRAM_ID;
}

export function shieldedPoolCpiAuthority(): PublicKey {
  return SHIELDED_POOL_CPI_AUTHORITY;
}

export function protocolConfig(): PublicKey {
  return PublicKey.findProgramAddressSync([seed("protocol_config")], SHIELDED_POOL_PROGRAM_ID)[0];
}

export function solInterface(): PublicKey {
  return SOL_INTERFACE;
}

export function splAssetCounter(): PublicKey {
  return PublicKey.findProgramAddressSync([seed("spl_asset_counter")], SHIELDED_POOL_PROGRAM_ID)[0];
}

export function splAssetRegistry(mint: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync(
    [seed("spl_asset_registry"), mint.toBytes()],
    SHIELDED_POOL_PROGRAM_ID,
  )[0];
}

export function splAssetVault(mint: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync(
    [seed("spl_asset_vault"), mint.toBytes()],
    SHIELDED_POOL_PROGRAM_ID,
  )[0];
}

export function associatedTokenProgramId(): PublicKey {
  return ASSOCIATED_TOKEN_PROGRAM_ID;
}

export function splTokenProgramId(): PublicKey {
  return SPL_TOKEN_PROGRAM_ID;
}

export function associatedTokenAddress(owner: PublicKey, mint: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync(
    [owner.toBytes(), SPL_TOKEN_PROGRAM_ID.toBytes(), mint.toBytes()],
    ASSOCIATED_TOKEN_PROGRAM_ID,
  )[0];
}

export function zoneConfig(zoneProgram: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [seed("spp_zone_config"), zoneProgram.toBytes()],
    SHIELDED_POOL_PROGRAM_ID,
  );
}

export function zoneAuth(zoneProgram: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync([seed("zone_auth")], zoneProgram);
}
