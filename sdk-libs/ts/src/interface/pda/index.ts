import { findAssociatedTokenPda } from "@solana-program/token";
import {
  getAddressEncoder,
  getProgramDerivedAddress,
  type Address,
  type ProgramDerivedAddress,
} from "@solana/kit";

import { copyBytes } from "../internal.js";
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

/**
 * Named for Rust's `pda::nullifier_marker`: the account the pool creates for a
 * spent nullifier, seeded by the input tree and the nullifier itself.
 */
export async function nullifierMarkerPda(
  tree: Address,
  nullifier: Uint8Array,
): Promise<ProgramDerivedAddress> {
  return getProgramDerivedAddress({
    programAddress: SHIELDED_POOL_PROGRAM_ID,
    seeds: [
      encoder.encode("nullifier"),
      addressEncoder.encode(tree),
      copyBytes(nullifier, 32, "nullifier"),
    ],
  });
}

export async function nullifierMarkerAddress(
  tree: Address,
  nullifier: Uint8Array,
): Promise<Address> {
  return (await nullifierMarkerPda(tree, nullifier))[0];
}

export async function ringAuthAddress(ringProgramId: Address): Promise<Address> {
  const [address] = await getProgramDerivedAddress({
    programAddress: ringProgramId,
    seeds: [encoder.encode("ring_auth")],
  });
  return address;
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
