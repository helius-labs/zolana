import { findAssociatedTokenPda } from "@solana-program/token";
import {
  getAddressEncoder,
  getProgramDerivedAddress,
  isOffCurveAddress,
  type Address,
  type ProgramDerivedAddress,
  type ProgramDerivedAddressBump,
} from "@solana/kit";

import { copyBytes, encodeBase58, fail, sha256, unsigned } from "../internal.js";
import {
  SHIELDED_POOL_CPI_AUTHORITY,
  SHIELDED_POOL_PROGRAM_ID,
  SOL_INTERFACE,
  SPL_TOKEN_PROGRAM_ID,
} from "../program.js";

const encoder = new TextEncoder();
const addressEncoder = getAddressEncoder();
const PDA_MARKER = encoder.encode("ProgramDerivedAddress");

/**
 * Synchronous `find_program_address` for the shielded pool. Kit's derivation is
 * async because it hashes through WebCrypto; the client needs its default tree
 * inside a synchronous constructor, so this mirrors Kit byte for byte and is
 * pinned against it in the tests.
 */
function findShieldedPoolAddressSync(seeds: readonly Uint8Array[]): ProgramDerivedAddress {
  const programId = addressEncoder.encode(SHIELDED_POOL_PROGRAM_ID);
  for (let bump = 255; bump > 0; bump -= 1) {
    const candidate = encodeBase58(
      sha256(
        Uint8Array.from([...seeds.flatMap((seed) => [...seed]), bump, ...programId, ...PDA_MARKER]),
      ),
    );
    if (isOffCurveAddress(candidate)) return [candidate, bump as ProgramDerivedAddressBump];
  }
  fail("INTERFACE_INVALID_ADDRESS", { reason: "no viable PDA bump" });
}

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
 * Named for Rust's `pda::nullifier_pda`: the account the pool creates for a
 * spent nullifier, seeded by the input tree and the nullifier itself.
 */
export async function nullifierPda(
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

export async function nullifierPdaAddress(tree: Address, nullifier: Uint8Array): Promise<Address> {
  return (await nullifierPda(tree, nullifier))[0];
}

/**
 * Named for Rust's `pda::tree_with_bump`: the pool creates every tree at
 * `["tree", tree_id as u16 LE]`, so tree 0 is the default tree.
 */
export function treeWithBump(treeId: number): ProgramDerivedAddress {
  const seed = new Uint8Array(2);
  new DataView(seed.buffer).setUint16(0, unsigned(treeId, 0xffff, "treeId"), true);
  return findShieldedPoolAddressSync([encoder.encode("tree"), seed]);
}

export function treeAddress(treeId: number): Address {
  return treeWithBump(treeId)[0];
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
