import { findAssociatedTokenPda } from "@solana-program/token";
import { getAddressEncoder, getProgramDerivedAddress, } from "@solana/kit";
import { SHIELDED_POOL_CPI_AUTHORITY, SHIELDED_POOL_PROGRAM_ID, SOL_INTERFACE, SPL_TOKEN_PROGRAM_ID, } from "../program.js";
const encoder = new TextEncoder();
const addressEncoder = getAddressEncoder();
function derive(seed, address) {
    return getProgramDerivedAddress({
        programAddress: SHIELDED_POOL_PROGRAM_ID,
        seeds: [
            encoder.encode(seed),
            ...(address === undefined ? [] : [addressEncoder.encode(address)]),
        ],
    });
}
export async function protocolConfigAddress() {
    return (await derive("protocol_config"))[0];
}
export function solInterfaceAddress() {
    return SOL_INTERFACE;
}
export function shieldedPoolCpiAuthorityAddress() {
    return SHIELDED_POOL_CPI_AUTHORITY;
}
export async function splAssetCounterAddress() {
    return (await derive("spl_asset_counter"))[0];
}
export async function splAssetRegistryAddress(mint) {
    return (await derive("spl_asset_registry", mint))[0];
}
export function splAssetVaultPda(mint) {
    return derive("spl_asset_vault", mint);
}
export async function splAssetVaultAddress(mint) {
    return (await splAssetVaultPda(mint))[0];
}
export async function associatedTokenAddress(owner, mint, tokenProgram) {
    return (await findAssociatedTokenPda({
        owner,
        mint,
        tokenProgram: tokenProgram ?? SPL_TOKEN_PROGRAM_ID,
    }))[0];
}
