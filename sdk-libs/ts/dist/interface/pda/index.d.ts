import { type Address, type ProgramDerivedAddress } from "@solana/kit";
export declare function protocolConfigAddress(): Promise<Address>;
export declare function solInterfaceAddress(): Address;
export declare function shieldedPoolCpiAuthorityAddress(): Address;
export declare function splAssetCounterAddress(): Promise<Address>;
export declare function splAssetRegistryAddress(mint: Address): Promise<Address>;
export declare function splAssetVaultPda(mint: Address): Promise<ProgramDerivedAddress>;
export declare function splAssetVaultAddress(mint: Address): Promise<Address>;
export declare function associatedTokenAddress(owner: Address, mint: Address, tokenProgram?: Address | null): Promise<Address>;
