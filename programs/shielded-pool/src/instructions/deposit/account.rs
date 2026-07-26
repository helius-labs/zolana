use light_array_map::pubkey_eq;
use pinocchio::{
    address::{address_eq, Address},
    error::ProgramError,
    AccountView,
};
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{DepositAssetKind, MAX_DEPOSIT_ASSETS},
    state::SplAssetRegistry,
    SHIELDED_POOL_CPI_AUTHORITY, SPL_ASSET_VAULT_PDA_SEED, SPL_TOKEN_PROGRAM_ID,
};

use crate::instructions::{
    hash::solana_pk_hash,
    settlement::{
        read_token_account, validate_sol_interface, Settlement, SettlementAccountsSol,
        SettlementAccountsSpl,
    },
    zone_config::loader::load_zone_config,
};

const SYSTEM_PROGRAM_ID: Address = Address::new_from_array([0u8; 32]);

/// One deposited asset: its validated settlement accounts plus the asset
/// identity committed into UTXO hashes. `asset_field` is `solana_pk_hash`
/// of `asset`, computed once per group so batch entries reuse it.
pub struct DepositAssetGroup<'a> {
    /// Deposited asset: the SPL mint, or all-zero for native SOL.
    pub asset: [u8; 32],
    pub asset_field: [u8; 32],
    /// Reuses `transact`'s settlement shape; proofless deposits only ever produce
    /// the deposit variants (SOL into the interface, SPL into the vault).
    pub settlement: Settlement<'a>,
}

/// Validated accounts for a proofless deposit batch. `deposit` carries no SPP
/// proof, so the settlement accounts the proof would otherwise constrain (vault
/// PDA, asset registry, token-account mints/owners) are verified here on-chain.
pub struct DepositAccounts<'a> {
    pub tree: &'a mut AccountView,
    /// Settlement groups in account order: the SOL group first when present,
    /// then one group per SPL mint. `DepositEntry::asset_index` indexes this.
    pub groups: Vec<DepositAssetGroup<'a>>,
}

impl<'a> DepositAccounts<'a> {
    /// Account layout after `tree`, `depositor` (and `zone_config` on the zone
    /// rail): one group per entry of `assets`, in that order, then the program
    /// account. A `Sol` group reads (`system_program`, `sol_interface`); an `Spl`
    /// group reads (`token_program`, `user_token`, `vault`, `registry`). The
    /// instruction data declares the layout, so nothing is inferred from the
    /// account count: too few accounts hits NotEnoughAccountKeys and too many
    /// leaves the iterator non-empty (InvalidSettlementAccounts).
    pub fn validate_and_parse<const HAS_ZONE: bool>(
        program_id: &Address,
        accounts: &'a mut [AccountView],
        assets: &[DepositAssetKind],
    ) -> Result<(Self, Option<[u8; 32]>), ProgramError> {
        if assets.is_empty() {
            return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
        }
        if assets.len() > MAX_DEPOSIT_ASSETS {
            return Err(ShieldedPoolError::TooManyDepositAssets.into());
        }

        let mut iter = AccountIterator::new(accounts);

        let tree = iter.next_mut("tree")?;
        // Either spl token account authority, or source for deposited SOL.
        let depositor = iter.next_signer("depositor")?;

        // `zone_deposit` passes the `ZoneConfig` account (the zone's `zone_auth`
        // PDA) first. It must sign and is validated by owner/discriminator -- the
        // create-time derivation already bound it to its program -- and its stored
        // `program_id` becomes the UTXO's `zone_program_id`. The plain `deposit`
        // has no zone; its program data is authorized by the depositor signer.
        let zone_program_id = if HAS_ZONE {
            let account = iter.next_signer("zone_config")?;
            let config = load_zone_config(account)?;
            Some(config.program_id.to_bytes())
        } else {
            None
        };

        let mut groups: Vec<DepositAssetGroup<'_>> = Vec::with_capacity(assets.len());
        for kind in assets {
            let group = match kind {
                DepositAssetKind::Sol => {
                    let system_program = iter.next_account("system_program")?;
                    let sol_interface = iter.next_account("sol_interface")?;
                    let bump = validate_sol(depositor, system_program, sol_interface)?;
                    DepositAssetGroup {
                        asset: [0u8; 32],
                        asset_field: solana_pk_hash(&[0u8; 32])?,
                        settlement: Settlement::Sol(SettlementAccountsSol {
                            sol_interface,
                            sol_interface_bump: bump,
                            recipient: depositor,
                        }),
                    }
                }
                DepositAssetKind::Spl { vault_bump } => {
                    let token_program = iter.next_account("token_program")?;
                    let user_token = iter.next_account("user_token")?;
                    let vault = iter.next_account("vault")?;
                    let registry = iter.next_account("registry")?;
                    let mint = validate_spl(
                        program_id,
                        depositor,
                        user_token,
                        vault,
                        registry,
                        token_program,
                        *vault_bump,
                    )?;
                    DepositAssetGroup {
                        asset: mint,
                        asset_field: solana_pk_hash(&mint)?,
                        settlement: Settlement::Spl(SettlementAccountsSpl {
                            cpi_authority: None,
                            mint,
                            vault,
                            recipient: depositor,
                            user_token_account: user_token,
                            token_program,
                        }),
                    }
                }
            };
            // Two groups naming the same asset would split one asset's settlement
            // across two transfers and let an entry pick either.
            if groups
                .iter()
                .any(|existing| pubkey_eq(&existing.asset, &group.asset))
            {
                return Err(ShieldedPoolError::DuplicateDepositAsset.into());
            }
            groups.push(group);
        }

        let program_account = iter.next_account("program")?;
        if !address_eq(program_account.address(), program_id) {
            return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
        }
        if !iter.iterator_is_empty() {
            return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
        }

        Ok((Self { tree, groups }, zone_program_id))
    }
}

/// Validate the native-SOL deposit accounts and return the interface PDA bump.
/// Deposit lamports leave the depositor signer, so it must be writable.
fn validate_sol(
    depositor: &AccountView,
    system_program: &AccountView,
    sol_interface: &AccountView,
) -> Result<u8, ProgramError> {
    if !address_eq(system_program.address(), &SYSTEM_PROGRAM_ID)
        || !sol_interface.is_writable()
        || !depositor.is_writable()
        || !sol_interface.owned_by(&SYSTEM_PROGRAM_ID)
    {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }

    validate_sol_interface(sol_interface)
}

/// Validate the SPL deposit accounts and return the deposited mint. The vault is
/// pinned to its canonical per-mint PDA: owner+mint alone would accept any
/// cpi-authority-owned token account of the right mint, splitting liquidity.
fn validate_spl(
    program_id: &Address,
    depositor: &AccountView,
    user_token: &AccountView,
    vault: &AccountView,
    registry: &AccountView,
    token_program: &AccountView,
    vault_bump: u8,
) -> Result<[u8; 32], ProgramError> {
    let spl_token_program_id = Address::from(SPL_TOKEN_PROGRAM_ID); // TODO: support t22
    if !address_eq(token_program.address(), &spl_token_program_id)
        || !user_token.is_writable()
        || !vault.is_writable()
    {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }

    let user_token_state = read_token_account(user_token, token_program.address())?;
    let vault_state = read_token_account(vault, token_program.address())?;
    let mint = read_asset_registry_mint(registry, program_id)?;
    let cpi_authority = SHIELDED_POOL_CPI_AUTHORITY;

    if mint != user_token_state.mint
        || mint != vault_state.mint
        || vault_state.owner != cpi_authority
    {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }

    let expected_vault = Address::derive_address(
        &[SPL_ASSET_VAULT_PDA_SEED, mint.as_slice()],
        Some(vault_bump),
        program_id,
    );
    if !address_eq(vault.address(), &expected_vault) {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }

    // Deposit tokens leave the depositor's token account.
    if user_token_state.owner != depositor.address().to_bytes() {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }

    Ok(mint)
}

fn read_asset_registry_mint(
    account: &AccountView,
    program_id: &Address,
) -> Result<[u8; 32], ProgramError> {
    if !account.owned_by(program_id) {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }
    let data = account
        .try_borrow()
        .map_err(|_| ShieldedPoolError::InvalidSettlementAccounts)?;
    let registry: &SplAssetRegistry = bytemuck::try_from_bytes(&data)
        .map_err(|_| ShieldedPoolError::InvalidSettlementAccounts)?;
    registry
        .check_discriminator()
        .map_err(|_| ShieldedPoolError::InvalidSettlementAccounts)?;
    Ok(registry.mint.to_bytes())
}
