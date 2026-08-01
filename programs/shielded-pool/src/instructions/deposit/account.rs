use light_array_map::pubkey_eq;
use pinocchio::{
    address::{address_eq, Address},
    error::ProgramError,
    AccountView,
};
use zolana_account_checks::AccountIterator;
use zolana_hasher::primitives::hash_bytes;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{DepositAssetKind, MAX_DEPOSIT_ASSETS},
};

use crate::instructions::{
    ring_config::loader::load_ring_config,
    settlement::{
        validate_sol_settlement, validate_spl_deposit_settlement, Settlement,
        SettlementAccountsSol, SplDepositAccounts, ValidatedSplSettlement,
    },
};

/// One deposited asset: its validated settlement accounts plus the asset
/// identity committed into UTXO hashes. `asset_field` is `hash_bytes`
/// of `asset`, computed once per group so batch entries reuse it.
pub struct DepositAssetGroup<'a> {
    /// Deposited asset: the SPL mint, or all-zero for native SOL.
    pub asset: [u8; 32],
    pub asset_field: [u8; 32],
    /// Reuses `transact`'s settlement shape; proofless deposits only ever produce
    /// the deposit variants (SOL into the interface, SPL into the interface).
    pub settlement: Settlement<'a>,
}

/// Validated accounts for a proofless deposit batch. `deposit` carries no SPP
/// proof, so the settlement accounts the proof would otherwise constrain
/// (canonical interface PDA and token-account mints/owners) are verified here
/// on-chain.
pub struct DepositAccounts<'a> {
    pub tree: &'a mut AccountView,
    /// Settlement groups in account order: the SOL group first when present,
    /// then one group per SPL mint. `DepositEntry::asset_index` indexes this.
    pub groups: Vec<DepositAssetGroup<'a>>,
}

impl<'a> DepositAccounts<'a> {
    /// Account layout after `tree`, `depositor` (and `ring_config` on the ring
    /// rail), then the program account: one group per entry of `assets`, in order.
    /// A `Sol` group reads (`system_program`, `sol_interface`); an `Spl`
    /// group reads (`token_program`, `mint`, `user_token`, `spl_interface`). The
    /// instruction data declares the layout, so nothing is inferred from the
    /// account count: too few accounts hits NotEnoughAccountKeys and too many
    /// leaves the iterator non-empty (InvalidSettlementAccounts).
    pub fn validate_and_parse<const HAS_RING: bool>(
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

        // `ring_deposit` passes the `RingConfig` account (the ring's `ring_auth`
        // PDA) first. It must sign and is validated by owner/discriminator -- the
        // create-time derivation already bound it to its program -- and its stored
        // `program_id` becomes the UTXO's `ring_program_id`. The plain `deposit`
        // has no ring; its program data is authorized by the depositor signer.
        let ring_program_id = if HAS_RING {
            let account = iter.next_signer("ring_config")?;
            let config = load_ring_config(account)?;
            Some(config.program_id.to_bytes())
        } else {
            None
        };

        let program_account = iter.next_account("spp_program")?;
        if !address_eq(program_account.address(), program_id) {
            return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
        }

        let mut groups: Vec<DepositAssetGroup<'_>> = Vec::with_capacity(assets.len());
        for kind in assets {
            let group = match kind {
                DepositAssetKind::Sol => {
                    let system_program = iter.next_account("system_program")?;
                    let sol_interface = iter.next_account("sol_interface")?;
                    let bump = validate_sol(depositor, system_program, sol_interface)?;
                    DepositAssetGroup {
                        asset: [0u8; 32],
                        asset_field: hash_bytes(&[0u8; 32])?,
                        settlement: Settlement::SolDeposit(SettlementAccountsSol {
                            sol_interface_account: sol_interface,
                            sol_interface_bump: bump,
                            recipient_account: depositor,
                        }),
                    }
                }
                DepositAssetKind::Spl { spl_interface_bump } => {
                    let token_program = iter.next_account("token_program")?;
                    let mint_account = iter.next_account("mint")?;
                    let user_token = iter.next_account("user_token")?;
                    let spl_interface = iter.next_account("spl_interface")?;
                    let mint_state = validate_spl(
                        SplDepositValidationAccounts {
                            token_authority: depositor,
                            mint_account,
                            user_token_account: user_token,
                            spl_interface_account: spl_interface,
                            token_program_account: token_program,
                        },
                        *spl_interface_bump,
                    )?;
                    DepositAssetGroup {
                        asset: mint_state.mint,
                        asset_field: hash_bytes(&mint_state.mint)?,
                        settlement: Settlement::SplDeposit(SplDepositAccounts {
                            mint_account,
                            decimals: mint_state.decimals,
                            spl_interface_account: spl_interface,
                            token_authority_account: depositor,
                            user_token_account: user_token,
                            token_program_account: token_program,
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
        if !iter.iterator_is_empty() {
            return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
        }

        Ok((Self { tree, groups }, ring_program_id))
    }
}

/// Validate the native-SOL deposit accounts and return the interface PDA bump.
/// Deposit lamports leave the depositor signer, so it must be writable.
fn validate_sol(
    depositor: &AccountView,
    system_program: &AccountView,
    sol_interface: &AccountView,
) -> Result<u8, ProgramError> {
    if !pinocchio_system::check_id(system_program.address()) {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }

    validate_sol_settlement(sol_interface, depositor)
}

/// Validate the SPL deposit accounts and return the deposited mint. The interface is
/// pinned to its canonical per-mint PDA: owner+mint alone would accept any
/// cpi-authority-owned token account of the right mint, splitting liquidity.
struct SplDepositValidationAccounts<'a> {
    token_authority: &'a AccountView,
    mint_account: &'a AccountView,
    user_token_account: &'a AccountView,
    spl_interface_account: &'a AccountView,
    token_program_account: &'a AccountView,
}

fn validate_spl(
    accounts: SplDepositValidationAccounts<'_>,
    spl_interface_bump: u8,
) -> Result<ValidatedSplSettlement, ProgramError> {
    let SplDepositValidationAccounts {
        token_authority,
        mint_account,
        user_token_account,
        spl_interface_account,
        token_program_account,
    } = accounts;
    validate_spl_deposit_settlement(
        mint_account,
        spl_interface_account,
        user_token_account,
        token_program_account,
        spl_interface_bump,
        token_authority,
    )
}
