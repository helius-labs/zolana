use borsh::{BorshDeserialize, BorshSerialize};
use bytemuck::from_bytes_mut;
use light_program_profiler::profile;
use pinocchio::{AccountView, ProgramResult};
use zolana_account_checks::AccountIterator;

use crate::{
    error::DynamicSwapError,
    instructions::shared::{verify_pda, CreatePdaAccount},
    state::{discriminator::PAIR, Pair},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct CreatePairData {
    pub price: u64,
    pub source_asset_id: u64,
    pub destination_asset_id: u64,
    /// The maker's settle window in slots; see `Pair::expiry_slots`.
    pub expiry_slots: u64,
    /// The worst-case owed per escrow; see `Pair::max_order_size`.
    pub max_order_size: u64,
    /// The source asset's UTXO commitment; see `Pair::source_asset`.
    pub source_asset: [u8; 32],
    /// The destination asset's UTXO commitment; see `Pair::destination_asset`.
    pub destination_asset: [u8; 32],
    /// The maker receipt destination; see `Pair::maker_receipt_owner_hash`.
    pub maker_receipt_owner_hash: [u8; 32],
    /// The maker's encryption pubkey; see `Pair::maker_encryption_pubkey`.
    pub maker_encryption_pubkey: [u8; 33],
}

#[inline(never)]
#[profile]
pub fn process_create_pair_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let CreatePairData {
        price,
        source_asset_id,
        destination_asset_id,
        expiry_slots,
        max_order_size,
        source_asset,
        destination_asset,
        maker_receipt_owner_hash,
        maker_encryption_pubkey,
    } = CreatePairData::try_from_slice(data)
        .map_err(|_| DynamicSwapError::InvalidInstructionData)?;
    // See `update_price`: a zero price leaves `create_escrow` unable to write a
    // nonzero `execution_price`, so the escrow could never settle.
    if price == 0 {
        return Err(DynamicSwapError::InvalidPrice.into());
    }
    // A zero window would make every escrow cancellable immediately and
    // unsettleable.
    if expiry_slots == 0 {
        return Err(DynamicSwapError::InvalidExpiry.into());
    }
    // A zero max_order_size would make every escrow unprovable (owed is
    // nonzero in escrow_open) and every reservation empty.
    if max_order_size == 0 {
        return Err(DynamicSwapError::InvalidMaxOrderSize.into());
    }
    // The maker encryption pubkey must be a SEC1-compressed P256 point; a
    // malformed key would make every order UTXO handoff undecryptable, leaving
    // takers only the cancel path.
    if !matches!(maker_encryption_pubkey.first(), Some(0x02) | Some(0x03)) {
        return Err(DynamicSwapError::InvalidEncryptionPubkey.into());
    }

    let mut iter = AccountIterator::new(accounts);
    let payer = iter.next_signer_mut("payer")?;
    let pair_account = iter.next_mut("pair")?;
    let system_program = iter.next_account("system_program")?;
    if !pinocchio_system::check_id(system_program.address()) {
        return Err(pinocchio::error::ProgramError::IncorrectProgramId);
    }

    let authority = *payer.address().as_array();
    let source_asset_id_le = source_asset_id.to_le_bytes();
    let destination_asset_id_le = destination_asset_id.to_le_bytes();

    let pair_bump = verify_pda(
        pair_account.address(),
        &[
            Pair::SEED_PREFIX,
            &authority,
            &source_asset_id_le,
            &destination_asset_id_le,
        ],
        &crate::ID,
    )?;
    CreatePdaAccount::<4> {
        fee_payer: payer,
        new_account: pair_account,
        space: Pair::SIZE,
        owner: &crate::ID,
        signer_seeds: [
            Pair::SEED_PREFIX,
            &authority,
            &source_asset_id_le,
            &destination_asset_id_le,
        ],
        bump: pair_bump,
    }
    .execute()?;

    {
        let mut bytes = pair_account
            .try_borrow_mut()
            .map_err(|_| DynamicSwapError::InvalidInstructionData)?;
        // `CreatePdaAccount` just allocated exactly `Pair::SIZE` bytes.
        let state = from_bytes_mut::<Pair>(&mut bytes[..]);
        *state = Pair {
            discriminator: PAIR,
            bump: pair_bump,
            _pad: [0; 6],
            authority: *payer.address(),
            source_asset_id,
            destination_asset_id,
            price,
            expiry_slots,
            max_order_size,
            // The pool starts empty and unreserved; deposits and open escrows
            // move these counters from here on.
            available_liquidity: 0,
            open_reservations: 0,
            source_asset,
            destination_asset,
            maker_receipt_owner_hash,
            maker_encryption_pubkey,
            _pad2: [0; 7],
        };
    }

    Ok(())
}
