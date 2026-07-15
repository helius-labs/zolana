use light_program_profiler::profile;
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use wincode::{SchemaRead, SchemaWrite};
use zolana_account_checks::AccountIterator;
use zolana_hasher::{Hasher, Poseidon};
use zolana_interface::instruction::instruction_data::transact::TransactIxData;

use crate::{
    error::SwapError,
    instructions::{
        shared::{check_after_window, cpi_spp_transact_signed, hash_field, u64_right_align},
        verifier::{verify_groth16, CompressedGroth16Proof},
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CancelProof {
    pub proof_a: [u8; 32],
    pub proof_b: [u8; 64],
    pub proof_c: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CancelIxData {
    pub proof: CancelProof,
    /// The committed order `expiry` the cancel proof reveals as a public input.
    /// Separate from `transact.expiry_unix_ts` (the SPP relayer deadline): cancel
    /// requires `now > order_expiry`, which is necessarily in the past, whereas
    /// SPP rejects a `transact` whose `expiry_unix_ts` is in the past. The
    /// order's committed terms hash includes `order_expiry`; the proof
    /// recomputes it.
    pub order_expiry: u64,
    pub transact: TransactIxData,
}

pub struct CancelPublicInput<'a> {
    pub private_tx_hash: &'a [u8; 32],
    pub expiry: u64,
    pub maker_owner_pk_field: &'a [u8; 32],
}

impl CancelPublicInput<'_> {
    pub fn hash(&self) -> Result<[u8; 32], ProgramError> {
        Poseidon::hashv(&[
            self.private_tx_hash.as_slice(),
            u64_right_align(self.expiry).as_slice(),
            self.maker_owner_pk_field.as_slice(),
        ])
        .map_err(|_| SwapError::HashingFailed.into())
    }
}

#[inline(never)]
#[profile]
pub fn process_cancel_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    iter.next_signer_mut("payer")?;
    // The maker signs the cancel; the cancel proof recomputes the order's
    // committed maker_owner_hash from this pubkey (owner_pk_field), so only the
    // maker can cancel and the maker knows the refund blinding it chose.
    let maker_owner_pk_field = hash_field(iter.next_signer("maker")?.address().as_array())?;

    let CancelIxData {
        proof,
        order_expiry,
        transact,
    } = wincode::deserialize_exact(data).map_err(|_| SwapError::InvalidInstructionData)?;

    let clock = Clock::get()?;
    check_after_window(clock.unix_timestamp, order_expiry)?;

    verify_groth16(
        CompressedGroth16Proof {
            a: &proof.proof_a,
            b: &proof.proof_b,
            c: &proof.proof_c,
            commitment: None,
        },
        CancelPublicInput {
            private_tx_hash: &transact.private_tx_hash,
            expiry: order_expiry,
            maker_owner_pk_field: &maker_owner_pk_field,
        }
        .hash()?,
        &crate::verifying_keys::cancel::VERIFYINGKEY,
    )?;

    let transact_bytes = transact
        .serialize()
        .map_err(|_| SwapError::InvalidInstructionData)?;
    let spp_accounts = iter.remaining()?;
    cpi_spp_transact_signed(spp_accounts, &transact_bytes)
}
