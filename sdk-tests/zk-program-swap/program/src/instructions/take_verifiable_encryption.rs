use light_program_profiler::profile;
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use wincode::{SchemaRead, SchemaWrite};
use zolana_account_checks::AccountIterator;
use zolana_hasher::{Hasher, Poseidon};
use zolana_interface::{
    instruction::instruction_data::transact::TransactIxData, merge_utils::ciphertext_hash,
};

use crate::{
    error::SwapError,
    instructions::{
        shared::{check_within_window, cpi_spp_transact_signed, u64_right_align},
        verifier::{verify_groth16, CompressedGroth16Proof},
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct TakeVerifiableEncryptionProof {
    pub proof_a: [u8; 32],
    pub proof_b: [u8; 64],
    pub proof_c: [u8; 32],
    pub commitment: [u8; 32],
    pub commitment_pok: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct TakeVerifiableEncryptionIxData {
    pub proof: TakeVerifiableEncryptionProof,
    pub transact: TransactIxData,
}

pub struct TakeVerifiableEncryptionPublicInput<'a> {
    pub private_tx_hash: &'a [u8; 32],
    pub expiry: u64,
    pub destination_ciphertext: &'a [u8],
}

impl TakeVerifiableEncryptionPublicInput<'_> {
    pub fn hash(&self) -> Result<[u8; 32], ProgramError> {
        let ct_hash = ciphertext_hash(self.destination_ciphertext)
            .map_err(|_| ProgramError::from(SwapError::HashingFailed))?;
        Poseidon::hashv(&[
            self.private_tx_hash.as_slice(),
            u64_right_align(self.expiry).as_slice(),
            ct_hash.as_slice(),
        ])
        .map_err(|_| SwapError::HashingFailed.into())
    }
}

#[inline(never)]
#[profile]
pub fn process_take_verifiable_encryption_ix(
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    iter.next_signer_mut("payer")?;

    let TakeVerifiableEncryptionIxData { proof, transact } =
        wincode::deserialize_exact(data).map_err(|_| SwapError::InvalidInstructionData)?;

    let clock = Clock::get()?;
    check_within_window(clock.unix_timestamp, transact.expiry_unix_ts)?;

    let destination_ciphertext = transact
        .outputs
        .last()
        .and_then(|output| output.data.as_deref())
        .ok_or(SwapError::InvalidInstructionData)?;

    verify_groth16(
        CompressedGroth16Proof {
            a: &proof.proof_a,
            b: &proof.proof_b,
            c: &proof.proof_c,
            commitment: Some((&proof.commitment, &proof.commitment_pok)),
        },
        TakeVerifiableEncryptionPublicInput {
            private_tx_hash: &transact.private_tx_hash,
            expiry: transact.expiry_unix_ts,
            destination_ciphertext,
        }
        .hash()?,
        &crate::verifying_keys::take_verifiable_encryption::VERIFYINGKEY,
    )?;

    let transact_bytes = transact
        .serialize()
        .map_err(|_| SwapError::InvalidInstructionData)?;
    let spp_accounts = iter.remaining()?;
    cpi_spp_transact_signed(spp_accounts, &transact_bytes)
}
