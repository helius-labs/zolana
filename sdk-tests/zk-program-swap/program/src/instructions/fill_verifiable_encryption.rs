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
        shared::{check_within_window, cpi_spp_transact_signed, u64_to_field},
        verifier::{verify_groth16, CompressedGroth16Proof},
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct FillVerifiableEncryptionProof {
    pub proof_a: [u8; 32],
    pub proof_b: [u8; 64],
    pub proof_c: [u8; 32],
    pub commitment: [u8; 32],
    pub commitment_pok: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct FillVerifiableEncryptionIxData {
    pub proof: FillVerifiableEncryptionProof,
    pub transact: TransactIxData,
}

pub struct FillVerifiableEncryptionPublicInput<'a> {
    pub private_tx_hash: &'a [u8; 32],
    pub expiry: u64,
    pub destination_ciphertext: &'a [u8],
}

impl FillVerifiableEncryptionPublicInput<'_> {
    pub fn hash(&self) -> Result<[u8; 32], ProgramError> {
        let ct_hash = ciphertext_hash(self.destination_ciphertext)
            .map_err(|_| ProgramError::from(SwapError::HashingFailed))?;
        Poseidon::hashv(&[
            self.private_tx_hash.as_slice(),
            u64_to_field(self.expiry).as_slice(),
            ct_hash.as_slice(),
        ])
        .map_err(|_| SwapError::HashingFailed.into())
    }
}

#[inline(never)]
#[profile]
pub fn process_fill_verifiable_encryption(
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    let _payer = iter.next_signer_mut("payer")?;

    let FillVerifiableEncryptionIxData { proof, transact } =
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
        FillVerifiableEncryptionPublicInput {
            private_tx_hash: &transact.private_tx_hash,
            expiry: transact.expiry_unix_ts,
            destination_ciphertext,
        }
        .hash()?,
        &crate::verifying_keys::fill_verifiable_encryption::VERIFYINGKEY,
    )?;

    let transact_bytes = transact
        .serialize()
        .map_err(|_| SwapError::InvalidInstructionData)?;
    let spp_accounts = iter.remaining()?;
    cpi_spp_transact_signed(spp_accounts, &transact_bytes)
}
