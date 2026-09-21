use custom_ring_interface::{
    deposit_verifying_key::VERIFYINGKEY, tag, CustomRingProof, DepositContext, DepositPublicInput,
};
use custom_ring_interface::{
    RingDepositAuditCapsule, MAX_RING_DEPOSIT_AUDIT_SLOTS, RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN,
};
use pinocchio::{error::ProgramError, Address, ProgramResult};
use zolana_interface::instruction::instruction_data::deposit::RingDepositIxDataRef;

use crate::{error::CustomRingError, instructions::verifier::verify_groth16};

/// Ring disclosure proof wrapped around an unchanged SPP deposit instruction.
pub(crate) struct AuditedDeposit<'a> {
    pub proof: CustomRingProof,
    pub spp_data: &'a [u8],
}

impl<'a> AuditedDeposit<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, ProgramError> {
        let (&outer_tag, rest) = data
            .split_first()
            .ok_or(CustomRingError::InvalidInstructionData)?;
        let (proof, spp_data) = rest
            .split_at_checked(CustomRingProof::SIZE)
            .ok_or(CustomRingError::InvalidInstructionData)?;
        if outer_tag != tag::AUDITED_DEPOSIT || spp_data.first() != Some(&tag::DEPOSIT) {
            return Err(CustomRingError::InvalidInstructionData.into());
        }
        Ok(Self {
            proof: wincode::deserialize_exact(proof)
                .map_err(|_| CustomRingError::InvalidInstructionData)?,
            spp_data,
        })
    }
}

/// Trusted ring context paired with the deposit commitments and published
/// ciphertexts.
pub(crate) struct DepositVerification<'a, 'data> {
    pub program_id: &'a Address,
    pub tree: &'a Address,
    pub auditor_pk: &'a [u8; 33],
    pub audited: &'a AuditedDeposit<'data>,
    pub deposit: &'a RingDepositIxDataRef<'data>,
}

impl DepositVerification<'_, '_> {
    #[inline(never)]
    pub fn verify(self) -> ProgramResult {
        // 1. Require one indexed capsule per output under a shared ephemeral
        // encryption key.
        let count = self.deposit.deposits.len();
        if !(1..=MAX_RING_DEPOSIT_AUDIT_SLOTS).contains(&count) {
            return Err(CustomRingError::InvalidDepositDisclosure.into());
        }
        let mut owners = [[0; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS];
        let mut ciphertexts =
            [[0; RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN]; MAX_RING_DEPOSIT_AUDIT_SLOTS];
        let mut eph_pk = [0; 33];
        for (slot, entry) in self.deposit.deposits.iter().enumerate() {
            let capsule = RingDepositAuditCapsule::parse(entry.encrypted.ciphertext)
                .map_err(|_| CustomRingError::InvalidDepositDisclosure)?
                .ok_or(CustomRingError::InvalidDepositDisclosure)?;
            if usize::from(capsule.slot_index) != slot {
                return Err(CustomRingError::InvalidDepositDisclosure.into());
            }
            if slot == 0 {
                eph_pk = *capsule.eph_pk;
            } else if capsule.eph_pk != &eph_pk {
                return Err(CustomRingError::InvalidDepositDisclosure.into());
            }
            owners[slot] = *entry.owner_utxo_hash;
            ciphertexts[slot] = *capsule.ciphertext;
        }
        // 2. Bind disclosure to the actual ring, destination tree and full SPP
        // deposit bytes.
        let context_hash = DepositContext {
            program_id: self.program_id.as_array(),
            tree: self.tree.as_array(),
            spp_data: self.audited.spp_data,
        }
        .hash()
        .map_err(|_| CustomRingError::HashingFailed)?;
        let public_input = DepositPublicInput {
            context_hash: &context_hash,
            owner_utxo_hashes: &owners[..count],
            ciphertexts: &ciphertexts[..count],
            auditor_pk: self.auditor_pk,
            eph_pk: &eph_pk,
        }
        .hash()
        .map_err(|_| CustomRingError::HashingFailed)?;
        // 3. Prove the auditor can recover each deposited owner commitment's
        // opening.
        verify_groth16(&self.audited.proof, public_input, &VERIFYINGKEY)
    }
}
