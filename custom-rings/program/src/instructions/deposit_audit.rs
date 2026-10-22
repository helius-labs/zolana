use custom_ring_interface::{
    key_catalog::RingCircuit, tag, AuditedDepositPrefix, CustomRingError, CustomRingProof,
    DepositContext, DepositPublicInput, RingDepositAuditCapsule, MAX_RING_DEPOSIT_AUDIT_SLOTS,
    RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN, TAGGED_X25519_KEY_LEN, VIEWING_PUBKEY_TAG,
};
use pinocchio::{Address, ProgramResult};
use zolana_interface::instruction::instruction_data::deposit::RingDepositIxDataRef;

use crate::instructions::verifier::{ring_key, RingProof};

pub(crate) struct AuditedDeposit<'a> {
    pub proof: CustomRingProof,
    pub registry_root_index: u8,
    pub spp_data: &'a [u8],
}

impl<'a> AuditedDeposit<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, CustomRingError> {
        let (prefix, spp_data) = data
            .split_at_checked(AuditedDepositPrefix::SIZE)
            .ok_or(CustomRingError::InvalidInstructionData)?;
        let prefix = AuditedDepositPrefix::parse(prefix)?;
        if prefix.tag != tag::AUDITED_DEPOSIT || spp_data.first() != Some(&tag::DEPOSIT) {
            return Err(CustomRingError::InvalidAuditedDeposit);
        }
        Ok(Self {
            proof: prefix.proof,
            registry_root_index: prefix.registry_root_index,
            spp_data,
        })
    }
}

#[must_use]
pub(crate) struct DepositVerification<'a> {
    pub program_id: &'a Address,
    pub tree: &'a Address,
    pub auditor_pubkey: &'a [u8; TAGGED_X25519_KEY_LEN],
    pub anonymous: bool,
    pub member_registry_root: Option<&'a [u8; 32]>,
    pub audited: &'a AuditedDeposit<'a>,
    pub deposit: &'a RingDepositIxDataRef<'a>,
}

impl DepositVerification<'_> {
    #[inline(never)]
    pub fn verify(self) -> ProgramResult {
        // One capsule per output at its own index, all under one ephemeral key.
        let invalid = CustomRingError::InvalidDepositDisclosure;
        let count = self.deposit.deposits.len();
        if !(1..=MAX_RING_DEPOSIT_AUDIT_SLOTS).contains(&count) {
            return Err(invalid.into());
        }
        let mut owners = [[0; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS];
        let mut ciphertexts =
            [[0; RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN]; MAX_RING_DEPOSIT_AUDIT_SLOTS];
        let mut eph_pk = [0; TAGGED_X25519_KEY_LEN];
        for (slot, entry) in self.deposit.deposits.iter().enumerate() {
            let capsule = RingDepositAuditCapsule::parse(entry.encrypted.ciphertext)
                .ok()
                .flatten()
                .filter(|capsule| usize::from(capsule.slot_index) == slot)
                .filter(|capsule| capsule.eph_pk[0] == VIEWING_PUBKEY_TAG)
                .filter(|capsule| slot == 0 || *capsule.eph_pk == eph_pk)
                .ok_or(invalid)?;
            eph_pk = *capsule.eph_pk;
            owners[slot] = *entry.owner_utxo_hash;
            ciphertexts[slot] = *capsule.ciphertext;
        }
        let context_hash = DepositContext {
            program_id: self.program_id.as_array(),
            tree: self.tree.as_array(),
            spp_data: self.audited.spp_data,
        }
        .hash()
        .map_err(CustomRingError::from)?;
        let public_input = DepositPublicInput {
            context_hash: &context_hash,
            anonymous: self.anonymous,
            owner_utxo_hashes: &owners[..count],
            ciphertexts: &ciphertexts[..count],
            auditor_pk: self.auditor_pubkey,
            eph_pk: &eph_pk,
            member_registry_root: self.member_registry_root,
        }
        .hash()
        .map_err(CustomRingError::from)?;
        // The auditor can recover the opening of each deposited owner commitment.
        RingProof {
            proof: &self.audited.proof,
            statement: public_input,
            key: ring_key(RingCircuit::Deposit)?,
        }
        .verify()
    }
}
