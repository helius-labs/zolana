use custom_ring_interface::{
    deposit_verifying_key::VERIFYINGKEY, tag, AuditedDepositPrefix, CustomRingError,
    CustomRingProof, DepositContext, DepositPublicInput, RingDepositAuditCapsule, RingMode,
    MAX_RING_DEPOSIT_AUDIT_SLOTS, RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN, TAGGED_X25519_KEY_LEN,
    VIEWING_PUBKEY_TAG,
};
use pinocchio::{Address, ProgramResult};
use zolana_interface::instruction::instruction_data::deposit::RingDepositIxDataRef;

use crate::instructions::{loader::AuditedConfig, verifier::verify_groth16};

pub(crate) struct AuditedDeposit<'a> {
    pub proof: CustomRingProof,
    pub registry_root_index: u8,
    pub spp_data: &'a [u8],
}

impl<'a> AuditedDeposit<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, CustomRingError> {
        let (prefix, spp_data) = data
            .split_at_checked(core::mem::size_of::<AuditedDepositPrefix>())
            .ok_or(CustomRingError::InvalidInstructionData)?;
        let prefix: &AuditedDepositPrefix = bytemuck::from_bytes(prefix);
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

/// The disclosure proof over the actual ring, destination tree and deposit bytes.
#[inline(never)]
pub(crate) fn verify_deposit_disclosure(
    program_id: &Address,
    tree: &Address,
    config: &AuditedConfig,
    member_registry_root: Option<&[u8; 32]>,
    audited: &AuditedDeposit<'_>,
    deposit: &RingDepositIxDataRef<'_>,
) -> ProgramResult {
    // One capsule per output at its own index, all under one ephemeral key.
    let invalid = CustomRingError::InvalidDepositDisclosure;
    let count = deposit.deposits.len();
    if !(1..=MAX_RING_DEPOSIT_AUDIT_SLOTS).contains(&count) {
        return Err(invalid.into());
    }
    let mut owners = [[0; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS];
    let mut ciphertexts = [[0; RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN]; MAX_RING_DEPOSIT_AUDIT_SLOTS];
    let mut eph_pk = [0; TAGGED_X25519_KEY_LEN];
    for (slot, entry) in deposit.deposits.iter().enumerate() {
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
        program_id: program_id.as_array(),
        tree: tree.as_array(),
        spp_data: audited.spp_data,
    }
    .hash()
    .map_err(CustomRingError::from)?;
    let public_input = DepositPublicInput {
        context_hash: &context_hash,
        anonymous: config.mode == RingMode::Anonymous,
        owner_utxo_hashes: &owners[..count],
        ciphertexts: &ciphertexts[..count],
        auditor_pk: &config.auditor_pubkey,
        eph_pk: &eph_pk,
        member_registry_root,
    }
    .hash()
    .map_err(CustomRingError::from)?;
    // The auditor can recover the opening of each deposited owner commitment.
    verify_groth16(&audited.proof, public_input, &VERIFYINGKEY)
}
