use bytemuck::{Pod, Zeroable};
use custom_ring_interface::{
    deposit_verifying_key::VERIFYINGKEY, tag, CustomRingError, CustomRingProof, DepositContext,
    DepositPublicInput, RingDepositAuditCapsule, MAX_RING_DEPOSIT_AUDIT_SLOTS,
    RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN,
};
use pinocchio::{Address, ProgramResult};
use zolana_interface::instruction::instruction_data::deposit::RingDepositIxDataRef;

use crate::instructions::verifier::verify_groth16;

/// `tag || proof || key_registry_root_index`, then the SPP deposit instruction unchanged.
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
struct AuditedPrefix {
    tag: u8,
    proof: CustomRingProof,
    key_registry_root_index: u8,
}

pub(crate) struct AuditedDeposit<'a> {
    pub proof: CustomRingProof,
    pub key_registry_root_index: u8,
    pub spp_data: &'a [u8],
}

impl<'a> AuditedDeposit<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, CustomRingError> {
        let invalid = CustomRingError::InvalidInstructionData;
        let (prefix, spp_data) = data
            .split_at_checked(core::mem::size_of::<AuditedPrefix>())
            .ok_or(invalid)?;
        let prefix: &AuditedPrefix = bytemuck::from_bytes(prefix);
        if prefix.tag != tag::AUDITED_DEPOSIT || spp_data.first() != Some(&tag::DEPOSIT) {
            return Err(invalid);
        }
        Ok(Self {
            proof: prefix.proof,
            key_registry_root_index: prefix.key_registry_root_index,
            spp_data,
        })
    }
}

/// The disclosure proof over the actual ring, destination tree and deposit bytes.
#[inline(never)]
pub(crate) fn verify_deposit_disclosure(
    program_id: &Address,
    tree: &Address,
    auditor_pk: &[u8; 33],
    key_registry_root: Option<&[u8; 32]>,
    audited: &AuditedDeposit<'_>,
    deposit: &RingDepositIxDataRef<'_>,
) -> ProgramResult {
    // 1. One capsule per output at its own index, all under one ephemeral key.
    let invalid = CustomRingError::InvalidDepositDisclosure;
    let count = deposit.deposits.len();
    if !(1..=MAX_RING_DEPOSIT_AUDIT_SLOTS).contains(&count) {
        return Err(invalid.into());
    }
    let mut owners = [[0; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS];
    let mut ciphertexts = [[0; RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN]; MAX_RING_DEPOSIT_AUDIT_SLOTS];
    let mut eph_pk = [0; 33];
    for (slot, entry) in deposit.deposits.iter().enumerate() {
        let capsule = RingDepositAuditCapsule::parse(entry.encrypted.ciphertext)
            .ok()
            .flatten()
            .filter(|capsule| usize::from(capsule.slot_index) == slot)
            .filter(|capsule| slot == 0 || *capsule.eph_pk == eph_pk)
            .ok_or(invalid)?;
        eph_pk = *capsule.eph_pk;
        owners[slot] = *entry.owner_utxo_hash;
        ciphertexts[slot] = *capsule.ciphertext;
    }
    // 2. Bind the statement to this ring, the tree and the full SPP deposit bytes.
    let context_hash = DepositContext {
        program_id: program_id.as_array(),
        tree: tree.as_array(),
        spp_data: audited.spp_data,
    }
    .hash()
    .map_err(CustomRingError::from)?;
    let public_input = DepositPublicInput {
        context_hash: &context_hash,
        owner_utxo_hashes: &owners[..count],
        ciphertexts: &ciphertexts[..count],
        auditor_pk,
        eph_pk: &eph_pk,
        key_registry_root,
    }
    .hash()
    .map_err(CustomRingError::from)?;
    // 3. The auditor can recover the opening of each deposited owner commitment.
    verify_groth16(&audited.proof, public_input, &VERIFYINGKEY)
}
