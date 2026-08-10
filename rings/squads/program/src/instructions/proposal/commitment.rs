//! Versioned proposal-context binding. The encrypted amount/blinding core is
//! stored in the proposal account. This module recomputes the public
//! operation, asset, and destination layer on-chain.

use pinocchio::error::ProgramError;
use zolana_squads_interface::{error::SquadsRingError, state::proposal::Proposal, types::Address};

use crate::shared::proof::poseidon_hash;

const PROPOSAL_V2_DOMAIN: &[u8] = b"ZOLANA/SQUADS/PROPOSAL/V2";
const WITHDRAWAL_OPERATION: u8 = 1;
const TRANSFER_OPERATION: u8 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProposalOperation {
    Withdrawal,
    Transfer,
}

impl ProposalOperation {
    fn field(self) -> [u8; 32] {
        let mut field = [0u8; 32];
        field[31] = match self {
            Self::Withdrawal => WITHDRAWAL_OPERATION,
            Self::Transfer => TRANSFER_OPERATION,
        };
        field
    }
}

fn domain_field() -> [u8; 32] {
    let mut field = [0u8; 32];
    field[32 - PROPOSAL_V2_DOMAIN.len()..].copy_from_slice(PROPOSAL_V2_DOMAIN);
    field
}

/// Compute the proposal public input the ring circuit returns when proposals
/// are enabled. `Proposal.proposal_hash` is the private v2 core.
pub fn proposal_commitment_hash(
    proposal: &Proposal,
    operation: ProposalOperation,
) -> Result<[u8; 32], ProgramError> {
    let asset = hash_public_address(proposal.asset)?;
    let destination = match operation {
        ProposalOperation::Transfer => proposal.recipient.to_bytes(),
        ProposalOperation::Withdrawal => hash_public_address(proposal.recipient)?,
    };
    poseidon_hash(
        &[
            domain_field(),
            operation.field(),
            proposal.proposal_hash,
            asset,
            destination,
        ],
        SquadsRingError::ProofHashingFailed,
    )
}

fn hash_public_address(address: Address) -> Result<[u8; 32], ProgramError> {
    zolana_hasher::primitives::hash_bytes(address.as_array())
        .map_err(|_| SquadsRingError::ProofHashingFailed.into())
}

/// Check public fields from the immutable proposal record against the accounts
/// that receive the withdrawal. Transfers have no public asset settlement. The
/// circuit binds their asset, but their recipient VKA is still checked here.
pub fn verify_execution_context(
    proposal: &Proposal,
    actual_asset: Address,
    actual_destination: Address,
) -> Result<(), ProgramError> {
    if proposal.asset != actual_asset {
        return Err(SquadsRingError::ProposalAssetMismatch.into());
    }
    if proposal.recipient != actual_destination {
        return Err(SquadsRingError::ProposalRecipientMismatch.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proposal(asset: Address, destination: Address) -> Proposal {
        Proposal::new(
            Address::new_from_array([1u8; 32]),
            destination,
            asset,
            [2u8; 32],
            [3u8; 88],
            100,
            Address::new_from_array([4u8; 32]),
        )
    }

    #[test]
    fn rejects_asset_substitution() {
        let approved_asset = Address::new_from_array([5u8; 32]);
        let destination = Address::new_from_array([6u8; 32]);
        let record = proposal(approved_asset, destination);
        let error =
            verify_execution_context(&record, Address::new_from_array([7u8; 32]), destination)
                .unwrap_err();
        assert_eq!(
            error,
            ProgramError::Custom(SquadsRingError::ProposalAssetMismatch as u32)
        );
    }

    #[test]
    fn public_address_hashes_match_sdk_pinned_vectors() {
        assert_eq!(
            hash_public_address(Address::new_from_array([3u8; 32])).unwrap(),
            [
                0x03, 0xdf, 0x2d, 0x93, 0xdf, 0xa1, 0xb0, 0x06, 0xbb, 0xad, 0x4e, 0x16, 0x63, 0x8c,
                0xc7, 0x92, 0x1f, 0x64, 0x88, 0xce, 0x29, 0x5d, 0xe4, 0x67, 0x1e, 0x79, 0xeb, 0x7f,
                0x17, 0x7f, 0xbd, 0xb4,
            ]
        );
        assert_eq!(
            hash_public_address(Address::new_from_array([5u8; 32])).unwrap(),
            [
                0x05, 0xf8, 0xab, 0xf0, 0xc3, 0x1c, 0x1f, 0x86, 0xe6, 0xd1, 0x24, 0x3f, 0xe8, 0x69,
                0xab, 0xfc, 0xf6, 0x06, 0x96, 0xfd, 0xe3, 0x5e, 0xdc, 0x1c, 0x1a, 0xfd, 0x6a, 0x14,
                0x3d, 0xcd, 0x2a, 0x2a,
            ]
        );

        let mut record = proposal(
            Address::new_from_array([3u8; 32]),
            Address::new_from_array([5u8; 32]),
        );
        record.proposal_hash = [
            0x2c, 0xa1, 0x5b, 0x83, 0x0d, 0x4a, 0xc5, 0xff, 0xf8, 0x43, 0x0f, 0x00, 0xbf, 0x6b,
            0xb8, 0xc0, 0x25, 0xda, 0xa8, 0x86, 0xee, 0x97, 0x0e, 0x73, 0xcd, 0xa7, 0xa1, 0xdb,
            0xe5, 0x4d, 0x8a, 0x4e,
        ];
        assert_eq!(
            proposal_commitment_hash(&record, ProposalOperation::Withdrawal).unwrap(),
            [
                0x03, 0x56, 0xda, 0xc9, 0xf8, 0x28, 0xbf, 0x58, 0x77, 0xcb, 0xcb, 0xa1, 0xcd, 0x73,
                0xed, 0xdb, 0x9e, 0x8e, 0xf2, 0x4b, 0xd1, 0x3d, 0xeb, 0xdb, 0x56, 0xa4, 0x14, 0x9e,
                0x43, 0xbd, 0xae, 0xb3,
            ],
            "program and SDK proposal commitments diverged"
        );
    }

    #[test]
    fn rejects_withdrawal_destination_substitution() {
        let asset = Address::new_from_array([5u8; 32]);
        let approved_destination = Address::new_from_array([6u8; 32]);
        let record = proposal(asset, approved_destination);
        let error = verify_execution_context(&record, asset, Address::new_from_array([7u8; 32]))
            .unwrap_err();
        assert_eq!(
            error,
            ProgramError::Custom(SquadsRingError::ProposalRecipientMismatch as u32)
        );
    }
}
