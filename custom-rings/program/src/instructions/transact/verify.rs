use custom_ring_interface::{
    key_catalog::RingCircuit, AuditBinding, CustomRingError, ParsedTransact, PolicyStatement,
    RingMode, RingProgramConfig,
};
use pinocchio::{error::ProgramError, Address, ProgramResult};
use zolana_ring_policy::ring_id_field;

use super::accounts::TransactAccounts;
use crate::instructions::verifier::{ring_key, RingProof};

#[must_use]
pub(super) struct RingStatements<'a> {
    pub program_id: &'a Address,
    pub config: &'a RingProgramConfig,
    pub transfer: &'a ParsedTransact<'a>,
    pub accounts: &'a TransactAccounts<'a>,
    pub epoch: u64,
    pub first_contact_root: &'a [u8; 32],
    pub key_escrow: bool,
}

impl RingStatements<'_> {
    #[inline(never)]
    pub fn verify(self) -> ProgramResult {
        let ring_id = ring_id_field(self.program_id.as_array()).map_err(CustomRingError::from)?;
        let audit_statement = self
            .transfer
            .audit_statement(AuditBinding {
                ring_id: &ring_id,
                auditor_pubkey: &self.config.auditor_pubkey,
                epoch: self.epoch,
                first_contact_root: self.first_contact_root,
                key_escrow: self.key_escrow,
            })?
            .hash()
            .map_err(CustomRingError::from)?;
        // Both keys resolve before either pairing.
        let policy = self.policy_proof(&ring_id)?;
        let data = self.transfer.data();
        let audit = RingProof {
            proof: data.audit_proof,
            statement: audit_statement,
            key: ring_key(RingCircuit::audit(self.transfer.layout(), data.n_out))?,
        };
        audit.verify()?;
        if let Some(policy) = policy {
            policy.verify()?;
        }
        Ok(())
    }

    #[inline(never)]
    fn policy_proof(&self, ring_id: &[u8; 32]) -> Result<Option<RingProof<'_>>, ProgramError> {
        let Some(roots) = &self.accounts.policy else {
            return Ok(None);
        };
        let data = self.transfer.data();
        let slots = &self.accounts.public_slots;
        let public_assets = slots.asset_fields().map_err(CustomRingError::from)?;
        let public_amounts = slots.amount_fields().map_err(CustomRingError::from)?;
        let statement = PolicyStatement {
            key: data.rail.policy_key(),
            private_tx_hash: data.private_tx_hash,
            policy_hash: &roots.policy_hash,
            ring_id,
            approval_required: data.approval_required,
            key_escrow: self.key_escrow,
            own_root: &roots.own_root,
            curator_root: &roots.curator_root,
            sender: &self.accounts.sender,
            public_assets: &public_assets,
            public_amounts: &public_amounts,
        }
        .hash()
        .map_err(CustomRingError::from)?;
        Ok(Some(RingProof {
            proof: roots.proof,
            statement,
            key: ring_key(RingCircuit::policy(data.rail, data.n_in, data.n_out))?,
        }))
    }
}

/// Registry mode alone, its policy proof escrows every output nullifier key.
pub(super) fn escrows_keys(config: &RingProgramConfig) -> Result<bool, CustomRingError> {
    Ok(config.mode()? == RingMode::Registry)
}
