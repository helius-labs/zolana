use custom_ring_interface::MAX_RING_DEPOSIT_AUDIT_SLOTS;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use thiserror::Error;
use zolana_interface::instruction::{
    DepositAsset, DepositBuildError, RingAssetDeposit, RingDeposit,
};

use crate::{
    instructions::{cosigner::RingPrefix, spend_window::window_metas},
    CustomRing, CustomRingProof, EscrowBinding,
};

#[derive(Debug, Error)]
pub enum DepositInstructionError {
    #[error(transparent)]
    Build(#[from] DepositBuildError),
    #[error("an escrowed ring accepts audited deposits only")]
    AuditRequired,
}

#[must_use]
/// An enabled deposit audit requires a proof bound to the exact SPP payload.
pub struct Deposit {
    pub ring: CustomRing,
    pub tree: Address,
    /// Funds the deposit; writable and a signer for SOL.
    pub depositor: Address,
    pub deposits: Vec<RingAssetDeposit>,
    pub proof: Option<CustomRingProof>,
    pub escrow: EscrowBinding,
    pub cosigner: Option<Address>,
}

impl Deposit {
    pub fn instruction(self) -> Result<Instruction, DepositInstructionError> {
        let Self {
            ring,
            tree,
            depositor,
            deposits,
            proof,
            escrow,
            cosigner,
        } = self;

        if proof.is_none() && escrow != EscrowBinding::Off {
            return Err(DepositInstructionError::AuditRequired);
        }
        if proof.is_some() && deposits.len() > MAX_RING_DEPOSIT_AUDIT_SLOTS {
            return Err(DepositBuildError::TooManyEntries {
                count: deposits.len(),
                max: MAX_RING_DEPOSIT_AUDIT_SLOTS,
            }
            .into());
        }

        let windows = window_metas(ring, settled_mints(&deposits));
        let deposit = RingDeposit {
            tree,
            depositor,
            ring_program_id: ring.program_id(),
            deposits,
        };
        let mut instruction = deposit.instruction()?;
        if let Some(proof) = proof {
            let mut data = vec![custom_ring_interface::tag::AUDITED_DEPOSIT];
            data.extend(wincode::serialize(&proof).map_err(|_| DepositBuildError::Serialization)?);
            data.push(escrow.root_index());
            data.extend_from_slice(&instruction.data);
            instruction.data = data;
        }
        let mut prefix = RingPrefix { ring, cosigner }.metas();
        prefix.push(AccountMeta::new_readonly(ring.deposit_audit_pda(), false));
        prefix.extend(escrow.meta(ring));
        prefix.extend(windows);
        instruction.accounts.splice(0..0, prefix);
        Ok(instruction)
    }
}

/// Matches SPP's SOL-first, then distinct-SPL first-appearance settlement order.
/// A different order would shift spend-window accounts away from the assets they gate.
fn settled_mints(deposits: &[RingAssetDeposit]) -> Vec<Address> {
    let mut has_sol = false;
    let mut spl = Vec::new();
    for deposit in deposits {
        match deposit.asset {
            DepositAsset::Sol => has_sol = true,
            DepositAsset::Spl(accounts) if !spl.contains(&accounts.mint) => {
                spl.push(accounts.mint);
            }
            DepositAsset::Spl(_) => {}
        }
    }
    if has_sol {
        spl.insert(0, Address::default());
    }
    spl
}
