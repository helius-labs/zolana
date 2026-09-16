use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use zolana_event::MAX_RING_DEPOSIT_AUDIT_SLOTS;
use zolana_interface::instruction::{DepositBuildError, RingAssetDeposit, RingDeposit};

use crate::{
    instructions::{
        cosigner::{RingPolicy, RingPrefix},
        spend_window::window_metas,
    },
    CustomRing, CustomRingProof,
};

#[must_use]
/// An enabled deposit audit requires a proof bound to the exact SPP payload.
pub struct Deposit {
    pub ring: CustomRing,
    pub tree: Address,
    /// Funds the deposit; writable and a signer for SOL.
    pub depositor: Address,
    pub deposits: Vec<RingAssetDeposit>,
    pub proof: Option<CustomRingProof>,
    pub cosigner: Option<Address>,
    /// Mirrors the ring config's policy flag.
    pub has_policy: bool,
}

impl Deposit {
    pub fn instruction(self) -> Result<Instruction, DepositBuildError> {
        let Self {
            ring,
            tree,
            depositor,
            deposits,
            proof,
            cosigner,
            has_policy,
        } = self;

        if proof.is_some() && deposits.len() > MAX_RING_DEPOSIT_AUDIT_SLOTS {
            return Err(DepositBuildError::TooManyEntries {
                count: deposits.len(),
                max: MAX_RING_DEPOSIT_AUDIT_SLOTS,
            });
        }

        let deposit = RingDeposit {
            tree,
            depositor,
            ring_program_id: ring.program_id(),
            deposits,
        };
        let windows = window_metas(ring, deposit.settled_mints()?);
        let mut instruction = deposit.instruction()?;
        if let Some(proof) = proof {
            let mut data = vec![custom_ring_interface::tag::AUDITED_DEPOSIT];
            data.extend(wincode::serialize(&proof).map_err(|_| DepositBuildError::Serialization)?);
            data.extend_from_slice(&instruction.data);
            instruction.data = data;
        }
        let mut prefix = RingPrefix {
            ring,
            cosigner,
            policy: if has_policy {
                RingPolicy::Config
            } else {
                RingPolicy::Off
            },
        }
        .metas();
        prefix.insert(
            3,
            AccountMeta::new_readonly(ring.deposit_audit_pda(), false),
        );
        prefix.extend(windows);
        instruction.accounts.splice(0..0, prefix);
        Ok(instruction)
    }
}
