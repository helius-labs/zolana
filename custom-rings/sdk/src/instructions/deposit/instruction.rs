use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use zolana_interface::instruction::{DepositBuildError, RingAssetDeposit, RingDeposit};

use crate::{config_pda, PROGRAM_ID};

/// Ring deposit: SPP's `RING_DEPOSIT` instruction re-targeted at this program.
///
/// The ring proves nothing for a deposit, amounts are public on-chain, so it
/// checks its asset policy, lends its `ring_auth` signature and forwards the
/// instruction data byte for byte, tag included. Encoding and SPP's account
/// layout stay in the interface builder, and the ring config is prepended for
/// the policy read. This wrapper pins `ring_program_id`, which selects both the
/// instruction target and the `ring_auth` PDA that has to sign inside the
/// forwarded CPI. Those two must never disagree, and here they cannot.
pub struct Deposit {
    pub tree: Address,
    /// Funds the deposit; writable and a signer for SOL.
    pub depositor: Address,
    pub deposits: Vec<RingAssetDeposit>,
}

impl Deposit {
    pub fn instruction(self) -> Result<Instruction, DepositBuildError> {
        let Self {
            tree,
            depositor,
            deposits,
        } = self;

        let mut ix = RingDeposit {
            tree,
            depositor,
            ring_program_id: PROGRAM_ID,
            deposits,
        }
        .instruction()?;
        ix.accounts
            .insert(0, AccountMeta::new_readonly(config_pda(), false));
        Ok(ix)
    }
}
