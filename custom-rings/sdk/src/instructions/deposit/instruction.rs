use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use zolana_interface::instruction::{DepositBuildError, RingAssetDeposit, RingDeposit};

use crate::{
    instructions::{cosigner::cosigner_metas, spend_window::window_metas},
    CustomRing,
};

#[must_use]
/// Ring deposit: SPP's `RING_DEPOSIT` instruction re-targeted at this program.
///
/// The ring proves nothing for a deposit -- amounts are public on-chain -- so it
/// only lends its `ring_auth` signature and forwards the instruction data byte for
/// byte, tag included. Encoding and the account layout therefore stay in the
/// interface builder; this wrapper exists to pin `ring_program_id`, which selects
/// both the instruction target and the `ring_auth` PDA that has to sign inside the
/// forwarded CPI. Those two must never disagree, and here they cannot. The ring's
/// `[cosigner_pda, cosigner]` prefix and one spend window slot per settled mint
/// precede the forwarded list.
pub struct Deposit {
    pub ring: CustomRing,
    pub tree: Address,
    /// Funds the deposit; writable and a signer for SOL.
    pub depositor: Address,
    pub deposits: Vec<RingAssetDeposit>,
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
            cosigner,
            has_policy,
        } = self;

        let deposit = RingDeposit {
            tree,
            depositor,
            ring_program_id: ring.program_id(),
            deposits,
        };
        let windows = window_metas(ring, deposit.settled_mints()?);
        let mut instruction = deposit.instruction()?;
        let mut prefix = vec![AccountMeta::new_readonly(ring.config_pda(), false)];
        prefix.extend(cosigner_metas(ring, cosigner));
        if has_policy {
            prefix.push(AccountMeta::new_readonly(ring.policy_config_pda(), false));
        }
        prefix.extend(windows);
        instruction.accounts.splice(0..0, prefix);
        Ok(instruction)
    }
}
