use solana_address::Address;
use solana_instruction::Instruction;
use zolana_interface::instruction::{DepositBuildError, RingAssetDeposit, RingDeposit};

use crate::CustomRing;

#[must_use]
/// Ring deposit: SPP's `RING_DEPOSIT` instruction re-targeted at this program.
///
/// The ring proves nothing for a deposit -- amounts are public on-chain -- so it
/// only lends its `ring_auth` signature and forwards the instruction data byte for
/// byte, tag included. Encoding and the account layout therefore stay in the
/// interface builder; this wrapper exists to pin `ring_program_id`, which selects
/// both the instruction target and the `ring_auth` PDA that has to sign inside the
/// forwarded CPI. Those two must never disagree, and here they cannot.
pub struct Deposit {
    pub ring: CustomRing,
    pub tree: Address,
    /// Funds the deposit; writable and a signer for SOL.
    pub depositor: Address,
    pub deposits: Vec<RingAssetDeposit>,
}

impl Deposit {
    pub fn instruction(self) -> Result<Instruction, DepositBuildError> {
        let Self {
            ring,
            tree,
            depositor,
            deposits,
        } = self;

        RingDeposit {
            tree,
            depositor,
            ring_program_id: ring.program_id(),
            deposits,
        }
        .instruction()
    }
}
