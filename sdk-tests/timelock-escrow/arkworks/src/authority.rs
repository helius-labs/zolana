use timelock_escrow_program::{ESCROW_AUTHORITY_PDA_SEED, ID};
use zk_program_sdk::ProgramOwner;

pub fn escrow_authority() -> ProgramOwner {
    ProgramOwner::find(&[ESCROW_AUTHORITY_PDA_SEED], &ID)
}
