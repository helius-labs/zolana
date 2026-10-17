use pinocchio::Address;
use zolana_program::ProgramOwner;

use crate::{escrow_authority_seeds, ID};

pub fn escrow_authority(creator: &Address) -> ProgramOwner {
    ProgramOwner::find(&escrow_authority_seeds(creator), &ID)
}
