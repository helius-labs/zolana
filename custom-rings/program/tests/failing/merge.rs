use custom_ring_interface::tag;
use custom_ring_program::CustomRingError;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;

use crate::common::{deposit_fixture, setup_mollusk};

fn custom(error: CustomRingError) -> ProgramError {
    ProgramError::Custom(error as u32)
}

fn merge_fixture() -> crate::common::Fixture {
    let mut fixture = deposit_fixture();
    fixture.data_mut()[0] = tag::MERGE;
    fixture
}

#[test]
fn merge_reaches_the_spp_cpi() {
    let (mollusk, _) = setup_mollusk();
    merge_fixture().expect_spp_cpi(&mollusk);
}

#[test]
fn merge_rejects_an_impostor_spp_program() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = merge_fixture();
    fixture.substitute("spp_program", Pubkey::new_from_array([71; 32]));
    fixture.expect_err(
        &mollusk,
        custom(CustomRingError::InvalidShieldedPoolProgram),
    );
}

#[test]
fn merge_requires_the_custom_ring_authority() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = merge_fixture();
    fixture.substitute("ring_config", Pubkey::new_from_array([72; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::MissingRingAuth));
}
