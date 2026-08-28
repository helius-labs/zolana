use mollusk_svm::result::ProgramResult;

use crate::common::{
    auditor_pubkey, authority, create_config_fixture, ed25519_reader, grant_read_access_fixture,
    init_spp_ring_config_fixture, initialized_config_account, p256_reader,
    revoke_read_access_fixture, set_authority_fixture, setup_mollusk, Fixture,
};
use custom_ring_interface::{
    CREATE_CONFIG_COMPUTE_UNIT_LIMIT, INIT_SPP_RING_CONFIG_COMPUTE_UNIT_LIMIT,
    READ_ACCESS_COMPUTE_UNIT_LIMIT, SET_AUTHORITY_COMPUTE_UNIT_LIMIT,
};

fn consumed(fixture: Fixture) -> u64 {
    let (mollusk, _) = setup_mollusk();
    let result = mollusk.process_instruction(fixture.instruction(), fixture.accounts());
    assert_eq!(result.program_result, ProgramResult::Success);
    result.compute_units_consumed
}

/// SPP is absent from mollusk, the run stops at the CPI.
fn consumed_until_spp_cpi(fixture: Fixture) -> u64 {
    let (mollusk, _) = setup_mollusk();
    let result = mollusk.process_instruction(fixture.instruction(), fixture.accounts());
    assert!(matches!(
        result.program_result,
        ProgramResult::UnknownError(_)
    ));
    result.compute_units_consumed
}

#[test]
fn operator_instructions_fit_their_published_budgets() {
    assert!(
        consumed(create_config_fixture(auditor_pubkey(2)))
            <= u64::from(CREATE_CONFIG_COMPUTE_UNIT_LIMIT)
    );
    assert!(
        consumed_until_spp_cpi(init_spp_ring_config_fixture(initialized_config_account(
            authority(),
            auditor_pubkey(2)
        ))) <= u64::from(INIT_SPP_RING_CONFIG_COMPUTE_UNIT_LIMIT)
    );
    assert!(consumed(set_authority_fixture()) <= u64::from(SET_AUTHORITY_COMPUTE_UNIT_LIMIT));
    for reader in [ed25519_reader(7), p256_reader()] {
        assert!(
            consumed(grant_read_access_fixture(&reader))
                <= u64::from(READ_ACCESS_COMPUTE_UNIT_LIMIT)
        );
        assert!(
            consumed(revoke_read_access_fixture(&reader))
                <= u64::from(READ_ACCESS_COMPUTE_UNIT_LIMIT)
        );
    }
}
