use mollusk_svm::result::ProgramResult;

use crate::common::{
    auditor_pubkey, authority, cosigner, create_config_fixture, create_key_registry_root_fixture,
    create_policy_fixture, delegate, ed25519_reader, grant_read_access_fixture,
    init_spp_ring_config_fixture, initialized_config_account, p256_reader,
    revoke_read_access_fixture, set_authority_fixture, set_cosigner_data, set_cosigner_fixture,
    set_delegate_data, set_delegate_fixture, set_paused_fixture, set_spend_window_data,
    set_spend_window_fixture, setup_mollusk, Fixture, USDC,
};
use custom_ring_interface::{
    CoSignScope, CREATE_CONFIG_COMPUTE_UNIT_LIMIT, CREATE_KEY_REGISTRY_ROOT_COMPUTE_UNIT_LIMIT,
    CREATE_POLICY_COMPUTE_UNIT_LIMIT, INIT_SPP_RING_CONFIG_COMPUTE_UNIT_LIMIT,
    READ_ACCESS_COMPUTE_UNIT_LIMIT, SET_AUTHORITY_COMPUTE_UNIT_LIMIT,
    SET_CO_SIGNER_COMPUTE_UNIT_LIMIT, SET_DELEGATE_COMPUTE_UNIT_LIMIT,
    SET_PAUSED_COMPUTE_UNIT_LIMIT, SET_SPEND_WINDOW_COMPUTE_UNIT_LIMIT,
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
    fixture.expect_spp_cpi(&mollusk)
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
    assert!(
        consumed_until_spp_cpi(set_paused_fixture(1)) <= u64::from(SET_PAUSED_COMPUTE_UNIT_LIMIT)
    );
    assert!(consumed(create_policy_fixture()) <= u64::from(CREATE_POLICY_COMPUTE_UNIT_LIMIT));
    assert!(
        consumed(set_delegate_fixture(set_delegate_data(delegate()), None))
            <= u64::from(SET_DELEGATE_COMPUTE_UNIT_LIMIT)
    );
    assert!(
        consumed(set_cosigner_fixture(
            set_cosigner_data(cosigner(), CoSignScope::ALL.bits(), &[(USDC, 1)]),
            None
        )) <= u64::from(SET_CO_SIGNER_COMPUTE_UNIT_LIMIT)
    );
    assert!(
        consumed(set_spend_window_fixture(
            USDC,
            set_spend_window_data(USDC, 100, 1, 1),
            None
        )) <= u64::from(SET_SPEND_WINDOW_COMPUTE_UNIT_LIMIT)
    );
    assert!(
        consumed(create_key_registry_root_fixture(None))
            <= u64::from(CREATE_KEY_REGISTRY_ROOT_COMPUTE_UNIT_LIMIT)
    );
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
