use mollusk_svm::result::ProgramResult;

use crate::common::{
    auditor_pubkey, authority, cosigner, create_config_fixture, create_key_registry_root_fixture,
    create_policy_fixture, delegate, ed25519_reader, grant_read_access_fixture,
    init_spp_ring_config_fixture, initialized_config_account, p256_reader,
    revoke_read_access_fixture, set_authority_fixture, set_cosigner_data, set_cosigner_fixture,
    set_delegate_data, set_delegate_fixture, set_paused_fixture, setup_mollusk, Fixture, USDC,
};
use custom_ring_interface::{compute_unit_limit, CoSignScope, InstructionTag};

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
        consumed(create_config_fixture(auditor_pubkey(4)))
            <= u64::from(compute_unit_limit(InstructionTag::CreateConfig))
    );
    assert!(
        consumed_until_spp_cpi(init_spp_ring_config_fixture(initialized_config_account(
            authority(),
            auditor_pubkey(4)
        ))) <= u64::from(compute_unit_limit(InstructionTag::InitSppRingConfig))
    );
    assert!(
        consumed(set_authority_fixture())
            <= u64::from(compute_unit_limit(InstructionTag::SetAuthority))
    );
    assert!(
        consumed_until_spp_cpi(set_paused_fixture(1))
            <= u64::from(compute_unit_limit(InstructionTag::SetPaused))
    );
    assert!(
        consumed(create_policy_fixture())
            <= u64::from(compute_unit_limit(InstructionTag::CreatePolicy))
    );
    assert!(
        consumed(set_delegate_fixture(set_delegate_data(delegate()), None))
            <= u64::from(compute_unit_limit(InstructionTag::SetDelegate))
    );
    assert!(
        consumed(set_cosigner_fixture(
            set_cosigner_data(cosigner(), CoSignScope::ALL.bits(), &[(USDC, 1)]),
            None
        )) <= u64::from(compute_unit_limit(InstructionTag::SetCoSigner))
    );
    assert!(
        consumed(create_key_registry_root_fixture(None))
            <= u64::from(compute_unit_limit(InstructionTag::CreateKeyRegistryRoot))
    );
    for reader in [ed25519_reader(7), p256_reader()] {
        assert!(
            consumed(grant_read_access_fixture(&reader))
                <= u64::from(compute_unit_limit(InstructionTag::GrantReadAccess))
        );
        assert!(
            consumed(revoke_read_access_fixture(&reader))
                <= u64::from(compute_unit_limit(InstructionTag::GrantReadAccess))
        );
    }
}
