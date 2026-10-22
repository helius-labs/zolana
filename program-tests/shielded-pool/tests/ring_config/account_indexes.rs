//! The account positions a ring program reads from SPP's ring account lists.

use pinocchio::AccountView;
use shielded_pool_program::{
    instructions::settlement::Settlement,
    testing::{DepositAccounts, MergeRingAccounts},
};
use shielded_pool_tests::support::transact::{ring_config_view, TEST_RING_CONFIG};
use zolana_account_checks::account_info::test_account_info::get_account_view;
use zolana_interface::{
    instruction::DepositAssetKind, RING_DEPOSIT_DEPOSITOR_INDEX, RING_DEPOSIT_RING_CONFIG_INDEX,
    RING_MERGE_PAYER_INDEX, RING_MERGE_RING_CONFIG_INDEX, SHIELDED_POOL_PROGRAM_ID, SOL_INTERFACE,
};

const POOL: [u8; 32] = SHIELDED_POOL_PROGRAM_ID;

fn writable(address: [u8; 32], owner: [u8; 32]) -> AccountView {
    get_account_view(address, owner, false, true, false, vec![])
}

fn program(address: [u8; 32]) -> AccountView {
    get_account_view(address, [0; 32], false, false, true, vec![])
}

fn addresses(accounts: &[AccountView]) -> Vec<[u8; 32]> {
    accounts
        .iter()
        .map(|account| account.address().to_bytes())
        .collect()
}

#[test]
fn merge_ring_accounts_sit_where_the_ring_program_reads_them() {
    let mut accounts = vec![
        writable([1; 32], POOL),
        writable([2; 32], POOL),
        program([0; 32]),
        program(POOL),
        writable([5; 32], POOL),
    ];
    accounts.insert(RING_MERGE_RING_CONFIG_INDEX, ring_config_view([3; 32]));
    accounts.insert(
        RING_MERGE_PAYER_INDEX,
        get_account_view([4; 32], [0; 32], true, true, false, vec![]),
    );
    let addresses = addresses(&accounts);
    let parsed = MergeRingAccounts::validate_and_parse(&mut accounts, 1, None).unwrap();
    assert_eq!(parsed.ring_program_id, TEST_RING_CONFIG.program_id);
    assert_eq!(
        parsed.payer.address().to_bytes(),
        addresses[RING_MERGE_PAYER_INDEX]
    );
}

#[test]
fn ring_deposit_accounts_sit_where_the_ring_program_reads_them() {
    let mut accounts = vec![
        writable([1; 32], POOL),
        program(POOL),
        program([0; 32]),
        writable(SOL_INTERFACE, [0; 32]),
    ];
    accounts.insert(
        RING_DEPOSIT_DEPOSITOR_INDEX,
        get_account_view([4; 32], [0; 32], true, true, false, vec![]),
    );
    accounts.insert(RING_DEPOSIT_RING_CONFIG_INDEX, ring_config_view([3; 32]));
    let addresses = addresses(&accounts);
    let (parsed, ring_program_id) = DepositAccounts::validate_and_parse::<true>(
        &POOL.into(),
        &mut accounts,
        &[DepositAssetKind::Sol],
    )
    .unwrap();
    assert_eq!(
        ring_program_id,
        Some(TEST_RING_CONFIG.program_id.to_bytes())
    );
    let Settlement::SolDeposit(sol) = &parsed.groups[0].settlement else {
        panic!("a SOL deposit group");
    };
    assert_eq!(
        sol.recipient_account.address().to_bytes(),
        addresses[RING_DEPOSIT_DEPOSITOR_INDEX]
    );
}
