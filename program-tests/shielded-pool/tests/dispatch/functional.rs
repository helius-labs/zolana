use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use zolana_interface::instruction::tag;

use shielded_pool_tests::support::runtime::program_test;
use zolana_program_test::ZolanaProgramTest;

#[test]
fn direct_emit_event_is_a_noop_and_is_not_indexed() {
    let mut rpc = program_test();
    let outcome = rpc
        .create_and_send_default_payer_transaction(
            &[Instruction {
                program_id: rpc.program_id,
                accounts: vec![],
                data: vec![tag::EMIT_EVENT],
            }],
            &[],
        )
        .expect("emit-event no-op");
    assert!(outcome.events.is_empty());
    assert!(rpc.indexer().utxos().is_empty());
}

/// INV-EMIT-EVENT-01 frame: EmitEvent with writable funded accounts attached
/// leaves every account's lamports and data byte-for-byte unchanged -- a state
/// change here would be an arbitrary-write primitive.
#[test]
fn direct_emit_event_leaves_attached_writable_accounts_untouched() {
    let mut rpc = program_test();
    let system_owned = Pubkey::new_unique();
    rpc.airdrop(&system_owned, 3_000_000).expect("fund account");
    let program_owned = Pubkey::new_unique();
    rpc.svm
        .set_account(
            program_owned,
            Account {
                lamports: 2_000_000,
                data: vec![0xC3; 64],
                owner: rpc.program_id,
                executable: false,
                rent_epoch: 0,
            },
        )
        .expect("write program-owned account");
    let system_owned_before = observable_state(&mut rpc, &system_owned);
    let program_owned_before = observable_state(&mut rpc, &program_owned);

    let outcome = rpc
        .create_and_send_default_payer_transaction(
            &[Instruction {
                program_id: rpc.program_id,
                accounts: vec![
                    AccountMeta::new(system_owned, false),
                    AccountMeta::new(program_owned, false),
                ],
                data: vec![tag::EMIT_EVENT, 7, 7, 7],
            }],
            &[],
        )
        .expect("emit-event with writable accounts");
    assert!(outcome.events.is_empty());
    assert_eq!(
        observable_state(&mut rpc, &system_owned),
        system_owned_before,
        "system-owned account must be untouched"
    );
    assert_eq!(
        observable_state(&mut rpc, &program_owned),
        program_owned_before,
        "program-owned account must be untouched"
    );
}

fn observable_state(rpc: &mut ZolanaProgramTest, address: &Pubkey) -> (u64, Vec<u8>, Pubkey, bool) {
    let account = rpc.svm.get_account(address).expect("account");
    (
        account.lamports,
        account.data,
        account.owner,
        account.executable,
    )
}

/// INV-EMIT-EVENT-02: every payload byte string after the tag is accepted --
/// the payload is never parsed on-chain.
#[test]
fn direct_emit_event_accepts_every_payload_shape() {
    let mut rpc = program_test();
    let large: Vec<u8> = (0..1024u32)
        .map(|i| (i.wrapping_mul(31) % 251) as u8)
        .collect();
    for payload in [Vec::new(), vec![0xFF], large] {
        let mut data = vec![tag::EMIT_EVENT];
        data.extend_from_slice(&payload);
        rpc.create_and_send_default_payer_transaction(
            &[Instruction {
                program_id: rpc.program_id,
                accounts: vec![],
                data,
            }],
            &[],
        )
        .unwrap_or_else(|err| {
            panic!(
                "emit-event must accept a {}-byte payload: {err:?}",
                payload.len()
            )
        });
    }
    assert!(rpc.indexer().utxos().is_empty());
}
