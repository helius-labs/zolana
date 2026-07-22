use solana_keypair::Keypair;
use solana_signer::Signer;
use zolana_interface::{instruction::UpdateProtocolConfigData, pda};
use zolana_program_test::ZolanaProgramTest;

#[test]
fn create_and_update_protocol_config() {
    let mut backend = ZolanaProgramTest::new().expect("program test");
    let authority = Keypair::new();
    assert!(backend.account_data(&pda::protocol_config()).is_none());
    backend
        .create_protocol_config(&authority)
        .expect("create protocol config");
    assert!(backend.account_data(&pda::protocol_config()).is_some());

    let next_forester = Keypair::new();
    backend
        .send_protocol_config_update(
            &authority,
            UpdateProtocolConfigData::ForesterAuthority(next_forester.pubkey().to_bytes().into()),
        )
        .expect("update forester authority");
    assert!(backend
        .last_transaction_trace()
        .expect("update trace")
        .changed_accounts()
        .any(|account| account.address == pda::protocol_config()));
}
