use solana_keypair::Keypair;
use solana_signer::Signer;
use zolana_interface::pda;
use zolana_test_utils::litesvm_asserts::litesvm_assert_protocol_config;

use crate::common::program_test;

#[test]
fn protocol_config_creation_succeeds_for_prefunded_pda() {
    let mut prefunded_rpc = program_test();
    let prefunded = pda::protocol_config();
    prefunded_rpc
        .airdrop(&prefunded, 1_000_000)
        .expect("prefund config PDA");
    let prefunded_authority = Keypair::new();
    let created = prefunded_rpc
        .create_protocol_config(&prefunded_authority)
        .expect("create config over prefunded PDA");
    assert_eq!(created, prefunded);
    litesvm_assert_protocol_config(&prefunded_rpc, &created, &prefunded_authority.pubkey());
}
