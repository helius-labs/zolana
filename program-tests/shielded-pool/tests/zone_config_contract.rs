use solana_keypair::Keypair;
use solana_signer::Signer;
use zolana_test_utils::backend::LiteSvmPoolBackend;

#[test]
fn zone_config_create_update_and_owner_rotation() {
    let mut backend = LiteSvmPoolBackend::initialized();
    backend
        .rpc
        .load_zone_test_program()
        .expect("load zone test program");
    let zone_config = backend
        .rpc
        .create_zone_config(&backend.authority, &backend.authority.pubkey(), true)
        .expect("create zone config");
    backend
        .rpc
        .update_zone_config(&backend.authority, &zone_config, false)
        .expect("disable zone authority execution");
    let next = Keypair::new();
    backend
        .rpc
        .update_zone_config_owner(&backend.authority, &zone_config, &next)
        .expect("rotate zone owner");
    backend
        .rpc
        .update_zone_config(&next, &zone_config, true)
        .expect("new owner update");
}
