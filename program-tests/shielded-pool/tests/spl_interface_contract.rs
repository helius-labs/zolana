use zolana_interface::pda;
use zolana_test_utils::backend::LiteSvmPoolBackend;

#[test]
fn asset_counter_assigns_distinct_canonical_interfaces() {
    let mut backend = LiteSvmPoolBackend::initialized();
    backend
        .rpc
        .create_asset_counter(&backend.authority)
        .expect("create asset counter");
    assert!(backend
        .rpc
        .account_data(&pda::spl_asset_counter())
        .is_some());

    let first = backend.rpc.create_mint().expect("first mint");
    let second = backend.rpc.create_mint().expect("second mint");
    let first_accounts = backend
        .rpc
        .create_spl_interface(&backend.authority, &first)
        .expect("first interface");
    let second_accounts = backend
        .rpc
        .create_spl_interface(&backend.authority, &second)
        .expect("second interface");
    assert_ne!(first_accounts, second_accounts);
    for address in [
        pda::spl_asset_registry(&first),
        pda::spl_asset_vault(&first),
        pda::spl_asset_registry(&second),
        pda::spl_asset_vault(&second),
    ] {
        assert!(
            backend.rpc.account_data(&address).is_some(),
            "missing {address}"
        );
    }
}
