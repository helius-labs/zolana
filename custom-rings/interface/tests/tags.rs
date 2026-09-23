use custom_ring_interface::tag;

#[test]
fn ring_dispatch_tags_do_not_collide_with_forwarded_spp_tags() {
    let tags = [
        tag::CREATE_CONFIG,
        tag::INIT_SPP_RING_CONFIG,
        tag::TRANSACT,
        tag::DEPOSIT,
        tag::MERGE,
        tag::GRANT_READ_ACCESS,
        tag::REVOKE_READ_ACCESS,
        tag::SET_AUTHORITY,
        tag::CREATE_POLICY,
        tag::CREATE_ENTRY,
        tag::UPDATE_ENTRY,
        tag::SET_POLICY_SOURCE,
        tag::SET_PAUSED,
        tag::SET_POLICY_RULES,
        tag::SET_CO_SIGNER,
        tag::CLEAR_CO_SIGNER,
        tag::SET_SPEND_WINDOW,
        tag::CLEAR_SPEND_WINDOW,
        tag::SET_DELEGATE,
        tag::DELEGATE_TRANSACT,
        tag::REGISTER_SPEND,
        tag::CREATE_KEY_REGISTRY_ROOT,
        tag::REGISTER_KEY,
        tag::SET_DEPOSIT_AUDIT,
        tag::AUDITED_DEPOSIT,
    ];
    let unique: std::collections::BTreeSet<_> = tags.into_iter().collect();
    assert_eq!(unique.len(), tags.len());
    assert_eq!(tag::SET_CO_SIGNER, 28);
}
