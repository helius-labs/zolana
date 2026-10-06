use super::*;

use zolana_client::{
    user_registry::{fetch_user_record_checked, register_if_absent, StrictRegistration},
    IndexerRpcConfig,
};

/// Photon does not index the registry: `getUserRecords` reads the owners'
/// record accounts from the validator at one slot and reports that slot as its
/// context, so a record is served as soon as its registration confirms, with
/// no indexing lag to wait out.
#[test]
#[serial]
fn registered_user_record_is_served_by_photon() -> TestResult {
    restart_localnet();

    let mut rpc = SolanaRpc::new(zolana_test_utils::localnet::localnet_rpc_url());
    let indexer = ZolanaIndexer::new(zolana_test_utils::localnet::localnet_indexer_url());

    let owner = Keypair::new();
    rpc.airdrop(&owner.pubkey(), 1_000_000_000)?;
    let shielded = shielded_ed25519_from_solana(&owner)?;
    let StrictRegistration::Written(signature) = register_if_absent(&rpc, &owner, &shielded)?
    else {
        return Err(anyhow!(
            "a fresh localnet owner cannot already hold a record"
        ));
    };
    let registered_slot = wait_for("registration status", || {
        Ok(rpc
            .get_signature_statuses(vec![signature])?
            .into_iter()
            .flatten()
            .next()
            .map(|status| status.slot))
    })?;

    // A full batch of unregistered owners ahead of the registered one pins the
    // null entries, request order, and the two-call read a full batch takes.
    let mut owners = (1..zolana_client::MAX_USER_RECORD_OWNERS)
        .map(|_| Address::new_from_array(Keypair::new().pubkey().to_bytes()))
        .collect::<Vec<_>>();
    owners.push(Address::new_from_array(owner.pubkey().to_bytes()));
    let response = wait_for("user records", || {
        indexer
            .get_user_records(
                owners.clone(),
                Some(IndexerRpcConfig::at_slot(registered_slot)),
            )
            .map(Some)
    })?;

    assert!(
        response.context.slot >= registered_slot,
        "records read at slot {} predate the registration at slot {registered_slot}",
        response.context.slot
    );
    let on_chain = fetch_user_record_checked(&rpc, owner.pubkey())?;
    let mut expected = vec![None; owners.len() - 1];
    expected.push(Some(on_chain.clone()));
    assert_eq!(response.records, expected);

    let address = shielded.shielded_address()?;
    assert_eq!(on_chain.owner_p256, None);
    assert_eq!(on_chain.nullifier_pubkey, address.nullifier_pubkey);
    assert_eq!(on_chain.viewing_pubkey, *address.viewing_pubkey.as_bytes());
    assert!(!on_chain.merging_enabled);
    Ok(())
}
