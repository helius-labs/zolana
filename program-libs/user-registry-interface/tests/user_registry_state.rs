use borsh::to_vec;
use zolana_user_registry_interface::UserRecord;

#[test]
fn size_covers_max_serialized_size() {
    let record = UserRecord {
        owner: [7u8; 32].into(),
        bump: 254,
        owner_p256: Some([2u8; 33]),
        nullifier_pubkey: [9u8; 32],
        viewing_pubkey: [3u8; 33],
        merging_enabled: true,
    };
    let body = to_vec(&record).unwrap();
    assert_eq!(UserRecord::DISCRIMINATOR_LEN + body.len(), UserRecord::SIZE);
}
