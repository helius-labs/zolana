use zolana_keypair::{
    merge::{merge_dummy_nullifier, merge_output_blinding},
    random_blinding, NullifierKey, ViewingKey,
};

use crate::KeypairWorld;

pub(crate) fn ecdh_symmetric(world: &mut KeypairWorld, a: String, b: String) {
    assert_eq!(
        world.vk(&a).ecdh(&world.vk(&b).pubkey()).unwrap(),
        world.vk(&b).ecdh(&world.vk(&a).pubkey()).unwrap()
    );
}

pub(crate) fn viewing_roundtrip(world: &mut KeypairWorld, name: String) {
    let vk = world.vk(&name);
    let bytes = vk.secret_bytes();
    let restored = ViewingKey::from_bytes(&bytes).unwrap();
    assert_eq!(vk.pubkey(), restored.pubkey());
    assert_eq!(*bytes, *restored.secret_bytes());
}

pub(crate) fn tags_advance(world: &mut KeypairWorld, name: String) {
    let vk = world.vk(&name);
    assert_eq!(
        vk.get_sender_view_tag(0).unwrap(),
        vk.get_sender_view_tag(0).unwrap()
    );
    assert_ne!(
        vk.get_sender_view_tag(0).unwrap(),
        vk.get_sender_view_tag(1).unwrap()
    );
    assert_ne!(
        vk.get_recipient_request_view_tag(0).unwrap(),
        vk.get_recipient_request_view_tag(1).unwrap()
    );
    assert_ne!(
        vk.get_sender_view_tag(0).unwrap(),
        vk.get_recipient_request_view_tag(0).unwrap()
    );
    assert_eq!(vk.get_sender_view_tag(0).unwrap()[0], 0);
    assert_eq!(vk.get_recipient_request_view_tag(0).unwrap()[0], 0);
}

/// The merged output is indexed by the first input nullifier: its blinding is
/// derived deterministically from the owner's nullifier secret and that
/// nullifier, so the owner recovers the output without a published merge view
/// tag (removed with `merge_view_tag`).
pub(crate) fn merge_tags_advance(_world: &mut KeypairWorld, _name: String) {
    let nullifier_key = NullifierKey::from_secret(random_blinding()[1..].try_into().unwrap());
    let first_nullifier = random_blinding();
    let other_nullifier = random_blinding();
    let base = merge_output_blinding(&nullifier_key, &first_nullifier).unwrap();
    assert_eq!(
        base,
        merge_output_blinding(&nullifier_key, &first_nullifier).unwrap()
    );
    assert_ne!(
        base,
        merge_output_blinding(&nullifier_key, &other_nullifier).unwrap()
    );
    // The dummy slot nullifiers derive from the same secret, per slot index.
    let dummy_0 = merge_dummy_nullifier(&nullifier_key, &first_nullifier, 0).unwrap();
    assert_eq!(
        dummy_0,
        merge_dummy_nullifier(&nullifier_key, &first_nullifier, 0).unwrap()
    );
    assert_ne!(
        dummy_0,
        merge_dummy_nullifier(&nullifier_key, &first_nullifier, 1).unwrap()
    );
}

pub(crate) fn shared_tag_symmetric(
    world: &mut KeypairWorld,
    sender: String,
    recipient: String,
    i: u64,
) {
    let send = world
        .vk(&sender)
        .get_send_shared_view_tag(&world.vk(&recipient).pubkey(), i)
        .unwrap();
    let recv = world
        .vk(&recipient)
        .get_recipient_shared_view_tag(&world.vk(&sender).pubkey(), i)
        .unwrap();
    assert_eq!(send, recv);
    assert_eq!(send[0], 0);
}

pub(crate) fn shared_tag_per_index(
    world: &mut KeypairWorld,
    sender: String,
    recipient: String,
    i: u64,
    j: u64,
) {
    let recipient_pubkey = world.vk(&recipient).pubkey();
    let ti = world
        .vk(&sender)
        .get_send_shared_view_tag(&recipient_pubkey, i)
        .unwrap();
    let tj = world
        .vk(&sender)
        .get_send_shared_view_tag(&recipient_pubkey, j)
        .unwrap();
    assert_ne!(ti, tj);
}

pub(crate) fn bootstrap_tag(world: &mut KeypairWorld, name: String) {
    let vk = world.vk(&name);
    assert_eq!(vk.recipient_bootstrap_view_tag(), vk.pubkey().x());
}

pub(crate) fn tx_key_deterministic(world: &mut KeypairWorld, name: String) {
    let vk = world.vk(&name);
    let k1 = vk.get_transaction_viewing_key(&[3u8; 32]).unwrap();
    let k2 = vk.get_transaction_viewing_key(&[3u8; 32]).unwrap();
    assert_eq!(k1.pubkey(), k2.pubkey());
    let other = vk.get_transaction_viewing_key(&[4u8; 32]).unwrap();
    assert_ne!(k1.pubkey(), other.pubkey());
}

pub(crate) fn p_const_matches(_world: &mut KeypairWorld) {
    use p256::{
        elliptic_curve::{
            hash2curve::{ExpandMsgXmd, GroupDigest},
            sec1::ToEncodedPoint,
        },
        NistP256,
    };
    use sha2::Sha256;
    use zolana_keypair::constants::{DST_VIEW_ROOT_P_CONST, P_CONST_SEC1};

    let point = NistP256::hash_from_bytes::<ExpandMsgXmd<Sha256>>(&[b""], &[DST_VIEW_ROOT_P_CONST])
        .unwrap();
    let sec1 = point.to_affine().to_encoded_point(true);
    assert_eq!(sec1.as_bytes(), P_CONST_SEC1);
}

pub(crate) fn sender_view_tag_golden(
    world: &mut KeypairWorld,
    name: String,
    counter: u64,
    expected: String,
) {
    let tag = world.vk(&name).get_sender_view_tag(counter).unwrap();
    assert_eq!(hex::encode(tag), expected);
}
