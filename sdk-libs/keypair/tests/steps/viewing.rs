use cucumber::then;
use zolana_keypair::ViewingKey;

use crate::KeypairWorld;

#[then(expr = "{string} and {string} agree on a shared secret")]
fn ecdh_symmetric(world: &mut KeypairWorld, a: String, b: String) {
    assert_eq!(
        world.vk(&a).ecdh(&world.vk(&b).pubkey()),
        world.vk(&b).ecdh(&world.vk(&a).pubkey())
    );
}

#[then(expr = "viewing key {string} round-trips through its secret bytes")]
fn viewing_roundtrip(world: &mut KeypairWorld, name: String) {
    let vk = world.vk(&name);
    let bytes = vk.secret_bytes();
    let restored = ViewingKey::from_bytes(&bytes).unwrap();
    assert_eq!(vk.pubkey(), restored.pubkey());
    assert_eq!(*bytes, *restored.secret_bytes());
}

#[then(expr = "sender and request view tags for {string} advance with their counters")]
fn tags_advance(world: &mut KeypairWorld, name: String) {
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
}

#[then(expr = "merge view tags for {string} are namespaced by authority and counter")]
fn merge_tags_namespaced(world: &mut KeypairWorld, name: String) {
    let vk = world.vk(&name);
    let auth_a = [1u8; 33];
    let auth_b = [2u8; 33];
    let base = vk.get_merge_view_tag(&auth_a, 0).unwrap();
    assert_eq!(base, vk.get_merge_view_tag(&auth_a, 0).unwrap());
    assert_ne!(base, vk.get_merge_view_tag(&auth_a, 1).unwrap());
    assert_ne!(base, vk.get_merge_view_tag(&auth_b, 0).unwrap());
}

#[then(expr = "{string} and {string} derive the same shared view tag at index {int}")]
fn shared_tag_symmetric(world: &mut KeypairWorld, sender: String, recipient: String, i: u64) {
    let send = world
        .vk(&sender)
        .get_send_shared_view_tag(&world.vk(&recipient).pubkey(), i)
        .unwrap();
    let recv = world
        .vk(&recipient)
        .get_shared_view_tag(&world.vk(&sender).pubkey(), i)
        .unwrap();
    assert_eq!(send, recv);
}

#[then(
    expr = "{string} derives different shared view tags toward {string} at indices {int} and {int}"
)]
fn shared_tag_per_index(
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

#[then(expr = "the bootstrap tag of {string} is its viewing public key x-coordinate")]
fn bootstrap_tag(world: &mut KeypairWorld, name: String) {
    let vk = world.vk(&name);
    assert_eq!(vk.recipient_bootstrap_view_tag(), vk.pubkey().x());
}

#[then(expr = "the transaction viewing key of {string} is deterministic per first nullifier")]
fn tx_key_deterministic(world: &mut KeypairWorld, name: String) {
    let vk = world.vk(&name);
    let k1 = vk.get_transaction_viewing_key(&[3u8; 32]).unwrap();
    let k2 = vk.get_transaction_viewing_key(&[3u8; 32]).unwrap();
    assert_eq!(k1.pubkey(), k2.pubkey());
    let other = vk.get_transaction_viewing_key(&[4u8; 32]).unwrap();
    assert_ne!(k1.pubkey(), other.pubkey());
}
