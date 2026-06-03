use cucumber::{then, when};
use zolana_keypair::ViewingKey;

use crate::KeypairWorld;

#[then(expr = "{string} and {string} agree on a shared secret")]
fn ecdh_symmetric(world: &mut KeypairWorld, a: String, b: String) {
    assert_eq!(
        world.vk(&a).ecdh(&world.vk(&b).viewing_pubkey()),
        world.vk(&b).ecdh(&world.vk(&a).viewing_pubkey())
    );
}

#[then(expr = "viewing key {string} round-trips through its secret bytes")]
fn viewing_roundtrip(world: &mut KeypairWorld, name: String) {
    let vk = world.vk(&name);
    let bytes = vk.secret_bytes();
    let restored = ViewingKey::from_bytes(&bytes).unwrap();
    assert_eq!(vk.viewing_pubkey(), restored.viewing_pubkey());
    assert_eq!(*bytes, *restored.secret_bytes());
}

#[then(expr = "viewing key {string} derives four distinct, stable secrets")]
fn four_distinct_secrets(world: &mut KeypairWorld, name: String) {
    let vk = world.vk(&name);
    assert_eq!(
        vk.sender_view_tag_secret().unwrap(),
        vk.sender_view_tag_secret().unwrap()
    );
    let secrets = [
        vk.sender_view_tag_secret().unwrap(),
        vk.recipient_view_tag_secret().unwrap(),
        vk.merge_view_tag_secret().unwrap(),
        vk.tx_viewing_secret().unwrap(),
    ];
    for i in 0..secrets.len() {
        for j in (i + 1)..secrets.len() {
            assert_ne!(secrets[i], secrets[j]);
        }
    }
}

#[then(expr = "{string} and {string} derive different sender view-tag secrets")]
fn distinct_sender_secrets(world: &mut KeypairWorld, a: String, b: String) {
    assert_ne!(
        world.vk(&a).sender_view_tag_secret().unwrap(),
        world.vk(&b).sender_view_tag_secret().unwrap()
    );
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
        .get_send_shared_view_tag(&world.vk(&recipient).viewing_pubkey(), i)
        .unwrap();
    let recv = world
        .vk(&recipient)
        .get_shared_view_tag(&world.vk(&sender).viewing_pubkey(), i)
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
    let recipient_pubkey = world.vk(&recipient).viewing_pubkey();
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
    assert_eq!(vk.recipient_bootstrap_view_tag(), vk.viewing_pubkey().x());
}

#[then(expr = "the transaction viewing key of {string} is deterministic per first nullifier")]
fn tx_key_deterministic(world: &mut KeypairWorld, name: String) {
    let vk = world.vk(&name);
    let k1 = vk.get_transaction_viewing_key(&[3u8; 32]).unwrap();
    let k2 = vk.get_transaction_viewing_key(&[3u8; 32]).unwrap();
    assert_eq!(k1.viewing_pubkey(), k2.viewing_pubkey());
    let other = vk.get_transaction_viewing_key(&[4u8; 32]).unwrap();
    assert_ne!(k1.viewing_pubkey(), other.viewing_pubkey());
}

#[when(expr = "{string} derives a transaction viewing key {string} from nullifier {int}")]
fn derive_tx_key(world: &mut KeypairWorld, src: String, dst: String, n: u8) {
    let tx = world
        .vk(&src)
        .get_transaction_viewing_key(&[n; 32])
        .unwrap();
    world.viewing.insert(dst, tx);
}

#[when(expr = "{string} encrypts {string} to {string} as {string}")]
fn encrypt_to(
    world: &mut KeypairWorld,
    src: String,
    plaintext: String,
    recipient: String,
    dst: String,
) {
    let ct = world
        .vk(&src)
        .encrypt(&world.vk(&recipient).viewing_pubkey(), plaintext.as_bytes())
        .unwrap();
    world.bytes.insert(dst, ct);
}

#[when(expr = "{string} encrypts {string} to {string} with info {string} as {string}")]
fn encrypt_to_with_info(
    world: &mut KeypairWorld,
    src: String,
    plaintext: String,
    recipient: String,
    info: String,
    dst: String,
) {
    let ct = world
        .vk(&src)
        .encrypt_with(
            &world.vk(&recipient).viewing_pubkey(),
            plaintext.as_bytes(),
            info.as_bytes(),
            &[],
        )
        .unwrap();
    world.bytes.insert(dst, ct);
}

#[when(expr = "{string} encrypts {string} to {string} with aad {string} as {string}")]
fn encrypt_to_with_aad(
    world: &mut KeypairWorld,
    src: String,
    plaintext: String,
    recipient: String,
    aad: String,
    dst: String,
) {
    let ct = world
        .vk(&src)
        .encrypt_with(
            &world.vk(&recipient).viewing_pubkey(),
            plaintext.as_bytes(),
            b"TSPP/tx",
            aad.as_bytes(),
        )
        .unwrap();
    world.bytes.insert(dst, ct);
}

#[then(expr = "{string} decrypts {string} from {string} as {string}")]
fn decrypts_to(
    world: &mut KeypairWorld,
    recipient: String,
    ct: String,
    tx: String,
    expected: String,
) {
    let pt = world
        .vk(&recipient)
        .decrypt(&world.buf(&ct), &world.vk(&tx).viewing_pubkey())
        .unwrap();
    assert_eq!(pt, expected.as_bytes());
}

#[then(expr = "{string} cannot decrypt {string} from {string}")]
fn cannot_decrypt(world: &mut KeypairWorld, recipient: String, ct: String, tx: String) {
    assert!(world
        .vk(&recipient)
        .decrypt(&world.buf(&ct), &world.vk(&tx).viewing_pubkey())
        .is_err());
}

#[then(expr = "a tampered {string} cannot be decrypted by {string} from {string}")]
fn tampered_cannot_decrypt(world: &mut KeypairWorld, ct: String, recipient: String, tx: String) {
    let mut bytes = world.buf(&ct);
    bytes[0] ^= 0xff;
    assert!(world
        .vk(&recipient)
        .decrypt(&bytes, &world.vk(&tx).viewing_pubkey())
        .is_err());
}

#[then(expr = "{string} cannot decrypt {string} from {string} with info {string}")]
fn cannot_decrypt_info(
    world: &mut KeypairWorld,
    recipient: String,
    ct: String,
    tx: String,
    info: String,
) {
    assert!(world
        .vk(&recipient)
        .decrypt_with(
            &world.buf(&ct),
            &world.vk(&tx).viewing_pubkey(),
            info.as_bytes(),
            &[],
        )
        .is_err());
}

#[then(expr = "{string} cannot decrypt {string} from {string} with aad {string}")]
fn cannot_decrypt_aad(
    world: &mut KeypairWorld,
    recipient: String,
    ct: String,
    tx: String,
    aad: String,
) {
    assert!(world
        .vk(&recipient)
        .decrypt_with(
            &world.buf(&ct),
            &world.vk(&tx).viewing_pubkey(),
            b"TSPP/tx",
            aad.as_bytes(),
        )
        .is_err());
}

#[then(expr = "{string} encrypting {string} to {string} yields ciphertext {string}")]
fn kem_golden(
    world: &mut KeypairWorld,
    eph: String,
    plaintext: String,
    rcpt: String,
    expected: String,
) {
    let ct = world
        .vk(&eph)
        .encrypt(&world.vk(&rcpt).viewing_pubkey(), plaintext.as_bytes())
        .unwrap();
    assert_eq!(hex::encode(&ct), expected);
}
