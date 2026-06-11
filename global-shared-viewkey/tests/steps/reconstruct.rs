use cucumber::{then, when};
use p256::SecretKey;
use rand::rngs::OsRng;
use zolana_global_shared_viewkey::InnerPolicy;

use crate::GsvkWorld;

#[when(expr = "the authority splits the key {int}-of-{int} with inner policies {string}")]
fn split_the_key(world: &mut GsvkWorld, threshold: u8, entity_count: u8, policies_spec: String) {
    let policies = parse_policies(&policies_spec);
    assert_eq!(
        policies.len(),
        entity_count as usize,
        "policy count must match the outer entity count"
    );
    let setup = world
        .authority
        .as_ref()
        .expect("authority not set")
        .setup(SecretKey::random(&mut OsRng), threshold, policies)
        .expect("setup");
    world.setup = Some(setup);
}

#[when(expr = "each entity returns {string} sub-shares")]
fn each_entity_returns(world: &mut GsvkWorld, counts_spec: String) {
    let counts = parse_counts(&counts_spec);
    let setup = world.setup.as_ref().expect("setup not set");
    world.returned = setup
        .entities
        .iter()
        .zip(counts.iter())
        .map(|(shares, take)| shares.iter().take(*take).cloned().collect())
        .collect();
}

#[then("the key is reconstructed")]
fn key_reconstructed(world: &mut GsvkWorld) {
    let authority = world.authority.as_ref().expect("authority not set");
    let setup = world.setup.as_ref().expect("setup not set");
    let recovered = authority
        .reconstruct(setup, &world.returned)
        .expect("reconstruct");
    assert_eq!(recovered.public_key(), setup.data_pubkey);
}

#[then("reconstruction fails")]
fn reconstruction_fails(world: &mut GsvkWorld) {
    let authority = world.authority.as_ref().expect("authority not set");
    let setup = world.setup.as_ref().expect("setup not set");
    assert!(authority.reconstruct(setup, &world.returned).is_err());
}

fn parse_policies(spec: &str) -> Vec<InnerPolicy> {
    spec.split(',')
        .map(|item| {
            let (t, m) = item
                .trim()
                .split_once("-of-")
                .expect("inner policy must be written as t-of-m");
            InnerPolicy::new(
                t.trim().parse().expect("inner t must be a number"),
                m.trim().parse().expect("inner m must be a number"),
            )
        })
        .collect()
}

fn parse_counts(spec: &str) -> Vec<usize> {
    spec.split(',')
        .map(|n| n.trim().parse().expect("count must be a number"))
        .collect()
}
