//! Address inputs: the derivation matches the on-chain `NewAddress`, and every
//! field rule is refused with its own reason.
use solana_address::Address;
use zolana_keypair::{PublicKey, ShieldedKeypair, SigningKey};
use zolana_program::compression::{AddressSeed, NewAddress, PdaOwner};
use zolana_transaction::{
    utxo::SppProofInputUtxo, AddressInputError as A, Mint, TransactionError as E,
};

const SEED: [u8; 32] = [7; 32];

fn keypair(seed: u8) -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32])).unwrap()
}

fn flip_last(bytes: &mut [u8; 32]) {
    if let Some(byte) = bytes.last_mut() {
        *byte ^= 1;
    }
}
const TREE: u16 = 3;

fn address() -> SppProofInputUtxo {
    SppProofInputUtxo::new_address(keypair(1).signing_pubkey(), SEED, TREE).unwrap()
}

type Mutation = fn(&mut SppProofInputUtxo);

fn p256_owner() -> PublicKey {
    ShieldedKeypair::from_keypair(SigningKey::from_p256_bytes(&[3; 32]).unwrap())
        .unwrap()
        .signing_pubkey()
}

fn refused(reason: A) -> Result<(), E> {
    Err(E::InvalidAddressInput(reason))
}

/// The client derivation and the program's `NewAddress::derive` agree on the
/// slot's UTXO hash and on the address (the slot's nullifier), for a PDA owner
/// and for an Ed25519 owner, whose identity hashes the same way.
#[test]
fn address_matches_the_canonical_new_address_derivation() {
    let pda = Address::new_from_array([9; 32]);
    let ed25519 = keypair(1);
    let ed25519_address = Address::new_from_array(
        ed25519
            .signing_pubkey()
            .as_ed25519()
            .expect("ed25519 owner"),
    );
    for (owner, owner_address) in [
        (PublicKey::from_pda(&pda), pda),
        (ed25519.signing_pubkey(), ed25519_address),
    ] {
        for tree_id in [0u16, TREE, u16::MAX] {
            let input = SppProofInputUtxo::new_address(owner, SEED, tree_id).unwrap();
            let canonical = NewAddress::derive(
                &PdaOwner::new(&owner_address).unwrap(),
                AddressSeed::new(SEED).unwrap(),
                tree_id,
            )
            .unwrap();
            assert_eq!(
                (input.utxo_hash, input.nullifier),
                (*canonical.utxo_hash(), *canonical.address())
            );
        }
    }
}

#[test]
fn new_address_refuses_a_missing_or_p256_owner_and_a_non_canonical_seed() {
    let owner = keypair(1).signing_pubkey();
    let result = |owner: PublicKey, seed: [u8; 32]| {
        SppProofInputUtxo::new_address(owner, seed, TREE).map(|_| ())
    };
    assert_eq!(result(PublicKey::zeroed(), SEED), refused(A::MissingOwner));
    assert_eq!(result(p256_owner(), SEED), refused(A::P256Owner));
    assert_eq!(result(owner, [0xff; 32]), refused(A::NonCanonicalSeed));
    assert_eq!(result(owner, SEED), Ok(()));
}

/// Each case changes one field of a valid address, so each refusal comes from
/// the rule that field breaks.
#[test]
fn validate_address_names_the_broken_rule() {
    let cases: Vec<(A, Mutation)> = vec![
        (A::NotAnAddress, |input| input.address = false),
        (A::MissingOwner, |input| {
            input.utxo.owner = PublicKey::zeroed()
        }),
        (A::P256Owner, |input| input.utxo.owner = p256_owner()),
        (A::NonCanonicalSeed, |input| {
            input.utxo.blinding = [0xff; 32]
        }),
        (A::NonZeroNullifierKey, |input| {
            input.nullifier_pubkey = [1; 32]
        }),
        (A::NonZeroAmount, |input| input.utxo.amount = 1),
        (A::NonZeroAsset, |input| {
            input.utxo.asset = Mint {
                asset: Address::new_from_array([4; 32]),
                asset_id: 4,
            }
        }),
        (A::CarriesData, |input| input.data_hash = Some([1; 32])),
        (A::CarriesRing, |input| {
            input.utxo.ring_program_id = Some(Address::new_from_array([5; 32]))
        }),
        (A::CarriesRing, |input| input.ring_data_hash = Some([1; 32])),
        (A::Compact, |input| input.compact = true),
        (A::CacheSlot, |input| input.cache_slot = Some(0)),
        (A::NonZeroLeafIndex, |input| input.leaf_index = 1),
        (A::HashMismatch, |input| flip_last(&mut input.utxo_hash)),
        (A::NullifierMismatch, |input| {
            flip_last(&mut input.nullifier)
        }),
        (A::HashMismatch, |input| input.tree_id = TREE + 1),
    ];
    assert_eq!(address().validate_address(), Ok(()));
    for (reason, mutate) in cases {
        let mut input = address();
        mutate(&mut input);
        assert_eq!(input.validate_address(), refused(reason), "{reason:?}");
    }
}

#[test]
fn an_address_cannot_take_a_cache_slot() {
    assert_eq!(
        address().with_cache_slot(0).map(|_| ()),
        refused(A::CacheSlot)
    );
}
