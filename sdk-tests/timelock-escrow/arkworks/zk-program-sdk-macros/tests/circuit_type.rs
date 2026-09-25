use borsh::{BorshDeserialize, BorshSerialize};
use zk_program_sdk::{
    circuit::{CircuitType, DataHash, UtxoData},
    conversion::{to_bytes, Allocator, FromCircuit, ProofInput},
    hasher::{state_discriminator, DataHasher, Discriminator, Hasher, Poseidon},
    Owner,
};
use zolana_hasher::primitives::right_align;
use zolana_keypair::{ShieldedKeypair, SigningKey};

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, CircuitType)]
struct Limits {
    daily: u64,
    frozen: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, CircuitType)]
struct Portfolio {
    owner: Owner,
    nonce: u32,
    limits: Limits,
    balances: [u64; 3],
    label: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, CircuitType)]
struct Issuer {
    value: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, CircuitType)]
struct Credential {
    value: u64,
}

fn native<T: ProofInput>(value: &T) -> T::Circuit {
    value
        .instantiate(&Allocator::native())
        .expect("native instantiation")
}

fn circuit_hash<T: DataHash>(state: &T) -> [u8; 32] {
    to_bytes(&DataHash::hash(state).expect("circuit hash")).expect("hash bytes")
}

fn byte_hash<T: DataHasher>(state: &T) -> [u8; 32] {
    DataHasher::hash::<Poseidon>(state).expect("byte hash")
}

fn portfolio() -> Portfolio {
    let address = ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[5u8; 32]))
        .expect("keypair")
        .shielded_address()
        .expect("address");
    Portfolio {
        owner: Owner::try_from(&address).expect("owner"),
        nonce: 4,
        limits: Limits {
            daily: 1_000,
            frozen: true,
        },
        balances: [10, 20, 30],
        label: [7u8; 32],
    }
}

#[test]
fn the_discriminator_is_the_sha256_prefix_of_the_state_name() {
    assert_eq!(
        Limits::DISCRIMINATOR,
        state_discriminator("Limits").expect("discriminator")
    );
    assert_eq!(
        Portfolio::DISCRIMINATOR,
        state_discriminator("Portfolio").expect("discriminator")
    );
}

#[test]
fn the_circuit_hash_is_poseidon_over_the_discriminator_then_the_fields() {
    let limits = Limits {
        daily: 1_000,
        frozen: true,
    };
    let expected = Poseidon::hashv(&[
        &right_align(&Limits::DISCRIMINATOR),
        &right_align(&1_000u64.to_be_bytes()),
        &right_align(&[1u8]),
    ])
    .expect("poseidon");
    assert_eq!(circuit_hash(&native(&limits)), expected);
}

#[test]
fn the_circuit_and_byte_hashes_agree_for_a_nested_state() {
    let portfolio = portfolio();
    assert_eq!(circuit_hash(&native(&portfolio)), byte_hash(&portfolio));
}

#[test]
fn the_default_state_is_the_zero_state() {
    let zero = Portfolio {
        owner: Owner {
            tag: 0,
            key: [0u8; 32],
            nullifier_pk: [0u8; 32],
        },
        nonce: 0,
        limits: Limits {
            daily: 0,
            frozen: false,
        },
        balances: [0; 3],
        label: [0u8; 32],
    };
    assert_eq!(circuit_hash(&PortfolioCircuit::default()), byte_hash(&zero));
}

#[test]
fn from_circuit_maps_every_field_back() {
    let portfolio = portfolio();
    assert_eq!(
        Portfolio::from_circuit(&native(&portfolio)).expect("from circuit"),
        portfolio
    );
}

#[test]
fn utxo_data_is_the_borsh_encoding_of_the_state() {
    let portfolio = portfolio();
    assert_eq!(
        native(&portfolio).utxo_data().expect("utxo data"),
        borsh::to_vec(&portfolio).expect("borsh")
    );
}

#[test]
fn states_with_the_same_fields_never_share_a_hash() {
    assert_ne!(
        circuit_hash(&native(&Issuer { value: 3 })),
        circuit_hash(&native(&Credential { value: 3 }))
    );
}

#[test]
fn twins_of_states_are_circuit_types() {
    fn assert_circuit_type<T: zk_program_sdk::circuit::CircuitType>() {}
    assert_circuit_type::<PortfolioCircuit>();
    assert_circuit_type::<LimitsCircuit>();
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn the_discriminator_and_the_state_hash_are_pinned() {
    assert_eq!(hex(&Limits::DISCRIMINATOR), "b15b5ef11321b302");
    let limits = Limits {
        daily: 1_000,
        frozen: true,
    };
    let limits_hash = "22a26bb261e683e5911ed5a0de951aa45c21df8e1c02da1a8317e4b0e9f959c0";
    assert_eq!(hex(&byte_hash(&limits)), limits_hash);
    assert_eq!(hex(&circuit_hash(&native(&limits))), limits_hash);
}
