use borsh::{BorshDeserialize, BorshSerialize};
use zolana_hasher::primitives::{hash_bytes, right_align};
use zolana_keypair::{ShieldedKeypair, SigningKey};
use zolana_program::{
    circuit::{CircuitType, DataHash, HashBytes, UtxoData, UtxoState},
    conversion::{to_bytes, Allocator, FromCircuit, ProofInput},
    hasher::{
        state_discriminator, DataHasher, Discriminator, Hasher, HasherError, Poseidon, ToByteArray,
    },
    Bytes, EncryptionCodec, UtxoOwner,
};

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, UtxoState)]
struct Limits {
    daily: u64,
    frozen: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, UtxoState)]
struct Portfolio {
    owner: UtxoOwner,
    nonce: u32,
    limits: Limits,
    balances: [u64; 3],
    label: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, UtxoState)]
struct Issuer {
    value: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, UtxoState)]
struct Credential {
    value: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, UtxoState)]
struct AddressState {
    account: solana_address::Address,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, UtxoState)]
struct ByteState {
    data: Bytes<32>,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, CircuitType)]
struct CustomBytes {
    data: Bytes<16>,
}

impl ToByteArray for CustomBytes {
    fn to_byte_array(&self) -> Result<[u8; 32], HasherError> {
        hash_bytes(&self.data.0)
    }
}

impl DataHash for CustomBytesCircuit {
    fn hash(&self) -> Result<zolana_program::circuit::CircuitVar, zolana_program::CircuitError> {
        self.data.hash_bytes()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, UtxoState)]
struct CustomByteState {
    data: CustomBytes,
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
    DataHasher::hash(state).expect("byte hash")
}

fn portfolio() -> Portfolio {
    let address = ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[5u8; 32]))
        .expect("keypair")
        .shielded_address()
        .expect("address");
    Portfolio {
        owner: UtxoOwner::try_from(&address).expect("owner"),
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
fn solana_address_state_preserves_all_bytes_and_matches_the_native_hash() {
    for bytes in [[0u8; 32], [0xff; 32]] {
        let state = AddressState {
            account: solana_address::Address::new_from_array(bytes),
        };
        let circuit = native(&state);
        let _: &zolana_program::circuit::SolanaAddress = &circuit.account;
        assert_eq!(
            (
                AddressState::from_circuit(&circuit).expect("from circuit"),
                circuit_hash(&circuit),
                circuit.utxo_data().expect("utxo data"),
            ),
            (
                state.clone(),
                byte_hash(&state),
                borsh::to_vec(&state).expect("borsh"),
            )
        );
    }
}

#[test]
fn bytes32_state_preserves_all_bytes_and_matches_the_existing_commitment() {
    for bytes in [[0u8; 32], [0xff; 32], core::array::from_fn(|i| i as u8)] {
        let state = ByteState { data: Bytes(bytes) };
        let circuit = native(&state);
        let expected = Poseidon::hashv(&[
            &right_align(&ByteState::DISCRIMINATOR),
            &hash_bytes(&bytes).expect("byte commitment"),
        ])
        .expect("state commitment");
        assert_eq!(
            (
                ByteState::from_circuit(&circuit).expect("from circuit"),
                byte_hash(&state),
                circuit_hash(&circuit),
                circuit.utxo_data().expect("utxo data"),
            ),
            (
                state.clone(),
                expected,
                expected,
                borsh::to_vec(&state).expect("borsh"),
            )
        );
    }
}

#[test]
fn custom_state_fields_can_define_their_own_byte_encoding() {
    let state = CustomByteState {
        data: CustomBytes {
            data: Bytes([0xff; 16]),
        },
    };
    let circuit = native(&state);
    assert_eq!(
        (
            CustomByteState::from_circuit(&circuit).expect("from circuit"),
            circuit_hash(&circuit),
            circuit.utxo_data().expect("utxo data"),
        ),
        (
            state.clone(),
            byte_hash(&state),
            borsh::to_vec(&state).expect("borsh"),
        )
    );
}

#[test]
fn the_default_state_has_zero_values_and_a_valid_owner() {
    let zero = Portfolio {
        owner: UtxoOwner {
            tag: zolana_hasher::primitives::SOLANA_OWNER_TAG,
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
        (
            native(&portfolio).utxo_data().expect("utxo data"),
            portfolio
                .serialize_for_encryption()
                .expect("encryption codec"),
            Portfolio::deserialize_after_decryption(&borsh::to_vec(&portfolio).expect("borsh"))
                .expect("decryption codec"),
        ),
        (
            borsh::to_vec(&portfolio).expect("borsh"),
            borsh::to_vec(&portfolio).expect("borsh"),
            portfolio,
        )
    );
}

#[test]
fn the_default_encryption_codec_rejects_truncated_and_trailing_bytes() {
    let mut bytes = portfolio().serialize_for_encryption().expect("encode");
    assert!(Portfolio::deserialize_after_decryption(&bytes[..bytes.len() - 1]).is_err());
    bytes.push(0);
    assert!(Portfolio::deserialize_after_decryption(&bytes).is_err());
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
    fn assert_circuit_type<T: zolana_program::circuit::CircuitType>() {}
    assert_circuit_type::<PortfolioCircuit>();
    assert_circuit_type::<LimitsCircuit>();
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn the_discriminator_and_the_state_hash_are_pinned() {
    assert_eq!(hex(&Limits::DISCRIMINATOR), "f23695767619b981");
    let limits = Limits {
        daily: 1_000,
        frozen: true,
    };
    let limits_hash = "2365ec38d7481dd3ce2a43ca09f796ead3aec510edace48d3c07065d69a37c14";
    assert_eq!(hex(&byte_hash(&limits)), limits_hash);
    assert_eq!(hex(&circuit_hash(&native(&limits))), limits_hash);
}

#[derive(Clone, Debug, PartialEq, Eq, CircuitType)]
struct Point {
    x: u64,
    y: u32,
}

#[test]
fn a_plain_circuit_type_converts_both_ways_without_a_data_hash() {
    let point = Point { x: 7, y: 9 };
    assert_eq!(
        Point::from_circuit(&native(&point)).expect("from circuit"),
        point
    );
    let _default = <Point as ProofInput>::Circuit::default();
}
