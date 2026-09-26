use borsh::{BorshDeserialize, BorshSerialize};
use zk_program_sdk::{
    circuit::{self, checked_utxo_data, poseidon, CircuitType, CircuitVar, DataHash, UtxoData},
    conversion::{to_bytes, Allocator, FromCircuit, ProofInput},
    hasher::{DataHasher, Hasher, HasherError, ToByteArray},
    Bytes, Owner, RelationError,
};
use zolana_keypair::{ShieldedKeypair, SigningKey};

fn native<T: ProofInput>(value: &T) -> T::Circuit {
    value
        .instantiate(&Allocator::native())
        .expect("native instantiation")
}

fn circuit_hash<T: DataHash>(value: &T) -> [u8; 32] {
    to_bytes(&DataHash::hash(value).expect("circuit hash")).expect("hash bytes")
}

fn byte_hash<T: ToByteArray>(value: &T) -> [u8; 32] {
    value.to_byte_array().expect("byte hash")
}

#[test]
fn integer_bool_and_field_hashes_match_their_bytes() {
    assert_eq!(circuit_hash(&native(&42u64)), byte_hash(&42u64));
    assert_eq!(circuit_hash(&native(&7u32)), byte_hash(&7u32));
    assert_eq!(circuit_hash(&native(&3u16)), byte_hash(&3u16));
    assert_eq!(circuit_hash(&native(&true)), byte_hash(&true));
    assert_eq!(circuit_hash(&native(&false)), byte_hash(&false));
    assert_eq!(circuit_hash(&native(&[3u8; 32])), byte_hash(&[3u8; 32]));
}

#[test]
fn array_hashes_match_their_bytes() {
    assert_eq!(
        circuit_hash(&native(&[1u64, 2, 3])),
        byte_hash(&[1u64, 2, 3])
    );
    assert_eq!(
        circuit_hash(&native(&[[1u16, 2], [3, 4]])),
        byte_hash(&[[1u16, 2], [3, 4]])
    );
}

#[test]
fn byte_string_hashes_match_their_bytes() {
    let bytes = Bytes([5u8; 40]);
    assert_eq!(circuit_hash(&native(&bytes)), byte_hash(&bytes));
}

#[test]
fn owner_hashes_match_their_bytes_for_every_curve() {
    let ed25519 = ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[5u8; 32]))
        .expect("ed25519 keypair")
        .shielded_address()
        .expect("ed25519 address");
    let p256 = ShieldedKeypair::new_p256()
        .expect("p256 keypair")
        .shielded_address()
        .expect("p256 address");
    for address in [ed25519, p256] {
        let owner = Owner::try_from(&address).expect("owner");
        assert_eq!(circuit_hash(&native(&owner)), byte_hash(&owner));
    }
    let default_owner = Owner {
        tag: 0,
        key: [0u8; 32],
        nullifier_pk: [0u8; 32],
    };
    assert_eq!(
        circuit_hash(&circuit::Owner::default()),
        byte_hash(&default_owner)
    );
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
struct Tally {
    count: u64,
}

#[derive(Clone, Debug)]
struct TallyCircuit {
    count: CircuitVar,
}

impl CircuitType for TallyCircuit {}

impl ProofInput for Tally {
    type Circuit = TallyCircuit;

    fn instantiate(&self, allocator: &Allocator) -> Result<TallyCircuit, RelationError> {
        Ok(TallyCircuit {
            count: self.count.instantiate(allocator)?,
        })
    }
}

impl FromCircuit for Tally {
    fn from_circuit(circuit: &TallyCircuit) -> Result<Self, RelationError> {
        Ok(Self {
            count: u64::from_circuit(&circuit.count)?,
        })
    }
}

impl DataHash for TallyCircuit {
    fn hash(&self) -> Result<CircuitVar, RelationError> {
        poseidon(core::slice::from_ref(&self.count))
    }
}

impl UtxoData for TallyCircuit {
    type Client = Tally;
}

impl DataHasher for Tally {
    fn hash<H: Hasher>(&self) -> Result<[u8; 32], HasherError> {
        H::hashv(&[&self.count.to_byte_array()?])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
struct SkewedTally {
    count: u64,
}

#[derive(Clone, Debug)]
struct SkewedTallyCircuit {
    count: CircuitVar,
}

impl CircuitType for SkewedTallyCircuit {}

impl ProofInput for SkewedTally {
    type Circuit = SkewedTallyCircuit;

    fn instantiate(&self, allocator: &Allocator) -> Result<SkewedTallyCircuit, RelationError> {
        Ok(SkewedTallyCircuit {
            count: self.count.instantiate(allocator)?,
        })
    }
}

impl FromCircuit for SkewedTally {
    fn from_circuit(circuit: &SkewedTallyCircuit) -> Result<Self, RelationError> {
        Ok(Self {
            count: u64::from_circuit(&circuit.count)?,
        })
    }
}

impl DataHash for SkewedTallyCircuit {
    fn hash(&self) -> Result<CircuitVar, RelationError> {
        poseidon(core::slice::from_ref(&self.count))
    }
}

impl UtxoData for SkewedTallyCircuit {
    type Client = SkewedTally;
}

impl DataHasher for SkewedTally {
    fn hash<H: Hasher>(&self) -> Result<[u8; 32], HasherError> {
        let count = self.count.to_byte_array()?;
        H::hashv(&[&count, &count])
    }
}

#[test]
fn checked_utxo_data_encodes_a_state_whose_hashes_agree() {
    let state = Tally { count: 9 };
    assert_eq!(
        checked_utxo_data(&native(&state)).expect("utxo data"),
        borsh::to_vec(&state).expect("borsh")
    );
}

#[test]
fn checked_utxo_data_refuses_a_state_whose_hashes_differ() {
    assert!(matches!(
        checked_utxo_data(&native(&SkewedTally { count: 9 })),
        Err(RelationError::DataHashMismatch)
    ));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn owner_and_byte_string_hashes_are_pinned() {
    let owner = Owner::try_from(
        &ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[5u8; 32]))
            .expect("keypair")
            .shielded_address()
            .expect("address"),
    )
    .expect("owner");
    let owner_hash = "05d071ebb448440419d769caad296d191612bfcc0646d5fec914a4054542fff5";
    assert_eq!(hex(&byte_hash(&owner)), owner_hash);
    assert_eq!(hex(&circuit_hash(&native(&owner))), owner_hash);

    let default_owner = Owner {
        tag: 0,
        key: [0u8; 32],
        nullifier_pk: [0u8; 32],
    };
    let default_hash = "175352575ea4560d77e6e115b63b29ae2a02bfbd9deac37a678e5289e7314d6a";
    assert_eq!(hex(&byte_hash(&default_owner)), default_hash);
    assert_eq!(hex(&circuit_hash(&circuit::Owner::default())), default_hash);

    let bytes = Bytes([5u8; 40]);
    let bytes_hash = "10a6f2298793fffc5b7c4676dbe185bdfe73b294ca129c29fe23114a81eea163";
    assert_eq!(hex(&byte_hash(&bytes)), bytes_hash);
    assert_eq!(hex(&circuit_hash(&native(&bytes))), bytes_hash);
}
