use borsh::{BorshDeserialize, BorshSerialize};
use solana_address::Address;
use spr_keypair::ViewingKey;
use spr_program::{
    hasher::{data_hash, unique_data_hash, DataHasher, Hasher, HasherError, Poseidon},
    DataUtxo, ProgramOwner,
};
use spr_transaction::{Mint, SppProofOutputUtxo};

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
struct State {
    value: u64,
}

impl DataHasher for State {
    fn hash(&self) -> Result<[u8; 32], HasherError> {
        Poseidon::hashv(&[&spr_hasher::primitives::right_align(
            &self.value.to_be_bytes(),
        )])
    }
}

#[test]
fn ordinary_and_addressed_state_decode_with_their_respective_hash_domains() {
    let owner = ProgramOwner::new(Address::new_from_array([9; 32]));
    let viewer = ViewingKey::from_bytes(&[7; 32]);
    let recipient = owner.address(viewer.pubkey()).unwrap();
    let state = State { value: 42 };
    let encoded = borsh::to_vec(&state).unwrap();

    let ordinary_hash = data_hash(&state.hash().unwrap()).unwrap();
    let ordinary = SppProofOutputUtxo::new(Mint::SOL, 0, recipient)
        .unwrap()
        .with_utxo_data(encoded.clone(), ordinary_hash);
    let ordinary = DataUtxo::<State>::try_from(owner.input(&ordinary, 0, 0).unwrap()).unwrap();
    assert_eq!(ordinary.data, state);
    assert_eq!(ordinary.address, None);
    assert_eq!(ordinary.utxo.data_hash, Some(ordinary_hash));

    let address = [3u8; 32];
    let unique_hash = unique_data_hash(&address, &state.hash().unwrap()).unwrap();
    let mut unique_data = address.to_vec();
    unique_data.extend_from_slice(&encoded);
    let unique = SppProofOutputUtxo::new(Mint::SOL, 0, recipient)
        .unwrap()
        .with_utxo_data(unique_data.clone(), unique_hash);
    let unique = DataUtxo::<State>::try_from(owner.input(&unique, 0, 1).unwrap()).unwrap();
    assert_eq!(unique.data, state);
    assert_eq!(unique.address, Some(address));
    assert_eq!(unique.utxo.data_hash, Some(unique_hash));

    unique_data[39] ^= 1;
    let tampered = SppProofOutputUtxo::new(Mint::SOL, 0, recipient)
        .unwrap()
        .with_utxo_data(unique_data, unique_hash);
    assert!(DataUtxo::<State>::try_from(owner.input(&tampered, 0, 2).unwrap()).is_err());
}

#[test]
fn ring_notes_open_under_their_ring_program_and_ring_data_hash() {
    let owner = ProgramOwner::new(Address::new_from_array([9; 32]));
    let recipient = owner
        .address(ViewingKey::from_bytes(&[7; 32]).pubkey())
        .unwrap();
    let ring = Address::new_from_array([5; 32]);
    let ring_data_hash = [1u8; 32];
    let tree_id = 3;

    let hashed = SppProofOutputUtxo::new(Mint::SOL, 8, recipient)
        .unwrap()
        .with_ring_data_hash(ring, ring_data_hash);
    let input = owner.input(&hashed, tree_id, 4).unwrap();
    assert_eq!(input.utxo.ring_program_id, Some(ring));
    assert_eq!(input.ring_data_hash, Some(ring_data_hash));
    assert_eq!(input.utxo_hash, hashed.hash(tree_id).unwrap());

    let unhashed = SppProofOutputUtxo::new(Mint::SOL, 8, recipient)
        .unwrap()
        .with_ring_program_id(ring);
    let input = owner.input(&unhashed, tree_id, 5).unwrap();
    assert_eq!(input.utxo.ring_program_id, Some(ring));
    assert_eq!(input.ring_data_hash, None);
    assert_eq!(input.utxo_hash, unhashed.hash(tree_id).unwrap());

    let state = State { value: 42 };
    let state_hash = data_hash(&state.hash().unwrap()).unwrap();
    let with_state = hashed
        .clone()
        .with_utxo_data(borsh::to_vec(&state).unwrap(), state_hash);
    let decoded =
        DataUtxo::<State>::try_from(owner.input(&with_state, tree_id, 6).unwrap()).unwrap();
    assert_eq!(decoded.data, state);
    assert_eq!(decoded.utxo.ring_data_hash, Some(ring_data_hash));

    let stranger = ProgramOwner::new(Address::new_from_array([8; 32]));
    let refused = stranger.input(&hashed, tree_id, 7).err().unwrap();
    assert_eq!(refused.name(), "ClientError.NotProgramOutput");
}

impl spr_program::EncryptionCodec for State {
    fn serialize_for_encryption(&self) -> std::io::Result<Vec<u8>> {
        borsh::to_vec(self)
    }

    fn deserialize_after_decryption(bytes: &[u8]) -> std::io::Result<Self> {
        <Self as borsh::BorshDeserialize>::try_from_slice(bytes)
    }
}
