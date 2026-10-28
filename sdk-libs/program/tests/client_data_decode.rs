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

impl spr_program::EncryptionCodec for State {
    fn serialize_for_encryption(&self) -> std::io::Result<Vec<u8>> {
        borsh::to_vec(self)
    }

    fn deserialize_after_decryption(bytes: &[u8]) -> std::io::Result<Self> {
        <Self as borsh::BorshDeserialize>::try_from_slice(bytes)
    }
}
