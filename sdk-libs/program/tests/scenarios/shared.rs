use solana_address::Address;
use solana_signature::Signature;
use spr_hasher::{Hasher, Poseidon};
use spr_keypair::{random_blinding, ShieldedKeypair, SigningKey};
use spr_program::{testing::check_private_variables, Groth16Prover, ProofResult, ZkProgramCircuit};
use spr_transaction::{utxo::Utxo, Data, Mint, WalletUtxo};

pub const TREE_ID: u16 = 3;
pub const USDC: Mint = Mint::new(Address::new_from_array([4u8; 32]), 4);

pub fn keypair(seed: u8) -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32])).expect("keypair")
}

pub fn token_input(
    owner: &ShieldedKeypair,
    mint: Mint,
    amount: u64,
    leaf_index: u64,
) -> WalletUtxo {
    let address = owner.shielded_address().expect("owner address");
    let utxo = Utxo {
        owner: owner.signing_pubkey(),
        asset: mint,
        amount,
        blinding: random_blinding(),
        ring_program_id: None,
        data: Data::default(),
    };
    let utxo_hash = utxo
        .hash(&address.nullifier_pubkey, &[0u8; 32], &[0u8; 32], TREE_ID)
        .expect("utxo hash");
    let nullifier = owner
        .nullifier(&utxo_hash, &utxo.blinding)
        .expect("nullifier");
    let transaction_key = owner
        .get_transaction_viewing_key(&nullifier)
        .expect("synced transaction key");
    WalletUtxo {
        nullifier,
        tx_viewing_key: Some(*transaction_key.secret_bytes()),
        utxo,
        nullifier_pubkey: address.nullifier_pubkey,
        utxo_hash,
        data_hash: None,
        ring_data_hash: None,
        tree_id: TREE_ID,
        leaf_index,
        latest_tree_id: Some(TREE_ID),
        slot: 0,
        tx_signature: Signature::default(),
        slot_index: 0,
    }
}

pub fn poseidon_bytes(inputs: &[[u8; 32]]) -> [u8; 32] {
    let slices: Vec<&[u8]> = inputs.iter().map(<[u8; 32]>::as_slice).collect();
    Poseidon::hashv(&slices).expect("poseidon")
}

/// Proves `proof_inputs` after checking that it leaves no private variable
/// unconstrained.
pub fn prove<P: ZkProgramCircuit>(
    prover: &Groth16Prover<P>,
    proof_inputs: &P,
    proof: &'static str,
) -> ProofResult {
    let report = check_private_variables(proof_inputs).expect(proof);
    assert!(
        report.free.is_empty(),
        "{proof} leaves private variables unconstrained: {:?}",
        report.free
    );
    prover.prove(proof_inputs).expect(proof)
}

// Native state commitments for the hand-written circuit examples.
macro_rules! native_state_hash {
    ($state:ty, [$($prefix:expr),*], $($field:ident),+ $(,)?) => {
        impl spr_program::hasher::DataHasher for $state {
            fn hash(&self) -> Result<[u8; 32], spr_program::hasher::HasherError> {
                use spr_program::hasher::{Hasher, Poseidon, ToByteArray};
                Poseidon::hashv(&[
                    $($prefix.to_byte_array()?.as_slice(),)*
                    $(self.$field.to_byte_array()?.as_slice(),)+
                ])
            }
        }
        impl spr_program::EncryptionCodec for $state {
            fn serialize_for_encryption(&self) -> std::io::Result<Vec<u8>> {
                borsh::to_vec(self)
            }

            fn deserialize_after_decryption(bytes: &[u8]) -> std::io::Result<Self> {
                <Self as borsh::BorshDeserialize>::try_from_slice(bytes)
            }
        }
        impl spr_program::hasher::ToByteArray for $state {
            fn to_byte_array(&self) -> Result<[u8; 32], spr_program::hasher::HasherError> {
                spr_program::hasher::DataHasher::hash(self)
            }
        }
    };
}
pub(crate) use native_state_hash;
