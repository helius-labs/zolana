#[path = "common/input.rs"]
mod input_fixture;
#[path = "test_indexer.rs"]
mod test_indexer;

use input_fixture::wallet_utxo;
use solana_address::Address;
use spr_client::{MergeProver, Rpc};
use spr_interface::instruction::{
    instruction_data::merge_transact::MergeProof, MergeRingAuthority,
};
use spr_keypair::{random_blinding, NullifierKey, ShieldedKeypair, SigningKey};
use spr_transaction::{
    instructions::merge::{MergeSeed, MergeTransaction},
    Data, Mint, Utxo,
};
use test_indexer::TestIndexer;

const TREE_ID: u16 = 0;

#[test]
fn a_zero_key_ring_merge_proves_under_its_seed_and_publishes_its_owner() {
    let ring = Address::new_from_array([9u8; 32]);
    let keypair =
        ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[7u8; 32])).unwrap();
    let zero_key = NullifierKey::from_secret([0; 31]);
    let mut owner = keypair.shielded_address().unwrap();
    owner.nullifier_pubkey = zero_key.pubkey().unwrap();
    let mut seed_bytes = [0x11u8; 32];
    seed_bytes[0] = 0;
    let seed = MergeSeed::from_bytes(seed_bytes).unwrap();

    let mut indexer = TestIndexer::new();
    let inputs = (0..2)
        .map(|_| {
            let utxo = Utxo {
                owner: owner.signing_pubkey,
                asset: Mint::SOL,
                amount: 100,
                blinding: random_blinding(),
                ring_program_id: Some(ring),
                data: Data::default(),
            };
            let hash = utxo
                .hash(&owner.nullifier_pubkey, &[0; 32], &[0; 32], TREE_ID)
                .unwrap();
            wallet_utxo(utxo, &zero_key, TREE_ID, indexer.add_utxo(hash), None, None)
        })
        .collect();
    let prepared = MergeTransaction::new_with_ring(inputs, ring, None)
        .unwrap()
        .encrypt_zero_key(&owner, seed)
        .unwrap();
    let proofs = indexer
        .get_input_merkle_proofs(&prepared.input_utxo_hashes().unwrap(), None)
        .unwrap();
    let dummy_nullifier_proofs = prepared
        .dummy_nullifiers()
        .into_iter()
        .map(|nullifier| indexer.dummy_nullifier_proof(nullifier))
        .collect();
    assert!(matches!(
        prepared.seed(&keypair.nullifier_key),
        Err(spr_transaction::TransactionError::MergeSeedWithNullifierKey)
    ));
    let result = MergeProver {
        transaction: prepared,
        nullifier_key: zero_key,
        proofs,
        dummy_nullifier_proofs,
        cache: None,
    }
    .build()
    .unwrap();

    let owner_hash = owner.signing_pubkey.owner_proof_input_hash().unwrap();
    assert_eq!(result.inputs.merge_seed.to_bytes_be(), seed_bytes[1..]);
    assert_eq!(result.inputs.published_owner.to_bytes_be(), owner_hash[..]);
    assert_eq!(
        result.ring_instruction_data(MergeProof::zeroed()).authority,
        MergeRingAuthority::OwnerSigned
    );
}
