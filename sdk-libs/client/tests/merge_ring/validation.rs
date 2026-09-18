use solana_address::Address;
use zolana_client::{prover::MergeRingCacheTarget, ClientError, MergeRingProver};
use zolana_keypair::{ShieldedKeypair, SigningKey};
use zolana_transaction::SppProofOutputUtxo;

#[test]
fn cached_merge_rejects_zero_owner_blinding() {
    let owner = ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[1; 32]))
        .expect("test owner");
    let prover = MergeRingProver {
        inputs: Vec::new(),
        output: SppProofOutputUtxo::default(),
        expiry_unix_ts: 0,
        signing_pubkey: owner.signing_pubkey(),
        nullifier_key: owner.nullifier_key,
        output_tree_id: 0,
        ring_program_id: Address::new_from_array([2; 32]),
        cache: Some(MergeRingCacheTarget {
            address: Address::new_from_array([3; 32]),
            slot: 0,
            owner_blinding: [0; 32],
        }),
    };
    assert!(matches!(
        prover.build(),
        Err(ClientError::ZeroCacheOwnerBlinding)
    ));
}
