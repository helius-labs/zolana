//! Prover tests for squads smart-account withdrawal and transfer proofs.
//!
//! An in-memory `TestIndexer` supplies self-consistent `SpendProof`s to a
//! freshly spawned prover.

#![cfg(feature = "prover")]

use std::{collections::HashMap, sync::Once};

use num_bigint::BigUint;
use p256::SecretKey;
use zolana_client::{
    spawn_prover, InputUtxoContext, MerkleContext, MerkleProof, NonInclusionProof, Rpc, SpendProof,
    NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT,
};
use zolana_hasher::Poseidon;
use zolana_keypair::{NullifierKey, P256Pubkey, PublicKey};
use zolana_merkle_tree::{indexed::IndexedMerkleTree, MerkleTree};
use zolana_squads_interface::SQUADS_ZONE_PROGRAM_ID;
use zolana_squads_sdk::prover::{
    prove_squads_smart_account_transfer, prove_squads_smart_account_withdrawal,
    SquadsSmartAccountIdentity, SquadsSmartAccountTransferRequest,
    SquadsSmartAccountWithdrawalRequest, SquadsTransferInput, SquadsTransferRecipient,
    SquadsWithdrawalInput, WithdrawalDestination,
};
use zolana_transaction::{
    instructions::transact::BN254_MODULUS_DEC, Address, Data, Utxo, SOL_MINT,
};

fn test_merkle_context() -> MerkleContext {
    MerkleContext {
        tree_type: 0,
        tree: Address::default(),
    }
}

struct TestIndexer {
    state_tree: MerkleTree<Poseidon>,
    nullifier_tree: IndexedMerkleTree<Poseidon, usize>,
    leaf_index: HashMap<[u8; 32], usize>,
}

fn nullifier_upper_bound() -> BigUint {
    BigUint::parse_bytes(BN254_MODULUS_DEC.as_bytes(), 10).expect("modulus") - 1u32
}

impl TestIndexer {
    fn new() -> Self {
        let state_tree = MerkleTree::<Poseidon>::new(STATE_TREE_HEIGHT, 0);
        let nullifier_tree = IndexedMerkleTree::<Poseidon, usize>::new_with_next_value(
            NULLIFIER_TREE_HEIGHT,
            0,
            nullifier_upper_bound(),
        )
        .expect("indexed nullifier tree");
        Self {
            state_tree,
            nullifier_tree,
            leaf_index: HashMap::new(),
        }
    }

    fn add_utxo(&mut self, utxo_hash: [u8; 32]) {
        let index = self.state_tree.leaves().len();
        self.state_tree
            .append(&utxo_hash)
            .expect("append state leaf");
        self.leaf_index.insert(utxo_hash, index);
    }

    fn input_merkle_proof(
        &self,
        commitment: &InputUtxoContext,
    ) -> Result<SpendProof, zolana_client::ClientError> {
        let leaf_index = *self
            .leaf_index
            .get(&commitment.utxo_hash)
            .expect("utxo hash not indexed; call add_utxo first");
        let path = self
            .state_tree
            .get_proof_of_leaf(leaf_index, true)
            .expect("state proof")
            .to_vec();
        let state = MerkleProof {
            leaf: commitment.utxo_hash,
            merkle_context: test_merkle_context(),
            path,
            leaf_index: leaf_index as u64,
            root: self.state_tree.root(),
            root_seq: 0,
            root_index: 0,
        };

        let proof = self
            .nullifier_tree
            .get_non_inclusion_proof(&BigUint::from_bytes_be(&commitment.nullifier))
            .expect("nullifier non-inclusion proof");
        let nullifier = NonInclusionProof {
            leaf: commitment.nullifier,
            merkle_context: test_merkle_context(),
            path: proof.merkle_proof.to_vec(),
            low_element: proof.leaf_lower_range_value,
            low_element_index: proof.leaf_index as u64,
            high_element: proof.leaf_higher_range_value,
            high_element_index: 0,
            root: proof.root,
            root_seq: 0,
            root_index: 0,
        };

        Ok(SpendProof { state, nullifier })
    }
}

impl Rpc for TestIndexer {
    fn get_input_merkle_proofs(
        &self,
        input_utxo_commitments: &[InputUtxoContext],
        _config: Option<zolana_client::IndexerRpcConfig>,
    ) -> Result<Vec<SpendProof>, zolana_client::ClientError> {
        input_utxo_commitments
            .iter()
            .map(|commitment| self.input_merkle_proof(commitment))
            .collect()
    }
}

fn start_prover() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        std::env::set_var(
            "ZOLANA_PROVER_KEYS_DIR",
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../../prover/server/proving-keys"
            ),
        );
    });
    spawn_prover().expect("start prover");
}

fn prover_url() -> String {
    match std::env::var("ZOLANA_PROVER_URL") {
        Ok(url) if !url.trim().is_empty() => url.trim().to_string(),
        _ => "http://127.0.0.1:3001".to_string(),
    }
}

fn p256_secret(n: u8) -> SecretKey {
    let mut bytes = [0u8; 32];
    bytes[31] = n;
    SecretKey::from_slice(&bytes).expect("valid p256 scalar")
}

fn squads_address() -> Address {
    Address::new_from_array(SQUADS_ZONE_PROGRAM_ID)
}

/// The SPP UTXO stores the 31-byte blinding right-aligned in 32 bytes.
fn right_align_31(bytes: &[u8; 31]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[1..32].copy_from_slice(bytes);
    out
}

/// Build the input UTXO exactly as `smart_account.rs` does. Any difference
/// makes the SPP proof and the zone proof disagree.
fn spend_proof_for_input(
    indexer: &mut TestIndexer,
    identity: &SquadsSmartAccountIdentity,
    index: usize,
    amount: u64,
    blinding: &[u8; 31],
) -> SpendProof {
    let owner = PublicKey::from_ed25519(&identity.owner_vault.to_bytes());
    let nullifier_key = NullifierKey::from_secret(identity.nullifier_secret);
    let nullifier_pk = nullifier_key.pubkey().expect("nullifier pubkey");
    let utxo = Utxo {
        owner,
        asset: SOL_MINT,
        amount,
        blinding: right_align_31(blinding),
        ring_program_id: Some(squads_address()),
        data: Data::default(),
    };
    let utxo_hash = utxo
        .hash(&nullifier_pk, &[0u8; 32], &[0u8; 32])
        .expect("utxo hash");
    let nullifier = nullifier_key
        .nullifier(&utxo_hash, &right_align_31(blinding))
        .expect("nullifier");
    indexer.add_utxo(utxo_hash);
    indexer
        .get_input_merkle_proofs(
            &[InputUtxoContext {
                index,
                utxo_hash,
                nullifier,
            }],
            None,
        )
        .expect("merkle proofs")
        .into_iter()
        .next()
        .expect("one spend proof")
}

fn identity() -> SquadsSmartAccountIdentity {
    SquadsSmartAccountIdentity {
        owner_vault: Address::new_from_array([3u8; 32]),
        nullifier_secret: [7u8; 31],
        viewing_secret: p256_secret(11),
    }
}

fn recipient() -> SquadsTransferRecipient {
    let owner_secret = p256_secret(23);
    let owner_p256 = P256Pubkey::from_p256(&owner_secret.public_key());
    let owner_public = PublicKey::from_p256(&owner_p256);
    let owner_pk_field = owner_public
        .owner_proof_input_hash()
        .expect("owner pk field");
    let nullifier_key = NullifierKey::from_secret([9u8; 31]);
    let nullifier_pubkey = nullifier_key.pubkey().expect("nullifier pubkey");
    let viewing_pubkey = P256Pubkey::from_p256(&p256_secret(29).public_key());
    SquadsTransferRecipient {
        owner_pk_field,
        nullifier_pubkey,
        viewing_pubkey,
    }
}

#[test]
fn smart_account_withdrawal_1x1_proves() {
    start_prover();
    let identity = identity();
    let mut indexer = TestIndexer::new();
    let blinding = [13u8; 31];
    let amount = 1000u64;
    let spend_proof = spend_proof_for_input(&mut indexer, &identity, 0, amount, &blinding);

    let req = SquadsSmartAccountWithdrawalRequest {
        identity: identity.clone(),
        input: SquadsWithdrawalInput {
            asset: SOL_MINT,
            amount,
            blinding,
            spend_proof,
        },
        withdrawn: 700,
        destination: WithdrawalDestination::Sol {
            user_sol_account: identity.owner_vault,
        },
        asset: SOL_MINT,
        payer_address: squads_address(),
        payer_pubkey_hash: [0u8; 32],
        expiry_unix_ts: 0,
        salt: [0u8; 16],
        sender_view_tag: [0u8; 32],
        proposal: None,
        prover_url: prover_url(),
    };

    prove_squads_smart_account_withdrawal(req).expect("withdrawal 1x1 proof");
}

#[test]
fn smart_account_transfer_2x2_proves() {
    start_prover();
    let identity = identity();
    let mut indexer = TestIndexer::new();
    let blinding_a = [17u8; 31];
    let blinding_b = [19u8; 31];
    let proof_a = spend_proof_for_input(&mut indexer, &identity, 0, 700, &blinding_a);
    let proof_b = spend_proof_for_input(&mut indexer, &identity, 1, 300, &blinding_b);

    let req = SquadsSmartAccountTransferRequest {
        payer_address: squads_address(),
        identity: identity.clone(),
        inputs: vec![
            SquadsTransferInput {
                asset: SOL_MINT,
                amount: 700,
                blinding: blinding_a,
                spend_proof: proof_a,
            },
            SquadsTransferInput {
                asset: SOL_MINT,
                amount: 300,
                blinding: blinding_b,
                spend_proof: proof_b,
            },
        ],
        recipient: recipient(),
        transferred: 400,
        recipient_blinding: [21u8; 31],
        payer_pubkey_hash: [0u8; 32],
        expiry_unix_ts: 0,
        salt: [0u8; 16],
        sender_view_tag: [0u8; 32],
        recipient_view_tag: [0u8; 32],
        proposal: None,
        prover_url: prover_url(),
    };

    prove_squads_smart_account_transfer(req).expect("transfer 2x2 proof");
}

#[test]
fn smart_account_transfer_1_real_input_with_dummy_proves() {
    // One real input padded with a synthesized dummy keeps the circuit shape (2, 2).
    start_prover();
    let identity = identity();
    let mut indexer = TestIndexer::new();
    let blinding = [23u8; 31];
    let amount = 1000u64;
    let spend_proof = spend_proof_for_input(&mut indexer, &identity, 0, amount, &blinding);

    let req = SquadsSmartAccountTransferRequest {
        payer_address: squads_address(),
        identity: identity.clone(),
        inputs: vec![SquadsTransferInput {
            asset: SOL_MINT,
            amount,
            blinding,
            spend_proof,
        }],
        recipient: recipient(),
        transferred: 400,
        recipient_blinding: [27u8; 31],
        payer_pubkey_hash: [0u8; 32],
        expiry_unix_ts: 0,
        salt: [0u8; 16],
        sender_view_tag: [0u8; 32],
        recipient_view_tag: [0u8; 32],
        proposal: None,
        prover_url: prover_url(),
    };

    let proof = prove_squads_smart_account_transfer(req).expect("transfer 1-real+dummy proof");
    assert_eq!(proof.change_amount, 600);
    assert_eq!(proof.nullifiers.len(), 2);
    assert_eq!(proof.input_root_indices.len(), 2);
    assert_ne!(proof.nullifiers.first(), proof.nullifiers.get(1));
}
