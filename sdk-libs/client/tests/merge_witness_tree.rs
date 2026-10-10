#![cfg(feature = "reqwest")]

//! `MergeSubmission::prove` refuses a witness with a proof from another tree
//! than the merge's inputs: a merge proof verifies only against the tree its
//! witness came from. The refusal comes before anything is proved.

#[path = "common/input.rs"]
mod input_fixture;

use borsh::to_vec;
use input_fixture::wallet_utxo;
use solana_account::Account;
use solana_address::Address;
use zolana_client::{
    client::ZolanaClient, rpc::IndexerRpcConfig, ClientError, InputWitnesses, MergeSubmission,
    MerkleContext, MerkleProof, NonInclusionProof, ProverClient, Rpc, SpendProof, WitnessReader,
};
use zolana_interface::pda;
use zolana_keypair::{random_blinding, ShieldedKeypair, SigningKey};
use zolana_transaction::{
    instructions::merge::MergeTransaction, utxo::SppProofInputUtxo, Data, Mint, Utxo,
};
use zolana_user_registry_interface::{user_record_pda, user_registry_program_id, UserRecord};

const TREE_ID: u16 = 2;

/// Serves the owner's user record, merging enabled.
struct Chain {
    record: Account,
}

impl Rpc for Chain {
    fn get_account(&self, _address: Address) -> Result<Option<Account>, ClientError> {
        Ok(Some(self.record.clone()))
    }
}

/// Answers every witness request with the same witness.
struct Witnesses(InputWitnesses);

impl Rpc for Witnesses {}

impl WitnessReader for Witnesses {
    fn input_witnesses(
        &self,
        _inputs: &[&SppProofInputUtxo],
        _dummy_nullifiers: &[[u8; 32]],
        _config: Option<IndexerRpcConfig>,
    ) -> Result<InputWitnesses, ClientError> {
        Ok(self.0.clone())
    }
}

fn record_account(owner: Address, keypair: &ShieldedKeypair) -> Account {
    let address = keypair.shielded_address().expect("address");
    let record = UserRecord {
        owner,
        bump: user_record_pda(&owner).1,
        owner_p256: None,
        nullifier_pubkey: address.nullifier_pubkey,
        viewing_pubkey: *address.viewing_pubkey.as_bytes(),
        merging_enabled: true,
    };
    let mut data = vec![UserRecord::DISCRIMINATOR];
    data.extend_from_slice(&to_vec(&record).expect("serialize user record"));
    data.resize(UserRecord::SIZE, 0);
    Account {
        lamports: 1,
        data,
        owner: user_registry_program_id(),
        executable: false,
        rent_epoch: 0,
    }
}

fn non_inclusion(tree: Address) -> NonInclusionProof {
    NonInclusionProof {
        leaf: [3; 32],
        merkle_context: MerkleContext { tree_type: 0, tree },
        path: Vec::new(),
        low_element: [0; 32],
        low_element_index: 0,
        high_element: [4; 32],
        high_element_index: 0,
        root: [5; 32],
        root_seq: 0,
        root_index: 0,
    }
}

fn witnesses(state: Address, nullifier: Address, dummy: Address) -> InputWitnesses {
    InputWitnesses {
        spend_proofs: vec![SpendProof {
            state: MerkleProof {
                leaf: [1; 32],
                merkle_context: MerkleContext {
                    tree_type: 0,
                    tree: state,
                },
                path: Vec::new(),
                leaf_index: 0,
                root: [2; 32],
                root_seq: 0,
                root_index: 0,
            },
            nullifier: non_inclusion(nullifier),
        }],
        dummy_nullifier_proofs: vec![non_inclusion(dummy)],
    }
}

#[test]
fn a_witness_proof_from_another_tree_than_the_inputs_is_refused() {
    let sender = ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[7u8; 32]))
        .expect("eddsa sender keypair");
    let address = sender.shielded_address().expect("address");
    let owner = Address::new_from_array(address.signing_pubkey.as_ed25519().expect("ed25519"));
    let inputs = (0..2)
        .map(|leaf_index| {
            let utxo = Utxo {
                owner: sender.signing_pubkey(),
                asset: Mint::SOL,
                amount: 100,
                blinding: random_blinding(),
                ring_program_id: None,
                data: Data::default(),
            };
            wallet_utxo(utxo, &sender.nullifier_key, TREE_ID, leaf_index, None, None)
        })
        .collect();
    let merge = MergeTransaction::new(inputs)
        .expect("merge")
        .encrypt(&sender)
        .expect("encrypt merge");
    let tree = pda::tree(TREE_ID);
    let other = pda::tree(TREE_ID + 1);

    for witness in [
        witnesses(other, tree, tree),
        witnesses(tree, other, tree),
        witnesses(tree, tree, other),
    ] {
        let client = ZolanaClient::new(
            Chain {
                record: record_account(owner, &sender),
            },
            Witnesses(witness),
            ProverClient::new("http://unused.invalid".to_string()),
        );
        let proved = MergeSubmission::new(&merge, owner, &address, &sender.nullifier_key)
            .prove_sync(&client);
        assert!(matches!(
            proved,
            Err(ClientError::MergeInputTreeMismatch { proof_tree, input_tree })
                if proof_tree == other.to_bytes() && input_tree == tree.to_bytes()
        ));
    }
}
