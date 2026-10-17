use custom_ring_interface::{RingProgramConfig, RING_PROGRAM_CONFIG};
use solana_address::Address;
use zolana_client::{AsyncProverClient, AsyncZolanaClient};
use zolana_interface::{
    instruction::{
        instruction_data::{merge_ring::MergeRingIxData, merge_transact::MergeProof},
        tag::RING_MERGE_TRANSACT,
        MergeTransactIxData,
    },
    pda,
};
use zolana_keypair::{ShieldedKeypair, X25519Secret};
use zolana_transaction::Mint;

use super::support::{account, no_witnesses, note, tree_account, Accounts};
use crate::{
    CustomRing, CustomRingMerge, CustomRingMergeInstruction, MergeProofInput, PoolTree,
    PreparedCustomRingMerge, RingError, MERGE_DEFAULT_INPUT_COUNT,
};

fn ring() -> CustomRing {
    CustomRing::new(Address::new_from_array([9; 32]))
}

fn prepared(owner: &ShieldedKeypair, tree_id: u16) -> PreparedCustomRingMerge {
    let inputs = [3, 5]
        .map(|amount| note(owner, amount, tree_id, Some(ring().program_id())))
        .into();
    CustomRingMerge::new(ring(), inputs, None)
        .unwrap()
        .encrypt(owner)
        .unwrap()
}

#[test]
fn merge_keeps_owner_asset_amount_and_ring() {
    let owner = ShieldedKeypair::new_ed25519().unwrap();
    let prepared = prepared(&owner, 0);
    assert_eq!(prepared.ring(), ring());
    // Two notes pad to the smallest merge width.
    assert_eq!(prepared.inputs().len(), 8);
    assert_eq!(prepared.output().amount, 8);
    assert_eq!(prepared.output().ring_program_id, Some(ring().program_id()));
    assert_eq!(prepared.output().asset, Mint::SOL);
}

#[test]
fn notes_of_another_ring_are_not_merged_into_this_one() {
    let owner = ShieldedKeypair::new_ed25519().unwrap();
    let foreign = vec![
        note(&owner, 3, 0, Some(ring().program_id())),
        note(&owner, 5, 0, Some(Address::new_from_array([8; 32]))),
    ];
    assert!(CustomRingMerge::new(ring(), foreign, None).is_err());
}

#[test]
fn instruction_targets_the_same_ring_and_uses_its_authority() {
    let data = MergeRingIxData {
        output_ring_data_hash: [7; 32],
        merge: MergeTransactIxData {
            cache_slot: None,
            expiry_unix_ts: u64::MAX,
            proof: MergeProof::zeroed(),
            output_utxo_hash: [0; 32],
            nullifiers: vec![[0; 32]; MERGE_DEFAULT_INPUT_COUNT],
            utxo_tree_root_index: 0,
            nullifier_tree_root_index: 0,
            private_tx_hash: [0; 32],
            eddsa_owner: false,
        },
    };
    let cosigner = Address::new_from_array([4; 32]);
    let instruction = CustomRingMergeInstruction {
        cosigner: Some(cosigner),
        ring: ring(),
        input_tree: Address::new_from_array([1; 32]),
        output_tree: Address::new_from_array([2; 32]),
        payer: Address::new_from_array([3; 32]),
        data,
    }
    .instruction();
    assert_eq!(instruction.program_id, ring().program_id());
    assert_eq!(instruction.accounts[0].pubkey, ring().config_pda());
    assert_eq!(instruction.accounts[1].pubkey, ring().cosigner_pda());
    assert_eq!(instruction.accounts[2].pubkey, cosigner);
    assert!(instruction.accounts[2].is_signer);
    assert_eq!(
        instruction.accounts[5].pubkey,
        pda::ring_auth(&ring().program_id()).0
    );
    assert!(!instruction.accounts[5].is_signer);
    assert_eq!(instruction.data.first(), Some(&RING_MERGE_TRANSACT));
}

struct NoIndexer;

#[async_trait::async_trait]
impl zolana_client::AsyncRpc for NoIndexer {}

no_witnesses!(NoIndexer);

fn config() -> RingProgramConfig {
    RingProgramConfig {
        discriminator: RING_PROGRAM_CONFIG,
        authority: Address::new_from_array([3; 32]),
        auditor_pubkey: *X25519Secret::new().pubkey().as_bytes(),
        bump: Address::find_program_address(&[RingProgramConfig::SEED], &ring().program_id()).1,
        has_policy: 0,
        mode: 0,
    }
}

#[tokio::test]
async fn a_merge_refuses_a_missing_ring_and_inputs_of_another_tree() {
    let owner = ShieldedKeypair::new_ed25519().unwrap();
    let input = |tree: PoolTree| MergeProofInput {
        nullifier_key: owner.nullifier_key.clone(),
        input_tree: tree.address,
        output_tree: tree.address,
    };
    let zero = PoolTree::from_id(0);
    let five = PoolTree::from_id(5);
    let unconfigured =
        AsyncZolanaClient::new(Accounts::default(), NoIndexer, AsyncProverClient::local());
    assert!(matches!(
        prepared(&owner, 0).prove(input(zero), &unconfigured).await,
        Err(RingError::MissingRingConfig)
    ));
    let accounts = Accounts::default()
        .with(ring().config_pda(), account(ring().program_id(), &config()))
        .with(five.address, tree_account(five));
    let client = AsyncZolanaClient::new(accounts, NoIndexer, AsyncProverClient::local());
    assert!(matches!(
        prepared(&owner, 0).prove(input(five), &client).await,
        Err(RingError::InputTreeMismatch)
    ));
}
