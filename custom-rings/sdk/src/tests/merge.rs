use custom_ring_interface::{
    merge_disclosure_field_count, CustomRingMergeIxData, CustomRingMergeIxDataRef,
    RingProgramConfig, RING_PROGRAM_CONFIG,
};
use solana_address::Address;
use zeroize::Zeroizing;
use zolana_client::prover::ProveRequest;
use zolana_client::{AsyncProverClient, AsyncZolanaClient};
use zolana_interface::{
    instruction::{
        instruction_data::merge_transact::{MergeOutputEncryption, MergeProof},
        tag::RING_MERGE_TRANSACT,
        MergeTransactIxData,
    },
    pda,
};
use zolana_keypair::X25519Pubkey;
use zolana_keypair::{ShieldedKeypair, X25519Keypair};
use zolana_transaction::Mint;

use super::support::{account, no_witnesses, note, tree_account, Accounts};
use crate::{
    prover::{RingCircuit, RingRequest},
    request::{MergeAnonymousBody, MergeSlot, RecordWitness},
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
    let data = CustomRingMergeIxData {
        registry_root_index: 0,
        output_ring_data_hash: [7; 32],
        disclosure: None,
        merge: MergeTransactIxData {
            cache_slot: None,
            expiry_unix_ts: u64::MAX,
            proof: MergeProof::zeroed(),
            output_utxo_hash: [0; 32],
            output_encryption: MergeOutputEncryption::PoseidonCtrV1 {
                salt: [0; 16],
                ciphertext: [[0; 32]; 3],
            },
            nullifiers: vec![[0; 32]; MERGE_DEFAULT_INPUT_COUNT],
            utxo_tree_root_index: 0,
            nullifier_tree_root_index: 0,
            private_tx_hash: [0; 32],
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
        instruction.accounts[3].pubkey,
        ring().member_registry_root_pda()
    );
    assert!(!instruction.accounts[3].is_signer);
    assert_eq!(
        instruction.accounts[6].pubkey,
        pda::ring_auth(&ring().program_id()).0
    );
    assert!(!instruction.accounts[5].is_signer);
    assert_eq!(instruction.data.first(), Some(&RING_MERGE_TRANSACT));
    let parsed = CustomRingMergeIxDataRef::from_bytes(&instruction.data[1..]).unwrap();
    assert_eq!(parsed.registry_root_index, 0);
    assert_eq!(parsed.output_ring_data_hash, &[7; 32]);
    assert_eq!(parsed.merge.nullifiers.len(), MERGE_DEFAULT_INPUT_COUNT);
}

struct NoIndexer;

#[async_trait::async_trait]
impl zolana_client::AsyncRpc for NoIndexer {}

no_witnesses!(NoIndexer);

fn config() -> RingProgramConfig {
    RingProgramConfig {
        discriminator: RING_PROGRAM_CONFIG,
        authority: Address::new_from_array([3; 32]),
        auditor_pubkey: *X25519Keypair::new().pubkey().as_bytes(),
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

/// The anonymous preview sizes the disclosure of its own width, any other ring carries none.
#[test]
fn an_anonymous_preview_carries_the_disclosure_of_its_width() {
    let owner = ShieldedKeypair::new_ed25519().unwrap();
    let prepared = prepared(&owner, 0);
    let tree = PoolTree::from_id(0);
    let input = MergeProofInput {
        nullifier_key: owner.nullifier_key.clone(),
        input_tree: tree.address,
        output_tree: tree.address,
    };
    let payer = Address::new_from_array([3; 32]);
    for (instruction, fields) in [
        (
            prepared
                .anonymous_preview_instruction(&input, payer, None)
                .unwrap(),
            Some(merge_disclosure_field_count(8)),
        ),
        (prepared.preview_instruction(&input, payer, None), None),
    ] {
        let parsed = CustomRingMergeIxDataRef::from_bytes(&instruction.data[1..]).unwrap();
        assert_eq!(
            parsed.disclosure.map(|disclosure| disclosure.fields.len()),
            fields
        );
    }
}

#[test]
fn an_anonymous_merge_past_the_widest_fitting_width_is_refused() {
    let owner = ShieldedKeypair::new_ed25519().unwrap();
    let inputs = (1..=25)
        .map(|amount| note(&owner, amount, 0, Some(ring().program_id())))
        .collect();
    let prepared = CustomRingMerge::new(ring(), inputs, None)
        .unwrap()
        .encrypt(&owner)
        .unwrap();
    let tree = PoolTree::from_id(0);
    let input = MergeProofInput {
        nullifier_key: owner.nullifier_key.clone(),
        input_tree: tree.address,
        output_tree: tree.address,
    };
    assert!(matches!(
        prepared.anonymous_preview_instruction(&input, Address::new_from_array([3; 32]), None),
        Err(RingError::AnonymousMergeTooWide { width: 52 })
    ));
}

/// The Rust body spells every wire the Go decoder reads for the pinned statement.
#[test]
fn the_anonymous_merge_body_matches_the_go_request() {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../test-vectors/ring-merge-anonymous.json"
    ))
    .unwrap();
    let request = &vector["request"];
    let bytes = |value: &serde_json::Value| -> Vec<u8> {
        hex::decode(value.as_str().unwrap().trim_start_matches("0x")).unwrap()
    };
    let field = |value: &serde_json::Value| -> [u8; 32] { bytes(value).try_into().unwrap() };
    let body = MergeAnonymousBody {
        circuit_type: RingCircuit::MergeAnonymous { inputs: 8 },
        public_input_hash: field(&request["publicInputHash"]),
        private_tx_hash: field(&request["privateTxHash"]),
        output_utxo_hash: field(&request["outputUtxoHash"]),
        first_nullifier: field(&request["firstNullifier"]),
        ring_program_id: field(&request["ringProgramId"]),
        member_registry_root: field(&request["memberRegistryRoot"]),
        auditor_pk: X25519Pubkey::from_bytes(bytes(&vector["auditor_pk"]).try_into().unwrap())
            .unwrap(),
        salt: field(&request["salt"]),
        eph_sk: Zeroizing::new(field(&request["ephSk"])),
        disclosure_key: Zeroizing::new(field(&request["disclosureKey"])),
        owner_key: field(&request["ownerKey"]),
        nullifier_secret: Zeroizing::new(field(&request["nullifierSecret"])),
        mint_chunks: [
            field(&request["mintChunks"][0]),
            field(&request["mintChunks"][1]),
        ],
        inputs: request["inputs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|input| MergeSlot {
                domain: field(&input["domain"]),
                tree_id: field(&input["treeId"]),
                amount: field(&input["amount"]),
                blinding: field(&input["blinding"]),
                ring_data_hash: field(&input["ringDataHash"]),
            })
            .collect(),
        output_tree_id: field(&request["outputTreeId"]),
        output_ring_data_hash: field(&request["outputRingDataHash"]),
        member_record: RecordWitness {
            next: field(&request["memberRecord"]["next"]),
            lists: request["memberRecord"]["lists"].as_u64().unwrap(),
            escrow_key: field(&request["memberRecord"]["escrowKey"]),
            index: request["memberRecord"]["index"].as_u64().unwrap(),
            path: request["memberRecord"]["path"]
                .as_array()
                .unwrap()
                .iter()
                .map(field)
                .collect(),
        },
    };
    let encoded: serde_json::Value =
        serde_json::from_str(&RingRequest(&body).body().unwrap()).unwrap();
    assert_eq!(&encoded, request);
}

#[test]
fn ring_merge_accepts_fifty_inputs_and_rejects_larger_plans_before_proving() {
    let owner = ShieldedKeypair::new_ed25519().unwrap();
    let inputs: Vec<_> = (0..52)
        .map(|i| note(&owner, i + 1, 0, Some(ring().program_id())))
        .collect();
    for count in [51, 52] {
        assert!(matches!(
            CustomRingMerge::new(ring(), inputs[..count].to_vec(), None),
            Err(zolana_transaction::TransactionError::TooManyInputs { got, max: 50 })
                if got == count
        ));
    }
    let prepared = CustomRingMerge::new(ring(), inputs[..50].to_vec(), None)
        .unwrap()
        .encrypt(&owner)
        .unwrap();
    assert_eq!(prepared.inputs().len(), 52);
    assert_eq!(
        prepared
            .inputs()
            .iter()
            .filter(|input| !input.is_compact())
            .count(),
        50
    );
    assert_eq!(prepared.output().amount, 50 * 51 / 2);
}
