use p256::{elliptic_curve::rand_core::OsRng, SecretKey};
use solana_account::Account;
use solana_keypair::Keypair;
use zolana_client::{
    rpc::{
        Context, EncryptedUtxoMatch, GetEncryptedUtxosByTagsResponse,
        GetNonInclusionProofsResponse, GetShieldedTransactionsByTagsResponse, MerkleContext,
        NonInclusionProof, OutputContext, OutputSlot, ShieldedTransaction,
    },
    ClientError, Rpc,
};
use zolana_interface::event::{encode_output_data, encode_verifiably_encrypted, ProoflessOutput};
use zolana_keypair::{merge::encrypt_verifiable, P256Pubkey};
use zolana_squads_client::{
    seed_viewing_key_account, tags::view_tag_from_shared_viewing_key, GetBalancesRequest,
    SquadsBackend, ViewingKeyAccountSeed,
};
use zolana_squads_interface::types::Address;
use zolana_squads_sdk::encrypted_utxo::encrypt_recipient_ciphertext;
use zolana_transaction::{
    instructions::transact::signed_transaction::asset_field, EncryptedScheme, SOL_MINT,
};

struct MockIndexer {
    vka_address: Address,
    vka_data: Vec<u8>,
    deposits: Vec<EncryptedUtxoMatch>,
    transfers: Vec<ShieldedTransaction>,
}

impl Rpc for MockIndexer {
    fn get_account(&self, address: Address) -> core::result::Result<Option<Account>, ClientError> {
        if address == self.vka_address {
            Ok(Some(Account {
                lamports: 1,
                data: self.vka_data.clone(),
                owner: Address::default(),
                executable: false,
                rent_epoch: 0,
            }))
        } else {
            Ok(None)
        }
    }

    fn get_encrypted_utxos_by_tags(
        &self,
        _tags: Vec<[u8; 32]>,
        _cursor: Option<Vec<u8>>,
        _limit: Option<u32>,
    ) -> core::result::Result<GetEncryptedUtxosByTagsResponse, ClientError> {
        Ok(GetEncryptedUtxosByTagsResponse {
            context: Context { slot: 0 },
            matches: self.deposits.clone(),
            next_cursor: None,
        })
    }

    fn get_shielded_transactions_by_tags(
        &self,
        _tags: Vec<[u8; 32]>,
        _cursor: Option<Vec<u8>>,
        _limit: Option<u32>,
    ) -> core::result::Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        Ok(GetShieldedTransactionsByTagsResponse {
            context: Context { slot: 0 },
            transactions: self.transfers.clone(),
            next_cursor: None,
        })
    }

    fn get_non_inclusion_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
    ) -> core::result::Result<GetNonInclusionProofsResponse, ClientError> {
        // Every queried nullifier is absent (unspent): return a proof each.
        let proofs = leaves
            .into_iter()
            .map(|leaf| NonInclusionProof {
                leaf,
                merkle_context: MerkleContext {
                    tree_type: 0,
                    tree: tree_account,
                },
                path: Vec::new(),
                low_element: [0u8; 32],
                low_element_index: 0,
                high_element: [0u8; 32],
                high_element_index: 0,
                root: [0u8; 32],
                root_seq: 0,
                root_index: 0,
            })
            .collect();
        Ok(GetNonInclusionProofsResponse {
            context: Context { slot: 0 },
            proofs,
        })
    }
}

#[test]
fn get_balances_sums_deposit_and_transfer_via_auditor_key() {
    let shared = SecretKey::random(&mut OsRng);
    let ephemeral = SecretKey::random(&mut OsRng);
    let auditor = SecretKey::random(&mut OsRng);
    let auditor_pk = P256Pubkey::from_p256(&auditor.public_key());
    let nullifier_secret = [3u8; 32];
    let vka_address = Address::new_from_array([42u8; 32]);

    let vka = seed_viewing_key_account(
        ViewingKeyAccountSeed {
            owner: Address::new_from_array([1u8; 32]),
            owner_kind: 1,
            state: 1,
            encryption_scheme: 0,
            key_nonce: 0,
        },
        &shared,
        &ephemeral,
        &nullifier_secret,
        &[],
        &[auditor_pk],
    )
    .expect("seed account");
    let tag = view_tag_from_shared_viewing_key(&vka.shared_viewing_key);

    // A proofless SOL deposit of 1_000_000.
    let deposit_output = ProoflessOutput {
        owner: [1u8; 32],
        blinding: [5u8; 31],
        asset: SOL_MINT.to_bytes(),
        amount: 1_000_000,
        data_hash: None,
        utxo_data: None,
        zone_program_id: None,
        zone_data_hash: None,
        zone_data: None,
        memo: None,
    };
    let deposit_match = EncryptedUtxoMatch {
        slot: 1,
        tx_signature: solana_signature::Signature::default(),
        output_slot: OutputSlot {
            view_tag: tag,
            output_context: OutputContext {
                hash: [7u8; 32],
                tree: Address::default(),
                leaf_index: 0,
            },
            payload: encode_output_data(deposit_output),
        },
        tx_viewing_pk: None,
        salt: None,
    };

    // An encrypted SOL transfer of 500 to this account's shared viewing key.
    let asset_fe = asset_field(&SOL_MINT).expect("asset fe");
    let tx_viewing_sk = SecretKey::random(&mut OsRng);
    let tx_viewing_pk = P256Pubkey::from_p256(&tx_viewing_sk.public_key());
    let shared_pk = P256Pubkey::from_p256(&shared.public_key());
    let ciphertext =
        encrypt_recipient_ciphertext(&tx_viewing_sk, &shared_pk, 500, &asset_fe, &[9u8; 31])
            .expect("encrypt recipient");
    let transfer_tx = ShieldedTransaction {
        slot: 2,
        tx_signature: solana_signature::Signature::from([1u8; 64]),
        tx_viewing_pk: Some(tx_viewing_pk),
        salt: Some([0u8; 16]),
        output_slots: vec![OutputSlot {
            view_tag: tag,
            output_context: OutputContext {
                hash: [8u8; 32],
                tree: Address::default(),
                leaf_index: 1,
            },
            payload: ciphertext.to_vec(),
        }],
        nullifiers: Vec::new(),
        proofless: false,
    };

    let indexer = MockIndexer {
        vka_address,
        vka_data: vka.serialize().expect("serialize vka"),
        deposits: vec![deposit_match],
        transfers: vec![transfer_tx],
    };
    let rpc = MockIndexer {
        vka_address,
        vka_data: vka.serialize().expect("serialize vka"),
        deposits: Vec::new(),
        transfers: Vec::new(),
    };

    let backend = SquadsBackend::new(
        auditor,
        Keypair::new(),
        Address::default(),
        Address::default(),
        "http://127.0.0.1:3001",
        indexer,
        rpc,
    );

    let response = backend
        .get_balances(GetBalancesRequest {
            viewing_key_account: vka_address,
            skip_utxos: false,
            signature: [0u8; 64],
        })
        .expect("get balances");

    assert_eq!(response.balances.len(), 1);
    let sol = response.balances.first().expect("sol balance");
    assert_eq!(sol.asset_id, 1);
    assert_eq!(sol.mint, Address::default());
    assert_eq!(sol.amount, 1_000_500);
    assert_eq!(sol.utxos.len(), 2);
}

#[test]
fn get_balances_includes_merged_output() {
    let shared = SecretKey::random(&mut OsRng);
    let ephemeral = SecretKey::random(&mut OsRng);
    let auditor = SecretKey::random(&mut OsRng);
    let auditor_pk = P256Pubkey::from_p256(&auditor.public_key());
    let nullifier_secret = [3u8; 32];
    let vka_address = Address::new_from_array([42u8; 32]);

    let vka = seed_viewing_key_account(
        ViewingKeyAccountSeed {
            owner: Address::new_from_array([1u8; 32]),
            owner_kind: 1,
            state: 1,
            encryption_scheme: 0,
            key_nonce: 0,
        },
        &shared,
        &ephemeral,
        &nullifier_secret,
        &[],
        &[auditor_pk],
    )
    .expect("seed account");
    let tag = view_tag_from_shared_viewing_key(&vka.shared_viewing_key);

    // A merged SOL output of 2_500 verifiably encrypted to the account's shared
    // viewing key. The plaintext is `amount(8 BE) || asset_field(32) || blinding(31)`
    // and the transaction carries no tx-level tx_viewing_pk (it lives in the blob).
    let asset_fe = asset_field(&SOL_MINT).expect("asset fe");
    let merged_amount: u64 = 2_500;
    let merged_blinding = [11u8; 31];
    let mut plaintext = Vec::with_capacity(8 + 32 + 31);
    plaintext.extend_from_slice(&merged_amount.to_be_bytes());
    plaintext.extend_from_slice(&asset_fe);
    plaintext.extend_from_slice(&merged_blinding);

    let tx_viewing_sk = SecretKey::random(&mut OsRng);
    let shared_pk = P256Pubkey::from_p256(&shared.public_key());
    let (ciphertext, tx_viewing_pk) =
        encrypt_verifiable(&tx_viewing_sk, &shared_pk, &plaintext).expect("encrypt merge");

    let mut blob = Vec::new();
    blob.push(EncryptedScheme::Merge.as_byte());
    blob.extend_from_slice(tx_viewing_pk.as_bytes());
    blob.extend_from_slice(&ciphertext);
    let payload = encode_verifiably_encrypted(blob);

    let merge_tx = ShieldedTransaction {
        slot: 3,
        tx_signature: solana_signature::Signature::from([2u8; 64]),
        tx_viewing_pk: None,
        salt: None,
        output_slots: vec![OutputSlot {
            view_tag: tag,
            output_context: OutputContext {
                hash: [12u8; 32],
                tree: Address::default(),
                leaf_index: 3,
            },
            payload,
        }],
        nullifiers: Vec::new(),
        proofless: false,
    };

    let indexer = MockIndexer {
        vka_address,
        vka_data: vka.serialize().expect("serialize vka"),
        deposits: Vec::new(),
        transfers: vec![merge_tx],
    };
    let rpc = MockIndexer {
        vka_address,
        vka_data: vka.serialize().expect("serialize vka"),
        deposits: Vec::new(),
        transfers: Vec::new(),
    };

    let backend = SquadsBackend::new(
        auditor,
        Keypair::new(),
        Address::default(),
        Address::default(),
        "http://127.0.0.1:3001",
        indexer,
        rpc,
    );

    let response = backend
        .get_balances(GetBalancesRequest {
            viewing_key_account: vka_address,
            skip_utxos: false,
            signature: [0u8; 64],
        })
        .expect("get balances");

    assert_eq!(response.balances.len(), 1);
    let sol = response.balances.first().expect("sol balance");
    assert_eq!(sol.asset_id, 1);
    assert_eq!(sol.amount, merged_amount);
    assert_eq!(sol.utxos.len(), 1);
    let utxo = sol.utxos.first().expect("merged utxo");
    assert_eq!(utxo.utxo_hash, [12u8; 32]);
    assert_eq!(utxo.amount, merged_amount);
    assert_eq!(utxo.blinding, merged_blinding);
}
