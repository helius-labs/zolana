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
use zolana_interface::event::{encode_output_data, ProoflessOutput};
use zolana_keypair::P256Pubkey;
use zolana_squads_client::{
    seed_viewing_key_account, tags::view_tag_from_shared_viewing_key, GetBalancesRequest,
    ReadAuthorization, SquadsBackend, SquadsBackendError, ViewingKeyAccountSeed,
};
use zolana_squads_interface::{types::Address, SQUADS_ZONE_PROGRAM_ID};
use zolana_squads_sdk::encrypted_utxo::encrypt_recipient_ciphertext;
use zolana_transaction::{instructions::transact::asset_field, SOL_MINT};

/// The suite reads its own seeded account, so it supplies a policy that
/// authorizes the read.
struct AllowSeededRead;

impl ReadAuthorization for AllowSeededRead {
    fn authorize(
        &self,
        _viewing_key_account: Address,
        _signature: &[u8; 64],
    ) -> Result<(), SquadsBackendError> {
        Ok(())
    }
}

struct MockIndexer {
    vka_address: Address,
    vka_data: Vec<u8>,
    deposits: Vec<EncryptedUtxoMatch>,
    transfers: Vec<ShieldedTransaction>,
    /// When set, every non-inclusion request fails as if the indexer were down.
    unavailable: bool,
}

impl Rpc for MockIndexer {
    fn get_account(&self, address: Address) -> core::result::Result<Option<Account>, ClientError> {
        if address == self.vka_address {
            Ok(Some(Account {
                lamports: 1,
                data: self.vka_data.clone(),
                owner: Address::new_from_array(SQUADS_ZONE_PROGRAM_ID),
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
        _config: Option<zolana_client::IndexerRpcConfig>,
    ) -> core::result::Result<GetEncryptedUtxosByTagsResponse, ClientError> {
        Ok(GetEncryptedUtxosByTagsResponse {
            context: Context { block_time: 0 },
            matches: self.deposits.clone(),
            next_cursor: None,
        })
    }

    fn get_shielded_transactions_by_tags(
        &self,
        _tags: Vec<[u8; 32]>,
        _cursor: Option<Vec<u8>>,
        _limit: Option<u32>,
        _config: Option<zolana_client::IndexerRpcConfig>,
    ) -> core::result::Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        Ok(GetShieldedTransactionsByTagsResponse {
            context: Context { block_time: 0 },
            transactions: self.transfers.clone(),
            next_cursor: None,
        })
    }

    fn get_non_inclusion_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
        _config: Option<zolana_client::IndexerRpcConfig>,
    ) -> core::result::Result<GetNonInclusionProofsResponse, ClientError> {
        if self.unavailable {
            return Err(ClientError::IndexerUnavailable("connection reset".into()));
        }
        // Every queried nullifier is absent (unspent), so each leaf gets a proof.
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
            context: Context { block_time: 0 },
            proofs,
        })
    }
}

/// A proofless SOL deposit of `amount`, tagged for `tag`.
fn sol_deposit_match(tag: [u8; 32], amount: u64) -> EncryptedUtxoMatch {
    let output = ProoflessOutput {
        owner: [1u8; 32],
        blinding: [5u8; 32],
        asset: SOL_MINT.to_bytes(),
        amount,
        data_hash: None,
        utxo_data: None,
        ring_program_id: None,
        ring_data_hash: None,
        ring_data: None,
        memo: None,
    };
    EncryptedUtxoMatch {
        slot: 1,
        tx_signature: solana_signature::Signature::default(),
        output_slot: OutputSlot {
            view_tag: tag,
            output_context: OutputContext {
                hash: [7u8; 32],
                tree: Address::default(),
                leaf_index: 0,
            },
            payload: encode_output_data(output),
        },
        tx_viewing_pk: None,
        salt: None,
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

    let deposit_match = sol_deposit_match(tag, 1_000_000);

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
        messages: Vec::new(),
        nullifiers: Vec::new(),
        proofless: false,
    };

    let indexer = MockIndexer {
        vka_address,
        vka_data: vka.serialize().expect("serialize vka"),
        deposits: vec![deposit_match],
        transfers: vec![transfer_tx],
        unavailable: false,
    };
    let rpc = MockIndexer {
        vka_address,
        vka_data: vka.serialize().expect("serialize vka"),
        deposits: Vec::new(),
        transfers: Vec::new(),
        unavailable: false,
    };

    let backend = SquadsBackend::new(
        auditor,
        Keypair::new(),
        Address::default(),
        Address::default(),
        "http://127.0.0.1:3001",
        indexer,
        rpc,
    )
    .with_read_authorization(AllowSeededRead);

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

/// Without a policy that authorizes the caller, a backend decrypts nothing.
#[test]
fn default_backend_denies_a_balance_read() {
    let indexer = MockIndexer {
        vka_address: Address::default(),
        vka_data: Vec::new(),
        deposits: Vec::new(),
        transfers: Vec::new(),
        unavailable: false,
    };
    let rpc = MockIndexer {
        vka_address: Address::default(),
        vka_data: Vec::new(),
        deposits: Vec::new(),
        transfers: Vec::new(),
        unavailable: false,
    };
    let backend = SquadsBackend::new(
        SecretKey::random(&mut OsRng),
        Keypair::new(),
        Address::default(),
        Address::default(),
        "http://127.0.0.1:1",
        indexer,
        rpc,
    );

    let error = backend
        .get_balances(GetBalancesRequest {
            viewing_key_account: Address::new_from_array([42u8; 32]),
            skip_utxos: true,
            signature: [0u8; 64],
        })
        .expect_err("an unauthorized read must not decrypt");
    assert!(matches!(error, SquadsBackendError::UnauthorizedRead(_)));
}

/// A transport failure must not read as spent. Reporting the UTXO as spent
/// drops it from the balance and from the crank's spendable set, so a merge or
/// settlement would build over the wrong input set.
#[test]
fn indexer_transport_failure_does_not_read_as_spent() {
    let shared = SecretKey::random(&mut OsRng);
    let ephemeral = SecretKey::random(&mut OsRng);
    let auditor = SecretKey::random(&mut OsRng);
    let auditor_pk = P256Pubkey::from_p256(&auditor.public_key());
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
        &[3u8; 32],
        &[],
        &[auditor_pk],
    )
    .expect("seed viewing key account");
    let tag = view_tag_from_shared_viewing_key(&vka.shared_viewing_key);
    let vka_data = vka.serialize().expect("serialize vka");

    let backend = SquadsBackend::new(
        auditor,
        Keypair::new(),
        Address::default(),
        Address::default(),
        "http://127.0.0.1:1",
        MockIndexer {
            vka_address,
            vka_data: vka_data.clone(),
            deposits: vec![sol_deposit_match(tag, 1_000_000)],
            transfers: Vec::new(),
            unavailable: true,
        },
        MockIndexer {
            vka_address,
            vka_data,
            deposits: Vec::new(),
            transfers: Vec::new(),
            unavailable: false,
        },
    )
    .with_read_authorization(AllowSeededRead);

    let error = backend
        .get_balances(GetBalancesRequest {
            viewing_key_account: vka_address,
            skip_utxos: false,
            signature: [0u8; 64],
        })
        .expect_err("an unreachable indexer must not report the utxo as spent");
    assert!(matches!(
        error,
        SquadsBackendError::Client(ClientError::IndexerUnavailable(_))
    ));
}
