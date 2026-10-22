use solana_account::Account;
use solana_keypair::Keypair;
use zolana_client::{
    rpc::{
        Context, GetNonInclusionProofsResponse, GetShieldedTransactionsByNullifiersResponse,
        GetShieldedTransactionsByTagsResponse, MerkleContext, NonInclusionProof, OutputContext,
        OutputSlot, ShieldedTransaction,
    },
    ClientError, IndexerRpcConfig, Rpc,
};
use zolana_event::{
    encode_encrypted_ring_deposit_output, EncryptedRingDepositData, EncryptedRingDepositOutput,
};
use zolana_hasher::primitives::solana_owner_identity;
use zolana_keypair::X25519Keypair;
use zolana_keypair::{NullifierKey, PublicKey, X25519Pubkey};
use zolana_squads_client::{
    seed_viewing_key_account, tags::view_tag_from_shared_viewing_key, AssetBalance, DecryptedUtxo,
    GetBalancesRequest, GetBalancesResponse, SquadsBackend, ViewingKeyAccountSeed, SOL_ASSET_ID,
};
use zolana_squads_interface::{types::Address, SQUADS_RING_PROGRAM_ID};
use zolana_squads_sdk::{
    encrypted_utxo::{encrypt_recipient_ciphertext, encrypt_sender_ciphertext},
    prover::derive_spend_secrets,
};
use zolana_transaction::{
    instructions::{merge::merge_output_blinding, transact::asset_field},
    Data, Mint, Utxo, SOL_MINT,
};

const VKA_ADDRESS: Address = Address::new_from_array([42u8; 32]);
const SPL_ASSET_ID: u64 = 2;
const SPL_MINT: Address = Address::new_from_array([77u8; 32]);
const OTHER_TAG: [u8; 32] = [0xEEu8; 32];

#[derive(Clone)]
struct MockIndexer {
    vka_data: Vec<u8>,
    transactions: Vec<ShieldedTransaction>,
    spent_nullifiers: Vec<[u8; 32]>,
}

fn context() -> Context {
    Context {
        block_time: 0,
        slot: 0,
    }
}

impl Rpc for MockIndexer {
    fn get_account(&self, address: Address) -> core::result::Result<Option<Account>, ClientError> {
        Ok((address == VKA_ADDRESS).then(|| Account {
            lamports: 1,
            data: self.vka_data.clone(),
            owner: Address::default(),
            executable: false,
            rent_epoch: 0,
        }))
    }

    fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        _cursor: Option<Vec<u8>>,
        _limit: Option<u32>,
        _config: Option<IndexerRpcConfig>,
    ) -> core::result::Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        Ok(GetShieldedTransactionsByTagsResponse {
            context: context(),
            output_tree_id: None,
            transactions: self
                .transactions
                .iter()
                .filter(|tx| tx.output_slots.iter().any(|s| tags.contains(&s.view_tag)))
                .cloned()
                .collect(),
            next_cursor: None,
            scanned_through: None,
        })
    }

    fn get_shielded_transactions_by_nullifiers(
        &self,
        nullifiers: Vec<[u8; 32]>,
        _cursor: Option<Vec<u8>>,
        _limit: Option<u32>,
        _config: Option<IndexerRpcConfig>,
    ) -> core::result::Result<GetShieldedTransactionsByNullifiersResponse, ClientError> {
        Ok(GetShieldedTransactionsByNullifiersResponse {
            context: context(),
            output_tree_id: None,
            transactions: self
                .transactions
                .iter()
                .filter(|tx| tx.nullifiers.iter().any(|n| nullifiers.contains(n)))
                .cloned()
                .collect(),
            next_cursor: None,
            scanned_through: None,
        })
    }

    fn get_non_inclusion_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
        _config: Option<IndexerRpcConfig>,
    ) -> core::result::Result<GetNonInclusionProofsResponse, ClientError> {
        let proofs = leaves
            .into_iter()
            .filter(|leaf| !self.spent_nullifiers.contains(leaf))
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
            context: context(),
            proofs,
        })
    }
}

/// A 248-bit blinding: a BN254 field element.
fn blinding(byte: u8) -> [u8; 32] {
    core::array::from_fn(|i| if i == 0 { 0 } else { byte })
}

struct Holder {
    owner_identity: [u8; 32],
    nullifier_pubkey: [u8; 32],
    nullifier_key: NullifierKey,
    tag: [u8; 32],
}

impl Holder {
    fn mint(asset_id: u64) -> Mint {
        if asset_id == SOL_ASSET_ID {
            Mint::SOL
        } else {
            Mint::new(SPL_MINT, asset_id)
        }
    }

    fn utxo(
        &self,
        asset_id: u64,
        amount: u64,
        blinding: [u8; 32],
        tree_id: u16,
        leaf_index: u64,
    ) -> DecryptedUtxo {
        let utxo_hash = Utxo {
            owner: PublicKey::from_owner_identity(self.owner_identity),
            asset: Self::mint(asset_id),
            amount,
            blinding,
            ring_program_id: Some(Address::new_from_array(SQUADS_RING_PROGRAM_ID)),
            data: Data::default(),
        }
        .hash(&self.nullifier_pubkey, &[0u8; 32], &[0u8; 32], tree_id)
        .expect("utxo hash");
        DecryptedUtxo {
            utxo_hash,
            asset_id,
            amount,
            blinding,
            tree_id,
            leaf_index,
        }
    }

    fn nullifier(&self, utxo: &DecryptedUtxo) -> [u8; 32] {
        self.nullifier_key
            .nullifier(&utxo.utxo_hash, &utxo.blinding)
            .expect("nullifier")
    }
}

fn slot(view_tag: [u8; 32], utxo: &DecryptedUtxo, payload: Vec<u8>) -> OutputSlot {
    OutputSlot {
        view_tag,
        output_context: OutputContext {
            hash: utxo.utxo_hash,
            tree_id: utxo.tree_id,
            leaf_index: utxo.leaf_index,
        },
        payload,
    }
}

fn deposit_payload(utxo: &DecryptedUtxo, mint: Address) -> Vec<u8> {
    encode_encrypted_ring_deposit_output(EncryptedRingDepositOutput {
        owner_utxo_hash: [0u8; 32],
        asset: mint.to_bytes(),
        amount: utxo.amount,
        data_hash: None,
        ring_program_id: SQUADS_RING_PROGRAM_ID,
        ring_data_hash: [0u8; 32],
        encrypted: EncryptedRingDepositData {
            tx_viewing_pk: [0u8; 33],
            salt: [0u8; 16],
            ciphertext: utxo.blinding.to_vec(),
        },
    })
}

fn transaction(
    signature_byte: u8,
    tx_viewing_pk: Option<X25519Pubkey>,
    output_slots: Vec<OutputSlot>,
    nullifiers: Vec<[u8; 32]>,
    proofless: bool,
) -> ShieldedTransaction {
    ShieldedTransaction {
        slot: u64::from(signature_byte),
        tx_signature: solana_signature::Signature::from([signature_byte; 64]),
        event_index: None,
        tx_viewing_pk,
        salt: tx_viewing_pk.map(|_| [0u8; 16]),
        output_slots,
        messages: Vec::new(),
        nullifiers,
        proofless,
        ring_config: None,
        ring_program_id: Some(Address::new_from_array(SQUADS_RING_PROGRAM_ID)),
    }
}

/// One account's history: deposits (one later spent, two later merged, one
/// forged), a transfer received from another account, a spend that leaves
/// change, and a merge. Only the deposit, the received transfer, the change and
/// the merge output are unspent.
#[test]
fn get_balances_scans_deposits_transfers_change_and_merges() {
    let shared = X25519Keypair::new();
    let auditor = X25519Keypair::new();
    let auditor_pk = auditor.pubkey();
    let nullifier_secret = [3u8; 32];
    let owner_identity = solana_owner_identity(&[1u8; 32]).expect("owner identity");

    let vka = seed_viewing_key_account(
        ViewingKeyAccountSeed {
            owner: Address::new_from_array(owner_identity),
            owner_kind: 2,
            state: 1,
            encryption_scheme: zolana_squads_interface::constants::ENCRYPTION_SCHEME_X25519_AES,
            key_nonce: 0,
        },
        &shared,
        &X25519Keypair::new(),
        &nullifier_secret,
        &[],
        &[auditor_pk],
    )
    .expect("seed account");
    let low_secret: [u8; 31] = nullifier_secret
        .get(1..)
        .and_then(|s| s.try_into().ok())
        .expect("low 31 bytes");
    let account = Holder {
        owner_identity,
        nullifier_pubkey: vka.nullifier_pubkey,
        nullifier_key: NullifierKey::from_secret(low_secret),
        tag: view_tag_from_shared_viewing_key(&vka.shared_viewing_key),
    };
    let sol_fe = asset_field(&SOL_MINT).expect("sol asset field");

    let deposit = account.utxo(SOL_ASSET_ID, 1_000_000, blinding(5), 0, 0);
    let spent_deposit = account.utxo(SOL_ASSET_ID, 2_000, blinding(6), 0, 1);
    let merged_a = account.utxo(SOL_ASSET_ID, 300, blinding(7), 0, 2);
    let merged_b = account.utxo(SOL_ASSET_ID, 400, blinding(8), 0, 3);
    let spl_deposit = account.utxo(SPL_ASSET_ID, 50, blinding(9), 1, 0);
    let forged = account.utxo(SOL_ASSET_ID, 9_999, blinding(10), 0, 4);
    let mut forged_payload_utxo = forged;
    forged_payload_utxo.blinding = blinding(11);
    let foreign_deposit = account.utxo(SOL_ASSET_ID, 7_777, blinding(12), 0, 5);

    let deposit_tx = transaction(
        1,
        None,
        vec![
            slot(account.tag, &deposit, deposit_payload(&deposit, SOL_MINT)),
            slot(
                account.tag,
                &spent_deposit,
                deposit_payload(&spent_deposit, SOL_MINT),
            ),
            slot(account.tag, &merged_a, deposit_payload(&merged_a, SOL_MINT)),
            slot(account.tag, &merged_b, deposit_payload(&merged_b, SOL_MINT)),
            slot(
                account.tag,
                &spl_deposit,
                deposit_payload(&spl_deposit, SPL_MINT),
            ),
            slot(
                account.tag,
                &forged,
                deposit_payload(&forged_payload_utxo, SOL_MINT),
            ),
            slot(
                OTHER_TAG,
                &foreign_deposit,
                deposit_payload(&foreign_deposit, SOL_MINT),
            ),
        ],
        Vec::new(),
        true,
    );

    let received = account.utxo(SOL_ASSET_ID, 500, blinding(13), 0, 6);
    let sender_tx_viewing_sk = X25519Keypair::new();
    let recipient_ciphertext = encrypt_recipient_ciphertext(
        &sender_tx_viewing_sk,
        &shared.pubkey(),
        received.amount,
        &sol_fe,
        &received.blinding,
    )
    .expect("encrypt recipient");
    let received_tx = transaction(
        2,
        Some(sender_tx_viewing_sk.pubkey()),
        vec![slot(account.tag, &received, recipient_ciphertext.to_vec())],
        vec![[0xAAu8; 32]],
        false,
    );

    let spent_nullifier = account.nullifier(&spent_deposit);
    let secrets = derive_spend_secrets(&shared, &spent_nullifier).expect("spend secrets");
    let change = account.utxo(SOL_ASSET_ID, 1_500, secrets.change_blinding, 0, 7);
    let sender_ciphertext =
        encrypt_sender_ciphertext(&secrets.tx_viewing_sk, change.amount, &sol_fe)
            .expect("encrypt sender");
    let spend_tx = transaction(
        3,
        Some(X25519Pubkey::from_bytes(secrets.tx_viewing_pk).expect("tx viewing pk")),
        vec![slot(account.tag, &change, sender_ciphertext.to_vec())],
        vec![spent_nullifier, [0xBBu8; 32]],
        false,
    );

    let merge_first_nullifier = account.nullifier(&merged_a);
    let merge_blinding =
        merge_output_blinding(&account.nullifier_key, &merge_first_nullifier).expect("blinding");
    let merged = account.utxo(SOL_ASSET_ID, 700, merge_blinding, 0, 8);
    let merge_tx = transaction(
        4,
        None,
        vec![slot(merge_first_nullifier, &merged, Vec::new())],
        vec![merge_first_nullifier, account.nullifier(&merged_b)],
        false,
    );

    let indexer = MockIndexer {
        vka_data: vka.serialize().expect("serialize vka"),
        transactions: vec![deposit_tx, received_tx, spend_tx, merge_tx],
        spent_nullifiers: vec![
            spent_nullifier,
            merge_first_nullifier,
            account.nullifier(&merged_b),
        ],
    };
    let mut backend = SquadsBackend::new(
        auditor,
        Keypair::new(),
        Address::default(),
        0,
        "http://127.0.0.1:3001",
        indexer.clone(),
        indexer,
    );
    backend.register_asset(SPL_ASSET_ID, SPL_MINT);

    let balances = |skip_utxos| {
        backend
            .get_balances(GetBalancesRequest {
                viewing_key_account: VKA_ADDRESS,
                skip_utxos,
                signature: [0u8; 64],
            })
            .expect("get balances")
    };

    assert_eq!(
        balances(false),
        GetBalancesResponse {
            balances: vec![
                AssetBalance {
                    asset_id: SOL_ASSET_ID,
                    mint: SOL_MINT,
                    amount: 1_002_700,
                    utxos: vec![deposit, received, change, merged],
                },
                AssetBalance {
                    asset_id: SPL_ASSET_ID,
                    mint: SPL_MINT,
                    amount: 50,
                    utxos: vec![spl_deposit],
                },
            ],
        }
    );
    assert_eq!(
        balances(true),
        GetBalancesResponse {
            balances: vec![
                AssetBalance {
                    asset_id: SOL_ASSET_ID,
                    mint: SOL_MINT,
                    amount: 1_002_700,
                    utxos: Vec::new(),
                },
                AssetBalance {
                    asset_id: SPL_ASSET_ID,
                    mint: SPL_MINT,
                    amount: 50,
                    utxos: Vec::new(),
                },
            ],
        }
    );
}
