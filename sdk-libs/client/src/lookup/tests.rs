use std::sync::{Arc, Mutex};

use crate::rpc::{OutputContext, OutputSlot};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use solana_keypair::Keypair;
use solana_signer::Signer;
use spr_instruction::instruction::Transact;
use spr_interface::instruction::{CircuitId, InputUtxo, TransactProof, TreeContext};
use spr_transaction::{AssetRegistry, History, Mint, Utxo};

use super::*;
use crate::{compile_message, ComputeBudgetConfig};
use solana_transaction::versioned::VersionedTransaction;
use spr_interface::pda;
use spr_transaction::HistoryKind as ActivityKind;
use spr_transaction::{
    instructions::transact::ConfidentialTransaction, SppProofOutputUtxo, WalletUtxo,
};
use spr_user_registry_interface::MergeEncryptionScheme;
use std::str::FromStr;

type Handler = dyn Fn(&str, &Value) -> Value + Send + Sync;
struct ReaderRpc {
    handler: Arc<Handler>,
}
impl ReaderRpc {
    fn answer(&self, method: &str, params: Value) -> Result<Value, ClientError> {
        let response = (self.handler)(method, &params);
        if let Some(error) = response.get("error") {
            return Err(ClientError::Rpc(error.to_string()));
        }
        Ok(response["result"].clone())
    }
}
impl Rpc for ReaderRpc {
    fn get_confirmed_transaction(
        &self,
        signature: Signature,
    ) -> Result<Option<Confirmed>, ClientError> {
        Ok(
            serde_json::from_value(self.answer("getTransaction", json!([signature.to_string()]))?)
                .unwrap(),
        )
    }
    fn get_shielded_transactions_by_signature(
        &self,
        signature: Signature,
        _: Option<crate::IndexerRpcConfig>,
    ) -> Result<crate::GetShieldedTransactionsBySignatureResponse, ClientError> {
        let value = self.answer(
            "getShieldedTransactionsBySignature",
            json!({"signature":signature.to_string()}),
        )?;
        Ok(crate::GetShieldedTransactionsBySignatureResponse {
            context: crate::Context {
                slot: value["context"]["slot"].as_u64().unwrap(),
                block_time: 0,
            },
            output_tree_id: None,
            transactions: value["transactions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|event| crate::IndexedShieldedTransaction {
                    event_index: event["eventIndex"].as_u64().unwrap() as u16,
                    transaction: crate::indexer::decode_shielded_transaction(
                        serde_json::from_value(event["transaction"].clone()).unwrap(),
                    )
                    .unwrap(),
                })
                .collect(),
        })
    }
    fn get_user_records(
        &self,
        owners: Vec<Pubkey>,
        _: Option<crate::IndexerRpcConfig>,
    ) -> Result<crate::GetUserRecordsResponse, ClientError> {
        let value = self.answer(
            "getUserRecords",
            json!({"owners":owners.iter().map(ToString::to_string).collect::<Vec<_>>()}),
        )?;
        let records = value["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|record| {
                if record.is_null() {
                    return None;
                }
                Some(spr_user_registry_interface::UserRecord {
                    owner: record["owner"].as_str().unwrap().parse().unwrap(),
                    bump: 0,
                    nullifier_pubkey: bs58::decode(record["nullifierPubkey"].as_str().unwrap())
                        .into_vec()
                        .unwrap()
                        .try_into()
                        .unwrap(),
                    viewing_pubkey: STANDARD
                        .decode(record["viewingPubkey"].as_str().unwrap())
                        .unwrap()
                        .try_into()
                        .unwrap(),
                    merge_encryption: MergeEncryptionScheme::Disabled,
                })
            })
            .collect();
        Ok(crate::GetUserRecordsResponse {
            context: crate::Context {
                slot: 10,
                block_time: 0,
            },
            records,
        })
    }
    fn get_program_accounts_filtered(
        &self,
        _: Pubkey,
        _: &crate::ProgramAccountsFilter,
    ) -> Result<Vec<(Pubkey, solana_account::Account)>, ClientError> {
        let value = self.answer("getProgramAccounts", json!([]))?;
        Ok(value
            .as_array()
            .unwrap()
            .iter()
            .map(|item| {
                (
                    item["pubkey"].as_str().unwrap().parse().unwrap(),
                    solana_account::Account {
                        data: STANDARD
                            .decode(item["account"]["data"][0].as_str().unwrap())
                            .unwrap(),
                        owner: item["account"]["owner"].as_str().unwrap().parse().unwrap(),
                        ..Default::default()
                    },
                )
            })
            .collect())
    }
}
struct Reader {
    owner: Pubkey,
    address: spr_keypair::ShieldedAddress,
    keys: spr_transaction::LocalShieldedKeys,
    nullifier_key: spr_keypair::NullifierKey,
    rpc: ReaderRpc,
    registry: Mutex<AssetRegistry>,
}
impl Reader {
    fn transaction(&self, signature: String) -> Result<TransactionLookup, ClientError> {
        self.transaction_with_prepared(signature, &[])
    }
    fn transaction_with_prepared(
        &self,
        signature: String,
        outputs: &[spr_transaction::SppProofOutputUtxo],
    ) -> Result<TransactionLookup, ClientError> {
        let openings: Vec<_> = outputs
            .iter()
            .filter(|output| output.is_dummy() && !output.is_compact())
            .map(|output| DummyOutputOpening {
                tree_id: 0,
                blinding: output.blinding,
            })
            .collect();
        self.lookup(signature, &openings)
    }
    fn lookup(
        &self,
        signature: String,
        openings: &[DummyOutputOpening],
    ) -> Result<TransactionLookup, ClientError> {
        TransactionReader::new(&self.keys, &self.registry.lock().unwrap())
            .with_asset_discovery()
            .with_padding_openings(openings)
            .fetch(&self.rpc, signature.parse().unwrap())
    }
}
fn wallet(
    signer: &Keypair,
    handler: impl Fn(&str, &Value) -> Value + Send + Sync + 'static,
) -> (Reader, Arc<Mutex<Vec<String>>>) {
    let asked = Arc::new(Mutex::new(Vec::new()));
    let calls = Arc::clone(&asked);
    let handler = Arc::new(move |method: &str, params: &Value| {
        calls.lock().unwrap().push(method.to_string());
        handler(method, params)
    });
    let keypair = spr_keypair::ShieldedKeypair::from_keypair(
        spr_keypair::SigningKey::from_ed25519_bytes(&signer.to_bytes()[..32].try_into().unwrap()),
    )
    .unwrap();
    (
        Reader {
            owner: signer.pubkey(),
            address: keypair.shielded_address().unwrap(),
            keys: spr_transaction::LocalShieldedKeys::from_keypair(&keypair).unwrap(),
            nullifier_key: keypair.nullifier_key,
            rpc: ReaderRpc { handler },
            registry: Mutex::new(AssetRegistry::default()),
        },
        asked,
    )
}
fn identity(signer: &Keypair) -> Reader {
    wallet(signer, |method, _| panic!("unexpected request: {method}")).0
}

struct Fixture {
    signature: Signature,
    chain: Value,
    events: Vec<ShieldedTransaction>,
    registry: AssetRegistry,
    notes: Vec<WalletUtxo>,
    openings: Vec<SppProofOutputUtxo>,
    records: HashMap<Pubkey, spr_user_registry_interface::UserRecord>,
}

impl Fixture {
    /// Real encrypted default-ring spend, with known source notes only in the
    /// fixture. The lookup receives neither those notes nor any history page.
    fn spend(
        sender: &Reader,
        recipient: &Reader,
        private: u64,
        withdrawal: u64,
        assets: &[Mint],
    ) -> Self {
        Self::spend_with_cache(sender, recipient, private, withdrawal, assets, false)
    }

    fn spend_with_cache(
        sender: &Reader,
        recipient: &Reader,
        private: u64,
        withdrawal: u64,
        assets: &[Mint],
        cached: bool,
    ) -> Self {
        let payer = sender.owner;
        let mut registry = AssetRegistry::default();
        for mint in assets {
            if mint.asset != SOL_MINT {
                registry.insert(mint.asset_id, mint.asset).unwrap();
            }
        }
        let mut notes = Vec::new();
        for (index, asset) in assets.iter().enumerate() {
            let utxo = Utxo {
                owner: sender.address.signing_pubkey,
                asset: *asset,
                amount: 100,
                blinding: [index as u8 + 1; 32],
                ring_program_id: None,
                data: Default::default(),
            };
            let hash = utxo
                .hash(&sender.address.nullifier_pubkey, &[0; 32], &[0; 32], 0)
                .unwrap();
            let nullifier = utxo.nullifier(&hash, &sender.nullifier_key).unwrap();
            notes.push(WalletUtxo {
                utxo,
                nullifier_pubkey: sender.address.nullifier_pubkey,
                utxo_hash: hash,
                nullifier,
                tx_viewing_key: None,
                data_hash: None,
                ring_data_hash: None,
                tree_id: 0,
                leaf_index: index as u64,
                latest_tree_id: None,
                slot: 1,
                tx_signature: Signature::from([1; 64]),
                slot_index: index as u32,
            });
        }
        let mut transaction = ConfidentialTransaction::new(notes.clone(), payer).unwrap();
        let mut settlements = Vec::new();
        for asset in assets {
            if private > 0 {
                if asset.asset == SOL_MINT {
                    transaction
                        .transfer_sol(&recipient.address, private)
                        .unwrap();
                } else {
                    transaction
                        .transfer(&recipient.address, asset.asset, private)
                        .unwrap();
                }
            }
            if withdrawal > 0 {
                settlements.push(
                    transaction
                        .withdraw_to(
                            asset.asset,
                            withdrawal,
                            recipient.owner,
                            (asset.asset != SOL_MINT).then(pda::spl_token_program_id),
                        )
                        .unwrap(),
                );
            }
        }
        let inputs = transaction.encrypt(&sender.keys).unwrap();
        let tree_id = inputs.output_tree_id;
        // Read back only wire-visible data, just as the indexer does.
        let data = TransactIxData {
            expiry_unix_ts: u64::MAX,
            tx_viewing_pk: inputs.external_data.tx_viewing_pk,
            salt: inputs.external_data.salt,
            interface_transfers: inputs
                .external_data
                .interface_transfers
                .iter()
                .map(|leg| leg.interface_transfer())
                .collect(),
            data_hash: None,
            ring_data_hash: None,
            outputs: inputs.external_data.outputs.clone(),
            messages: vec![],
            private_tx_hash: [0; 32],
            circuit: CircuitId::ConfidentialEddsa(
                inputs.input_utxos.len() as u8,
                inputs.output_utxos.len() as u8,
                3,
            ),
            proof: TransactProof::zeroed(),
            inputs: inputs
                .input_utxos
                .iter()
                .filter(|input| !input.compact)
                .map(|input| InputUtxo {
                    nullifier_hash: input.nullifier(),
                    tree_index: 0,
                })
                .collect(),
            tree_contexts: vec![TreeContext {
                utxo_tree_root_index: 0,
                nullifier_tree_root_index: 0,
            }],
        };
        let mut builder = Transact {
            payer,
            input_trees: vec![pda::tree(0)],
            output_tree: pda::tree(tree_id),
            owner_signers: vec![sender.owner],
            interface_transfer_accounts: settlements,
            data,
        };
        let ix = if cached {
            builder.data.circuit = CircuitId::ConfidentialEddsaCached(
                inputs.input_utxos.len() as u8,
                inputs.output_utxos.len() as u8,
                3,
                spr_interface::verifying_keys::CacheAccess {
                    read_bitmap: 1,
                    write_slots: spr_interface::verifying_keys::CacheAccess::NO_WRITES,
                },
            );
            builder.instruction_with_cache_read(pda::cache(&payer, 9).0)
        } else {
            builder.instruction()
        };
        let signature = Signature::from([12; 64]);
        let message = compile_message(
            &payer,
            std::slice::from_ref(&ix),
            Default::default(),
            ComputeBudgetConfig::new(1_000_000),
        )
        .unwrap();
        let signed = VersionedTransaction {
            signatures: vec![signature],
            message,
        };
        let chain = json!({"slot": 10, "blockTime": 0, "version": 1,
            "transaction": {"signatures": [signature.to_string()], "message": {
                "header": signed.message.header(),
                "accountKeys": signed.message.static_account_keys().iter().map(ToString::to_string).collect::<Vec<_>>(),
                "recentBlockhash": signed.message.recent_blockhash().to_string(),
                "instructions": signed.message.instructions().iter().map(|ix| solana_transaction_status_client_types::UiCompiledInstruction::from(ix, None)).collect::<Vec<_>>(),
                "addressTableLookups": []
            }},
            "meta": {"err": null, "status": {"Ok": null}, "fee": 5000,
                "preBalances": [], "postBalances": [], "innerInstructions": [], "logMessages": [],
                "preTokenBalances": [], "postTokenBalances": [], "rewards": []}
        });
        let event = ShieldedTransaction {
            slot: 10,
            tx_signature: signature,
            event_index: Some(0),
            tx_viewing_pk: Some(
                spr_keypair::X25519Pubkey::from_bytes(builder.data.tx_viewing_pk).unwrap(),
            ),
            salt: Some(builder.data.salt),
            nullifiers: builder
                .data
                .inputs
                .iter()
                .map(|input| input.nullifier_hash)
                .collect(),
            output_slots: builder
                .data
                .outputs
                .iter()
                .enumerate()
                .map(|(index, output)| OutputSlot {
                    view_tag: fetch_tag(&output.owner_tag, |i| {
                        ix.accounts
                            .get(usize::from(i))
                            .map(|account| account.pubkey.to_bytes())
                    })
                    .unwrap(),
                    output_context: OutputContext {
                        hash: output.utxo_hash,
                        tree_id,
                        leaf_index: 100 + index as u64,
                    },
                    payload: output.data.clone().unwrap_or_default(),
                })
                .collect(),
            messages: vec![],
            proofless: false,
            ring_config: None,
            ring_program_id: None,
        };
        let record = spr_user_registry_interface::UserRecord {
            owner: recipient.owner,
            bump: 0,
            nullifier_pubkey: recipient.address.nullifier_pubkey,
            viewing_pubkey: *recipient.address.viewing_pubkey.as_bytes(),
            merge_encryption: MergeEncryptionScheme::Disabled,
        };
        Self {
            signature,
            chain,
            events: vec![event],
            registry,
            notes,
            openings: inputs.output_utxos.clone(),
            records: HashMap::from([(recipient.owner, record)]),
        }
    }

    fn indexer(&self, slot: u64) -> Value {
        json!({"context": {"slot": slot, "blockTime": 0}, "transactions": self.events.iter().enumerate().map(|(index, tx)| json!({
            "eventIndex": index, "transaction": {
                "slot": tx.slot, "txSignature": tx.tx_signature.to_string(), "eventIndex": tx.event_index,
                "txViewingPk": tx.tx_viewing_pk.map(|key| STANDARD.encode(key.as_bytes())),
                "salt": tx.salt.map(|salt| STANDARD.encode(salt)), "proofless": tx.proofless,
                "nullifiers": tx.nullifiers.iter().map(|hash| spr_api::Hash::from(*hash).to_base58()).collect::<Vec<_>>(),
                "messages": [], "outputSlots": tx.output_slots.iter().map(|slot| json!({
                    "viewTag": spr_api::Hash::from(slot.view_tag).to_base58(), "payload": STANDARD.encode(&slot.payload),
                    "outputContext": {"hash": spr_api::Hash::from(slot.output_context.hash).to_base58(),
                        "tree": pda::tree(slot.output_context.tree_id).to_string(), "treeId": slot.output_context.tree_id,
                        "leafIndex": slot.output_context.leaf_index}
                })).collect::<Vec<_>>()
            }
        })).collect::<Vec<_>>()})
    }

    fn open(self, signer: &Keypair) -> (Reader, Arc<Mutex<Vec<String>>>) {
        self.open_with_registry(signer, true)
    }

    fn prepared(&self, _: &Keypair) -> Vec<SppProofOutputUtxo> {
        self.openings.clone()
    }

    fn open_with_registry(
        self,
        signer: &Keypair,
        preload: bool,
    ) -> (Reader, Arc<Mutex<Vec<String>>>) {
        let registry = self.registry.clone();
        let indexed = self.indexer(10);
        let (wallet, calls) = wallet(signer, move |method, params| match method {
            "getShieldedTransactionsBySignature" => json!({"result": indexed}),
            "getTransaction" => json!({"result": self.chain}),
            "getProgramAccounts" => {
                json!({"result": self.notes.iter().filter(|note| note.utxo.asset.asset != SOL_MINT).map(|note| {
                let mint = note.utxo.asset;
                json!({"pubkey": pda::spl_asset_registry(&mint.asset).to_string(), "account": {
                    "owner": PROGRAM_ID_PUBKEY.to_string(), "lamports": 1000000, "executable": false, "rentEpoch": 0,
                    "data": [STANDARD.encode(spr_interface::state::SplAssetRegistry::account_bytes(mint.asset, mint.asset_id)), "base64"]
                }})
            }).collect::<Vec<_>>()})
            }
            "getUserRecords" => {
                let records = params["owners"].as_array().unwrap().iter().map(|owner| {
                    let owner = Pubkey::from_str(owner.as_str().unwrap()).unwrap();
                    self.records.get(&owner).map(|record| json!({"owner": record.owner.to_string(),
                        "nullifierPubkey": spr_api::Hash::from(record.nullifier_pubkey).to_base58(),
                        "viewingPubkey": STANDARD.encode(record.viewing_pubkey), "mergeEncryption": 0}))
                }).collect::<Vec<_>>();
                json!({"result": {"context": {"slot": 10, "blockTime": 0}, "records": records}})
            }
            _ => panic!("lookup must not fetch history: {method}"),
        });
        if preload {
            *wallet.registry.lock().unwrap() = registry;
        }
        (wallet, calls)
    }
}

#[test]
fn cold_lookup_matches_history_for_sends_withdrawals_and_multiple_assets() {
    let sender = Keypair::new();
    let recipient = Keypair::new();
    let owner = identity(&sender);
    let recipient_wallet = identity(&recipient);
    for (private, withdrawal) in [(20, 0), (0, 100), (10, 20)] {
        for (assets, cached) in [
            (vec![Mint::SOL], false),
            (vec![Mint::SOL], true),
            (vec![Mint::SOL, Mint::new(Pubkey::new_unique(), 7)], false),
            (vec![Mint::SOL, Mint::new(Pubkey::new_unique(), 7)], true),
        ] {
            let fixture = Fixture::spend_with_cache(
                &owner,
                &recipient_wallet,
                private,
                withdrawal,
                &assets,
                cached,
            );
            let decoded = decrypt(&owner.keys, &fixture.events, &fixture.registry).unwrap();
            let mut utxos = fixture.notes.clone();
            utxos.extend(verify_owned(&owner.keys, &decoded).unwrap().utxos);
            let expected = History {
                transactions: fixture.events.clone(),
                utxos,
                view_tags: [owner
                    .address
                    .signing_pubkey
                    .confidential_view_tag()
                    .unwrap()]
                .into_iter()
                .collect(),
                ..Default::default()
            }
            .entries();
            let confirmed: Confirmed = serde_json::from_value(fixture.chain.clone()).unwrap();
            let groups = ConfirmedInstructionGroups::try_from(confirmed)
                .expect("fixture instruction groups");
            assert!(
                transact_context(&fixture.events[0], &groups).is_some(),
                "fixture event matches its instruction"
            );
            let signature = fixture.signature.to_string();
            let (wallet, asked) = fixture.open(&sender);
            let result = wallet.transaction(signature).unwrap();
            assert_eq!(
                result.status,
                Status::Ready,
                "private={private}, withdrawal={withdrawal}, assets={assets:?}, calls={:?}",
                asked.lock().unwrap()
            );
            let rows = |entries: &[HistoryEntry]| {
                entries
                    .iter()
                    .map(|entry| {
                        (
                            entry.kind,
                            entry.mint,
                            entry.amount,
                            entry.tx_signature,
                            entry.slot,
                        )
                    })
                    .collect::<Vec<_>>()
            };
            assert_eq!(rows(&result.entries), rows(&expected));
            assert!(!result.entries.is_empty());
            assert_eq!(result.indexed_slot, 10);
            assert!(asked.lock().unwrap().iter().all(|method| [
                "getTransaction",
                "getShieldedTransactionsBySignature",
                "getUserRecords"
            ]
            .contains(&method.as_str())));
        }
    }
}

#[test]
fn incoming_unrelated_and_self_transfers_are_read_without_history() {
    let sender = Keypair::new();
    let recipient = Keypair::new();
    let owner = identity(&sender);
    let other = identity(&recipient);
    let fixture = Fixture::spend(&owner, &other, 20, 0, &[Mint::SOL]);
    let signature = fixture.signature.to_string();
    let (wallet, _) = fixture.open(&recipient);
    let incoming = wallet.transaction(signature).unwrap();
    assert_eq!(incoming.status, Status::Ready);
    assert_eq!(incoming.entries.len(), 1);
    assert_eq!(
        (incoming.entries[0].kind, incoming.entries[0].amount),
        (ActivityKind::Received, 20)
    );

    let fixture = Fixture::spend(&owner, &other, 20, 0, &[Mint::SOL]);
    let signature = fixture.signature.to_string();
    let (wallet, _) = fixture.open(&Keypair::new());
    let unrelated = wallet.transaction(signature).unwrap();
    assert_eq!(unrelated.status, Status::Ready);
    assert!(unrelated.entries.is_empty());

    let fixture = Fixture::spend(&owner, &owner, 20, 0, &[Mint::SOL]);
    let signature = fixture.signature.to_string();
    let (wallet, _) = fixture.open(&sender);
    let own = wallet.transaction(signature).unwrap();
    assert_eq!(own.status, Status::Ready);
    assert_eq!(
        (own.entries[0].kind, own.entries[0].amount),
        (ActivityKind::SelfTransfer, 100)
    );
}

#[test]
fn indexing_delay_not_found_and_indexed_empty_are_distinct() {
    let signer = Keypair::new();
    for (chain_slot, indexed_slot, expected) in [
        (Some(10), 9, Status::PendingIndexing),
        (Some(10), 10, Status::Ready),
        (None, 10, Status::NotFound),
    ] {
        let owner = identity(&signer);
        let mut fixture = Fixture::spend(&owner, &owner, 20, 0, &[Mint::SOL]);
        fixture.events.clear();
        let indexed = fixture.indexer(indexed_slot);
        let chain = chain_slot.map(|_| fixture.chain).unwrap_or(Value::Null);
        let (wallet, asked) = wallet(&signer, move |method, _| match method {
            "getShieldedTransactionsBySignature" => json!({"result": indexed}),
            "getTransaction" => json!({"result": chain}),
            _ => panic!("unexpected request: {method}"),
        });
        let result = wallet
            .transaction(Signature::from([12; 64]).to_string())
            .unwrap();
        assert_eq!(result.status, expected);
        assert_eq!(result.slot, chain_slot);
        assert!(result.entries.is_empty());
        assert_eq!(asked.lock().unwrap().len(), 2);
    }
}

#[test]
fn network_failures_are_not_empty_results() {
    let signer = Keypair::new();
    let (wallet, _) = wallet(
        &signer,
        |_, _| json!({"error": {"code": -32603, "message": "unavailable"}}),
    );
    assert!(matches!(
        wallet.transaction(Signature::from([12; 64]).to_string()),
        Err(ClientError::Rpc(_))
    ));
}

#[test]
fn missing_metadata_and_corrupt_ciphertexts_never_return_partial_rows() {
    let sender = Keypair::new();
    let recipient = Keypair::new();
    let owner = identity(&sender);
    let other = identity(&recipient);
    for mutation in [0, 1, 2] {
        let mut fixture = Fixture::spend(&owner, &other, 20, 0, &[Mint::SOL]);
        match mutation {
            0 => fixture.chain = Value::Null,
            1 => fixture.events[0].output_slots[0].payload[10] ^= 1,
            _ => fixture.records.clear(),
        }
        let signature = fixture.signature.to_string();
        let (wallet, _) = fixture.open(&sender);
        let result = wallet.transaction(signature).unwrap();
        assert_eq!(result.status, Status::Incomplete, "mutation {mutation}");
        assert!(result.entries.is_empty());
    }
    // A recipient can still authenticate its received notes when the chain
    // RPC has pruned the metadata required for sender-side settlements.
    let mut fixture = Fixture::spend(&owner, &other, 20, 0, &[Mint::SOL]);
    fixture.chain = Value::Null;
    let signature = fixture.signature.to_string();
    let (wallet, _) = fixture.open(&recipient);
    let result = wallet.transaction(signature).unwrap();
    assert_eq!(result.status, Status::Ready);
    assert_eq!(result.entries[0].amount, 20);
}

#[test]
fn deposit_events_are_aggregated_deduplicated_and_have_stable_asset_ids() {
    use spr_transaction::serialization::{OwnerCx, Proofless, ProoflessEncode, UtxoSerialization};
    let signer = Keypair::new();
    let owner = identity(&signer);
    let token = Mint::new(Pubkey::new_unique(), 7);
    let mut fixture = Fixture::spend(&owner, &owner, 20, 0, &[Mint::SOL, token]);
    let tag = owner
        .address
        .signing_pubkey
        .confidential_view_tag()
        .unwrap();
    let mut slots = Vec::new();
    for (index, asset) in [Mint::SOL, token].iter().enumerate() {
        let utxo = Utxo {
            owner: owner.address.signing_pubkey,
            asset: *asset,
            amount: 5 + index as u64,
            blinding: [index as u8; 32],
            ring_program_id: None,
            data: Default::default(),
        };
        let hash = utxo
            .hash(&owner.address.nullifier_pubkey, &[0; 32], &[0; 32], 0)
            .unwrap();
        let encoded = Proofless::encode(
            &[utxo],
            &OwnerCx {
                owner: owner.address.signing_pubkey,
                assets: &fixture.registry,
                ring_program_id: None,
                first_nullifier: None,
            },
            tag,
            &ProoflessEncode {
                owner_hash: owner.address.owner_hash().unwrap(),
                data_hash: None,
                ring_data_hash: None,
            },
        )
        .unwrap();
        slots.push(OutputSlot {
            view_tag: tag,
            output_context: OutputContext {
                hash,
                tree_id: 0,
                leaf_index: 100 + index as u64,
            },
            payload: encoded.data,
        });
    }
    fixture.events[0].output_slots = slots;
    fixture.events[0].proofless = true;
    fixture.events[0].tx_viewing_pk = None;
    fixture.events[0].salt = None;
    fixture.events[0].nullifiers.clear();
    fixture.chain = Value::Null;
    let mut duplicate = fixture.events[0].clone();
    duplicate.event_index = Some(1);
    fixture.events.push(duplicate);
    let signature = fixture.signature.to_string();
    let (wallet, _) = fixture.open(&signer);
    let result = wallet.transaction(signature).unwrap();
    assert_eq!(result.status, Status::Ready);
    assert_eq!(result.entries.len(), 2);
    assert_eq!(
        result
            .entries
            .iter()
            .map(|entry| (
                result.asset_registry.asset_id(&entry.mint).unwrap(),
                entry.amount
            ))
            .collect::<Vec<_>>(),
        vec![(1, 5), (7, 6)]
    );
    assert!(result
        .entries
        .iter()
        .all(|entry| entry.kind == ActivityKind::Deposit));
}

#[test]
fn a_cold_wallet_reads_a_merge_as_a_self_transfer() {
    use spr_interface::event::{encode_merge_output_data, MergeOutputDataRef};
    use spr_transaction::instructions::merge::{
        merge_output_blinding, merge_output_key, MergeOutputPlaintext,
    };
    let signer = Keypair::new();
    let owner = identity(&signer);
    let mut fixture = Fixture::spend(&owner, &owner, 20, 0, &[Mint::SOL]);
    let first = [1; 32];
    let salt = [3; 16];
    let key = merge_output_key(&owner.nullifier_key, &first).unwrap();
    let blinding = merge_output_blinding(&owner.nullifier_key, &first).unwrap();
    let plaintext = MergeOutputPlaintext {
        amount: 50,
        mint: SOL_MINT,
    };
    let ciphertext = plaintext.encrypt(&key, &salt).unwrap();
    let utxo = plaintext.into_utxo(owner.address.signing_pubkey, Mint::SOL, blinding, None);
    let hash = utxo
        .hash(&owner.address.nullifier_pubkey, &[0; 32], &[0; 32], 0)
        .unwrap();
    fixture.events[0].output_slots = vec![OutputSlot {
        view_tag: owner
            .address
            .signing_pubkey
            .confidential_view_tag()
            .unwrap(),
        output_context: OutputContext {
            hash,
            tree_id: 0,
            leaf_index: 100,
        },
        payload: encode_merge_output_data(MergeOutputDataRef {
            salt: &salt,
            ciphertext: &ciphertext,
            prefix: &[],
        }),
    }];
    fixture.events[0].tx_viewing_pk = None;
    fixture.events[0].salt = None;
    fixture.events[0].nullifiers = vec![first];
    fixture.chain = Value::Null;
    let mut corrupt = Fixture {
        signature: fixture.signature,
        chain: fixture.chain.clone(),
        events: fixture.events.clone(),
        registry: fixture.registry.clone(),
        notes: fixture.notes.clone(),
        openings: fixture.openings.clone(),
        records: fixture.records.clone(),
    };
    corrupt.events[0].output_slots[0].output_context.hash = [0; 32];
    let signature = fixture.signature.to_string();
    let (wallet, _) = fixture.open(&signer);
    let result = wallet.transaction(signature.clone()).unwrap();
    assert_eq!(result.status, Status::Ready);
    assert_eq!(
        (result.entries[0].kind, result.entries[0].amount),
        (ActivityKind::SelfTransfer, 50)
    );
    let (wallet, _) = corrupt.open(&signer);
    let result = wallet.transaction(signature).unwrap();
    assert_eq!(result.status, Status::Incomplete);
    assert!(result.entries.is_empty());
}

#[test]
fn a_full_private_send_with_recipient_tagged_padding_is_explicitly_incomplete() {
    let sender = Keypair::new();
    let recipient = Keypair::new();
    let fixture = Fixture::spend(
        &identity(&sender),
        &identity(&recipient),
        100,
        0,
        &[Mint::SOL],
    );
    let signature = fixture.signature.to_string();
    let (wallet, _) = fixture.open(&sender);
    let result = wallet.transaction(signature).unwrap();
    assert_eq!(result.status, Status::Incomplete);
    assert!(result.entries.is_empty());
}

#[test]
fn padding_openings_resolve_exact_balance_payments_without_history() {
    let sender = Keypair::new();
    let recipient = Keypair::new();
    let owner = identity(&sender);
    let receiver = identity(&recipient);
    for cached in [false, true] {
        for (private, withdrawal) in [(100, 0), (50, 50)] {
            for mint in [Mint::SOL, Mint::new(Pubkey::new_unique(), 7)] {
                let fixture = Fixture::spend_with_cache(
                    &owner,
                    &receiver,
                    private,
                    withdrawal,
                    &[mint],
                    cached,
                );
                let pending = fixture.prepared(&sender);
                let signature = fixture.signature.to_string();
                let (wallet, _) = fixture.open(&sender);
                let result = wallet
                    .transaction_with_prepared(signature.clone(), &pending)
                    .unwrap();
                assert_eq!(result.status, Status::Ready);
                assert_eq!(result.entries.len(), 1);
                let entry = &result.entries[0];
                assert_eq!(entry.kind, HistoryKind::Sent);
                assert_eq!(entry.amount, 100);
                assert_eq!(entry.mint, mint.asset);
                assert_eq!(entry.tx_signature.to_string(), signature);
                assert_eq!(entry.slot, 10);
            }
        }
    }
}

#[test]
fn padding_openings_cannot_hide_missing_or_tampered_details() {
    let sender = Keypair::new();
    let recipient = Keypair::new();
    let owner = identity(&sender);
    let receiver = identity(&recipient);
    for mutation in 0..8 {
        let mut fixture = Fixture::spend(&owner, &receiver, 100, 0, &[Mint::SOL]);
        let mut pending = fixture.prepared(&sender);
        let padding = pending.iter_mut().find(|output| output.is_dummy()).unwrap();
        match mutation {
            0 => padding.blinding[31] ^= 1,
            1 => padding.blinding[30] ^= 1,
            2 => padding.compact = true,
            3 => {
                pending = Fixture::spend(&owner, &receiver, 100, 0, &[Mint::SOL]).prepared(&sender);
            }
            4 => fixture.chain = Value::Null,
            5 => fixture.records.clear(),
            6 => {
                // Even calling a real recipient output a dummy cannot open its
                // commitment under the protocol's distinct dummy domain.
                pending[0].owner_address = None;
                pending[0].amount = 0;
                fixture
                    .records
                    .values_mut()
                    .next()
                    .unwrap()
                    .nullifier_pubkey = [0; 32];
            }
            _ => fixture.events[0].output_slots[0].payload[10] ^= 1,
        }
        let signature = fixture.signature.to_string();
        let (wallet, _) = fixture.open(&sender);
        let result = wallet
            .transaction_with_prepared(signature, &pending)
            .unwrap();
        assert_eq!(result.status, Status::Incomplete, "mutation {mutation}");
        assert!(result.entries.is_empty());
    }
}

#[test]
fn a_cold_token_lookup_discovers_only_asset_metadata_and_keeps_existing_mappings() {
    let sender = Keypair::new();
    let receiver = Keypair::new();
    let token = Mint::new(Pubkey::new_unique(), 7);
    let fixture = Fixture::spend(
        &identity(&sender),
        &identity(&receiver),
        10,
        20,
        &[Mint::SOL, token],
    );
    let signature = fixture.signature.to_string();
    let (wallet, asked) = fixture.open_with_registry(&sender, false);
    let result = wallet.transaction(signature).unwrap();
    assert_eq!(result.status, Status::Ready);
    assert_eq!(
        result
            .entries
            .iter()
            .map(|row| (
                result.asset_registry.asset_id(&row.mint).unwrap(),
                row.amount
            ))
            .collect::<Vec<_>>(),
        vec![(1, 30), (7, 30)]
    );
    assert_eq!(
        asked
            .lock()
            .unwrap()
            .iter()
            .filter(|method| method.as_str() == "getProgramAccounts")
            .count(),
        1
    );
}

#[test]
fn a_padding_opening_for_another_tree_cannot_hide_an_unreadable_slot() {
    let sender = Keypair::new();
    let recipient = Keypair::new();
    let fixture = Fixture::spend(
        &identity(&sender),
        &identity(&recipient),
        100,
        0,
        &[Mint::SOL],
    );
    let opening = fixture
        .openings
        .iter()
        .find(|output| output.is_dummy())
        .unwrap();
    let wrong_tree = DummyOutputOpening {
        tree_id: 1,
        blinding: opening.blinding,
    };
    let signature = fixture.signature.to_string();
    let (wallet, _) = fixture.open(&sender);
    let result = wallet.lookup(signature, &[wrong_tree]).unwrap();
    assert_eq!(result.status, Status::Incomplete);
    assert!(result.entries.is_empty());
}
