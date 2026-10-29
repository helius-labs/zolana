use super::*;
use crate::{
    compile_message,
    rpc::{OutputContext, OutputSlot},
    ComputeBudgetConfig, Context, GetShieldedTransactionsBySignatureResponse,
    GetUserRecordsResponse, IndexedShieldedTransaction, IndexerRpcConfig, ProgramAccountsFilter,
};
use serde_json::json;
use solana_account::Account;
use solana_signer::Signer;
use spr_instruction::instruction::Transact;
use spr_interface::{
    instruction::{CircuitId, InputUtxo, TransactProof, TreeContext},
    pda,
    state::SplAssetRegistry,
};
use spr_keypair::ShieldedKeypair;
use spr_transaction::{
    instructions::transact::ConfidentialTransaction, History, Mint, SppProofOutputUtxo, Utxo,
    WalletUtxo,
};
use spr_user_registry_interface::{MergeEncryptionScheme, UserRecord};
use std::sync::Mutex;

struct Fixture {
    signature: Signature,
    chain: Option<Confirmed>,
    events: Vec<ShieldedTransaction>,
    registry: AssetRegistry,
    notes: Vec<WalletUtxo>,
    openings: Vec<SppProofOutputUtxo>,
    records: HashMap<Pubkey, UserRecord>,
    indexed_slot: u64,
    calls: Mutex<Vec<&'static str>>,
    failing_call: Option<&'static str>,
}

impl Fixture {
    /// Real encrypted default-ring spend, with known source notes only in the
    /// fixture. The lookup receives neither those notes nor any history page.
    fn spend(
        sender: &ShieldedKeypair,
        recipient: &ShieldedKeypair,
        private: u64,
        withdrawal: u64,
        assets: &[Mint],
    ) -> Self {
        Self::spend_with_cache(sender, recipient, private, withdrawal, assets, false)
    }

    fn spend_with_cache(
        sender: &ShieldedKeypair,
        recipient: &ShieldedKeypair,
        private: u64,
        withdrawal: u64,
        assets: &[Mint],
        cached: bool,
    ) -> Self {
        let payer = sender.pubkey();
        let sender_address = sender.address().unwrap();
        let recipient_address = recipient.address().unwrap();
        let mut registry = AssetRegistry::default();
        for mint in assets {
            if mint.asset != SOL_MINT {
                registry.insert(mint.asset_id, mint.asset).unwrap();
            }
        }
        let mut notes = Vec::new();
        for (index, asset) in assets.iter().enumerate() {
            let utxo = Utxo {
                owner: sender_address.signing_pubkey,
                asset: *asset,
                amount: 100,
                blinding: [index as u8 + 1; 32],
                ring_program_id: None,
                data: Default::default(),
            };
            let hash = utxo
                .hash(&sender_address.nullifier_pubkey, &[0; 32], &[0; 32], 0)
                .unwrap();
            let nullifier = utxo.nullifier(&hash, &sender.nullifier_key).unwrap();
            notes.push(WalletUtxo {
                utxo,
                nullifier_pubkey: sender_address.nullifier_pubkey,
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
                        .transfer_sol(&recipient_address, private)
                        .unwrap();
                } else {
                    transaction
                        .transfer(&recipient_address, asset.asset, private)
                        .unwrap();
                }
            }
            if withdrawal > 0 {
                settlements.push(
                    transaction
                        .withdraw_to(
                            asset.asset,
                            withdrawal,
                            recipient.pubkey(),
                            (asset.asset != SOL_MINT).then(pda::spl_token_program_id),
                        )
                        .unwrap(),
                );
            }
        }
        let inputs = transaction.encrypt(sender).unwrap();
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
            owner_signers: vec![sender.pubkey()],
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
        let chain = json!({"slot": 10, "blockTime": 0, "version": 1,
            "transaction": {"signatures": [signature.to_string()], "message": {
                "header": message.header(),
                "accountKeys": message.static_account_keys().iter().map(ToString::to_string).collect::<Vec<_>>(),
                "recentBlockhash": message.recent_blockhash().to_string(),
                "instructions": message.instructions().iter().map(|ix| solana_transaction_status_client_types::UiCompiledInstruction::from(ix, None)).collect::<Vec<_>>(),
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
            owner: recipient.pubkey(),
            bump: 0,
            nullifier_pubkey: recipient_address.nullifier_pubkey,
            viewing_pubkey: *recipient_address.viewing_pubkey.as_bytes(),
            merge_encryption: MergeEncryptionScheme::Disabled,
        };
        Self {
            signature,
            chain: Some(serde_json::from_value(chain).unwrap()),
            events: vec![event],
            registry,
            notes,
            openings: inputs.output_utxos.clone(),
            records: HashMap::from([(recipient.pubkey(), record)]),
            indexed_slot: 10,
            calls: Mutex::new(vec![]),
            failing_call: None,
        }
    }

    fn reader<'a>(&'a self, keys: &'a ShieldedKeypair) -> TransactionReader<'a, ShieldedKeypair> {
        TransactionReader::new(keys, &self.registry).with_asset_discovery()
    }

    fn padding(&self) -> Vec<DummyOutputOpening> {
        self.openings
            .iter()
            .filter(|output| output.is_dummy())
            .map(|output| DummyOutputOpening {
                tree_id: 0,
                blinding: output.blinding,
            })
            .collect()
    }

    fn called(&self, method: &'static str) -> Result<(), ClientError> {
        self.calls.lock().unwrap().push(method);
        if self.failing_call == Some(method) {
            return Err(ClientError::Rpc("unavailable".into()));
        }
        Ok(())
    }
}

impl Rpc for Fixture {
    fn get_confirmed_transaction(
        &self,
        signature: Signature,
    ) -> Result<Option<Confirmed>, ClientError> {
        self.called("getTransaction")?;
        assert_eq!(signature, self.signature);
        Ok(self.chain.clone())
    }

    fn get_shielded_transactions_by_signature(
        &self,
        signature: Signature,
        _: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsBySignatureResponse, ClientError> {
        self.called("getShieldedTransactionsBySignature")?;
        assert_eq!(signature, self.signature);
        Ok(GetShieldedTransactionsBySignatureResponse {
            context: Context {
                slot: self.indexed_slot,
                block_time: 0,
            },
            output_tree_id: None,
            transactions: self
                .events
                .iter()
                .enumerate()
                .map(|(index, transaction)| IndexedShieldedTransaction {
                    event_index: index as u16,
                    transaction: transaction.clone(),
                })
                .collect(),
        })
    }

    fn get_user_records(
        &self,
        owners: Vec<Pubkey>,
        _: Option<IndexerRpcConfig>,
    ) -> Result<GetUserRecordsResponse, ClientError> {
        self.called("getUserRecords")?;
        Ok(GetUserRecordsResponse {
            context: Context {
                slot: self.indexed_slot,
                block_time: 0,
            },
            records: owners
                .iter()
                .map(|owner| self.records.get(owner).cloned())
                .collect(),
        })
    }

    fn get_program_accounts_filtered(
        &self,
        program: Pubkey,
        _: &ProgramAccountsFilter,
    ) -> Result<Vec<(Pubkey, Account)>, ClientError> {
        self.called("getProgramAccounts")?;
        assert_eq!(program, PROGRAM_ID_PUBKEY);
        Ok(self
            .notes
            .iter()
            .filter(|note| note.utxo.asset.asset != SOL_MINT)
            .map(|note| {
                let mint = note.utxo.asset;
                (
                    pda::spl_asset_registry(&mint.asset),
                    Account {
                        owner: PROGRAM_ID_PUBKEY,
                        data: SplAssetRegistry::account_bytes(mint.asset, mint.asset_id).to_vec(),
                        ..Default::default()
                    },
                )
            })
            .collect())
    }
}

#[test]
fn cold_lookup_matches_history_for_sends_withdrawals_and_multiple_assets() {
    let owner = ShieldedKeypair::new_ed25519().unwrap();
    let recipient = ShieldedKeypair::new_ed25519().unwrap();
    for (private, withdrawal) in [(20, 0), (0, 100), (10, 20)] {
        for (assets, cached) in [
            (vec![Mint::SOL], false),
            (vec![Mint::SOL], true),
            (vec![Mint::SOL, Mint::new(Pubkey::new_unique(), 7)], false),
            (vec![Mint::SOL, Mint::new(Pubkey::new_unique(), 7)], true),
        ] {
            let fixture =
                Fixture::spend_with_cache(&owner, &recipient, private, withdrawal, &assets, cached);
            let decoded = decrypt(&owner, &fixture.events, &fixture.registry).unwrap();
            let mut utxos = fixture.notes.clone();
            utxos.extend(verify_owned(&owner, &decoded).unwrap().utxos);
            let expected = History {
                transactions: fixture.events.clone(),
                utxos,
                view_tags: [owner.signing_pubkey().confidential_view_tag().unwrap()].into(),
                ..Default::default()
            }
            .entries();
            let result = fixture
                .reader(&owner)
                .fetch(&fixture, fixture.signature)
                .unwrap();
            assert_eq!(
                result.status,
                Status::Ready,
                "private={private}, withdrawal={withdrawal}, assets={assets:?}"
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
            assert!(fixture.calls.lock().unwrap().iter().all(|method| [
                "getTransaction",
                "getShieldedTransactionsBySignature",
                "getUserRecords",
            ]
            .contains(method)));
        }
    }
}

#[test]
fn incoming_unrelated_and_self_transfers_are_read_without_history() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let recipient = ShieldedKeypair::new_ed25519().unwrap();
    let fixture = Fixture::spend(&sender, &recipient, 20, 0, &[Mint::SOL]);
    let incoming = fixture
        .reader(&recipient)
        .fetch(&fixture, fixture.signature)
        .unwrap();
    assert_eq!(incoming.status, Status::Ready);
    assert_eq!(incoming.entries.len(), 1);
    assert_eq!(
        (incoming.entries[0].kind, incoming.entries[0].amount),
        (HistoryKind::Received, 20)
    );

    let unrelated = fixture
        .reader(&ShieldedKeypair::new_ed25519().unwrap())
        .fetch(&fixture, fixture.signature)
        .unwrap();
    assert_eq!(unrelated.status, Status::Ready);
    assert!(unrelated.entries.is_empty());

    let fixture = Fixture::spend(&sender, &sender, 20, 0, &[Mint::SOL]);
    let own = fixture
        .reader(&sender)
        .fetch(&fixture, fixture.signature)
        .unwrap();
    assert_eq!(own.status, Status::Ready);
    assert_eq!(
        (own.entries[0].kind, own.entries[0].amount),
        (HistoryKind::SelfTransfer, 100)
    );
}

#[test]
fn indexing_delay_not_found_and_indexed_empty_are_distinct() {
    let owner = ShieldedKeypair::new_ed25519().unwrap();
    for (chain_slot, indexed_slot, expected) in [
        (Some(10), 9, Status::PendingIndexing),
        (Some(10), 10, Status::Ready),
        (None, 10, Status::NotFound),
    ] {
        let mut fixture = Fixture::spend(&owner, &owner, 20, 0, &[Mint::SOL]);
        fixture.events.clear();
        fixture.indexed_slot = indexed_slot;
        if chain_slot.is_none() {
            fixture.chain = None;
        }
        let result = fixture
            .reader(&owner)
            .fetch(&fixture, fixture.signature)
            .unwrap();
        assert_eq!(result.status, expected);
        assert_eq!(result.slot, chain_slot);
        assert!(result.entries.is_empty());
        assert_eq!(fixture.calls.lock().unwrap().len(), 2);
    }
}

#[test]
fn network_failures_are_not_empty_results() {
    let owner = ShieldedKeypair::new_ed25519().unwrap();
    for method in ["getTransaction", "getShieldedTransactionsBySignature"] {
        let mut fixture = Fixture::spend(&owner, &owner, 20, 0, &[Mint::SOL]);
        fixture.failing_call = Some(method);
        assert!(matches!(
            fixture.reader(&owner).fetch(&fixture, fixture.signature),
            Err(ClientError::Rpc(_))
        ));
    }
}

#[test]
fn missing_metadata_and_corrupt_ciphertexts_never_return_partial_rows() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let recipient = ShieldedKeypair::new_ed25519().unwrap();
    for mutation in 0..3 {
        let mut fixture = Fixture::spend(&sender, &recipient, 20, 0, &[Mint::SOL]);
        match mutation {
            0 => fixture.chain = None,
            1 => fixture.events[0].output_slots[0].payload[10] ^= 1,
            _ => fixture.records.clear(),
        }
        let result = fixture
            .reader(&sender)
            .fetch(&fixture, fixture.signature)
            .unwrap();
        assert_eq!(result.status, Status::Incomplete, "mutation {mutation}");
        assert!(result.entries.is_empty());
    }
    // Received notes can still be authenticated when chain metadata is pruned.
    let mut fixture = Fixture::spend(&sender, &recipient, 20, 0, &[Mint::SOL]);
    fixture.chain = None;
    let result = fixture
        .reader(&recipient)
        .fetch(&fixture, fixture.signature)
        .unwrap();
    assert_eq!(result.status, Status::Ready);
    assert_eq!(result.entries[0].amount, 20);
}

#[test]
fn deposit_events_are_aggregated_deduplicated_and_have_stable_asset_ids() {
    use spr_transaction::serialization::{OwnerCx, Proofless, ProoflessEncode, UtxoSerialization};
    let owner = ShieldedKeypair::new_ed25519().unwrap();
    let address = owner.address().unwrap();
    let token = Mint::new(Pubkey::new_unique(), 7);
    let mut fixture = Fixture::spend(&owner, &owner, 20, 0, &[Mint::SOL, token]);
    let tag = address.signing_pubkey.confidential_view_tag().unwrap();
    let mut slots = Vec::new();
    for (index, asset) in [Mint::SOL, token].iter().enumerate() {
        let utxo = Utxo {
            owner: address.signing_pubkey,
            asset: *asset,
            amount: 5 + index as u64,
            blinding: [index as u8; 32],
            ring_program_id: None,
            data: Default::default(),
        };
        let hash = utxo
            .hash(&address.nullifier_pubkey, &[0; 32], &[0; 32], 0)
            .unwrap();
        let encoded = Proofless::encode(
            &[utxo],
            &OwnerCx {
                owner: address.signing_pubkey,
                assets: &fixture.registry,
                ring_program_id: None,
                first_nullifier: None,
            },
            tag,
            &ProoflessEncode {
                owner_hash: address.owner_hash().unwrap(),
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
    fixture.chain = None;
    let mut duplicate = fixture.events[0].clone();
    duplicate.event_index = Some(1);
    fixture.events.push(duplicate);
    let result = fixture
        .reader(&owner)
        .fetch(&fixture, fixture.signature)
        .unwrap();
    assert_eq!(result.status, Status::Ready);
    assert_eq!(result.entries.len(), 2);
    assert_eq!(
        result
            .entries
            .iter()
            .map(|entry| (
                result.asset_registry.asset_id(&entry.mint).unwrap(),
                entry.amount,
            ))
            .collect::<Vec<_>>(),
        vec![(1, 5), (7, 6)]
    );
    assert!(result
        .entries
        .iter()
        .all(|entry| entry.kind == HistoryKind::Deposit));
}

#[test]
fn a_cold_wallet_reads_a_merge_as_a_self_transfer() {
    use spr_interface::event::{encode_merge_output_data, MergeOutputDataRef};
    use spr_transaction::instructions::merge::{
        merge_output_blinding, merge_output_key, MergeOutputPlaintext,
    };
    let owner = ShieldedKeypair::new_ed25519().unwrap();
    let address = owner.address().unwrap();
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
    let utxo = plaintext.into_utxo(address.signing_pubkey, Mint::SOL, blinding, None);
    let hash = utxo
        .hash(&address.nullifier_pubkey, &[0; 32], &[0; 32], 0)
        .unwrap();
    fixture.events[0].output_slots = vec![OutputSlot {
        view_tag: address.signing_pubkey.confidential_view_tag().unwrap(),
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
    fixture.chain = None;
    let result = fixture
        .reader(&owner)
        .fetch(&fixture, fixture.signature)
        .unwrap();
    assert_eq!(result.status, Status::Ready);
    assert_eq!(
        (result.entries[0].kind, result.entries[0].amount),
        (HistoryKind::SelfTransfer, 50)
    );
    fixture.events[0].output_slots[0].output_context.hash = [0; 32];
    let result = fixture
        .reader(&owner)
        .fetch(&fixture, fixture.signature)
        .unwrap();
    assert_eq!(result.status, Status::Incomplete);
    assert!(result.entries.is_empty());
}

#[test]
fn a_full_private_send_with_recipient_tagged_padding_is_explicitly_incomplete() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let recipient = ShieldedKeypair::new_ed25519().unwrap();
    let fixture = Fixture::spend(&sender, &recipient, 100, 0, &[Mint::SOL]);
    let result = fixture
        .reader(&sender)
        .fetch(&fixture, fixture.signature)
        .unwrap();
    assert_eq!(result.status, Status::Incomplete);
    assert!(result.entries.is_empty());
}

#[test]
fn padding_openings_resolve_exact_balance_payments_without_history() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let recipient = ShieldedKeypair::new_ed25519().unwrap();
    for cached in [false, true] {
        for (private, withdrawal) in [(100, 0), (50, 50)] {
            for mint in [Mint::SOL, Mint::new(Pubkey::new_unique(), 7)] {
                let fixture = Fixture::spend_with_cache(
                    &sender,
                    &recipient,
                    private,
                    withdrawal,
                    &[mint],
                    cached,
                );
                let result = fixture
                    .reader(&sender)
                    .with_padding_openings(&fixture.padding())
                    .fetch(&fixture, fixture.signature)
                    .unwrap();
                assert_eq!(result.status, Status::Ready);
                assert_eq!(result.entries.len(), 1);
                let entry = &result.entries[0];
                assert_eq!(entry.kind, HistoryKind::Sent);
                assert_eq!(entry.amount, 100);
                assert_eq!(entry.mint, mint.asset);
                assert_eq!(entry.tx_signature, fixture.signature);
                assert_eq!(entry.slot, 10);
            }
        }
    }
}

#[test]
fn padding_openings_cannot_hide_missing_or_tampered_details() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let recipient = ShieldedKeypair::new_ed25519().unwrap();
    for mutation in 0..6 {
        let mut fixture = Fixture::spend(&sender, &recipient, 100, 0, &[Mint::SOL]);
        let mut padding = fixture.padding();
        match mutation {
            0 => padding[0].blinding[31] ^= 1,
            1 => padding = Fixture::spend(&sender, &recipient, 100, 0, &[Mint::SOL]).padding(),
            2 => fixture.chain = None,
            3 => fixture.records.clear(),
            4 => {
                // A real output cannot open under the dummy commitment domain.
                padding.push(DummyOutputOpening {
                    tree_id: 0,
                    blinding: fixture.openings[0].blinding,
                });
                fixture
                    .records
                    .values_mut()
                    .next()
                    .unwrap()
                    .nullifier_pubkey = [0; 32];
            }
            _ => fixture.events[0].output_slots[0].payload[10] ^= 1,
        }
        let result = fixture
            .reader(&sender)
            .with_padding_openings(&padding)
            .fetch(&fixture, fixture.signature)
            .unwrap();
        assert_eq!(result.status, Status::Incomplete, "mutation {mutation}");
        assert!(result.entries.is_empty());
    }
}

#[test]
fn a_cold_token_lookup_discovers_only_asset_metadata_and_keeps_existing_mappings() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let recipient = ShieldedKeypair::new_ed25519().unwrap();
    let token = Mint::new(Pubkey::new_unique(), 7);
    let fixture = Fixture::spend(&sender, &recipient, 10, 20, &[Mint::SOL, token]);
    let result = TransactionReader::new(&sender, &AssetRegistry::default())
        .with_asset_discovery()
        .fetch(&fixture, fixture.signature)
        .unwrap();
    assert_eq!(result.status, Status::Ready);
    assert_eq!(
        result
            .entries
            .iter()
            .map(|row| (
                result.asset_registry.asset_id(&row.mint).unwrap(),
                row.amount,
            ))
            .collect::<Vec<_>>(),
        vec![(1, 30), (7, 30)]
    );
    assert_eq!(
        fixture
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|method| **method == "getProgramAccounts")
            .count(),
        1
    );
}

#[test]
fn a_padding_opening_for_another_tree_cannot_hide_an_unreadable_slot() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let recipient = ShieldedKeypair::new_ed25519().unwrap();
    let fixture = Fixture::spend(&sender, &recipient, 100, 0, &[Mint::SOL]);
    let mut padding = fixture.padding();
    for opening in &mut padding {
        opening.tree_id = 1;
    }
    let result = fixture
        .reader(&sender)
        .with_padding_openings(&padding)
        .fetch(&fixture, fixture.signature)
        .unwrap();
    assert_eq!(result.status, Status::Incomplete);
    assert!(result.entries.is_empty());
}
