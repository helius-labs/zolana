//! `delegate move`, the permanent delegate spends a member's ring notes.

use std::collections::BTreeSet;

use anyhow::{bail, ensure, Context as _, Result};
use custom_ring_sdk::{
    ring_authority_width, CoSignScope, DelegateOutput, DelegateTransfer, DelegateTransferInput,
    ReadMemberRecord,
};
use solana_address::Address;
use solana_signer::Signer;
use zolana_client::{IndexerRpcConfig, Rpc};
use zolana_interface::pda;
use zolana_ring_client::{RingRecovery, SourceMember};
use zolana_ring_policy::Member;
use zolana_transaction::{
    instructions::transact::MAX_SPEND_INPUTS, select_spend_where, utxo::SppProofInputUtxo,
    WalletUtxo, SOL_MINT,
};

use crate::{
    assets,
    controls::{ring_auditor_key, NO_MEMBER_REGISTRY},
    file, line,
    transact::{self, PAYER_FEE_BUDGET, SENDER_FEE_BUDGET},
    Context, DelegateMoveArgs,
};

/// The source keeps note ownership until the delegate's signed move executes.
pub fn run_move(ctx: &Context, args: DelegateMoveArgs) -> Result<()> {
    let (to, source, amount) = (args.to, args.source, args.amount);
    ensure!(amount > 0, "the move amount must be greater than zero");
    let mint = args.mint.map_or(SOL_MINT, |mint| mint.0);
    let delegate = file::read_keypair(&ctx.path(&args.delegate_keypair))?;
    let stored = ctx
        .block(ctx.ring.delegate(ctx.chain()))?
        .context("the ring has no delegate")?;
    ensure!(
        stored == delegate.pubkey(),
        "the delegate keypair {} is not the ring's delegate {stored}",
        delegate.pubkey()
    );
    let cosigner = transact::cosigner(ctx, &args.cosigner, CoSignScope::TRANSFERS)?;
    // The auditor key decrypts recovery material, only the delegate signs.
    let auditor = ring_auditor_key(ctx, &args.auditor_key)?;
    let member = source
        .confidential_view_tag()
        .ok()
        .and_then(|tag| Member::owner_tag(&tag).ok())
        .context("the source shielded address does not derive a member identity")?;
    let assets = assets::resolve(ctx.rpc(), mint)?.registry;
    let record = ReadMemberRecord {
        ring: ctx.ring,
        member,
    };
    let record = ctx
        .block(record.read(ctx.chain()))?
        .context(NO_MEMBER_REGISTRY)?;
    let nullifier_key = match record.sealed_key() {
        Some(entry) => entry.open(&auditor)?,
        None => {
            bail!("member {source} has no registered key, it runs `zolana-ring key register` first")
        }
    };
    let recovery = RingRecovery::new(ctx.ring.program_id(), &auditor)
        .with_indexer_config(IndexerRpcConfig::at_slot(ctx.rpc().get_slot()?))
        .for_member(SourceMember {
            address: &source,
            nullifier_key: &nullifier_key,
        });
    let chain = ctx.chain();
    let recovered = ctx.block(recovery.run(chain.indexer(), chain.rpc(), &assets))?;
    if !recovered.unopened.is_empty() {
        line("unopened notes", recovered.unopened.len());
    }
    if !recovered.unsupported_deposits.is_empty() {
        line(
            "deposit recovery",
            format_args!(
                "{} recipient-tagged deposits lack auditor openings; their ownership and spent status are unknown",
                recovered.unsupported_deposits.len(),
            ),
        );
    }
    let notes = select(&recovered.utxos, ctx.ring.program_id(), mint, amount)?;
    let change = notes.iter().map(|note| note.utxo.amount).sum::<u64>() - amount;
    let authority = ctx.authority()?;
    ctx.require_balance(authority.pubkey(), SENDER_FEE_BUDGET + PAYER_FEE_BUDGET)?;
    ctx.ring_rpc().check_serves(ctx.ring.program_id())?;
    let mut outputs = vec![DelegateOutput {
        recipient: to,
        asset: mint,
        amount,
    }];
    if change > 0 {
        outputs.push(DelegateOutput {
            recipient: source,
            asset: mint,
            amount: change,
        });
    }
    let mut transfer = DelegateTransfer::new(DelegateTransferInput {
        ring: ctx.ring,
        delegate: delegate.pubkey(),
        payer: authority.pubkey(),
        source_nullifier_key: &nullifier_key,
        inputs: notes.iter().map(SppProofInputUtxo::from).collect(),
        outputs,
    })
    .with_output_tree_id(notes[0].tree_id)
    .with_assets(&assets);
    let mut signers: Vec<&(dyn Signer + Sync)> = vec![&delegate];
    if let Some(cosigner) = &cosigner {
        transfer = transfer.with_cosigner(cosigner.pubkey());
        signers.push(cosigner);
    }
    let moved = ctx.submit(transfer, authority, &signers)?;
    line("to", to);
    line("amount", format_args!("{amount} base units"));
    line("mint", mint);
    line("move", moved);
    Ok(())
}

/// The ring notes of one tree that fund `amount` within the delegate shape, the fewest
/// and smallest selection across trees, largest notes first within one.
fn select(
    notes: &[WalletUtxo],
    ring: Address,
    mint: Address,
    amount: u64,
) -> Result<Vec<WalletUtxo>> {
    let max_inputs = (1..=MAX_SPEND_INPUTS)
        .rev()
        .find(|inputs| ring_authority_width(*inputs).is_some())
        .unwrap_or(0);
    let trees: BTreeSet<u16> = notes.iter().map(|note| note.tree_id).collect();
    trees
        .into_iter()
        .filter_map(|tree| {
            select_spend_where(notes, mint, amount, max_inputs, |note| {
                note.utxo.ring_program_id == Some(ring) && note.tree_id == tree
            })
            .ok()
        })
        .min_by_key(|selected| {
            let total: u64 = selected.iter().map(|note| note.utxo.amount).sum();
            (selected.len(), total, pda::tree(selected[0].tree_id))
        })
        .with_context(|| {
            format!("no tree can fund {amount} base units within the delegate input limit")
        })
}

#[cfg(test)]
#[path = "../../client/tests/common/origin.rs"]
mod origin_fixture;

#[cfg(test)]
mod tests {
    use custom_ring_sdk::CustomRing;
    use solana_signature::Signature;
    use zolana_client::{
        rpc::GetShieldedTransactionsByNullifiersResponse, ClientError, Context,
        GetShieldedTransactionsByTagsResponse, IndexerRpcConfig, ProofInputUtxo, Rpc,
        ShieldedTransaction,
    };
    use zolana_client::{ProverClient, ZolanaClient};
    use zolana_keypair::{constants::SALT_LEN, ShieldedKeypair, ViewingKey, X25519Secret};
    use zolana_ring_client::{AuditError, AuditorEncryption, RingOrigin, TransactionOrigin};
    use zolana_transaction::{
        serialization::confidential::{
            Confidential, ConfidentialEncode, ConfidentialOutputPlaintext,
        },
        AssetRegistry, Data, Mint, OutputContext, OutputSlot, Utxo, UtxoSerialization,
        SOL_ASSET_ID,
    };

    use super::*;

    const SALT: [u8; SALT_LEN] = [5u8; SALT_LEN];
    fn ring() -> CustomRing {
        CustomRing::new(Address::new_from_array([9; 32]))
    }

    struct NoteFixture {
        ring_id: Option<Address>,
        asset: Address,
        tree_id: u16,
        amount: u64,
    }

    fn note(owner: &ShieldedKeypair, fixture: NoteFixture) -> WalletUtxo {
        let asset = if fixture.asset == SOL_MINT {
            Mint::SOL
        } else {
            Mint::new(fixture.asset, u64::from(fixture.asset.as_array()[0]))
        };
        WalletUtxo {
            tree_id: fixture.tree_id,
            utxo: Utxo {
                owner: owner.signing_pubkey(),
                asset,
                amount: fixture.amount,
                blinding: [fixture.amount as u8; 32],
                ring_program_id: fixture.ring_id,
                data: Data::default(),
            },
            nullifier_pubkey: owner.nullifier_key.pubkey().expect("nullifier pubkey"),
            utxo_hash: [fixture.amount as u8; 32],
            nullifier: [fixture.amount as u8; 32],
            data_hash: None,
            ring_data_hash: None,
            leaf_index: fixture.amount,
            slot: 0,
            tx_signature: Signature::default(),
            slot_index: 0,
        }
    }

    fn sol_note(owner: &ShieldedKeypair, amount: u64) -> WalletUtxo {
        note(
            owner,
            NoteFixture {
                ring_id: Some(ring().program_id()),
                asset: SOL_MINT,
                tree_id: 0,
                amount,
            },
        )
    }

    fn amounts(notes: &[WalletUtxo]) -> Vec<u64> {
        notes.iter().map(|held| held.utxo.amount).collect()
    }

    fn pick(notes: &[WalletUtxo], mint: Address, amount: u64) -> Result<Vec<WalletUtxo>> {
        select(notes, ring().program_id(), mint, amount)
    }

    #[test]
    fn selects_the_largest_source_notes_up_to_the_amount() {
        let owner = ShieldedKeypair::new_ed25519().expect("keypair");
        let notes = vec![sol_note(&owner, 5), sol_note(&owner, 6)];
        assert_eq!(
            amounts(&pick(&notes, SOL_MINT, 8).expect("selected")),
            [6, 5]
        );
    }

    #[test]
    fn selects_the_funded_tree_for_the_requested_mint() {
        let owner = ShieldedKeypair::new_ed25519().unwrap();
        let mint = Address::new_from_array([17; 32]);
        let ring_note = |asset, tree_id, amount| {
            note(
                &owner,
                NoteFixture {
                    ring_id: Some(ring().program_id()),
                    asset,
                    tree_id,
                    amount,
                },
            )
        };
        let notes = vec![
            ring_note(mint, 1, 3),
            ring_note(mint, 2, 8),
            ring_note(SOL_MINT, 0, 99),
        ];
        let selected = pick(&notes, mint, 5).expect("tree 2 funds it");
        assert_eq!((selected[0].tree_id, amounts(&selected)), (2, vec![8]));
        assert!(pick(&notes, mint, 9).is_err());
    }

    #[test]
    fn selects_a_feasible_tree_instead_of_a_larger_fragmented_balance() {
        let owner = ShieldedKeypair::new_ed25519().unwrap();
        let mut notes: Vec<_> = (0..6)
            .map(|index| {
                let mut held = note(
                    &owner,
                    NoteFixture {
                        ring_id: Some(ring().program_id()),
                        asset: SOL_MINT,
                        tree_id: 1,
                        amount: 1,
                    },
                );
                held.leaf_index = index;
                held
            })
            .collect();
        assert!(pick(&notes, SOL_MINT, 5).is_err(), "four inputs hold 4");
        notes.push(note(
            &owner,
            NoteFixture {
                ring_id: Some(ring().program_id()),
                asset: SOL_MINT,
                tree_id: 2,
                amount: 5,
            },
        ));
        let selected = pick(&notes, SOL_MINT, 5).expect("tree 2 funds it");
        assert_eq!((selected[0].tree_id, amounts(&selected)), (2, vec![5]));
    }

    #[test]
    fn a_fragmented_tree_is_selected_only_within_the_authority_shape() {
        let owner = ShieldedKeypair::new_ed25519().unwrap();
        let notes: Vec<_> = (0..6).map(|_| sol_note(&owner, 1)).collect();
        assert_eq!(pick(&notes, SOL_MINT, 4).expect("four inputs").len(), 4);
        let refused = pick(&notes, SOL_MINT, 5).expect_err("five inputs");
        assert!(
            refused.to_string().starts_with("no tree can fund 5"),
            "{refused}"
        );
    }

    #[test]
    fn a_zero_amount_or_a_short_source_selects_nothing() {
        let owner = ShieldedKeypair::new_ed25519().unwrap();
        let notes = vec![sol_note(&owner, 3)];
        assert!(pick(&notes, SOL_MINT, 0).is_err());
        assert!(pick(&notes, SOL_MINT, 8).is_err());
    }

    #[test]
    fn ignores_a_foreign_ring_mint_or_tree() {
        let owner = ShieldedKeypair::new_ed25519().expect("keypair");
        let other_ring = Address::new_from_array([7; 32]);
        let other_mint = Address::new_from_array([8; 32]);
        let fixture = |ring_id, asset, tree_id, amount| NoteFixture {
            ring_id,
            asset,
            tree_id,
            amount,
        };
        let notes = vec![
            note(&owner, fixture(Some(other_ring), SOL_MINT, 0, 20)),
            note(
                &owner,
                fixture(Some(ring().program_id()), other_mint, 0, 21),
            ),
            note(&owner, fixture(Some(ring().program_id()), SOL_MINT, 1, 22)),
            note(&owner, fixture(None, SOL_MINT, 0, 24)),
        ];
        assert_eq!(amounts(&pick(&notes, SOL_MINT, 5).expect("selected")), [22]);
    }

    struct RecoveredFixture {
        slot: OutputSlot,
        audit_opening: ProofInputUtxo,
        utxo: Utxo,
        nullifier: [u8; 32],
    }

    struct RingNote<'a> {
        tx_key: &'a ViewingKey,
        source: &'a ShieldedKeypair,
        amount: u64,
        blinding: u8,
    }

    impl RingNote<'_> {
        /// The committed leaf must come back from the auditor's plaintext alone.
        fn seal(self) -> RecoveredFixture {
            let ring = ring().program_id();
            let address = self.source.shielded_address().expect("address");
            let plaintext = ConfidentialOutputPlaintext {
                asset_id: SOL_ASSET_ID,
                amount: self.amount,
                blinding: [self.blinding; 32],
                ring_program_id: Some(ring),
                data: Data::default(),
            };
            let encoded = Confidential::encode_plaintext(
                &plaintext,
                address.confidential_view_tag().expect("owner tag"),
                &ConfidentialEncode {
                    tx: self.tx_key.clone(),
                    recipient_pubkey: address.viewing_pubkey,
                    salt: SALT,
                    slot_index: 0,
                },
            )
            .expect("encode");
            let utxo = Utxo {
                owner: self.source.signing_pubkey(),
                asset: Mint::SOL,
                amount: self.amount,
                blinding: [self.blinding; 32],
                ring_program_id: Some(ring),
                data: Data::default(),
            };
            let audit_opening = ProofInputUtxo::new(
                address.owner_hash().expect("owner hash"),
                &utxo.asset.asset,
                utxo.amount,
                &utxo.blinding,
                0,
            )
            .expect("audit opening")
            .with_ring([0u8; 32], &utxo.ring_program_id)
            .expect("ring opening");
            let commitment = audit_opening.hash().expect("commitment");
            let nullifier = utxo
                .nullifier(&commitment, &self.source.nullifier_key)
                .expect("nullifier");
            RecoveredFixture {
                slot: OutputSlot {
                    view_tag: encoded.view_tag,
                    output_context: OutputContext {
                        hash: commitment,
                        tree_id: 0,
                        leaf_index: 0,
                    },
                    payload: encoded.data,
                },
                audit_opening,
                utxo,
                nullifier,
            }
        }
    }

    struct RingTx<'a> {
        tx_key: &'a ViewingKey,
        auditor: &'a X25519Secret,
        signature: u8,
        output_slots: Vec<OutputSlot>,
        audit_openings: Vec<ProofInputUtxo>,
        nullifiers: Vec<[u8; 32]>,
    }

    impl RingTx<'_> {
        fn indexed(self) -> ShieldedTransaction {
            let auditor_pk = self.auditor.pubkey();
            let encryption = if self.audit_openings.is_empty() {
                AuditorEncryption::new(self.tx_key, &auditor_pk)
            } else {
                AuditorEncryption::new_with_outputs(
                    self.tx_key,
                    &auditor_pk,
                    SALT,
                    &self.audit_openings,
                )
            }
            .expect("auditor encryption");
            let message = encryption.message.to_message_data(&auditor_pk);
            ShieldedTransaction {
                slot: u64::from(self.signature),
                tx_signature: Signature::from([self.signature; 64]),
                event_index: Some(0),
                tx_viewing_pk: Some(self.tx_key.pubkey()),
                salt: Some(SALT),
                output_slots: self.output_slots,
                messages: vec![message],
                nullifiers: self.nullifiers,
                proofless: false,
                ring_config: None,
                ring_program_id: Some(ring().program_id()),
            }
        }
    }

    struct StubIndexer {
        transactions: Vec<ShieldedTransaction>,
    }

    impl Rpc for StubIndexer {
        fn get_shielded_transactions_by_ring(
            &self,
            _options: zolana_client::RingHistoryOptions,
            config: Option<IndexerRpcConfig>,
        ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
            self.get_shielded_transactions_by_tags(Vec::new(), None, None, config)
        }
        fn get_shielded_transactions_by_tags(
            &self,
            _tags: Vec<[u8; 32]>,
            _cursor: Option<Vec<u8>>,
            _limit: Option<u32>,
            _config: Option<IndexerRpcConfig>,
        ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
            Ok(GetShieldedTransactionsByTagsResponse {
                context: Context {
                    block_time: 0,
                    slot: 1,
                },
                output_tree_id: Some(0),
                transactions: self.transactions.clone(),
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
        ) -> Result<GetShieldedTransactionsByNullifiersResponse, ClientError> {
            Ok(GetShieldedTransactionsByNullifiersResponse {
                context: Context {
                    block_time: 0,
                    slot: 1,
                },
                output_tree_id: Some(0),
                transactions: self
                    .transactions
                    .iter()
                    .filter(|tx| tx.nullifiers.iter().any(|spent| nullifiers.contains(spent)))
                    .cloned()
                    .collect(),
                next_cursor: None,
                scanned_through: Some(Vec::new()),
            })
        }
    }

    struct AllRingInvoked<'a>(&'a [ShieldedTransaction]);

    impl TransactionOrigin for AllRingInvoked<'_> {
        async fn origin(
            &self,
            signature: Signature,
            _event_index: u16,
            _ring: Address,
        ) -> Result<RingOrigin, AuditError> {
            Ok(RingOrigin {
                event: super::origin_fixture::event(
                    self.0
                        .iter()
                        .find(|tx| tx.tx_signature == signature)
                        .expect("confirmed event"),
                ),
                ring_invoked: true,
                signers: Vec::new(),
                withdrawals: Vec::new(),
                deposits: Vec::new(),
            })
        }
    }

    fn recover(
        indexer: &StubIndexer,
        auditor: &X25519Secret,
        source: SourceMember<'_>,
    ) -> Result<Vec<WalletUtxo>, AuditError> {
        let stub = StubIndexer {
            transactions: indexer.transactions.clone(),
        };
        let zolana = ZolanaClient::new((), stub, ProverClient::local());
        let recovery = RingRecovery::new(ring().program_id(), auditor).for_member(source);
        let assets = AssetRegistry::default();
        zolana
            .block_on(recovery.run(
                zolana.as_async().indexer(),
                &AllRingInvoked(&indexer.transactions),
                &assets,
            ))
            .map(|recovered| recovered.utxos)
    }

    #[test]
    fn recovery_returns_the_source_unspent_notes_and_drops_the_spent_one() {
        let source = ShieldedKeypair::new_ed25519().expect("keypair");
        let auditor = X25519Secret::new();
        let tx_unspent = ViewingKey::new();
        let tx_spent = ViewingKey::new();
        let tx_burn = ViewingKey::new();
        let unspent = RingNote {
            tx_key: &tx_unspent,
            source: &source,
            amount: 6,
            blinding: 0x11,
        }
        .seal();
        let spent = RingNote {
            tx_key: &tx_spent,
            source: &source,
            amount: 5,
            blinding: 0x22,
        }
        .seal();
        let indexer = StubIndexer {
            transactions: vec![
                RingTx {
                    tx_key: &tx_unspent,
                    auditor: &auditor,
                    signature: 1,
                    output_slots: vec![unspent.slot.clone()],
                    audit_openings: vec![unspent.audit_opening.clone()],
                    nullifiers: Vec::new(),
                }
                .indexed(),
                RingTx {
                    tx_key: &tx_spent,
                    auditor: &auditor,
                    signature: 2,
                    output_slots: vec![spent.slot.clone()],
                    audit_openings: vec![spent.audit_opening.clone()],
                    nullifiers: Vec::new(),
                }
                .indexed(),
                RingTx {
                    tx_key: &tx_burn,
                    auditor: &auditor,
                    signature: 3,
                    output_slots: Vec::new(),
                    audit_openings: Vec::new(),
                    nullifiers: vec![spent.nullifier],
                }
                .indexed(),
            ],
        };
        let address = source.shielded_address().expect("address");
        let recovered = recover(
            &indexer,
            &auditor,
            SourceMember {
                address: &address,
                nullifier_key: &source.nullifier_key,
            },
        )
        .expect("recovery");

        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].utxo, unspent.utxo);

        let selected = pick(&recovered, SOL_MINT, 6).expect("selected");
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].utxo, unspent.utxo);
    }

    #[test]
    fn recovery_rejects_a_nullifier_key_from_another_member() {
        let source = ShieldedKeypair::new_ed25519().expect("keypair");
        let stranger = ShieldedKeypair::new_ed25519().expect("stranger");
        let indexer = StubIndexer {
            transactions: Vec::new(),
        };
        let address = source.shielded_address().expect("address");
        assert!(matches!(
            recover(
                &indexer,
                &X25519Secret::new(),
                SourceMember {
                    address: &address,
                    nullifier_key: &stranger.nullifier_key,
                },
            ),
            Err(AuditError::NullifierKeyMismatch)
        ));
    }
}
