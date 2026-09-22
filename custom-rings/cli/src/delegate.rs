use std::{collections::BTreeMap, path::Path};

use custom_ring_sdk::{
    CoSignScope, DelegateOutput, DelegateTransfer, DelegateTransferInput, KeyRegistrationError,
    ReadSealedKey, SetDelegate, TransactSend, TransferError, TransferProofEnvironment,
    SET_DELEGATE_COMPUTE_UNIT_LIMIT,
};
use solana_address::Address;
use solana_signer::Signer;
use thiserror::Error;
use zolana_client::{ClientError, ComputeBudgetConfig, Rpc, SppProofInputUtxo};
use zolana_interface::{instruction::CircuitId, N_PUBLIC_SLOTS};
use zolana_keypair::{ShieldedAddress, ViewingKey};
use zolana_ring_client::{
    RecoveryEnvironment, RecoveryError, RingEnvironment, RingRecovery, SourceMember,
};
use zolana_ring_policy::Member;
use zolana_ring_rpc::KeyFileError;
use zolana_transaction::{Wallet, WalletUtxo, SOL_MINT};

use crate::{
    assets, file,
    fund::MIN_AUTHORITY_BALANCE,
    keys, line,
    transact::{signers, CoSignerCheck, TransactError, PAYER_FEE_BUDGET, SENDER_FEE_BUDGET},
    Context, ContextError, DelegateCommand, DelegateMoveArgs, AUDITOR_KEY_FILE,
};

#[derive(Debug, Error)]
pub enum DelegateError {
    #[error(transparent)]
    Transact(Box<TransactError>),
    #[error("the ring has no config, run `zolana-ring init` first")]
    NoConfig,
    #[error("the ring has no delegate")]
    NotSet,
    #[error("the delegate keypair {given} is not the ring's delegate {stored}")]
    WrongDelegate { given: Address, stored: Address },
    #[error("the source holds {held} base units in the selected tree, the move needs {needed}")]
    InsufficientNotes { needed: u64, held: u128 },
    #[error("no tree can fund {needed} base units within the delegate input limit")]
    NoFundedTree { needed: u64 },
    #[error("the move amount must be greater than zero")]
    ZeroAmount,
    #[error("the selected change exceeds u64")]
    ChangeOverflow,
    #[error("the ring has no key registry, its authority must run `zolana-ring init` first")]
    NoKeyRegistry,
    #[error(transparent)]
    Auditor(KeyFileError),
    #[error("{} does not hold the ring auditor read key {ring_auditor}", path.display())]
    AuditorKeyRequired {
        path: std::path::PathBuf,
        ring_auditor: String,
    },
    #[error("the source shielded address does not derive a member identity")]
    SourceIdentity,
    #[error("member {0} has no registered key, it runs `zolana-ring key register` first")]
    MemberUnregistered(ShieldedAddress),
    #[error(transparent)]
    Registry(Box<KeyRegistrationError>),
    #[error(transparent)]
    Recovery(Box<RecoveryError>),
}

impl<E: Into<TransactError>> From<E> for DelegateError {
    fn from(error: E) -> Self {
        Self::Transact(Box::new(error.into()))
    }
}

struct NoteSelection<'a> {
    wallet: &'a Wallet,
    ring: Address,
    mint: Address,
    amount: u64,
}

struct SelectedNotes {
    notes: Vec<WalletUtxo>,
    total: u128,
}

pub fn run(ctx: &mut Context, command: DelegateCommand) -> Result<(), DelegateError> {
    match command {
        DelegateCommand::Set { delegate } => {
            ring_auditor_key(ctx, Path::new(AUDITOR_KEY_FILE))?;
            ctx.ring
                .read_key_registry_root(&ctx.rpc)?
                .ok_or(DelegateError::NoKeyRegistry)?;
            let authority = ctx.config.upgrade_authority().map_err(ContextError::from)?;
            ctx.fund_authority(&authority, MIN_AUTHORITY_BALANCE)?;
            ctx.rpc.create_and_send_transaction(
                &[SetDelegate {
                    ring: ctx.ring,
                    payer: authority.pubkey(),
                    authority: authority.pubkey(),
                    delegate,
                }
                .instruction()],
                authority.pubkey(),
                &[&authority],
                ComputeBudgetConfig::new(SET_DELEGATE_COMPUTE_UNIT_LIMIT),
            )?;
            line("delegate", format_args!("{delegate} set"));
        }
        DelegateCommand::Show => {}
        DelegateCommand::Move(args) => return run_move(ctx, *args),
    }
    match ctx.ring.read_delegate(&ctx.rpc)? {
        Some(delegate) => line("delegate", delegate.delegate),
        None => line("delegate", "none"),
    }
    Ok(())
}

/// The source keeps note ownership until the delegate's signed move executes.
fn run_move(ctx: &mut Context, args: DelegateMoveArgs) -> Result<(), DelegateError> {
    let DelegateMoveArgs {
        to,
        source,
        amount,
        mint,
        delegate_keypair,
        auditor_key,
        cosigner_keypair,
    } = args;
    if amount == 0 {
        return Err(DelegateError::ZeroAmount);
    }
    let mint = mint.map_or(SOL_MINT, |mint| mint.0);
    // 1. The configured Solana delegate key authorizes the move.
    let delegate = file::read_keypair(&ctx.project_path(&delegate_keypair))?;
    let stored = ctx
        .ring
        .read_delegate(&ctx.rpc)?
        .ok_or(DelegateError::NotSet)?;
    if stored.delegate != delegate.pubkey() {
        return Err(DelegateError::WrongDelegate {
            given: delegate.pubkey(),
            stored: stored.delegate,
        });
    }
    let cosigner = CoSignerCheck {
        keypair: cosigner_keypair.as_deref(),
        scope: CoSignScope::TRANSFERS,
        payment: None,
    }
    .load(ctx)?;
    // 2. The auditor key decrypts recovery material, it does not sign.
    let auditor = ring_auditor_key(ctx, &auditor_key)?;
    let registry = ctx
        .ring
        .read_key_registry_root(&ctx.rpc)?
        .ok_or(DelegateError::NoKeyRegistry)?;
    let member = Member::owner_tag(
        &source
            .confidential_view_tag()
            .map_err(|_| DelegateError::SourceIdentity)?,
    )
    .map_err(|_| DelegateError::SourceIdentity)?;

    let indexer = ctx.indexer();
    let assets = assets::resolve(&ctx.rpc, mint)
        .map_err(TransactError::from)?
        .registry;
    let read = ReadSealedKey {
        ring: ctx.ring,
        member,
        root: registry,
    };
    let nullifier_key = match read.read(&indexer) {
        Ok(entry) => entry
            .open(&auditor)
            .map_err(|error| DelegateError::Registry(Box::new(error)))?,
        Err(KeyRegistrationError::Client(error))
            if matches!(*error, ClientError::RingKeyRegistryMemberUnregistered) =>
        {
            return Err(DelegateError::MemberUnregistered(source));
        }
        Err(error) => return Err(DelegateError::Registry(Box::new(error))),
    };
    // 3. Accept verified openings and report incomplete recovery.
    let recovered = RingRecovery::new(ctx.ring.program_id(), &auditor)
        .for_member(SourceMember {
            address: &source,
            nullifier_key: &nullifier_key,
        })
        .run(RecoveryEnvironment {
            ring: RingEnvironment {
                indexer: &indexer,
                origin: &ctx.rpc,
            },
            assets: &assets,
            tree_ids: |tree| {
                custom_ring_sdk::tree_id(&ctx.rpc, tree).map_err(|error| match error {
                    TransferError::Client(source) => RecoveryError::Indexer(source),
                    _ => RecoveryError::UnknownTree(tree),
                })
            },
        })
        .map_err(|error| DelegateError::Recovery(Box::new(error)))?;
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
    let mut wallet = Wallet::new(source, assets.clone())?
        .with_deposit_payload_decoder(zolana_ring_client::deposit_payload);
    wallet.utxos = recovered.utxos;

    let selection = NoteSelection {
        wallet: &wallet,
        ring: ctx.ring.program_id(),
        mint,
        amount,
    };
    let tree = selection
        .tree()
        .ok_or(DelegateError::NoFundedTree { needed: amount })?;
    let tree_id = custom_ring_sdk::tree_id(&ctx.rpc, tree)?;
    let SelectedNotes { notes, total } = selection.notes(tree_id)?;

    let authority = ctx.authority_with_balance(SENDER_FEE_BUDGET + PAYER_FEE_BUDGET)?;
    ctx.ring_rpc().check_serves(ctx.ring.program_id())?;

    let inputs: Vec<SppProofInputUtxo> = notes
        .into_iter()
        .map(|held| {
            let mut input = SppProofInputUtxo::new(held.utxo, &nullifier_key).in_tree(tree_id);
            if let Some(data_hash) = held.data_hash {
                input = input.with_data_hash(data_hash);
            }
            if let Some(ring_data_hash) = held.ring_data_hash {
                input = input.with_ring_data_hash(ring_data_hash);
            }
            input
        })
        .collect();
    let mut outputs = vec![DelegateOutput {
        recipient: to,
        asset: mint,
        amount,
    }];
    let change = total
        .checked_sub(u128::from(amount))
        .ok_or(DelegateError::InsufficientNotes {
            needed: amount,
            held: total,
        })?;
    let change = u64::try_from(change).map_err(|_| DelegateError::ChangeOverflow)?;
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
        inputs,
        outputs,
    })
    .with_tree(tree)
    .with_assets(&assets);
    if let Some(cosigner) = &cosigner {
        transfer = transfer.with_cosigner(cosigner.pubkey());
    }
    let proven = transfer.prove(TransferProofEnvironment {
        indexer: &indexer,
        rpc: &ctx.rpc,
        prover: &ctx.prover(),
    })?;
    // 4. The permanent delegate signs beside any required co-signer.
    let signers = signers(
        &delegate,
        cosigner.as_ref().map(|keypair| keypair as &dyn Signer),
    );
    let moved = TransactSend {
        payer: &authority,
        signers: &signers,
        instruction: proven.instruction()?,
    }
    .send(&ctx.rpc)?;
    line("to", to);
    line("amount", format_args!("{amount} base units"));
    line("mint", mint);
    line("move", moved);
    Ok(())
}

/// The auditor read key cannot authorize ownership transfers or withdrawals.
fn ring_auditor_key(ctx: &Context, path: &Path) -> Result<ViewingKey, DelegateError> {
    let ring_auditor = ctx
        .ring
        .read_config(&ctx.rpc)?
        .ok_or(DelegateError::NoConfig)?
        .auditor_pubkey;
    let path = ctx.project_path(path);
    let auditor = keys::read_auditor_key(&path).map_err(DelegateError::Auditor)?;
    if auditor.pubkey() != ring_auditor {
        return Err(DelegateError::AuditorKeyRequired {
            path,
            ring_auditor: hex::encode(ring_auditor.as_bytes()),
        });
    }
    Ok(auditor)
}

impl NoteSelection<'_> {
    fn held(&self) -> impl Iterator<Item = &WalletUtxo> {
        self.wallet.utxos.iter().filter(|held| {
            !held.spent
                && held.utxo.ring_program_id == Some(self.ring)
                && held.utxo.asset == self.mint
        })
    }

    fn tree(&self) -> Option<Address> {
        let trees: BTreeMap<_, _> = self
            .held()
            .map(|held| (held.output_context.tree, held.tree_id))
            .collect();
        trees
            .into_iter()
            .filter_map(|(tree, id)| self.notes(id).ok().map(|notes| (tree, notes)))
            .min_by_key(|(tree, notes)| (notes.notes.len(), notes.total, *tree))
            .map(|(tree, _)| tree)
    }

    /// Largest first, up to the amount.
    fn notes(&self, tree_id: u16) -> Result<SelectedNotes, DelegateError> {
        if self.amount == 0 {
            return Err(DelegateError::ZeroAmount);
        }
        let mut notes: Vec<WalletUtxo> = self
            .held()
            .filter(|held| held.tree_id == tree_id)
            .cloned()
            .collect();
        notes.sort_by_key(|held| std::cmp::Reverse(held.utxo.amount));
        let mut selected = Vec::new();
        let mut total = 0u128;
        for note in notes {
            if total >= u128::from(self.amount) {
                break;
            }
            let Ok(width) = u8::try_from(selected.len() + 1) else {
                break;
            };
            if !CircuitId::RingAuthority(width, width, N_PUBLIC_SLOTS as u8).is_supported() {
                break;
            }
            total += u128::from(note.utxo.amount);
            selected.push(note);
        }
        if total < u128::from(self.amount) {
            return Err(DelegateError::InsufficientNotes {
                needed: self.amount,
                held: total,
            });
        }
        Ok(SelectedNotes {
            notes: selected,
            total,
        })
    }
}

#[cfg(test)]
mod tests {
    use custom_ring_sdk::CustomRing;
    use solana_signature::Signature;
    use zolana_client::{
        rpc::GetShieldedTransactionsByNullifiersResponse, Context,
        GetShieldedTransactionsByTagsResponse, IndexerRpcConfig, ShieldedTransaction,
    };
    use zolana_interface::pda;
    use zolana_keypair::{constants::SALT_LEN, ShieldedKeypair};
    use zolana_ring_client::{AuditorEncryption, OriginError, RingOrigin, TransactionOrigin};
    use zolana_transaction::{
        serialization::confidential::{
            Confidential, ConfidentialEncode, ConfidentialOutputPlaintext,
        },
        utxo::ProofInputUtxo,
        AssetRegistry, Data, OutputContext, OutputSlot, Utxo, UtxoSerialization, SOL_ASSET_ID,
    };

    use super::*;

    const SALT: [u8; SALT_LEN] = [5u8; SALT_LEN];
    const TREE: Address = Address::new_from_array([4u8; 32]);

    fn ring() -> CustomRing {
        CustomRing::new(Address::new_from_array([9; 32]))
    }

    struct NoteFixture {
        ring_id: Option<Address>,
        asset: Address,
        tree_id: u16,
        amount: u64,
        spent: bool,
    }

    fn note(owner: &ShieldedKeypair, fixture: NoteFixture) -> WalletUtxo {
        WalletUtxo {
            tree_id: fixture.tree_id,
            utxo: Utxo {
                owner: owner.signing_pubkey(),
                asset: fixture.asset,
                amount: fixture.amount,
                blinding: [fixture.amount as u8; 32],
                ring_program_id: fixture.ring_id,
                data: Data::default(),
            },
            output_context: OutputContext {
                hash: [fixture.amount as u8; 32],
                tree: pda::tree(fixture.tree_id),
                leaf_index: fixture.amount,
            },
            nullifier: [fixture.amount as u8; 32],
            data_hash: None,
            ring_data_hash: None,
            spent: fixture.spent,
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
                spent: false,
            },
        )
    }

    fn wallet_with(owner: &ShieldedKeypair, notes: Vec<WalletUtxo>) -> Wallet {
        let mut wallet = Wallet::new(
            owner.shielded_address().expect("address"),
            AssetRegistry::default(),
        )
        .expect("wallet");
        wallet.utxos = notes;
        wallet
    }

    fn selection<'a>(wallet: &'a Wallet, mint: Address, amount: u64) -> NoteSelection<'a> {
        NoteSelection {
            wallet,
            ring: ring().program_id(),
            mint,
            amount,
        }
    }

    fn amounts(notes: &SelectedNotes) -> Vec<u64> {
        notes.notes.iter().map(|held| held.utxo.amount).collect()
    }

    #[test]
    fn selects_the_largest_source_notes_up_to_the_amount() {
        let owner = ShieldedKeypair::new_ed25519().expect("keypair");
        let wallet = wallet_with(&owner, vec![sol_note(&owner, 5), sol_note(&owner, 6)]);
        let selected = selection(&wallet, SOL_MINT, 8).notes(0).expect("selected");
        assert_eq!(amounts(&selected), [6, 5]);
        assert_eq!(selected.total, 11);
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
                    spent: false,
                },
            )
        };
        let wallet = wallet_with(
            &owner,
            vec![
                ring_note(mint, 1, 3),
                ring_note(mint, 2, 8),
                ring_note(SOL_MINT, 0, 99),
            ],
        );
        assert_eq!(selection(&wallet, mint, 5).tree(), Some(pda::tree(2)));
        assert_eq!(selection(&wallet, mint, 9).tree(), None);
        assert_eq!(amounts(&selection(&wallet, mint, 5).notes(2).unwrap()), [8]);
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
                        spent: false,
                    },
                );
                held.output_context.leaf_index = index;
                held
            })
            .collect();
        notes.push(note(
            &owner,
            NoteFixture {
                ring_id: Some(ring().program_id()),
                asset: SOL_MINT,
                tree_id: 2,
                amount: 5,
                spent: false,
            },
        ));
        let wallet = wallet_with(&owner, notes);
        let selection = selection(&wallet, SOL_MINT, 5);
        assert_eq!(selection.tree(), Some(pda::tree(2)));
        assert_eq!(amounts(&selection.notes(2).unwrap()), [5]);
        assert!(matches!(
            selection.notes(1),
            Err(DelegateError::InsufficientNotes { needed: 5, held: 4 })
        ));
    }

    #[test]
    fn a_fragmented_tree_is_selected_only_within_the_authority_shape() {
        let owner = ShieldedKeypair::new_ed25519().unwrap();
        let wallet = wallet_with(&owner, (0..6).map(|_| sol_note(&owner, 1)).collect());
        let supported = selection(&wallet, SOL_MINT, 4);
        assert_eq!(supported.tree(), Some(pda::tree(0)));
        assert_eq!(supported.notes(0).unwrap().notes.len(), 4);
        assert_eq!(selection(&wallet, SOL_MINT, 5).tree(), None);
    }

    #[test]
    fn selected_totals_can_exceed_u64_when_payment_and_change_fit() {
        let owner = ShieldedKeypair::new_ed25519().unwrap();
        let wallet = wallet_with(
            &owner,
            vec![
                sol_note(&owner, u64::MAX - 1),
                sol_note(&owner, u64::MAX - 1),
            ],
        );
        let selection = selection(&wallet, SOL_MINT, u64::MAX);
        assert_eq!(selection.tree(), Some(pda::tree(0)));
        let selected = selection.notes(0).unwrap();
        assert_eq!(selected.notes.len(), 2);
        assert_eq!(selected.total, 2 * u128::from(u64::MAX - 1));
        assert_eq!(
            u64::try_from(selected.total - u128::from(u64::MAX)).unwrap(),
            u64::MAX - 2
        );
    }

    #[test]
    fn a_zero_amount_cannot_select_an_empty_delegate_move() {
        let owner = ShieldedKeypair::new_ed25519().unwrap();
        let wallet = wallet_with(&owner, vec![sol_note(&owner, 1)]);
        let selection = selection(&wallet, SOL_MINT, 0);
        assert_eq!(selection.tree(), None);
        assert!(matches!(selection.notes(0), Err(DelegateError::ZeroAmount)));
    }

    #[test]
    fn refuses_when_the_source_holds_too_little() {
        let owner = ShieldedKeypair::new_ed25519().expect("keypair");
        let wallet = wallet_with(&owner, vec![sol_note(&owner, 3)]);
        assert!(matches!(
            selection(&wallet, SOL_MINT, 8).notes(0),
            Err(DelegateError::InsufficientNotes { needed: 8, held: 3 })
        ));
    }

    #[test]
    fn ignores_a_foreign_ring_mint_tree_or_spent_note() {
        let owner = ShieldedKeypair::new_ed25519().expect("keypair");
        let other_ring = Address::new_from_array([7; 32]);
        let other_mint = Address::new_from_array([8; 32]);
        let fixture = |ring_id, asset, tree_id, amount, spent| NoteFixture {
            ring_id,
            asset,
            tree_id,
            amount,
            spent,
        };
        let wallet = wallet_with(
            &owner,
            vec![
                note(&owner, fixture(Some(other_ring), SOL_MINT, 0, 20, false)),
                note(
                    &owner,
                    fixture(Some(ring().program_id()), other_mint, 0, 21, false),
                ),
                note(
                    &owner,
                    fixture(Some(ring().program_id()), SOL_MINT, 1, 22, false),
                ),
                note(
                    &owner,
                    fixture(Some(ring().program_id()), SOL_MINT, 0, 23, true),
                ),
                note(&owner, fixture(None, SOL_MINT, 0, 24, false)),
            ],
        );
        assert!(matches!(
            selection(&wallet, SOL_MINT, 5).notes(0),
            Err(DelegateError::InsufficientNotes { needed: 5, held: 0 })
        ));
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
                asset: SOL_MINT,
                amount: self.amount,
                blinding: [self.blinding; 32],
                ring_program_id: Some(ring),
                data: Data::default(),
            };
            let audit_opening = utxo
                .proof_input(&address.nullifier_pubkey, &[0u8; 32], &[0u8; 32], 0)
                .expect("audit opening");
            let commitment = audit_opening.hash().expect("commitment");
            let nullifier = utxo
                .nullifier(&commitment, &self.source.nullifier_key)
                .expect("nullifier");
            RecoveredFixture {
                slot: OutputSlot {
                    view_tag: encoded.view_tag,
                    output_context: OutputContext {
                        hash: commitment,
                        tree: TREE,
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
        auditor: &'a ViewingKey,
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

    struct AllRingInvoked;

    impl TransactionOrigin for AllRingInvoked {
        fn origin(
            &self,
            _signature: Signature,
            _event_index: u16,
            _ring: Address,
        ) -> Result<RingOrigin, OriginError> {
            Ok(RingOrigin {
                ring_invoked: true,
                signers: Vec::new(),
                withdrawals: Vec::new(),
            })
        }
    }

    fn recover(
        indexer: &StubIndexer,
        auditor: &ViewingKey,
        source: SourceMember<'_>,
    ) -> Result<Vec<WalletUtxo>, RecoveryError> {
        RingRecovery::new(ring().program_id(), auditor)
            .for_member(source)
            .run(RecoveryEnvironment {
                ring: RingEnvironment {
                    indexer,
                    origin: &AllRingInvoked,
                },
                assets: &AssetRegistry::default(),
                tree_ids: |_tree| Ok(0u16),
            })
            .map(|recovered| recovered.utxos)
    }

    #[test]
    fn recovery_returns_the_source_unspent_notes_and_drops_the_spent_one() {
        let source = ShieldedKeypair::new_ed25519().expect("keypair");
        let auditor = ViewingKey::new();
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

        let mut wallet = Wallet::new(address, AssetRegistry::default()).expect("wallet");
        wallet.utxos = recovered;
        let selected = selection(&wallet, SOL_MINT, 6).notes(0).expect("selected");
        assert_eq!(selected.notes.len(), 1);
        assert_eq!(selected.notes[0].utxo, unspent.utxo);
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
                &ViewingKey::new(),
                SourceMember {
                    address: &address,
                    nullifier_key: &stranger.nullifier_key,
                },
            ),
            Err(RecoveryError::NullifierKeyMismatch)
        ));
    }
}
