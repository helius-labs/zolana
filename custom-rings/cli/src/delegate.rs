use std::path::PathBuf;

use custom_ring_sdk::{
    DelegateOutput, DelegateTransfer, DelegateTransferInput, SetDelegate, TransferProofEnvironment,
    V0WithLookupTable, SET_DELEGATE_COMPUTE_UNIT_LIMIT,
};
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_signer::Signer;
use thiserror::Error;
use zolana_client::{ClientError, Rpc, SppProofInputUtxo};
use zolana_interface::pda;
use zolana_keypair::{ShieldedAddress, ShieldedKeypair};
use zolana_transaction::{AssetRegistry, Utxo, Wallet, SOL_MINT};
use zolana_wallet::sync_wallet;

use crate::{
    file,
    fund::MIN_AUTHORITY_BALANCE,
    line,
    transact::{cosigner_keypair, TransactError, PAYER_FEE_BUDGET, SENDER_FEE_BUDGET},
    ui,
    ui::Icon,
    Context, ContextError, DelegateCommand,
};

#[derive(Debug, Error)]
pub enum DelegateError {
    #[error(transparent)]
    Transact(Box<TransactError>),
    #[error("the ring has no delegate")]
    NotSet,
    #[error("the delegate keypair {0} is not the ring's delegate {1}")]
    WrongDelegate(Address, Address),
    #[error("the source holds {held} lamports in the ring, the move needs {needed}")]
    InsufficientNotes { needed: u64, held: u64 },
    #[error("the delegate move supports SOL only, not {0}")]
    UnsupportedMint(Address),
}

impl<E: Into<TransactError>> From<E> for DelegateError {
    fn from(error: E) -> Self {
        Self::Transact(Box::new(error.into()))
    }
}

fn client(error: ClientError) -> TransactError {
    TransactError::Client(Box::new(error))
}

pub fn run(ctx: &mut Context, command: DelegateCommand) -> Result<(), DelegateError> {
    match command {
        DelegateCommand::Set { delegate } => {
            let authority = ctx.config.upgrade_authority().map_err(ContextError::from)?;
            ctx.fund_authority(&authority, MIN_AUTHORITY_BALANCE)?;
            ctx.rpc
                .create_and_send_transaction(
                    &[
                        ComputeBudgetInstruction::set_compute_unit_limit(
                            SET_DELEGATE_COMPUTE_UNIT_LIMIT,
                        ),
                        SetDelegate {
                            ring: ctx.ring,
                            payer: authority.pubkey(),
                            authority: authority.pubkey(),
                            delegate,
                        }
                        .instruction(),
                    ],
                    authority.pubkey(),
                    &[&authority],
                )
                .map_err(client)?;
            ui::heading(Icon::Auditor, &format!("delegate {delegate} set"));
        }
        DelegateCommand::Show => {}
        DelegateCommand::Move {
            to,
            source,
            amount,
            mint,
            delegate_keypair,
            cosigner_keypair: cosigner_path,
        } => {
            return run_move(
                ctx,
                MovePlan {
                    to,
                    source,
                    amount,
                    mint: mint.unwrap_or(SOL_MINT),
                    delegate_keypair,
                    cosigner_path,
                },
            );
        }
    }
    match ctx.ring.read_delegate(&ctx.rpc)? {
        Some(delegate) => line("delegate", delegate.delegate),
        None => line("delegate", "none"),
    }
    Ok(())
}

struct MovePlan {
    to: ShieldedAddress,
    source: PathBuf,
    amount: u64,
    mint: Address,
    delegate_keypair: PathBuf,
    cosigner_path: Option<PathBuf>,
}

/// Moves the source member's own ring notes, the delegate signs and never holds them.
fn run_move(ctx: &mut Context, plan: MovePlan) -> Result<(), DelegateError> {
    let MovePlan {
        to,
        source,
        amount,
        mint,
        delegate_keypair,
        cosigner_path,
    } = plan;
    if mint != SOL_MINT {
        return Err(DelegateError::UnsupportedMint(mint));
    }

    let delegate = file::read_keypair(&ctx.project_path(&delegate_keypair))?;
    let stored = ctx
        .ring
        .read_delegate(&ctx.rpc)?
        .ok_or(DelegateError::NotSet)?;
    if stored.delegate != delegate.pubkey() {
        return Err(DelegateError::WrongDelegate(
            delegate.pubkey(),
            stored.delegate,
        ));
    }
    let cosigner = cosigner_keypair(ctx, cosigner_path.as_deref())?;

    // The source key proves the notes, it never signs the transaction.
    let source_file = file::read_keypair(&ctx.project_path(&source))?;
    let source = ShieldedKeypair::from_keypair(&source_file)?;

    let indexer = ctx.indexer();
    let assets = AssetRegistry::default();
    let mut wallet = Wallet::new(source.shielded_address()?, assets.clone())?;
    sync_wallet(&mut wallet, &source, &indexer).map_err(client)?;

    let tree = pda::tree(0);
    let tree_id = custom_ring_sdk::tree_id(&ctx.rpc, tree)?;
    let notes = select_source_notes(&wallet, ctx.ring.program_id(), mint, tree_id, amount)?;
    let selected: u64 = notes.iter().map(|(utxo, _, _)| utxo.amount).sum();

    let authority = ctx.authority_with_balance(SENDER_FEE_BUDGET + PAYER_FEE_BUDGET)?;
    ctx.ring_rpc().check_serves(ctx.ring.program_id())?;

    let inputs: Vec<SppProofInputUtxo> = notes
        .into_iter()
        .map(|(utxo, data_hash, ring_data_hash)| {
            let mut input = SppProofInputUtxo::new(utxo, &source).in_tree(tree_id);
            if let Some(data_hash) = data_hash {
                input = input.with_data_hash(data_hash);
            }
            if let Some(ring_data_hash) = ring_data_hash {
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
    let change = selected - amount;
    if change > 0 {
        outputs.push(DelegateOutput {
            recipient: source.shielded_address()?,
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
    let mut signers: Vec<&dyn Signer> = vec![&delegate];
    signers.extend(cosigner.iter().map(|keypair| keypair as &dyn Signer));
    let moved = V0WithLookupTable {
        payer: &authority,
        signers: &signers,
        instruction: proven.instruction()?,
    }
    .send(&ctx.rpc)?;
    line("to", to);
    line("amount", format_args!("{amount} lamports"));
    line("move", moved);
    Ok(())
}

/// A selected note with the committed hashes that rebuild its input commitment.
type SelectedNote = (Utxo, Option<[u8; 32]>, Option<[u8; 32]>);

/// The source's own unspent notes of the mint in the tree, largest first, up to the amount.
fn select_source_notes(
    wallet: &Wallet,
    ring: Address,
    mint: Address,
    tree_id: u16,
    amount: u64,
) -> Result<Vec<SelectedNote>, DelegateError> {
    let mut notes: Vec<SelectedNote> = wallet
        .utxos
        .iter()
        .filter(|held| {
            !held.spent
                && held.tree_id == tree_id
                && held.utxo.ring_program_id == Some(ring)
                && held.utxo.asset == mint
        })
        .map(|held| (held.utxo.clone(), held.data_hash, held.ring_data_hash))
        .collect();
    notes.sort_by_key(|(utxo, _, _)| std::cmp::Reverse(utxo.amount));
    let mut selected = Vec::new();
    let mut held = 0u64;
    for note in notes {
        if held >= amount {
            break;
        }
        held = held.saturating_add(note.0.amount);
        selected.push(note);
    }
    if held < amount {
        return Err(DelegateError::InsufficientNotes {
            needed: amount,
            held,
        });
    }
    Ok(selected)
}

#[cfg(test)]
mod tests {
    use custom_ring_sdk::CustomRing;
    use zolana_transaction::{Data, OutputContext, Utxo, WalletUtxo};

    use super::*;

    fn ring() -> CustomRing {
        CustomRing::new(Address::new_from_array([9; 32]))
    }

    fn note(
        owner: &ShieldedKeypair,
        ring_id: Option<Address>,
        asset: Address,
        tree_id: u16,
        amount: u64,
        spent: bool,
    ) -> WalletUtxo {
        WalletUtxo {
            tree_id,
            utxo: Utxo {
                owner: owner.signing_pubkey(),
                asset,
                amount,
                blinding: [amount as u8; 32],
                ring_program_id: ring_id,
                data: Data::default(),
            },
            output_context: OutputContext {
                hash: [amount as u8; 32],
                tree: pda::tree(0),
                leaf_index: amount,
            },
            nullifier: [amount as u8; 32],
            data_hash: None,
            ring_data_hash: None,
            spent,
        }
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

    #[test]
    fn selects_the_source_notes_up_to_the_amount() {
        let owner = ShieldedKeypair::new_ed25519().expect("keypair");
        let wallet = wallet_with(
            &owner,
            vec![
                note(&owner, Some(ring().program_id()), SOL_MINT, 0, 6, false),
                note(&owner, Some(ring().program_id()), SOL_MINT, 0, 5, false),
            ],
        );
        let selected =
            select_source_notes(&wallet, ring().program_id(), SOL_MINT, 0, 8).expect("selected");
        let sum: u64 = selected.iter().map(|(utxo, _, _)| utxo.amount).sum();
        assert!(sum >= 8);
    }

    #[test]
    fn carries_the_committed_data_hashes() {
        let owner = ShieldedKeypair::new_ed25519().expect("keypair");
        let mut held = note(&owner, Some(ring().program_id()), SOL_MINT, 0, 9, false);
        held.data_hash = Some([1; 32]);
        held.ring_data_hash = Some([2; 32]);
        let wallet = wallet_with(&owner, vec![held]);
        let selected =
            select_source_notes(&wallet, ring().program_id(), SOL_MINT, 0, 9).expect("selected");
        assert_eq!(selected[0].1, Some([1; 32]));
        assert_eq!(selected[0].2, Some([2; 32]));
    }

    #[test]
    fn refuses_when_the_source_holds_too_little() {
        let owner = ShieldedKeypair::new_ed25519().expect("keypair");
        let wallet = wallet_with(
            &owner,
            vec![note(
                &owner,
                Some(ring().program_id()),
                SOL_MINT,
                0,
                3,
                false,
            )],
        );
        assert!(matches!(
            select_source_notes(&wallet, ring().program_id(), SOL_MINT, 0, 8),
            Err(DelegateError::InsufficientNotes { needed: 8, held: 3 })
        ));
    }

    #[test]
    fn ignores_a_foreign_ring_mint_tree_or_spent_note() {
        let owner = ShieldedKeypair::new_ed25519().expect("keypair");
        let other_ring = Address::new_from_array([7; 32]);
        let other_mint = Address::new_from_array([8; 32]);
        let wallet = wallet_with(
            &owner,
            vec![
                note(&owner, Some(other_ring), SOL_MINT, 0, 20, false),
                note(&owner, Some(ring().program_id()), other_mint, 0, 21, false),
                note(&owner, Some(ring().program_id()), SOL_MINT, 1, 22, false),
                note(&owner, Some(ring().program_id()), SOL_MINT, 0, 23, true),
                note(&owner, None, SOL_MINT, 0, 24, false),
            ],
        );
        assert!(matches!(
            select_source_notes(&wallet, ring().program_id(), SOL_MINT, 0, 5),
            Err(DelegateError::InsufficientNotes { needed: 5, held: 0 })
        ));
    }
}
