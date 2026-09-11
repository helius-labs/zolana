use std::path::PathBuf;

use custom_ring_sdk::{
    DelegateOutput, DelegateTransfer, DelegateTransferInput, RingDeposit, RingDepositReceipt,
    SetDelegate, TransferProofEnvironment, V0WithLookupTable, SET_DELEGATE_COMPUTE_UNIT_LIMIT,
};
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_signer::Signer;
use thiserror::Error;
use zolana_client::{ClientError, Rpc, SppProofInputUtxo};
use zolana_interface::{instruction::DepositAsset, pda};
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{AssetRegistry, SOL_MINT};

use crate::{
    file,
    fund::MIN_AUTHORITY_BALANCE,
    line,
    transact::{cosigner_keypair, wait_for_indexed_transaction, Session, TransactError},
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
            amount,
            delegate_keypair,
            cosigner_keypair: cosigner_path,
        } => {
            return run_move(ctx, to, amount, delegate_keypair, cosigner_path);
        }
    }
    match ctx.ring.read_delegate(&ctx.rpc)? {
        Some(delegate) => line("delegate", delegate.delegate),
        None => line("delegate", "none"),
    }
    Ok(())
}

/// Deposits `amount` to a throwaway member, then the delegate re-owns it to `to`.
fn run_move(
    ctx: &mut Context,
    to: ShieldedAddress,
    amount: u64,
    delegate_keypair: PathBuf,
    cosigner_path: Option<PathBuf>,
) -> Result<(), DelegateError> {
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
    let session = Session::open(ctx, amount)?;
    let member = zolana_keypair::ShieldedKeypair::new_ed25519()?;
    let tree = pda::tree(0);
    let RingDepositReceipt { signature, utxo } = RingDeposit {
        ring: ctx.ring,
        payer: &session.authority,
        recipient: &member,
        tree,
        asset: DepositAsset::Sol,
        amount,
        cosigner: cosigner.as_ref().map(|keypair| keypair as &dyn Signer),
    }
    .send(&ctx.rpc)?;
    line("deposit", signature);
    wait_for_indexed_transaction(&session.indexer, signature)?;

    let tree_id = custom_ring_sdk::tree_id(&ctx.rpc, tree)?;
    let assets = AssetRegistry::default();
    let mut transfer = DelegateTransfer::new(DelegateTransferInput {
        ring: ctx.ring,
        delegate: delegate.pubkey(),
        payer: session.authority.pubkey(),
        inputs: vec![SppProofInputUtxo::new(utxo, &member).in_tree(tree_id)],
        outputs: vec![DelegateOutput {
            recipient: to,
            asset: SOL_MINT,
            amount,
        }],
    })
    .with_tree(tree)
    .with_assets(&assets);
    if let Some(cosigner) = &cosigner {
        transfer = transfer.with_cosigner(cosigner.pubkey());
    }
    let proven = transfer.prove(TransferProofEnvironment {
        indexer: &session.indexer,
        rpc: &ctx.rpc,
        prover: &session.prover,
    })?;
    let mut signers: Vec<&dyn Signer> = vec![&delegate];
    signers.extend(cosigner.iter().map(|keypair| keypair as &dyn Signer));
    let moved = V0WithLookupTable {
        payer: &session.authority,
        signers: &signers,
        instruction: proven.instruction()?,
    }
    .send(&ctx.rpc)?;
    line("to", to);
    line("amount", format_args!("{amount} lamports"));
    line("move", moved);
    Ok(())
}
