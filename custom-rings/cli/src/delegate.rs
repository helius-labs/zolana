//! `delegate move`, the permanent delegate spends a member's ring notes.

use anyhow::{bail, ensure, Context as _, Result};
use custom_ring_sdk::{DelegateMove, DelegatePayment, MemberRecords};
use solana_signer::Signer;
use zolana_client::{IndexerRpcConfig, Rpc};
use zolana_ring_client::{RingRecovery, SourceMember};
use zolana_ring_policy::Member;
use zolana_transaction::SOL_MINT;

use crate::{
    assets,
    controls::{ring_auditor_key, DualControl},
    file, line, records,
    transact::{CoSigner, Demand, PAYER_FEE_BUDGET, SENDER_FEE_BUDGET},
    Context, DelegateMoveArgs,
};

/// The source keeps note ownership until the delegate's signed move executes.
pub fn run_move(ctx: &Context, args: DelegateMoveArgs) -> Result<()> {
    let (source, amount) = (args.source, args.amount);
    ensure!(amount > 0, "the move amount must be greater than zero");
    let mint = args.mint.map_or(SOL_MINT, |mint| mint.0);
    let config = ctx.ring_config()?;
    let delegate = file::read_keypair(&ctx.path(&args.delegate_keypair))?;
    let stored = config.delegate.context("the ring has no delegate")?;
    ensure!(
        stored == delegate.pubkey(),
        "the delegate keypair {} is not the ring's delegate {stored}",
        delegate.pubkey()
    );
    DualControl {
        cosigner: config.co_signer.as_ref().map(|cosigner| cosigner.signer),
        delegate: Some(stored),
    }
    .check()?;
    let cosigner = CoSigner::read(ctx, &args.cosigner)?;
    let move_cosigner = cosigner.sign(&config, Demand::Transfer)?;
    // The auditor key decrypts recovery material, only the delegate signs.
    let auditor = ring_auditor_key(ctx, &args.auditor_key)?;
    let read = records::read_one(
        &ctx.zolana,
        MemberRecords {
            ring: ctx.ring,
            members: &[Member::owner_tag(&source.confidential_view_tag()?)?],
        },
    )?;
    let Some(escrowed) = read.escrowed(&source.nullifier_pubkey)? else {
        bail!("member {source} has no registered key, it runs `zolana-ring key register` first");
    };
    let nullifier_key = escrowed.sealed.open(&auditor)?;
    let assets = assets::resolve(ctx.rpc(), mint)?.registry;
    let recovery = RingRecovery::new(ctx.ring.program_id(), &auditor)
        .with_mode(config.mode)
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
    let authority = ctx.authority()?;
    let transfer = ctx.block(
        DelegateMove {
            ring: ctx.ring,
            delegate: delegate.pubkey(),
            payer: authority.pubkey(),
            source,
            source_nullifier_key: &nullifier_key,
            utxos: &recovered.utxos,
            mint,
            payments: args
                .to
                .iter()
                .map(|to| DelegatePayment {
                    recipient: *to,
                    amount,
                })
                .collect(),
            assets: &assets,
        }
        .select(chain),
    )?;
    ctx.require_balance(authority.pubkey(), SENDER_FEE_BUDGET + PAYER_FEE_BUDGET)?;
    ctx.ring_rpc().check_serves(ctx.ring.program_id())?;
    let signers: Vec<_> = std::iter::once(&delegate as &(dyn Signer + Sync))
        .chain(move_cosigner)
        .collect();
    let moved = ctx.submit(transfer, authority, &signers)?;
    for to in &args.to {
        line("to", to);
    }
    line("amount", format_args!("{amount} base units each"));
    line("mint", mint);
    line("move", moved);
    Ok(())
}
