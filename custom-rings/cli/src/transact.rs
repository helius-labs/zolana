//! `transact` and `transfer`, two ring deposits spent in one transfer the auditor reads back.

use anyhow::{bail, ensure, Context as _, Result};
use custom_ring_sdk::ListRegistry;
use custom_ring_sdk::{
    CoSignScope, CustomRingCoSigner, CustomRingTransfer, CustomRingTransferInput, DepositAsset,
    PinnedPolicy, RingDeposit, RingDepositReceipt,
};
use solana_address::Address;
use solana_keypair::Keypair;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{IndexerRpcConfig, Rpc, UtxoScan};
use zolana_interface::pda;
use zolana_keypair::{shielded::ShieldedAddress, ShieldedKeypair};
use zolana_ring_client::ReaderKey;
use zolana_ring_policy::{ListId, Member, RuleTable};
use zolana_transaction::{
    instructions::transact::{canonical_shape, ConfidentialTransaction},
    WalletUtxo, SOL_MINT,
};

use crate::{
    assets, file, line, list, member,
    ui::{self, icon},
    Context, CosignerArg, TransactArgs, TransferArgs, SENDER_KEYPAIR_FILE,
};

/// Covers the sender's registrations and fees.
pub(crate) const SENDER_FEE_BUDGET: u64 = 20_000_000;
/// The deposit and transact fees.
pub(crate) const PAYER_FEE_BUDGET: u64 = 10_000_000;

/// Whatever the two deposits hold above `amount` stays with the sender.
struct Transfer<'a> {
    sender: &'a ShieldedKeypair,
    recipient: ShieldedAddress,
    amount: u64,
    deposits: [u64; 2],
    asset: DepositAsset,
    cosigner: Option<&'a Keypair>,
    policy: Option<&'a PinnedPolicy>,
    /// The demo lists both parties in `Allow`, a transfer leaves them to the operator.
    enrol: bool,
}

pub fn run(ctx: &Context, args: TransactArgs) -> Result<()> {
    let (policy, cosigner) = guard(ctx, &args.cosigner, SOL_MINT, args.amount)?;
    // The demo deposits the amount twice, funded before the first deposit.
    let authority = open(ctx, args.amount.saturating_mul(2))?;
    let reader = ReaderKey::ed25519(authority.pubkey())?;
    ensure!(
        granted(ctx, &reader)?,
        "reader {reader} is not granted, run `grant-reader {reader}` first"
    );
    let sender = ShieldedKeypair::from_keypair(&ctx.sender()?)?;
    let recipient = ShieldedKeypair::new_ed25519()?;
    // The change stays with the sender, so its balance shows next to the payment.
    let transfer = Transfer {
        sender: &sender,
        recipient: recipient.shielded_address()?,
        amount: args.amount,
        deposits: [args.amount; 2],
        asset: DepositAsset::Sol,
        cosigner: cosigner.as_ref(),
        policy: policy.as_ref(),
        enrol: true,
    };
    let (deposits, transact) = send(ctx, authority, &transfer)?;
    for (party, keys) in [("sender", &sender), ("recipient", &recipient)] {
        let viewing = hex::encode(keys.viewing_pubkey().as_bytes());
        line(
            party,
            format_args!("{}  viewing pk {viewing}", keys.pubkey()),
        );
    }
    line("sender tag", owner_tag(&sender.shielded_address()?)?);
    line("recipient tag", owner_tag(&transfer.recipient)?);
    print_signatures(ctx, &deposits, transact)?;
    read_back(ctx, authority, transact)
}

/// Deposit the amount into the ring and send all of it to a shielded address.
pub fn run_transfer(ctx: &Context, args: TransferArgs) -> Result<()> {
    ensure!(
        args.amount >= 2,
        "amount {} does not split across the two deposits a ring transfer spends",
        args.amount
    );
    let mint = args.mint.map_or(SOL_MINT, |mint| mint.0);
    let payer = ctx.authority()?.pubkey();
    let resolved = assets::resolve(ctx.rpc(), mint)?;
    let asset = resolved.deposit(ctx.rpc(), payer, args.token_account, args.amount)?;
    let sender = ShieldedKeypair::from_keypair(&ctx.sender()?)?;
    // Same-owner outputs stay inside the ring and charge no policy outflow.
    let same_owner = sender.signing_pubkey().owner_proof_input_hash()?
        == args.to.signing_pubkey.owner_proof_input_hash()?;
    let outflow = if same_owner { 0 } else { args.amount };
    let (policy, cosigner) = guard(ctx, &args.cosigner, mint, outflow)?;
    let authority = open(ctx, if mint == SOL_MINT { args.amount } else { 0 })?;
    let half = args.amount / 2;
    let transfer = Transfer {
        sender: &sender,
        recipient: args.to,
        amount: args.amount,
        deposits: [half, args.amount - half],
        asset,
        cosigner: cosigner.as_ref(),
        policy: policy.as_ref(),
        enrol: false,
    };
    let (deposits, transact) = send(ctx, authority, &transfer)?;
    line("to", args.to);
    line("amount", format_args!("{} base units", args.amount));
    line("mint", mint);
    let saved = sender.pubkey();
    line(
        "sender",
        format_args!("{saved}  saved in {SENDER_KEYPAIR_FILE}"),
    );
    print_signatures(ctx, &deposits, transact)?;
    // Reading the transfer back is a courtesy, the payment is already on chain.
    let reader = ReaderKey::ed25519(authority.pubkey())?;
    if !granted(ctx, &reader)? {
        println!("auditor view skipped, grant-reader {reader} to read the ring");
        return Ok(());
    }
    read_back(ctx, authority, transact)
}

/// The co-signer keypair a delegate move or a merge passes, checked against the ring.
pub(crate) fn cosigner(
    ctx: &Context,
    arg: &CosignerArg,
    scope: CoSignScope,
) -> Result<Option<Keypair>> {
    checked_cosigner(ctx, arg, scope, false)
}

/// The pinned policy and the co-signer a deposit followed by a transfer of `outflow` needs.
fn guard(
    ctx: &Context,
    arg: &CosignerArg,
    mint: Address,
    outflow: u64,
) -> Result<(Option<PinnedPolicy>, Option<Keypair>)> {
    let policy = ctx.block(ctx.ring.pinned_policy(ctx.chain()))?;
    let approval = approval(mint, outflow, policy.as_ref().map(|p| &p.table))?;
    let scope = CoSignScope::TRANSFERS | CoSignScope::DEPOSITS;
    Ok((policy, checked_cosigner(ctx, arg, scope, approval)?))
}

fn checked_cosigner(
    ctx: &Context,
    arg: &CosignerArg,
    scope: CoSignScope,
    approval: bool,
) -> Result<Option<Keypair>> {
    let keypair = arg
        .cosigner_keypair
        .as_deref()
        .map(|path| file::read_keypair(&ctx.path(path)))
        .transpose()?;
    let configured = ctx.block(ctx.ring.cosigner(ctx.chain()))?;
    let provided = keypair.as_ref().map(Signer::pubkey);
    check_cosigner(configured.as_ref(), provided, scope, approval)?;
    Ok(keypair)
}

/// A blanket scope over the operation or a private approval row needs the configured signer.
fn check_cosigner(
    configured: Option<&CustomRingCoSigner>,
    provided: Option<Address>,
    scope: CoSignScope,
    approval: bool,
) -> Result<()> {
    let Some(configured) = configured else {
        ensure!(
            !approval,
            "the policy needs approval but no co-signer is configured"
        );
        return Ok(());
    };
    if let Some(found) = provided.filter(|found| *found != configured.signer) {
        bail!(
            "the configured co-signer is {}, not {found}",
            configured.signer
        );
    }
    ensure!(
        provided.is_some() || !(approval || configured.scope.intersects(scope)),
        "the transfer needs the co-signer's approval, pass --cosigner-keypair"
    );
    Ok(())
}

/// An outflow limit demands the co-signer strictly above its nonzero threshold.
fn approval(mint: Address, outflow: u64, rules: Option<&RuleTable>) -> Result<bool> {
    let asset = *Member::asset(&mint)?.as_bytes();
    Ok(rules.is_some_and(|rules| {
        rules.limits().iter().any(|limit| {
            limit.asset == asset && limit.cosign_above != 0 && outflow > limit.cosign_above
        })
    }))
}

/// Only after the ring rpc serves the configured auditor is the authority funded.
fn open(ctx: &Context, deposited: u64) -> Result<&Keypair> {
    ctx.ring_rpc().check_serves(ctx.ring.program_id())?;
    let authority = ctx.authority()?;
    let fees = SENDER_FEE_BUDGET + PAYER_FEE_BUDGET;
    ctx.fund(authority.pubkey(), deposited.saturating_add(fees))?;
    Ok(authority)
}

fn granted(ctx: &Context, reader: &ReaderKey) -> Result<bool> {
    let record = ctx.block(ctx.ring.access_record(ctx.chain(), reader))?;
    Ok(record.is_some())
}

/// Two deposits fill both inputs of IN2_OUT2, the recipient and the change fill the outputs.
fn send(ctx: &Context, payer: &Keypair, t: &Transfer<'_>) -> Result<(Vec<Signature>, Signature)> {
    let cosigner = t.cosigner.map(|keypair| keypair as &(dyn Signer + Sync));
    let mut receipts = Vec::with_capacity(t.deposits.len());
    for amount in t.deposits {
        let deposit = RingDeposit {
            ring: ctx.ring,
            payer,
            recipient: t.sender,
            tree: pda::tree(0),
            asset: t.asset,
            amount,
            cosigner,
        };
        receipts.push(ctx.block(deposit.send(ctx.chain()))?);
    }
    // Photon learns a tree from its first indexed transaction.
    ctx.wait_for_indexed(receipts[1].signature)?;
    if let Some(policy) = t
        .policy
        .filter(|p| t.enrol && p.table.referenced().contains(ListId::Allow))
    {
        enrol_in_allow(ctx, payer, policy, t)?;
    }
    let fee = solana_system_interface::instruction::transfer(
        &payer.pubkey(),
        &t.sender.pubkey(),
        SENDER_FEE_BUDGET,
    );
    ctx.send(&[payer], &[fee])?;
    line("member key", member::ensure_key(ctx, t.sender)?);
    let inputs = deposited_notes(ctx, t.sender, &receipts)?;
    let tree_id = inputs[0].tree_id;
    let shape = canonical_shape(inputs.len(), 2)?;
    let mut transaction =
        ConfidentialTransaction::new_with_ring(inputs, t.sender.pubkey(), ctx.ring.program_id())?
            .with_output_tree_id(tree_id)?;
    if t.asset.mint() == SOL_MINT {
        transaction.transfer_sol(&t.recipient, t.amount)?;
    } else {
        transaction.transfer(&t.recipient, t.asset.mint(), t.amount)?;
    }
    transaction.pad_utxos(shape, &t.sender.shielded_address()?)?;
    let mut transfer = CustomRingTransfer::new(CustomRingTransferInput {
        ring: ctx.ring,
        sender: t.sender,
        nullifier_key: Some(&t.sender.nullifier_key),
        transaction,
    });
    if let Some(cosigner) = t.cosigner {
        transfer = transfer.with_cosigner(cosigner.pubkey());
    }
    let signers: Vec<_> = cosigner.into_iter().collect();
    let transact = ctx.submit(transfer, t.sender, &signers)?;
    Ok((receipts.iter().map(|r| r.signature).collect(), transact))
}

/// The deposited notes as the sender's own scan reads them, leaf and nullifier included.
fn deposited_notes(
    ctx: &Context,
    sender: &ShieldedKeypair,
    receipts: &[RingDepositReceipt],
) -> Result<Vec<WalletUtxo>> {
    let registry = ctx.rpc().asset_registry()?;
    let scanned = UtxoScan::new(sender, &registry)
        .with_ring_deposit_payload(ctx.ring.program_id(), zolana_ring_client::deposit_payload)
        .with_indexer_config(IndexerRpcConfig::at_slot(ctx.rpc().get_slot()?))
        .fetch(ctx.zolana.indexer())?
        .spendable;
    let notes: Vec<WalletUtxo> = receipts
        .iter()
        .filter_map(|receipt| {
            // The random blinding names the note, the scan adds the deposit's empty ring data.
            scanned
                .utxos()
                .find(|held| held.utxo.blinding == receipt.utxo.blinding)
        })
        .cloned()
        .collect();
    ensure!(
        notes.len() == receipts.len(),
        "the indexer returned {} of the {} deposited notes",
        notes.len(),
        receipts.len()
    );
    Ok(notes)
}

/// The table refuses both parties until their records carry `Allow`.
fn enrol_in_allow(
    ctx: &Context,
    authority: &Keypair,
    policy: &PinnedPolicy,
    t: &Transfer<'_>,
) -> Result<()> {
    if let Some(ListRegistry::Curator(registry)) = policy.config.registry_for(ListId::Allow) {
        line("allow", format_args!("curated by {registry}"));
        return Ok(());
    }
    for (party, address) in [
        ("sender", &t.sender.shielded_address()?),
        ("recipient", &t.recipient),
    ] {
        let member = Member::owner_tag(owner_tag(address)?.as_array())?;
        let change = list::set_list(ctx, authority, ListId::Allow, member, true)?;
        line("allow", format_args!("{party} {change}"));
    }
    Ok(())
}

/// The `list` member argument of a party.
fn owner_tag(address: &ShieldedAddress) -> Result<Address> {
    Ok(Address::new_from_array(address.confidential_view_tag()?))
}

fn print_signatures(ctx: &Context, deposits: &[Signature], transact: Signature) -> Result<()> {
    for signature in deposits {
        line("deposit", signature);
    }
    line("transact", transact);
    let meta = ctx
        .rpc()
        .fetch_confirmed_transaction(&transact)?
        .transaction
        .meta;
    let logs: Option<Vec<String>> = meta.and_then(|meta| meta.log_messages.into());
    for log in logs.iter().flatten() {
        if let Some(log) = log.strip_prefix("Program log: ") {
            println!("  log       {log}");
        }
    }
    Ok(())
}

/// What the auditor opens for a granted reader, once the indexer has the slot.
fn read_back(ctx: &Context, reader: &Keypair, signature: Signature) -> Result<()> {
    println!("waiting for the indexer and the ring rpc to open the transaction");
    ctx.wait_for_indexed(signature)?;
    let opened = ctx
        .ring_rpc()
        .wait_for_decrypted(ctx.ring.program_id(), reader, signature)
        .context("the ring rpc did not open the transfer")?;
    let heading = format!("auditor sees slot {} at {signature}", opened.slot);
    ui::heading(icon::AUDITOR, &heading);
    println!("  nullifiers {}", opened.nullifiers.len());
    for output in &opened.outputs {
        println!(
            "  slot {}  to {}  asset {}  amount {}",
            output.slot_index,
            hex::encode(&output.recipient_viewing_pk.0),
            output.asset.0,
            output.amount
        );
    }
    if !opened.undecryptable_slots.is_empty() {
        println!("  undecryptable slots {:?}", opened.undecryptable_slots);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use zolana_ring_policy::OutflowLimit;

    use super::*;

    const SIGNER: Address = Address::new_from_array([1; 32]);

    fn configured(scope: CoSignScope) -> CustomRingCoSigner {
        CustomRingCoSigner {
            signer: SIGNER,
            scope,
            thresholds: vec![],
        }
    }

    fn check(
        configured: Option<&CustomRingCoSigner>,
        provided: Option<Address>,
        approval: bool,
    ) -> Result<()> {
        let scope = CoSignScope::TRANSFERS | CoSignScope::DEPOSITS;
        check_cosigner(configured, provided, scope, approval)
    }

    fn refusal(result: Result<()>) -> String {
        result.expect_err("refused").to_string()
    }

    fn limits(cap: u64, cosign_above: u64) -> RuleTable {
        RuleTable::builder()
            .limits(&[OutflowLimit {
                asset: *Member::asset(&SOL_MINT).unwrap().as_bytes(),
                cap,
                cosign_above,
            }])
            .build()
    }

    #[test]
    fn blanket_scope_and_private_approval_require_the_configured_signer() {
        let deposits = configured(CoSignScope::DEPOSITS);
        assert!(refusal(check(Some(&deposits), None, false)).contains("pass --cosigner-keypair"));
        assert!(check(Some(&deposits), Some(SIGNER), false).is_ok());
        assert!(
            refusal(check(Some(&deposits), Some(Address::default()), false))
                .starts_with("the configured co-signer is")
        );
        let withdrawals = configured(CoSignScope::WITHDRAWALS);
        assert!(check(Some(&withdrawals), None, false).is_ok());
        assert!(refusal(check(Some(&withdrawals), None, true)).contains("pass --cosigner-keypair"));
        assert!(refusal(check(None, None, true)).contains("no co-signer is configured"));
        assert!(check(None, None, false).is_ok());
    }

    #[test]
    fn self_transfer_has_no_private_outflow_but_keeps_blanket_scope_checks() {
        let sender = ShieldedKeypair::new_ed25519().unwrap();
        let mut recipient = sender.shielded_address().unwrap();
        recipient.viewing_pubkey = zolana_keypair::ViewingKey::new().pubkey();
        assert_eq!(
            sender.signing_pubkey().owner_proof_input_hash().unwrap(),
            recipient.signing_pubkey.owner_proof_input_hash().unwrap()
        );
        // A same-owner transfer charges zero outflow, so no approval row fires.
        let approval = approval(SOL_MINT, 0, Some(&limits(0, 10))).unwrap();
        assert!(!approval);
        for (scope, required) in [
            (CoSignScope::WITHDRAWALS, false),
            (CoSignScope::DEPOSITS, true),
            (CoSignScope::TRANSFERS, true),
        ] {
            let configured = configured(scope);
            assert_eq!(check(Some(&configured), None, approval).is_err(), required);
            assert!(check(Some(&configured), Some(SIGNER), approval).is_ok());
            assert!(check(Some(&configured), Some(Address::default()), approval).is_err());
        }
    }

    #[test]
    fn a_different_owner_charges_the_payment_and_uses_a_strict_nonzero_threshold() {
        for (threshold, amount, required) in [(10, 10, false), (10, 11, true), (0, u64::MAX, false)]
        {
            let rules = limits(u64::MAX, threshold);
            assert_eq!(approval(SOL_MINT, amount, Some(&rules)).unwrap(), required);
        }
        assert!(!approval(SOL_MINT, u64::MAX, None).unwrap());
    }

    #[test]
    fn the_program_code_the_submission_retries_on_is_pinned() {
        use custom_ring_interface::CustomRingError;
        assert_eq!(CustomRingError::StaleMemberRegistryRoot as u32, 8161);
    }
}
