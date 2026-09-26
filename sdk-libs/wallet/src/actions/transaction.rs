use std::collections::BTreeSet;
use zolana_client::timing;

use solana_pubkey::Pubkey;
use zolana_interface::{
    pda, shape::Shape, MAX_INPUT_TREES, MAX_INTERFACE_TRANSFERS, SPL_TOKEN_2022_PROGRAM_ID,
    SPL_TOKEN_PROGRAM_ID,
};
use zolana_keypair::{
    shielded::ShieldedAddress, viewing_key::ViewTag, NullifierKey, ShieldedKeypair,
};
use zolana_program::instruction::{
    TransactInterfaceTransferAccounts, TransactSolTransferAccounts, TransactSplWithdrawalAccounts,
};
use zolana_transaction::{
    instructions::{
        merge::{MergeProofInputs, MergeTransaction, MAX_MERGE_INPUTS, MERGE_DEFAULT_INPUT_COUNT},
        transact::{auto_shapes, ConfidentialTransaction, SettlementTarget, SppProofInputs},
    },
    keys::LocalShieldedKeys,
    Address, TransactionError, WalletUtxo, SOL_MINT,
};

use crate::wallet::Wallet;

use solana_message::VersionedMessage;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;

use crate::{
    user_registry::{try_resolve_registered_address, try_resolve_registered_address_async},
    wallet_authority::{ApprovalRequest, SyncWalletAuthority, WalletAuthority},
};
use zolana_client::{
    client::ZolanaClient,
    error::ClientError,
    rpc::{sign_transaction, AsyncRpc, Rpc},
    SignedPrivateTransaction,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedAddress {
    pub owner: Pubkey,
    pub address: ShieldedAddress,
    pub view_tag: ViewTag,
}

#[derive(Clone)]
pub struct CreatedTransfer {
    pub transaction: UnsignedPrivateTransaction,
    pub recipient: TransferRecipient,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransferRecipient {
    Registered(ResolvedAddress),
    PublicWithdrawal {
        recipient: Pubkey,
        settlement_transfers: Vec<TransactInterfaceTransferAccounts>,
    },
}

impl TransferRecipient {
    pub fn pubkey(&self) -> Pubkey {
        match self {
            Self::Registered(recipient) => recipient.owner,
            Self::PublicWithdrawal { recipient, .. } => *recipient,
        }
    }

    pub fn is_public_withdrawal(&self) -> bool {
        matches!(self, Self::PublicWithdrawal { .. })
    }

    pub fn settlement_transfers(&self) -> &[TransactInterfaceTransferAccounts] {
        match self {
            Self::Registered(_) => &[],
            Self::PublicWithdrawal {
                settlement_transfers,
                ..
            } => settlement_transfers,
        }
    }
}

#[derive(Clone)]
pub struct CreatedWithdrawal {
    pub transaction: UnsignedPrivateTransaction,
    pub settlement_transfers: Vec<TransactInterfaceTransferAccounts>,
}

#[derive(Clone)]
pub struct UnsignedPrivateTransaction {
    payer: Address,
    tree: Address,
    inputs: Vec<WalletUtxo>,
    action: PrivateTransactionAction,
    settlement_transfers: Vec<TransactInterfaceTransferAccounts>,
    approval_summary: String,
}

impl UnsignedPrivateTransaction {
    pub fn payer(&self) -> Address {
        self.payer
    }

    pub fn tree(&self) -> Address {
        self.tree
    }

    pub fn input_count(&self) -> usize {
        self.inputs.len()
    }

    pub fn settlement_transfers(&self) -> &[TransactInterfaceTransferAccounts] {
        &self.settlement_transfers
    }
}

#[derive(Clone)]
enum PrivateTransactionAction {
    Transfer {
        recipient: ShieldedAddress,
        asset: Address,
        amount: u64,
    },
    Withdrawal {
        legs: Vec<UnsignedWithdrawalLeg>,
    },
    Split {
        asset: Address,
        num_outputs: u8,
        per_output_amount: u64,
    },
}

#[derive(Clone, Copy)]
struct UnsignedWithdrawalLeg {
    asset: Address,
    amount: u64,
    target: SettlementTarget,
}

pub struct TransferParams<'a, R> {
    pub rpc: &'a R,
    pub wallet: &'a Wallet,
    pub payer: Address,
    pub recipient: Pubkey,
    pub asset: Address,
    pub amount: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WithdrawalLeg {
    pub recipient: Pubkey,
    pub asset: Address,
    pub amount: u64,
    /// SPL Token or Token-2022 program for non-SOL assets.
    pub spl_token_program: Option<Pubkey>,
}

pub struct WithdrawalParams<'a> {
    pub wallet: &'a Wallet,
    pub payer: Address,
    pub legs: Vec<WithdrawalLeg>,
}

pub async fn create_transfer<R: AsyncRpc>(
    request: TransferParams<'_, R>,
) -> Result<CreatedTransfer, ClientError> {
    let recipient = try_resolve_registered_address_async(request.rpc, request.recipient).await?;
    let spl_token_program = if recipient.is_none() {
        resolve_asset_token_program_async(request.rpc, request.asset).await?
    } else {
        None
    };
    create_transfer_with_recipient(request, recipient, spl_token_program)
}

pub fn create_transfer_sync<R: Rpc>(
    request: TransferParams<'_, R>,
) -> Result<CreatedTransfer, ClientError> {
    let recipient = {
        let _t = timing::Phase::start("resolve_recipient", 0);
        try_resolve_registered_address(request.rpc, request.recipient)?
    };
    let spl_token_program = if recipient.is_none() {
        resolve_asset_token_program(request.rpc, request.asset)?
    } else {
        None
    };
    create_transfer_with_recipient(request, recipient, spl_token_program)
}

fn create_transfer_with_recipient<R>(
    request: TransferParams<'_, R>,
    recipient: Option<ResolvedAddress>,
    spl_token_program: Option<Pubkey>,
) -> Result<CreatedTransfer, ClientError> {
    let tree = resolve_spend_tree(request.wallet, request.asset, is_default_ring_spendable)?;
    let Some(recipient) = recipient else {
        let withdrawal = create_withdrawal(WithdrawalParams {
            wallet: request.wallet,
            payer: request.payer,
            legs: vec![WithdrawalLeg {
                recipient: request.recipient,
                asset: request.asset,
                amount: request.amount,
                spl_token_program,
            }],
        })?;
        return Ok(CreatedTransfer {
            transaction: withdrawal.transaction,
            recipient: TransferRecipient::PublicWithdrawal {
                recipient: request.recipient,
                settlement_transfers: withdrawal.settlement_transfers,
            },
        });
    };
    let inputs = select_inputs(
        request.wallet,
        &[tree],
        request.asset,
        request.amount,
        is_default_ring_spendable,
    )?;
    Ok(CreatedTransfer {
        transaction: UnsignedPrivateTransaction {
            payer: request.payer,
            tree,
            inputs,
            action: PrivateTransactionAction::Transfer {
                recipient: recipient.address,
                asset: request.asset,
                amount: request.amount,
            },
            settlement_transfers: Vec::new(),
            approval_summary: format!(
                "private transaction transfer of {} to {}",
                request.amount, request.recipient
            ),
        },
        recipient: TransferRecipient::Registered(recipient),
    })
}

async fn resolve_asset_token_program_async<R: AsyncRpc + ?Sized>(
    rpc: &R,
    asset: Address,
) -> Result<Option<Pubkey>, ClientError> {
    if asset == SOL_MINT {
        return Ok(None);
    }
    let mint = Pubkey::new_from_array(asset.to_bytes());
    let account = rpc
        .get_account(Address::new_from_array(mint.to_bytes()))
        .await?
        .ok_or(ClientError::AccountNotFound {
            address: mint.to_bytes(),
        })?;
    Ok(Some(validate_token_program_owner(mint, account.owner)?))
}

fn resolve_asset_token_program<R: Rpc + ?Sized>(
    rpc: &R,
    asset: Address,
) -> Result<Option<Pubkey>, ClientError> {
    if asset == SOL_MINT {
        return Ok(None);
    }
    let mint = Pubkey::new_from_array(asset.to_bytes());
    let account = rpc
        .get_account(Address::new_from_array(mint.to_bytes()))?
        .ok_or(ClientError::AccountNotFound {
            address: mint.to_bytes(),
        })?;
    Ok(Some(validate_token_program_owner(mint, account.owner)?))
}

fn validate_token_program_owner(mint: Pubkey, owner: Pubkey) -> Result<Pubkey, ClientError> {
    if owner == Pubkey::new_from_array(SPL_TOKEN_PROGRAM_ID)
        || owner == Pubkey::new_from_array(SPL_TOKEN_2022_PROGRAM_ID)
    {
        Ok(owner)
    } else {
        Err(ClientError::UnsupportedSplTokenProgram { mint, owner })
    }
}

pub fn create_withdrawal(request: WithdrawalParams<'_>) -> Result<CreatedWithdrawal, ClientError> {
    validate_withdrawal_legs(&request.legs)?;
    let required = aggregate_withdrawal_amounts(&request.legs)?;
    let (tree, inputs) = select_withdrawal_inputs(request.wallet, &required)?;
    let mut action_legs = Vec::with_capacity(request.legs.len());
    let mut settlement_transfers = Vec::with_capacity(request.legs.len());
    for leg in &request.legs {
        let (target, accounts) =
            withdrawal_target(leg.recipient, leg.asset, leg.spl_token_program)?;
        action_legs.push(UnsignedWithdrawalLeg {
            asset: leg.asset,
            amount: leg.amount,
            target,
        });
        settlement_transfers.push(accounts);
    }
    let approval_summary = request
        .legs
        .iter()
        .map(|leg| format!("{} to {}", leg.amount, leg.recipient))
        .collect::<Vec<_>>()
        .join(", ");
    Ok(CreatedWithdrawal {
        transaction: UnsignedPrivateTransaction {
            payer: request.payer,
            tree,
            inputs,
            action: PrivateTransactionAction::Withdrawal { legs: action_legs },
            settlement_transfers: settlement_transfers.clone(),
            approval_summary: format!("private transaction withdrawal of {approval_summary}"),
        },
        settlement_transfers,
    })
}

#[derive(Clone)]
pub struct CreatedSplit {
    pub transaction: UnsignedPrivateTransaction,
    pub num_outputs: u8,
    pub per_output_amount: u64,
}

pub struct SplitParams<'a> {
    pub wallet: &'a Wallet,
    pub payer: Address,
    pub asset: Address,
    pub parts: u8,
    pub input: Option<[u8; 32]>,
}

/// Build a 1-input -> N-output self-split: spend one plain utxo and re-mint it
/// as `parts` equal self-owned utxos. The input utxo is chosen by explicit
/// commitment hash or, when omitted, as the largest unspent plain utxo of the
/// asset on the single spend tree. The utxo must be plain (no ring binding, no
/// attached data) and its amount evenly divisible into `parts`.
pub fn create_split(request: SplitParams<'_>) -> Result<CreatedSplit, ClientError> {
    // A split re-mints into 2..=8 equal utxos. Reject an out-of-range arity up
    // front so a direct SDK caller gets a clear error before utxo selection;
    let max_parts = Shape::IN1_OUT8.n_outputs() as u8;
    if !(2..=max_parts).contains(&request.parts) {
        return Err(TransactionError::UnsupportedShape {
            n_in: 1,
            n_out: usize::from(request.parts),
        }
        .into());
    }
    let tree = match request.input {
        Some(hash) => named_input_tree(request.wallet, request.asset, hash)?,
        None => resolve_spend_tree(request.wallet, request.asset, is_plain_utxo)?,
    };

    let (input, per_output_amount) = select_split_utxo(
        request.wallet,
        tree,
        request.asset,
        request.parts,
        request.input,
    )?;
    let num_outputs = request.parts;
    Ok(CreatedSplit {
        transaction: UnsignedPrivateTransaction {
            payer: request.payer,
            tree,
            inputs: vec![input],
            action: PrivateTransactionAction::Split {
                asset: request.asset,
                num_outputs,
                per_output_amount,
            },
            settlement_transfers: Vec::new(),
            approval_summary: format!(
                "private transaction split into {num_outputs} utxos of {per_output_amount}"
            ),
        },
        num_outputs,
        per_output_amount,
    })
}

/// Select and validate the single input utxo a split spends, returning it with
/// the per-output amount. Rejects utxos carrying ring bindings or data, and
/// amounts that do not divide evenly into `parts`.
fn select_split_utxo(
    wallet: &Wallet,
    tree: Address,
    asset: Address,
    parts: u8,
    input: Option<[u8; 32]>,
) -> Result<(WalletUtxo, u64), ClientError> {
    let parts_u64 = u64::from(parts);
    let candidate = match input {
        Some(hash) => {
            let entry = wallet
                .unspent()
                .find(|entry| entry.utxo.asset.asset == asset && entry.utxo_hash == hash)
                .ok_or(ClientError::InputUtxoUnavailable { hash })?;
            // The utxo exists but lives on another tree: report the mismatch
            // rather than "unavailable", which the owner can see is untrue in
            // their own `wallet utxos` listing.
            if pda::tree(entry.tree_id()) != tree {
                return Err(ClientError::InputUtxoTreeMismatch {
                    hash,
                    utxo_tree: pda::tree(entry.tree_id()),
                    spend_tree: tree,
                });
            }
            entry
        }
        None => {
            // Auto-select the largest plain utxo that divides evenly into
            // `parts`. Track the largest plain candidate separately so a wallet
            // whose plain utxos exist but none divide reports the divisibility
            // problem, not a misleading "no balance".
            let mut largest_plain: Option<&WalletUtxo> = None;
            let mut largest_divisible: Option<&WalletUtxo> = None;
            for entry in wallet.unspent().filter(|entry| {
                entry.utxo.asset.asset == asset
                    && pda::tree(entry.tree_id()) == tree
                    // Apply the full eligibility predicate before picking the
                    // largest, so a large ring-bound or data-carrying utxo never
                    // shadows a smaller plain candidate that could actually split.
                    && is_plain_utxo(entry)
            }) {
                if largest_plain.is_none_or(|best| entry.utxo.amount > best.utxo.amount) {
                    largest_plain = Some(entry);
                }
                if parts_u64 != 0
                    && entry.utxo.amount % parts_u64 == 0
                    && largest_divisible.is_none_or(|best| entry.utxo.amount > best.utxo.amount)
                {
                    largest_divisible = Some(entry);
                }
            }
            match (largest_divisible, largest_plain) {
                (Some(entry), _) => entry,
                (None, Some(entry)) => {
                    return Err(ClientError::SplitNotDivisible {
                        amount: entry.utxo.amount,
                        parts,
                    })
                }
                (None, None) => {
                    return Err(ClientError::InsufficientBalance {
                        requested: 1,
                        available: 0,
                    })
                }
            }
        }
    };

    let hash = candidate.utxo_hash;
    if candidate.utxo.ring_program_id.is_some() {
        return Err(ClientError::SplitInputRingMismatch { hash });
    }
    if !is_plain_utxo(candidate) {
        return Err(ClientError::SplitInputHasData { hash });
    }

    let amount = candidate.utxo.amount;
    if parts == 0 || amount % parts_u64 != 0 {
        return Err(ClientError::SplitNotDivisible { amount, parts });
    }

    Ok((candidate.clone(), amount / parts_u64))
}

/// A prepared merge plus what a caller needs to report the outcome: how many real
/// utxos are consolidated, their summed amount, and the single spend tree the
/// merge binds.
pub struct CreatedMerge {
    pub prepared: MergeProofInputs,
    pub num_inputs: usize,
    pub merged_amount: u64,
    pub tree: Address,
}

pub struct MergeParams<'a> {
    pub wallet: &'a Wallet,
    pub keypair: &'a ShieldedKeypair,
    pub asset: Address,
    /// Explicit input utxo commitment hashes, or `None` to auto-sweep the wallet's
    /// smallest plain utxos of `asset`.
    pub inputs: Option<Vec<[u8; 32]>>,
}

/// Build an n-in/1-out consolidation of same-owner, same-asset plain utxos on
/// one spend tree, padded to the smallest supported merge shape (auto-sweeps
/// stay within the default shape; named inputs may reach the wide one). Unlike
/// a transfer, merge proves ownership in-circuit from
/// the keypair's nullifier secret and encrypts the single output to the owner's
/// viewing key, so it does not build an [`UnsignedPrivateTransaction`] or take an
/// authority signing step; the keypair is threaded straight to submission.
pub fn create_merge(request: MergeParams<'_>) -> Result<CreatedMerge, ClientError> {
    // Explicitly named inputs bind the spend to the first named utxo's tree
    // (the rest must match it), so `MergeTransaction::new` can report precise per-input
    // reasons; auto-sweep resolves the tree over the eligible (plain) utxos.
    let tree = match request.inputs.as_ref().and_then(|hashes| hashes.first()) {
        Some(&hash) => named_input_tree(request.wallet, request.asset, hash)?,
        None => resolve_spend_tree(request.wallet, request.asset, is_plain_utxo)?,
    };
    let inputs = select_merge_inputs(request.wallet, tree, request.asset, request.inputs)?;
    let num_inputs = inputs.len();
    // Finalize the output and padding before fetching proofs.
    let prepared = MergeTransaction::new(inputs)?.encrypt(request.keypair)?;
    Ok(CreatedMerge {
        merged_amount: prepared.output_utxo.amount,
        prepared,
        num_inputs,
        tree,
    })
}

pub struct SpendInputParams<'a> {
    pub wallet: &'a Wallet,
    pub asset: Address,
    pub amount: u64,
}

/// Inputs are grouped by tree in first-use order. `trees` contains exactly those
/// trees, in the same order as the input groups.
pub struct SelectedSpendInputs {
    pub inputs: Vec<WalletUtxo>,
    pub trees: Vec<Address>,
}

/// Default-ring notes only, a ring entry spends them through
/// `CustomRingTransfer`.
pub async fn select_input_utxos<A: WalletAuthority + ?Sized>(
    request: SpendInputParams<'_>,
    authority: &A,
) -> Result<SelectedSpendInputs, ClientError> {
    let (trees, inputs) = unsigned_input_utxos(request)?;
    let nullifier_key = authority.spend_nullifier_key().await?;
    Ok(SelectedSpendInputs {
        inputs: validate_input_keys(inputs, nullifier_key)?,
        trees,
    })
}

pub fn select_input_utxos_sync<A: SyncWalletAuthority + ?Sized>(
    request: SpendInputParams<'_>,
    authority: &A,
) -> Result<SelectedSpendInputs, ClientError> {
    let (trees, inputs) = unsigned_input_utxos(request)?;
    let nullifier_key = authority.spend_nullifier_key()?;
    Ok(SelectedSpendInputs {
        inputs: validate_input_keys(inputs, nullifier_key)?,
        trees,
    })
}

fn unsigned_input_utxos(
    request: SpendInputParams<'_>,
) -> Result<(Vec<Address>, Vec<WalletUtxo>), ClientError> {
    // Mirrors the TS eligibility, a default note carrying ring data proves on
    // no rail.
    let eligible =
        |entry: &WalletUtxo| is_default_ring_spendable(entry) && entry.ring_data_hash.is_none();
    let mut selected =
        select_bounded_inputs(request.wallet, request.asset, request.amount, eligible)?;
    let mut trees = Vec::new();
    for entry in &selected {
        if !trees.contains(&pda::tree(entry.tree_id())) {
            trees.push(pda::tree(entry.tree_id()));
        }
    }
    if trees.len() > MAX_INPUT_TREES {
        return Err(ClientError::AmbiguousTree {
            asset: request.asset,
            tree_count: trees.len(),
        });
    }
    selected.sort_by_key(|entry| {
        trees
            .iter()
            .position(|tree| *tree == pda::tree(entry.tree_id()))
    });
    let inputs = selected.into_iter().cloned().collect();
    Ok((trees, inputs))
}

/// Largest first, a fragmented balance covers with the fewest notes. Candidates
/// come from every eligible tree, so a balance that straddles a tree rollover
/// still covers. Tree limits apply to the selected notes.
fn select_bounded_inputs(
    wallet: &Wallet,
    asset: Address,
    amount: u64,
    eligible: impl Fn(&WalletUtxo) -> bool,
) -> Result<Vec<&WalletUtxo>, ClientError> {
    // Zero selects a note whose whole change would cross the ring boundary.
    if amount == 0 {
        return Err(ClientError::ZeroSpendAmount);
    }
    let max_inputs = auto_shapes()
        .map(|shape| shape.n_inputs())
        .max()
        .unwrap_or(0);
    let mut candidates: Vec<&WalletUtxo> = wallet
        .unspent()
        .filter(|entry| entry.utxo.asset.asset == asset && eligible(entry))
        .collect();
    candidates.sort_by_key(|entry| std::cmp::Reverse(entry.utxo.amount));
    let mut total = 0u64;
    for entry in &candidates {
        total = total
            .checked_add(entry.utxo.amount)
            .ok_or(ClientError::SelectedBalanceOverflow)?;
    }
    let mut selected = Vec::new();
    let mut available = 0u64;
    for entry in candidates.iter().copied().take(max_inputs) {
        selected.push(entry);
        available += entry.utxo.amount;
        if available >= amount {
            return Ok(selected);
        }
    }
    if total >= amount {
        return Err(ClientError::TooManyInputs {
            got: candidates.len(),
            max: max_inputs,
        });
    }
    Err(ClientError::InsufficientBalance {
        requested: amount,
        available: total,
    })
}

fn validate_input_keys(
    inputs: Vec<WalletUtxo>,
    nullifier_key: NullifierKey,
) -> Result<Vec<WalletUtxo>, ClientError> {
    let public_key = nullifier_key.pubkey()?;
    for (index, input) in inputs.iter().enumerate() {
        if input.nullifier_pubkey != public_key
            || nullifier_key.nullifier(&input.utxo_hash, &input.utxo.blinding)? != input.nullifier
        {
            return Err(ClientError::InputNullifierMismatch { index });
        }
    }
    Ok(inputs)
}

/// A ring-bound utxo's commitment covers its ring, the default-ring circuit
/// does not.
pub fn is_default_ring_spendable(entry: &WalletUtxo) -> bool {
    entry.utxo.ring_program_id.is_none()
}

/// Whether a wallet utxo is plain: no ring binding and no attached data. Only
/// plain utxos are mergeable or splittable; building a spend input drops the
/// utxo's committed data hashes, which would desync the commitment from the tree
/// otherwise. Option semantics: a `Some(_)` hash counts as data regardless of the
/// hash value. Public so the CLI's `utxos` listing classifies `kind` with the
/// exact predicate split/merge enforce, and the two cannot drift.
pub fn is_plain_utxo(entry: &WalletUtxo) -> bool {
    is_default_ring_spendable(entry)
        && entry.ring_data_hash.is_none()
        && entry.data_hash.is_none()
        && entry.utxo.data.is_empty()
}

/// Select the utxos a merge consolidates on `tree`. `None` auto-sweeps up to
/// [`MERGE_DEFAULT_INPUT_COUNT`] of the smallest plain utxos of `asset`
/// (ascending, dust first), so a sweep never pays for the wide shape on its
/// own. `Some(hashes)` takes exactly the named utxos: 2..=[`MAX_MERGE_INPUTS`]
/// distinct, unspent utxos of `asset` on `tree`, and `MergeTransaction::new` pads them to
/// the smallest supported shape; a non-plain named utxo is left for
/// `MergeTransaction::new` to reject with a precise reason.
fn select_merge_inputs(
    wallet: &Wallet,
    tree: Address,
    asset: Address,
    inputs: Option<Vec<[u8; 32]>>,
) -> Result<Vec<WalletUtxo>, ClientError> {
    match inputs {
        None => {
            let mut candidates: Vec<&WalletUtxo> = wallet
                .unspent()
                .filter(|entry| {
                    entry.utxo.asset.asset == asset
                        && pda::tree(entry.tree_id()) == tree
                        && is_plain_utxo(entry)
                })
                .collect();
            // Smallest first: a sweep clears dust and leaves large utxos intact.
            candidates.sort_by_key(|entry| entry.utxo.amount);
            candidates.truncate(MERGE_DEFAULT_INPUT_COUNT);
            if candidates.len() < 2 {
                return Err(ClientError::NothingToMerge { asset });
            }
            candidates
                .into_iter()
                .map(|entry| Ok(entry.clone()))
                .collect()
        }
        Some(hashes) => {
            if hashes.len() > MAX_MERGE_INPUTS {
                return Err(ClientError::TooManyInputs {
                    got: hashes.len(),
                    max: MAX_MERGE_INPUTS,
                });
            }
            if hashes.len() < 2 {
                return Err(ClientError::NothingToMerge { asset });
            }
            let mut seen = BTreeSet::new();
            let mut selected = Vec::with_capacity(hashes.len());
            for hash in hashes {
                if !seen.insert(hash) {
                    return Err(ClientError::DuplicateInputUtxo { hash });
                }
                let entry = wallet
                    .unspent()
                    .find(|entry| entry.utxo.asset.asset == asset && entry.utxo_hash == hash)
                    .ok_or(ClientError::InputUtxoUnavailable { hash })?;
                // Distinguish a wrong-tree utxo from an unknown one; the owner
                // can see the hash in their own `wallet utxos` listing.
                if pda::tree(entry.tree_id()) != tree {
                    return Err(ClientError::InputUtxoTreeMismatch {
                        hash,
                        utxo_tree: pda::tree(entry.tree_id()),
                        spend_tree: tree,
                    });
                }
                selected.push(entry.clone());
            }
            Ok(selected)
        }
    }
}

/// Build the unsigned v1 message for a private transaction, for a signer that
/// holds the fee-payer key elsewhere (an HSM or a custodian).
pub async fn build_private_transaction<A: WalletAuthority + ?Sized, R: AsyncRpc>(
    transaction: UnsignedPrivateTransaction,
    wallet: &Wallet,
    authority: &A,
    client: &ZolanaClient<R>,
    fee_payer: Pubkey,
) -> Result<VersionedMessage, ClientError> {
    let shielded = sign_shielded_transaction(transaction, wallet, authority).await?;
    let nullifier_key = authority.spend_nullifier_key().await?;
    let (blockhash, _) = client.rpc().get_latest_blockhash().await?;
    client
        .finish_submission_unsigned(&shielded, fee_payer, blockhash, &nullifier_key)
        .await
}

pub async fn sign_private_transaction<A: WalletAuthority + ?Sized, R: AsyncRpc>(
    transaction: UnsignedPrivateTransaction,
    wallet: &Wallet,
    authority: &A,
    client: &ZolanaClient<R>,
    fee_payer: &dyn Signer,
) -> Result<VersionedTransaction, ClientError> {
    sign_private_transaction_with_signers(transaction, wallet, authority, client, fee_payer, &[])
        .await
}

/// Build and sign a private transaction with the fee payer and any additional
/// native Ed25519 input owners committed by the shielded proof.
pub async fn sign_private_transaction_with_signers<A: WalletAuthority + ?Sized, R: AsyncRpc>(
    transaction: UnsignedPrivateTransaction,
    wallet: &Wallet,
    authority: &A,
    client: &ZolanaClient<R>,
    fee_payer: &dyn Signer,
    additional_native_signers: &[&dyn Signer],
) -> Result<VersionedTransaction, ClientError> {
    let blockhash = client.rpc().get_latest_blockhash().await?.0;
    let shielded = sign_shielded_transaction(transaction, wallet, authority).await?;
    let nullifier_key = authority.spend_nullifier_key().await?;
    let message = client
        .finish_submission_unsigned(&shielded, fee_payer.pubkey(), blockhash, &nullifier_key)
        .await?;
    sign_transaction(
        message,
        &native_signers(fee_payer, additional_native_signers),
    )
}

/// Build the unsigned v1 message for a private transaction, for a signer that
/// holds the fee-payer key elsewhere (an HSM or a custodian).
pub fn build_private_transaction_sync<A: SyncWalletAuthority + ?Sized, R: Rpc + Sync>(
    transaction: UnsignedPrivateTransaction,
    wallet: &Wallet,
    authority: &A,
    client: &ZolanaClient<R>,
    fee_payer: Pubkey,
) -> Result<VersionedMessage, ClientError> {
    let shielded = sign_shielded_transaction_sync(transaction, wallet, authority)?;
    let nullifier_key = authority.spend_nullifier_key()?;
    client.finish_submission_unsigned_sync(&shielded, fee_payer, &nullifier_key)
}

pub fn sign_private_transaction_sync<A: SyncWalletAuthority + ?Sized, R: Rpc + Sync>(
    transaction: UnsignedPrivateTransaction,
    wallet: &Wallet,
    authority: &A,
    client: &ZolanaClient<R>,
    fee_payer: &dyn Signer,
) -> Result<VersionedTransaction, ClientError> {
    sign_private_transaction_sync_with_signers(
        transaction,
        wallet,
        authority,
        client,
        fee_payer,
        &[],
    )
}

/// Synchronous counterpart of [`sign_private_transaction_with_signers`].
pub fn sign_private_transaction_sync_with_signers<
    A: SyncWalletAuthority + ?Sized,
    R: Rpc + Sync,
>(
    transaction: UnsignedPrivateTransaction,
    wallet: &Wallet,
    authority: &A,
    client: &ZolanaClient<R>,
    fee_payer: &dyn Signer,
    additional_native_signers: &[&dyn Signer],
) -> Result<VersionedTransaction, ClientError> {
    let shielded = {
        let _t = timing::Phase::start("sign_shielded", 0);
        sign_shielded_transaction_sync(transaction, wallet, authority)?
    };
    // The message carries its own blockhash, fetched after proving, so there is
    // no separate one here to keep in step with it.
    let nullifier_key = authority.spend_nullifier_key()?;
    let message = {
        let _t = timing::Phase::start("finish_submission", 0);
        client.finish_submission_unsigned_sync(&shielded, fee_payer.pubkey(), &nullifier_key)?
    };
    sign_transaction(
        message,
        &native_signers(fee_payer, additional_native_signers),
    )
}

fn native_signers<'a>(
    fee_payer: &'a dyn Signer,
    additional_native_signers: &[&'a dyn Signer],
) -> Vec<&'a dyn Signer> {
    let mut signers = Vec::with_capacity(1 + additional_native_signers.len());
    signers.push(fee_payer);
    signers.extend_from_slice(additional_native_signers);
    signers
}

#[doc(hidden)]
pub async fn sign_shielded_transaction<A: WalletAuthority + ?Sized>(
    transaction: UnsignedPrivateTransaction,
    wallet: &Wallet,
    authority: &A,
) -> Result<SignedPrivateTransaction, ClientError> {
    validate_unsigned_inputs(wallet, transaction.tree, &transaction.inputs)?;
    let address = authority.shielded_address().await?;
    let nullifier_key = authority.spend_nullifier_key().await?;
    let inputs = validate_input_keys(transaction.inputs, nullifier_key)?;
    let mut tx = ConfidentialTransaction::new(inputs, transaction.payer)?;
    match transaction.action {
        PrivateTransactionAction::Transfer {
            recipient,
            asset,
            amount,
        } => {
            if asset == SOL_MINT {
                tx.transfer_sol(&recipient, amount)?;
            } else {
                tx.transfer(&recipient, asset, amount)?;
            }
        }
        PrivateTransactionAction::Withdrawal { legs } => {
            for leg in legs {
                match leg.target {
                    SettlementTarget::Sol { user_sol_account } => {
                        tx.withdraw_sol(leg.amount, user_sol_account)?;
                    }
                    SettlementTarget::Spl { user_spl_token } => {
                        tx.withdraw(leg.asset, leg.amount, user_spl_token)?;
                    }
                }
            }
        }
        PrivateTransactionAction::Split {
            asset,
            num_outputs,
            per_output_amount,
        } => {
            for _ in 0..num_outputs {
                if asset == SOL_MINT {
                    tx.transfer_sol(&address, per_output_amount)?;
                } else {
                    tx.transfer(&address, asset, per_output_amount)?;
                }
            }
        }
    }
    let signed = encrypt_transaction(tx, authority, transaction.approval_summary).await?;
    Ok(SignedPrivateTransaction {
        transaction: signed,
        settlement_transfers: transaction.settlement_transfers,
    })
}

#[doc(hidden)]
pub fn sign_shielded_transaction_sync<A: SyncWalletAuthority + ?Sized>(
    transaction: UnsignedPrivateTransaction,
    wallet: &Wallet,
    authority: &A,
) -> Result<SignedPrivateTransaction, ClientError> {
    futures::executor::block_on(sign_shielded_transaction(transaction, wallet, authority))
}

/// Resolves the smallest shape that fits the real inputs and `n_outputs`, pads
/// the input slots up to it, and opens the transaction on it. The shape is fixed
/// before the inputs are, because the supported set is not a product set.
async fn encrypt_transaction<A: WalletAuthority + ?Sized>(
    transaction: ConfidentialTransaction,
    authority: &A,
    approval_summary: String,
) -> Result<SppProofInputs, ClientError> {
    // The per-transaction viewing key is taken through the key port, so the
    // encryption reads no long-lived secret of its own.
    let keys = LocalShieldedKeys::new(
        authority.shielded_address().await?,
        authority.viewing_keys().await?,
        authority.spend_nullifier_key().await?,
    )?;
    authority
        .request_user_approval(ApprovalRequest {
            solana_pubkey: authority.solana_pubkey(),
            summary: approval_summary,
        })
        .await?;
    Ok(transaction.encrypt(&keys)?)
}

fn withdrawal_target(
    recipient: Pubkey,
    asset: Address,
    spl_token_program: Option<Pubkey>,
) -> Result<(SettlementTarget, TransactInterfaceTransferAccounts), ClientError> {
    if asset == SOL_MINT {
        return Ok((
            SettlementTarget::Sol {
                user_sol_account: Address::new_from_array(recipient.to_bytes()),
            },
            TransactInterfaceTransferAccounts::Sol(TransactSolTransferAccounts { recipient }),
        ));
    }

    let mint = Pubkey::new_from_array(asset.to_bytes());
    let token_program = spl_token_program.ok_or(ClientError::MissingSplTokenProgram { mint })?;
    let user_spl_token =
        pda::associated_token_address_with_program(&recipient, &mint, &token_program);
    let vault = pda::spl_interface(&mint);
    Ok((
        SettlementTarget::Spl {
            user_spl_token: Address::new_from_array(user_spl_token.to_bytes()),
        },
        TransactInterfaceTransferAccounts::SplWithdrawal(TransactSplWithdrawalAccounts {
            mint,
            spl_interface: vault,
            user_token_account: user_spl_token,
            token_program,
        }),
    ))
}

fn validate_withdrawal_legs(legs: &[WithdrawalLeg]) -> Result<(), ClientError> {
    if legs.is_empty() {
        return Err(TransactionError::NoInterfaceTransfers.into());
    }
    if legs.len() > MAX_INTERFACE_TRANSFERS {
        return Err(TransactionError::TooManyInterfaceTransfers {
            got: legs.len(),
            max: MAX_INTERFACE_TRANSFERS,
        }
        .into());
    }
    for leg in legs {
        if leg.amount == 0 {
            return Err(TransactionError::ZeroInterfaceTransferAmount.into());
        }
    }
    Ok(())
}

fn aggregate_withdrawal_amounts(
    legs: &[WithdrawalLeg],
) -> Result<Vec<(Address, u64)>, ClientError> {
    let mut required = Vec::<(Address, u64)>::new();
    for leg in legs {
        if let Some((_, amount)) = required.iter_mut().find(|(asset, _)| *asset == leg.asset) {
            *amount = amount
                .checked_add(leg.amount)
                .ok_or(ClientError::SelectedBalanceOverflow)?;
        } else {
            required.push((leg.asset, leg.amount));
        }
    }
    Ok(required)
}

fn select_withdrawal_inputs(
    wallet: &Wallet,
    required: &[(Address, u64)],
) -> Result<(Address, Vec<WalletUtxo>), ClientError> {
    let (first_asset, _) = required
        .first()
        .copied()
        .ok_or(TransactionError::NoInterfaceTransfers)?;
    let tree = resolve_spend_tree(wallet, first_asset, is_default_ring_spendable)?;
    let mut inputs = Vec::new();

    for (asset, amount) in required {
        let asset_tree = resolve_spend_tree(wallet, *asset, is_default_ring_spendable)?;
        if asset_tree != tree {
            let hash = wallet
                .unspent()
                .find(|entry| {
                    entry.utxo.asset.asset == *asset
                        && pda::tree(entry.tree_id()) == asset_tree
                        && is_default_ring_spendable(entry)
                })
                .map(|entry| entry.utxo_hash)
                .ok_or(ClientError::InsufficientBalance {
                    requested: *amount,
                    available: 0,
                })?;
            return Err(ClientError::InputUtxoTreeMismatch {
                hash,
                utxo_tree: asset_tree,
                spend_tree: tree,
            });
        }
        inputs.extend(select_inputs(
            wallet,
            &[tree],
            *asset,
            *amount,
            is_default_ring_spendable,
        )?);
    }

    Ok((tree, inputs))
}

/// The tree an explicitly named input binds the spend to: the named utxo's own
/// tree. Explicit selection needs no eligibility scan; the downstream per-input
/// checks report precise reasons for ineligible utxos.
fn named_input_tree(
    wallet: &Wallet,
    asset: Address,
    hash: [u8; 32],
) -> Result<Address, ClientError> {
    wallet
        .unspent()
        .find(|entry| entry.utxo.asset.asset == asset && entry.utxo_hash == hash)
        .map(|entry| pda::tree(entry.tree_id()))
        .ok_or(ClientError::InputUtxoUnavailable { hash })
}

/// The distinct pool trees holding eligible funds, in the order a spend
/// declares them. A transact spends from at most [`MAX_INPUT_TREES`] trees, so
/// a wider spread still needs the caller to name a tree. Each caller passes the
/// predicate its own input selection applies.
fn resolve_spend_trees(
    wallet: &Wallet,
    asset: Address,
    eligible: impl Fn(&WalletUtxo) -> bool,
) -> Result<Vec<Address>, ClientError> {
    let trees: BTreeSet<Address> = wallet
        .unspent()
        .filter(|entry| entry.utxo.asset.asset == asset && eligible(entry))
        .map(|entry| pda::tree(entry.tree_id()))
        .collect();

    if trees.is_empty() {
        return Err(ClientError::InsufficientBalance {
            requested: 1,
            available: 0,
        });
    }
    if trees.len() > MAX_INPUT_TREES {
        return Err(ClientError::AmbiguousTree {
            asset,
            tree_count: trees.len(),
        });
    }
    Ok(trees.into_iter().collect())
}

/// The one tree a single-tree action binds to. Splits spend one input, and the
/// transfer and withdrawal paths still pass one `input_tree` account, so they
/// ask the owner to name a tree rather than pick one.
fn resolve_spend_tree(
    wallet: &Wallet,
    asset: Address,
    eligible: impl Fn(&WalletUtxo) -> bool,
) -> Result<Address, ClientError> {
    match resolve_spend_trees(wallet, asset, eligible)?.as_slice() {
        [tree] => Ok(*tree),
        trees => Err(ClientError::AmbiguousTree {
            asset,
            tree_count: trees.len(),
        }),
    }
}

fn select_inputs(
    wallet: &Wallet,
    trees: &[Address],
    asset: Address,
    amount: u64,
    eligible: impl Fn(&WalletUtxo) -> bool,
) -> Result<Vec<WalletUtxo>, ClientError> {
    let mut selected = Vec::new();
    let mut available = 0u64;
    for entry in wallet.unspent().filter(|entry| {
        entry.utxo.asset.asset == asset
            && trees.contains(&pda::tree(entry.tree_id()))
            && eligible(entry)
    }) {
        selected.push(entry.clone());
        available = available
            .checked_add(entry.utxo.amount)
            .ok_or(ClientError::SelectedBalanceOverflow)?;
        if available >= amount {
            return Ok(selected);
        }
    }

    Err(ClientError::InsufficientBalance {
        requested: amount,
        available,
    })
}

fn validate_unsigned_inputs(
    wallet: &Wallet,
    tree: Address,
    inputs: &[WalletUtxo],
) -> Result<(), ClientError> {
    for (index, input) in inputs.iter().enumerate() {
        let available = wallet.unspent().any(|entry| {
            pda::tree(entry.tree_id()) == tree
                && entry.utxo_hash == input.utxo_hash
                && entry.nullifier == input.nullifier
                && entry.data_hash == input.data_hash
                && entry.ring_data_hash == input.ring_data_hash
                && entry.utxo == input.utxo
        });
        if !available {
            return Err(ClientError::UnsignedInputUnavailable { index });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use borsh::to_vec;
    use solana_account::Account;
    use solana_signature::Signature;
    use zolana_keypair::{ShieldedKeypair, SigningKey};
    use zolana_transaction::{
        instructions::transact::SettlementTransfer, AssetRegistry, Data, DataRecord, Utxo,
    };

    use zolana_user_registry_interface::{user_record_pda, user_registry_program_id, UserRecord};

    use super::*;

    struct MockRpc {
        account: Option<(Address, Account)>,
    }

    impl Rpc for MockRpc {
        fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
            Ok(self
                .account
                .as_ref()
                .and_then(|(expected, account)| (*expected == address).then(|| account.clone())))
        }
    }

    #[async_trait::async_trait]
    impl AsyncRpc for MockRpc {
        async fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
            Rpc::get_account(self, address)
        }
    }

    fn account_data(record: &UserRecord) -> Vec<u8> {
        let mut data = vec![UserRecord::DISCRIMINATOR];
        data.extend_from_slice(&to_vec(record).expect("serialize user record"));
        data.resize(UserRecord::SIZE, 0);
        data
    }

    fn wallet_with_sol(keypair: ShieldedKeypair, amount: u64) -> Wallet {
        wallet_with_asset(keypair, SOL_MINT, amount)
    }

    /// Test fixtures live in the first localnet tree.
    // TODO(tree-id): resolve the tree id from the tree account.
    const TEST_TREE_ID: u16 = 0;
    /// A second pool tree, for the cases about a balance that straddles one.
    const SECOND_TREE_ID: u16 = 9;
    const RING_TREE_ID: u16 = 9;

    /// The tree every seeded fixture UTXO is hashed under. Derived from the id,
    /// so it is the address sync would resolve back to that same id.
    fn test_tree() -> Address {
        pda::tree(TEST_TREE_ID)
    }

    /// Move a seeded UTXO into another tree.
    fn place_in_tree(wallet: &mut Wallet, hash: [u8; 32], tree_id: u16) {
        wallet
            .utxos
            .iter_mut()
            .find(|entry| entry.utxo_hash == hash)
            .expect("seeded utxo")
            .tree_id = tree_id;
    }

    /// Record a spend of the seeded UTXO at `hash`. The wallet derives `spent`
    /// from its nullifier set, so a test spends a note by publishing its
    /// nullifier, exactly as a sync would.
    fn mark_spent(wallet: &mut Wallet, hash: [u8; 32]) {
        let nullifier = wallet
            .utxos
            .iter()
            .find(|entry| entry.utxo_hash == hash)
            .expect("seeded utxo")
            .nullifier;
        wallet.nullifiers.insert(nullifier);
    }

    fn ed25519_keypair(seed: u8) -> ShieldedKeypair {
        ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32]))
            .expect("Ed25519 keypair")
    }

    fn wallet_with_asset(keypair: ShieldedKeypair, asset: Address, amount: u64) -> Wallet {
        let registry = if asset == SOL_MINT {
            AssetRegistry::default()
        } else {
            AssetRegistry::new([(2, asset)]).expect("asset registry")
        };
        let mut wallet = Wallet::new(
            keypair.shielded_address().expect("shielded address"),
            registry,
        )
        .expect("wallet");
        let mut blinding = [7u8; 32];
        blinding[0] = 0;
        let utxo = Utxo {
            owner: keypair.signing_pubkey(),
            asset: zolana_transaction::Mint {
                asset,
                asset_id: if asset == SOL_MINT { 1 } else { 2 },
            },
            amount,
            blinding,
            ring_program_id: None,
            data: Data::default(),
        };
        let nullifier_pk = keypair.nullifier_key.pubkey().expect("nullifier pubkey");
        let hash = utxo
            .hash(&nullifier_pk, &[0u8; 32], &[0u8; 32], TEST_TREE_ID)
            .expect("utxo hash");
        let nullifier = utxo
            .nullifier(&hash, &keypair.nullifier_key)
            .expect("nullifier");
        wallet.utxos.push(WalletUtxo {
            utxo,
            nullifier_pubkey: nullifier_pk,
            utxo_hash: hash,
            nullifier,
            data_hash: None,
            ring_data_hash: None,
            tree_id: TEST_TREE_ID,
            leaf_index: 0,

            slot: 0,
            tx_signature: Signature::default(),
            slot_index: 0,
        });
        wallet
    }

    fn withdrawal_error(result: Result<CreatedWithdrawal, ClientError>) -> ClientError {
        match result {
            Err(error) => error,
            Ok(_) => panic!("withdrawal was expected to fail"),
        }
    }

    #[test]
    fn create_transfer_sync_to_registered_recipient_builds_shielded_transfer() {
        let sender = ShieldedKeypair::new_p256().unwrap();
        let recipient = ShieldedKeypair::new_p256().unwrap();
        let owner = Pubkey::new_unique();
        let (record_pda, bump) = user_record_pda(&owner);
        let record = UserRecord {
            owner: owner.to_bytes().into(),
            bump,
            owner_p256: Some(*recipient.signing_pubkey().as_p256().unwrap().as_bytes()),
            nullifier_pubkey: recipient.nullifier_key.pubkey().unwrap(),
            viewing_pubkey: *recipient.viewing_pubkey().as_bytes(),
            merging_enabled: false,
        };
        let rpc = MockRpc {
            account: Some((
                Address::new_from_array(record_pda.to_bytes()),
                Account {
                    lamports: 1,
                    data: account_data(&record),
                    owner: user_registry_program_id(),
                    executable: false,
                    rent_epoch: 0,
                },
            )),
        };
        let wallet = wallet_with_sol(sender, 10);

        let result = create_transfer_sync(TransferParams {
            rpc: &rpc,
            wallet: &wallet,
            payer: Address::default(),
            recipient: owner,
            asset: SOL_MINT,
            amount: 1,
        })
        .expect("transfer");

        assert!(matches!(
            result.recipient,
            TransferRecipient::Registered(resolved) if resolved.owner == owner
        ));
        assert!(result.recipient.settlement_transfers().is_empty());
    }

    #[tokio::test]
    async fn create_transfer_resolves_registered_recipient() {
        let sender = ShieldedKeypair::new_p256().unwrap();
        let recipient = ShieldedKeypair::new_p256().unwrap();
        let owner = Pubkey::new_unique();
        let (record_pda, bump) = user_record_pda(&owner);
        let record = UserRecord {
            owner: owner.to_bytes().into(),
            bump,
            owner_p256: Some(*recipient.signing_pubkey().as_p256().unwrap().as_bytes()),
            nullifier_pubkey: recipient.nullifier_key.pubkey().unwrap(),
            viewing_pubkey: *recipient.viewing_pubkey().as_bytes(),
            merging_enabled: false,
        };
        let rpc = MockRpc {
            account: Some((
                Address::new_from_array(record_pda.to_bytes()),
                Account {
                    lamports: 1,
                    data: account_data(&record),
                    owner: user_registry_program_id(),
                    executable: false,
                    rent_epoch: 0,
                },
            )),
        };
        let wallet = wallet_with_sol(sender, 10);

        let result = create_transfer(TransferParams {
            rpc: &rpc,
            wallet: &wallet,
            payer: Address::default(),
            recipient: owner,
            asset: SOL_MINT,
            amount: 1,
        })
        .await
        .expect("async transfer");

        assert!(matches!(
            result.recipient,
            TransferRecipient::Registered(resolved) if resolved.owner == owner
        ));
    }

    #[test]
    fn create_transfer_sync_to_unregistered_recipient_builds_public_withdrawal() {
        let sender = ShieldedKeypair::new_p256().unwrap();
        let wallet = wallet_with_sol(sender.clone(), 10);
        let recipient = Pubkey::new_unique();
        let rpc = MockRpc { account: None };

        let result = create_transfer_sync(TransferParams {
            rpc: &rpc,
            wallet: &wallet,
            payer: Address::default(),
            recipient,
            asset: SOL_MINT,
            amount: 1,
        })
        .expect("public withdrawal fallback");

        assert!(matches!(
            result.recipient,
            TransferRecipient::PublicWithdrawal {
                recipient: pubkey,
                settlement_transfers,
            } if pubkey == recipient
                && settlement_transfers == vec![
                    TransactInterfaceTransferAccounts::Sol(TransactSolTransferAccounts {
                        recipient
                    })
                ]
        ));
    }

    #[test]
    fn create_transfer_sync_to_unregistered_recipient_builds_spl_public_withdrawal() {
        let sender = ShieldedKeypair::new_p256().unwrap();
        let mint = Pubkey::new_unique();
        let asset = Address::new_from_array(mint.to_bytes());
        let wallet = wallet_with_asset(sender.clone(), asset, 10);
        let rpc = MockRpc {
            account: Some((
                Address::new_from_array(mint.to_bytes()),
                Account {
                    lamports: 1,
                    data: Vec::new(),
                    owner: pda::spl_token_program_id(),
                    executable: false,
                    rent_epoch: 0,
                },
            )),
        };
        let recipient = Pubkey::new_unique();
        let token_account = pda::associated_token_address(&recipient, &mint);

        let result = create_transfer_sync(TransferParams {
            rpc: &rpc,
            wallet: &wallet,
            payer: Address::default(),
            recipient,
            asset,
            amount: 1,
        })
        .expect("public withdrawal fallback");

        assert_eq!(
            result.recipient.settlement_transfers(),
            &[TransactInterfaceTransferAccounts::SplWithdrawal(
                TransactSplWithdrawalAccounts {
                    mint,
                    spl_interface: pda::spl_interface(&mint),
                    user_token_account: token_account,
                    token_program: pda::spl_token_program_id(),
                }
            )]
        );
    }

    #[test]
    fn create_withdrawal_builds_spl_settlement_to_recipient_ata() {
        let sender = ShieldedKeypair::new_p256().unwrap();
        let mint = Pubkey::new_unique();
        let asset = Address::new_from_array(mint.to_bytes());
        let wallet = wallet_with_asset(sender.clone(), asset, 10);
        let recipient = Pubkey::new_unique();
        let token_account = pda::associated_token_address(&recipient, &mint);

        let result = create_withdrawal(WithdrawalParams {
            wallet: &wallet,
            payer: Address::default(),
            legs: vec![WithdrawalLeg {
                recipient,
                asset,
                amount: 1,
                spl_token_program: Some(zolana_interface::pda::spl_token_program_id()),
            }],
        })
        .expect("withdrawal");

        assert_eq!(
            result.settlement_transfers,
            vec![TransactInterfaceTransferAccounts::SplWithdrawal(
                TransactSplWithdrawalAccounts {
                    mint,
                    spl_interface: pda::spl_interface(&mint),
                    user_token_account: token_account,
                    token_program: pda::spl_token_program_id(),
                }
            )]
        );
    }

    #[test]
    fn create_withdrawal_rejects_invalid_count_and_zero_amounts() {
        let sender = ShieldedKeypair::new_p256().unwrap();
        let wallet = wallet_with_sol(sender, 10);
        let payer = Address::default();

        let empty = withdrawal_error(create_withdrawal(WithdrawalParams {
            wallet: &wallet,
            payer,
            legs: Vec::new(),
        }));
        assert!(matches!(
            empty,
            ClientError::Transaction(TransactionError::NoInterfaceTransfers)
        ));

        let too_many = withdrawal_error(create_withdrawal(WithdrawalParams {
            wallet: &wallet,
            payer,
            legs: (0..=MAX_INTERFACE_TRANSFERS)
                .map(|_| WithdrawalLeg {
                    recipient: Pubkey::new_unique(),
                    asset: SOL_MINT,
                    amount: 1,
                    spl_token_program: Some(zolana_interface::pda::spl_token_program_id()),
                })
                .collect(),
        }));
        assert!(matches!(
            too_many,
            ClientError::Transaction(TransactionError::TooManyInterfaceTransfers {
                got,
                max
            }) if got == MAX_INTERFACE_TRANSFERS + 1 && max == MAX_INTERFACE_TRANSFERS
        ));

        let zero = withdrawal_error(create_withdrawal(WithdrawalParams {
            wallet: &wallet,
            payer,
            legs: vec![WithdrawalLeg {
                recipient: Pubkey::new_unique(),
                asset: SOL_MINT,
                amount: 0,
                spl_token_program: Some(zolana_interface::pda::spl_token_program_id()),
            }],
        }));
        assert!(matches!(
            zero,
            ClientError::Transaction(TransactionError::ZeroInterfaceTransferAmount)
        ));
    }

    #[test]
    fn create_withdrawal_accepts_more_than_five_same_asset_legs() {
        let sender = ShieldedKeypair::new_p256().unwrap();
        let wallet = wallet_with_sol(sender, 12);
        let legs = (0..12)
            .map(|_| WithdrawalLeg {
                recipient: Pubkey::new_unique(),
                asset: SOL_MINT,
                amount: 1,
                spl_token_program: Some(zolana_interface::pda::spl_token_program_id()),
            })
            .collect();

        let created = create_withdrawal(WithdrawalParams {
            wallet: &wallet,
            payer: Address::default(),
            legs,
        })
        .expect("same-asset legs above the old five-leg cap");

        assert_eq!(created.settlement_transfers.len(), 12);
    }

    #[test]
    fn create_withdrawal_supports_full_u64_amount() {
        let sender = ed25519_keypair(1);
        let authority =
            crate::wallet_authority::KeypairWalletAuthority::new(Pubkey::default(), &sender);
        let wallet = wallet_with_sol(sender.clone(), u64::MAX);
        let recipient = Pubkey::new_unique();
        let created = create_withdrawal(WithdrawalParams {
            wallet: &wallet,
            payer: Address::default(),
            legs: vec![WithdrawalLeg {
                recipient,
                asset: SOL_MINT,
                amount: u64::MAX,
                spl_token_program: Some(zolana_interface::pda::spl_token_program_id()),
            }],
        })
        .expect("full-u64 withdrawal");

        let signed =
            sign_shielded_transaction_sync(created.transaction, &wallet, &authority).unwrap();
        assert_eq!(
            signed.transaction.external_data.interface_transfers.first(),
            Some(&SettlementTransfer::Sol {
                is_deposit: false,
                amount: u64::MAX,
                user_sol_account: Address::new_from_array(recipient.to_bytes()),
            })
        );
    }

    #[test]
    fn create_withdrawal_preserves_two_sol_recipients() {
        let sender = ed25519_keypair(2);
        let authority =
            crate::wallet_authority::KeypairWalletAuthority::new(Pubkey::default(), &sender);
        let wallet = wallet_with_sol(sender.clone(), 10);
        let user = Pubkey::new_unique();
        let relayer = Pubkey::new_unique();
        let created = create_withdrawal(WithdrawalParams {
            wallet: &wallet,
            payer: Address::default(),
            legs: vec![
                WithdrawalLeg {
                    recipient: user,
                    asset: SOL_MINT,
                    amount: 6,
                    spl_token_program: Some(zolana_interface::pda::spl_token_program_id()),
                },
                WithdrawalLeg {
                    recipient: relayer,
                    asset: SOL_MINT,
                    amount: 2,
                    spl_token_program: Some(zolana_interface::pda::spl_token_program_id()),
                },
            ],
        })
        .expect("two-recipient withdrawal");

        assert_eq!(
            created.settlement_transfers,
            vec![
                TransactInterfaceTransferAccounts::Sol(TransactSolTransferAccounts {
                    recipient: user
                }),
                TransactInterfaceTransferAccounts::Sol(TransactSolTransferAccounts {
                    recipient: relayer
                }),
            ]
        );
        let signed =
            sign_shielded_transaction_sync(created.transaction, &wallet, &authority).unwrap();
        assert_eq!(
            signed.transaction.external_data.interface_transfers,
            vec![
                SettlementTransfer::Sol {
                    is_deposit: false,
                    amount: 6,
                    user_sol_account: Address::new_from_array(user.to_bytes()),
                },
                SettlementTransfer::Sol {
                    is_deposit: false,
                    amount: 2,
                    user_sol_account: Address::new_from_array(relayer.to_bytes()),
                },
            ]
        );
    }

    #[test]
    fn create_withdrawal_aggregates_repeated_spl_mint_once() {
        let sender = ShieldedKeypair::new_p256().unwrap();
        let mint = Pubkey::new_unique();
        let asset = Address::new_from_array(mint.to_bytes());
        let wallet = wallet_with_asset(sender, asset, 10);

        let created = create_withdrawal(WithdrawalParams {
            wallet: &wallet,
            payer: Address::default(),
            legs: vec![
                WithdrawalLeg {
                    recipient: Pubkey::new_unique(),
                    asset,
                    amount: 6,
                    spl_token_program: Some(zolana_interface::pda::spl_token_program_id()),
                },
                WithdrawalLeg {
                    recipient: Pubkey::new_unique(),
                    asset,
                    amount: 4,
                    spl_token_program: Some(zolana_interface::pda::spl_token_program_id()),
                },
            ],
        })
        .expect("repeated SPL mint");

        assert_eq!(created.transaction.input_count(), 1);
        assert_eq!(created.settlement_transfers.len(), 2);
        assert!(created.settlement_transfers.iter().all(|transfer| matches!(
            transfer,
            TransactInterfaceTransferAccounts::SplWithdrawal(_)
        )));
    }

    #[test]
    fn create_withdrawal_supports_mixed_sol_and_spl_assets() {
        let sender = ShieldedKeypair::new_p256().unwrap();
        let mint = Pubkey::new_unique();
        let asset = Address::new_from_array(mint.to_bytes());
        let mut wallet = wallet_with_sol(sender.clone(), 10);
        wallet.registry.insert(2, asset).expect("register SPL mint");
        let spl_input = wallet_with_asset(sender, asset, 10)
            .utxos
            .into_iter()
            .next()
            .expect("SPL input");
        wallet.utxos.push(spl_input);

        let created = create_withdrawal(WithdrawalParams {
            wallet: &wallet,
            payer: Address::default(),
            legs: vec![
                WithdrawalLeg {
                    recipient: Pubkey::new_unique(),
                    asset: SOL_MINT,
                    amount: 3,
                    spl_token_program: Some(zolana_interface::pda::spl_token_program_id()),
                },
                WithdrawalLeg {
                    recipient: Pubkey::new_unique(),
                    asset,
                    amount: 4,
                    spl_token_program: Some(zolana_interface::pda::spl_token_program_id()),
                },
            ],
        })
        .expect("mixed withdrawal");

        assert_eq!(created.transaction.input_count(), 2);
        assert!(matches!(
            created.settlement_transfers.first(),
            Some(TransactInterfaceTransferAccounts::Sol(_))
        ));
        assert!(matches!(
            created.settlement_transfers.get(1),
            Some(TransactInterfaceTransferAccounts::SplWithdrawal(_))
        ));
    }

    #[test]
    fn create_withdrawal_reports_aggregate_insufficient_balance() {
        let sender = ShieldedKeypair::new_p256().unwrap();
        let wallet = wallet_with_sol(sender, 10);
        let error = withdrawal_error(create_withdrawal(WithdrawalParams {
            wallet: &wallet,
            payer: Address::default(),
            legs: vec![
                WithdrawalLeg {
                    recipient: Pubkey::new_unique(),
                    asset: SOL_MINT,
                    amount: 6,
                    spl_token_program: Some(zolana_interface::pda::spl_token_program_id()),
                },
                WithdrawalLeg {
                    recipient: Pubkey::new_unique(),
                    asset: SOL_MINT,
                    amount: 5,
                    spl_token_program: Some(zolana_interface::pda::spl_token_program_id()),
                },
            ],
        }));

        assert!(matches!(
            error,
            ClientError::InsufficientBalance {
                requested: 11,
                available: 10
            }
        ));
    }

    #[test]
    fn create_withdrawal_rejects_inputs_on_different_trees() {
        let sender = ShieldedKeypair::new_p256().unwrap();
        let mint = Pubkey::new_unique();
        let asset = Address::new_from_array(mint.to_bytes());
        let mut wallet = wallet_with_sol(sender.clone(), 10);
        wallet.registry.insert(2, asset).expect("register SPL mint");
        let second_tree = pda::tree(SECOND_TREE_ID);
        let mut spl_input = wallet_with_asset(sender, asset, 10)
            .utxos
            .into_iter()
            .next()
            .expect("SPL input");
        spl_input.tree_id = SECOND_TREE_ID;
        wallet.utxos.push(spl_input);

        let error = withdrawal_error(create_withdrawal(WithdrawalParams {
            wallet: &wallet,
            payer: Address::default(),
            legs: vec![
                WithdrawalLeg {
                    recipient: Pubkey::new_unique(),
                    asset: SOL_MINT,
                    amount: 3,
                    spl_token_program: Some(zolana_interface::pda::spl_token_program_id()),
                },
                WithdrawalLeg {
                    recipient: Pubkey::new_unique(),
                    asset,
                    amount: 4,
                    spl_token_program: Some(zolana_interface::pda::spl_token_program_id()),
                },
            ],
        }));

        assert!(matches!(
            error,
            ClientError::InputUtxoTreeMismatch {
                utxo_tree,
                spend_tree,
                ..
            } if utxo_tree == second_tree && spend_tree == test_tree()
        ));
    }

    #[test]
    fn signing_rejects_input_spent_after_creation() {
        let sender = ShieldedKeypair::new_p256().unwrap();
        let authority =
            crate::wallet_authority::KeypairWalletAuthority::new(Pubkey::default(), &sender);
        let mut wallet = wallet_with_sol(sender.clone(), 10);
        let unsigned = create_withdrawal(WithdrawalParams {
            wallet: &wallet,
            payer: Address::default(),
            legs: vec![WithdrawalLeg {
                recipient: Pubkey::new_unique(),
                asset: SOL_MINT,
                amount: 1,
                spl_token_program: Some(zolana_interface::pda::spl_token_program_id()),
            }],
        })
        .expect("withdrawal")
        .transaction;
        let hash = wallet.utxos.first().expect("wallet utxo").utxo_hash;
        mark_spent(&mut wallet, hash);

        let error = match sign_shielded_transaction_sync(unsigned, &wallet, &authority) {
            Err(error) => error,
            Ok(_) => panic!("spent input must be rejected before approval"),
        };

        assert!(matches!(
            error,
            ClientError::UnsignedInputUnavailable { index: 0 }
        ));
    }

    #[test]
    fn action_path_preserves_input_commitment_hashes() {
        let sender = ed25519_keypair(3);
        let authority =
            crate::wallet_authority::KeypairWalletAuthority::new(Pubkey::default(), &sender);
        let mut wallet = wallet_with_sol(sender.clone(), 10);
        let data_hash = [13u8; 32];
        let nullifier_pubkey = sender.nullifier_key.pubkey().unwrap();
        let entry = wallet.utxos.first().expect("wallet utxo");
        let hash = entry
            .utxo
            .hash(&nullifier_pubkey, &data_hash, &[0u8; 32], TEST_TREE_ID)
            .unwrap();
        let nullifier = entry.utxo.nullifier(&hash, &sender.nullifier_key).unwrap();
        {
            let entry = wallet.utxos.first_mut().expect("wallet utxo");
            entry.utxo_hash = hash;
            entry.nullifier = nullifier;
            entry.data_hash = Some(data_hash);
        }
        let unsigned = create_withdrawal(WithdrawalParams {
            wallet: &wallet,
            payer: Address::default(),
            legs: vec![WithdrawalLeg {
                recipient: Pubkey::new_unique(),
                asset: SOL_MINT,
                amount: 1,
                spl_token_program: Some(zolana_interface::pda::spl_token_program_id()),
            }],
        })
        .unwrap()
        .transaction;

        let signed = sign_shielded_transaction_sync(unsigned, &wallet, &authority).unwrap();

        let inputs = signed.transaction.input_utxo_hashes().unwrap();
        assert_eq!(inputs.first().expect("input").utxo_hash, hash);
    }

    #[test]
    fn input_selection_keeps_every_input_on_one_tree() {
        let sender = ShieldedKeypair::new_p256().unwrap();
        let second_tree = pda::tree(SECOND_TREE_ID);
        let mut wallet = wallet_with_sol(sender.clone(), 10);
        if let Some(entry) = wallet.utxos.first_mut() {
            entry.tree_id = SECOND_TREE_ID;
        }

        let created = create_withdrawal(WithdrawalParams {
            wallet: &wallet,
            payer: Address::default(),
            legs: vec![WithdrawalLeg {
                recipient: Pubkey::new_unique(),
                asset: SOL_MINT,
                amount: 8,
                spl_token_program: Some(zolana_interface::pda::spl_token_program_id()),
            }],
        })
        .expect("tree with enough balance");

        assert_eq!(created.transaction.tree(), second_tree);
        assert_eq!(created.transaction.input_count(), 1);
    }

    #[test]
    fn resolve_spend_tree_infers_single_tree_balance() {
        let sender = ShieldedKeypair::new_p256().unwrap();
        let wallet = wallet_with_sol(sender, 10);

        let tree =
            resolve_spend_tree(&wallet, SOL_MINT, is_default_ring_spendable).expect("infer tree");

        assert_eq!(tree, test_tree());
    }

    #[test]
    fn resolve_spend_tree_errors_when_balance_spans_multiple_trees() {
        let sender = ShieldedKeypair::new_p256().unwrap();
        let mut wallet = wallet_with_sol(sender.clone(), 4);
        let mut second = wallet_with_sol(sender, 10).utxos.remove(0);
        second.tree_id = SECOND_TREE_ID;
        wallet.utxos.push(second);

        let error = match resolve_spend_tree(&wallet, SOL_MINT, is_default_ring_spendable) {
            Err(error) => error,
            Ok(_) => panic!("expected ambiguous tree error"),
        };

        assert!(matches!(
            error,
            ClientError::AmbiguousTree {
                asset,
                tree_count: 2,
            } if asset == SOL_MINT
        ));
    }

    #[test]
    fn create_withdrawal_infers_tree_when_omitted() {
        let sender = ShieldedKeypair::new_p256().unwrap();
        let wallet = wallet_with_sol(sender.clone(), 10);

        let created = create_withdrawal(WithdrawalParams {
            wallet: &wallet,
            payer: Address::default(),
            legs: vec![WithdrawalLeg {
                recipient: Pubkey::new_unique(),
                asset: SOL_MINT,
                amount: 1,
                spl_token_program: Some(zolana_interface::pda::spl_token_program_id()),
            }],
        })
        .expect("withdrawal");

        assert_eq!(created.transaction.tree(), test_tree());
    }

    #[test]
    fn create_split_accepts_plain_divisible_utxo() {
        let sender = ShieldedKeypair::new_p256().unwrap();
        let wallet = wallet_with_sol(sender, 800);

        let created = create_split(SplitParams {
            wallet: &wallet,
            payer: Address::default(),
            asset: SOL_MINT,
            parts: 8,
            input: None,
        })
        .expect("split");

        assert_eq!(created.num_outputs, 8);
        assert_eq!(created.per_output_amount, 100);
        assert_eq!(created.transaction.input_count(), 1);
    }

    #[test]
    fn create_split_rejects_indivisible_amount() {
        let sender = ShieldedKeypair::new_p256().unwrap();
        let wallet = wallet_with_sol(sender, 10);

        let error = match create_split(SplitParams {
            wallet: &wallet,
            payer: Address::default(),
            asset: SOL_MINT,
            parts: 3,
            input: None,
        }) {
            Err(error) => error,
            Ok(_) => panic!("an indivisible amount must be rejected"),
        };

        assert!(matches!(
            error,
            ClientError::SplitNotDivisible {
                amount: 10,
                parts: 3
            }
        ));
    }

    #[test]
    fn create_split_rejects_named_utxo_carrying_data() {
        let sender = ShieldedKeypair::new_p256().unwrap();
        let mut wallet = wallet_with_sol(sender, 800);
        let hash = wallet.utxos.first().expect("seeded utxo").utxo_hash;
        if let Some(entry) = wallet.utxos.first_mut() {
            entry.utxo.data = Data::new(vec![DataRecord::Memo(b"utxo".to_vec())]);
        }

        // An explicitly named non-plain utxo must error rather than silently
        // fall back; only auto-selection skips ineligible utxos.
        let error = match create_split(SplitParams {
            wallet: &wallet,
            payer: Address::default(),
            asset: SOL_MINT,
            parts: 8,
            input: Some(hash),
        }) {
            Err(error) => error,
            Ok(_) => panic!("a utxo carrying data must be rejected"),
        };

        assert!(matches!(error, ClientError::SplitInputHasData { .. }));
    }

    #[test]
    fn create_split_rejects_named_ring_bound_utxo() {
        let sender = ShieldedKeypair::new_p256().unwrap();
        let mut wallet = wallet_with_sol(sender, 800);
        let hash = wallet.utxos.first().expect("seeded utxo").utxo_hash;
        if let Some(entry) = wallet.utxos.first_mut() {
            entry.utxo.ring_program_id = Some(Address::new_from_array([3u8; 32]));
        }

        let error = match create_split(SplitParams {
            wallet: &wallet,
            payer: Address::default(),
            asset: SOL_MINT,
            parts: 8,
            input: Some(hash),
        }) {
            Err(error) => error,
            Ok(_) => panic!("a ring-bound utxo must be rejected"),
        };

        assert!(matches!(error, ClientError::SplitInputRingMismatch { .. }));
    }

    #[test]
    fn create_split_auto_select_skips_a_larger_ineligible_utxo() {
        let sender = ShieldedKeypair::new_p256().unwrap();
        let mut wallet = sol_wallet(&sender);
        // A larger data-carrying utxo must not shadow the smaller plain candidate.
        push_utxo(&mut wallet, &sender, 1600, [1u8; 31]);
        if let Some(entry) = wallet.utxos.last_mut() {
            entry.data_hash = Some([7u8; 32]);
        }
        push_utxo(&mut wallet, &sender, 800, [2u8; 31]);

        let created = create_split(SplitParams {
            wallet: &wallet,
            payer: Address::default(),
            asset: SOL_MINT,
            parts: 8,
            input: None,
        })
        .expect("auto-select falls back to the plain utxo");

        // 800 / 8, proving the larger 1600 data-carrying utxo was skipped.
        assert_eq!(created.per_output_amount, 100);
    }

    fn sol_wallet(keypair: &ShieldedKeypair) -> Wallet {
        Wallet::new(
            keypair.shielded_address().expect("shielded address"),
            AssetRegistry::default(),
        )
        .expect("wallet")
    }

    /// Push a plain SOL utxo of `amount` (distinct `blinding` keeps commitments
    /// unique) and return its commitment hash.
    fn push_utxo(
        wallet: &mut Wallet,
        keypair: &ShieldedKeypair,
        amount: u64,
        blinding: [u8; 31],
    ) -> [u8; 32] {
        let mut canonical_blinding = [0u8; 32];
        canonical_blinding[1..].copy_from_slice(&blinding);
        let utxo = Utxo {
            owner: keypair.signing_pubkey(),
            asset: zolana_transaction::Mint::SOL,
            amount,
            blinding: canonical_blinding,
            ring_program_id: None,
            data: Data::default(),
        };
        let nullifier_pk = keypair.nullifier_key.pubkey().expect("nullifier pubkey");
        let hash = utxo
            .hash(&nullifier_pk, &[0u8; 32], &[0u8; 32], TEST_TREE_ID)
            .expect("utxo hash");
        let nullifier = utxo
            .nullifier(&hash, &keypair.nullifier_key)
            .expect("nullifier");
        wallet.utxos.push(WalletUtxo {
            utxo,
            nullifier_pubkey: nullifier_pk,
            utxo_hash: hash,
            nullifier,
            data_hash: None,
            ring_data_hash: None,
            tree_id: TEST_TREE_ID,
            leaf_index: 0,

            slot: 0,
            tx_signature: Signature::default(),
            slot_index: 0,
        });
        hash
    }

    fn amounts(selected: &[WalletUtxo]) -> Vec<u64> {
        selected
            .iter()
            .map(|input_utxo| input_utxo.utxo.amount)
            .collect()
    }

    #[test]
    fn merge_auto_sweep_selects_smallest_plain_utxos_ascending() {
        let keypair = ShieldedKeypair::new_p256().unwrap();
        let mut wallet = sol_wallet(&keypair);
        for (index, amount) in [50u64, 10, 30].into_iter().enumerate() {
            push_utxo(&mut wallet, &keypair, amount, [index as u8 + 1; 31]);
        }

        let selected = select_merge_inputs(&wallet, test_tree(), SOL_MINT, None).unwrap();

        assert_eq!(amounts(&selected), vec![10, 30, 50]);
    }

    #[test]
    fn merge_auto_sweep_caps_at_shape_keeping_the_smallest_utxos() {
        let keypair = ShieldedKeypair::new_p256().unwrap();
        let mut wallet = sol_wallet(&keypair);
        for step in 1..=9u64 {
            push_utxo(&mut wallet, &keypair, step * 10, [step as u8; 31]);
        }

        let selected = select_merge_inputs(&wallet, test_tree(), SOL_MINT, None).unwrap();

        assert_eq!(selected.len(), MERGE_DEFAULT_INPUT_COUNT);
        assert_eq!(amounts(&selected), vec![10, 20, 30, 40, 50, 60, 70, 80]);
    }

    #[test]
    fn merge_auto_sweep_skips_ring_and_data_utxos() {
        let keypair = ShieldedKeypair::new_p256().unwrap();
        let mut wallet = sol_wallet(&keypair);
        push_utxo(&mut wallet, &keypair, 10, [1u8; 31]);
        push_utxo(&mut wallet, &keypair, 20, [2u8; 31]);
        // A ring-bound utxo and a data-carrying utxo must not be swept.
        push_utxo(&mut wallet, &keypair, 30, [3u8; 31]);
        if let Some(entry) = wallet.utxos.last_mut() {
            entry.utxo.ring_program_id = Some(Address::new_from_array([9u8; 32]));
        }
        push_utxo(&mut wallet, &keypair, 40, [4u8; 31]);
        if let Some(entry) = wallet.utxos.last_mut() {
            entry.data_hash = Some([7u8; 32]);
        }

        let selected = select_merge_inputs(&wallet, test_tree(), SOL_MINT, None).unwrap();

        assert_eq!(amounts(&selected), vec![10, 20]);
    }

    #[test]
    fn merge_auto_sweep_needs_at_least_two_utxos() {
        let keypair = ShieldedKeypair::new_p256().unwrap();
        let mut wallet = sol_wallet(&keypair);
        push_utxo(&mut wallet, &keypair, 10, [1u8; 31]);

        let error = match select_merge_inputs(&wallet, test_tree(), SOL_MINT, None) {
            Err(error) => error,
            Ok(_) => panic!("a single utxo cannot be merged"),
        };

        assert!(matches!(error, ClientError::NothingToMerge { asset } if asset == SOL_MINT));
    }

    #[test]
    fn merge_explicit_selection_takes_exactly_the_named_utxos() {
        let keypair = ShieldedKeypair::new_p256().unwrap();
        let mut wallet = sol_wallet(&keypair);
        let a = push_utxo(&mut wallet, &keypair, 10, [1u8; 31]);
        let b = push_utxo(&mut wallet, &keypair, 20, [2u8; 31]);
        push_utxo(&mut wallet, &keypair, 30, [3u8; 31]);

        let selected =
            select_merge_inputs(&wallet, test_tree(), SOL_MINT, Some(vec![a, b])).unwrap();

        assert_eq!(amounts(&selected), vec![10, 20]);
    }

    #[test]
    fn merge_explicit_selection_rejects_duplicate_utxos() {
        let keypair = ShieldedKeypair::new_p256().unwrap();
        let mut wallet = sol_wallet(&keypair);
        let a = push_utxo(&mut wallet, &keypair, 10, [1u8; 31]);

        let error = match select_merge_inputs(&wallet, test_tree(), SOL_MINT, Some(vec![a, a])) {
            Err(error) => error,
            Ok(_) => panic!("a repeated utxo must be rejected"),
        };

        assert!(matches!(error, ClientError::DuplicateInputUtxo { hash } if hash == a));
    }

    #[test]
    fn merge_explicit_selection_rejects_more_than_the_widest_shape() {
        const TOO_MANY: usize = MAX_MERGE_INPUTS + 1;
        let keypair = ShieldedKeypair::new_p256().unwrap();
        let wallet = sol_wallet(&keypair);
        let hashes: Vec<[u8; 32]> = (0..TOO_MANY)
            .map(|i| [u8::try_from(i).unwrap(); 32])
            .collect();

        let error = match select_merge_inputs(&wallet, test_tree(), SOL_MINT, Some(hashes)) {
            Err(error) => error,
            Ok(_) => panic!("more inputs than the widest merge shape must be rejected"),
        };

        assert!(matches!(
            error,
            ClientError::TooManyInputs {
                got: TOO_MANY,
                max: MAX_MERGE_INPUTS
            }
        ));
    }

    #[test]
    fn merge_explicit_selection_reaches_the_wide_shape() {
        let keypair = ShieldedKeypair::new_p256().unwrap();
        let mut wallet = sol_wallet(&keypair);
        let hashes: Vec<[u8; 32]> = (1..=MERGE_DEFAULT_INPUT_COUNT + 1)
            .map(|amount| {
                let seed = u8::try_from(amount).unwrap();
                push_utxo(&mut wallet, &keypair, amount as u64, [seed; 31])
            })
            .collect();

        let created = create_merge(MergeParams {
            wallet: &wallet,
            keypair: &keypair,
            asset: SOL_MINT,
            inputs: Some(hashes),
        })
        .expect("a named merge wider than the default shape pads to the wide shape");

        assert_eq!(created.num_inputs, MERGE_DEFAULT_INPUT_COUNT + 1);
        assert_eq!(created.prepared.input_utxos.len(), MAX_MERGE_INPUTS);
        assert_eq!(created.merged_amount, 45);
    }

    #[test]
    fn merge_explicit_selection_needs_at_least_two_utxos() {
        let keypair = ShieldedKeypair::new_p256().unwrap();
        let mut wallet = sol_wallet(&keypair);
        let a = push_utxo(&mut wallet, &keypair, 10, [1u8; 31]);

        let error = match select_merge_inputs(&wallet, test_tree(), SOL_MINT, Some(vec![a])) {
            Err(error) => error,
            Ok(_) => panic!("a single named utxo cannot be merged"),
        };

        assert!(matches!(error, ClientError::NothingToMerge { asset } if asset == SOL_MINT));
    }

    #[test]
    fn merge_explicit_selection_rejects_an_unknown_utxo() {
        let keypair = ShieldedKeypair::new_p256().unwrap();
        let mut wallet = sol_wallet(&keypair);
        let a = push_utxo(&mut wallet, &keypair, 10, [1u8; 31]);
        let missing = [0xabu8; 32];

        let error =
            match select_merge_inputs(&wallet, test_tree(), SOL_MINT, Some(vec![a, missing])) {
                Err(error) => error,
                Ok(_) => panic!("an unknown utxo must be rejected"),
            };

        assert!(matches!(error, ClientError::InputUtxoUnavailable { hash } if hash == missing));
    }

    /// A named utxo that exists but lives on another tree is reported as a tree
    /// mismatch (with both trees), not as "unavailable" -- the owner can see the
    /// hash in their own `wallet utxos` listing.
    #[test]
    fn merge_explicit_selection_reports_a_wrong_tree_utxo() {
        let keypair = ShieldedKeypair::new_p256().unwrap();
        let mut wallet = sol_wallet(&keypair);
        let a = push_utxo(&mut wallet, &keypair, 10, [1u8; 31]);
        let b = push_utxo(&mut wallet, &keypair, 20, [2u8; 31]);
        let other_tree = pda::tree(SECOND_TREE_ID);
        place_in_tree(&mut wallet, b, SECOND_TREE_ID);

        let error = match select_merge_inputs(&wallet, test_tree(), SOL_MINT, Some(vec![a, b])) {
            Err(error) => error,
            Ok(_) => panic!("a wrong-tree utxo must be rejected"),
        };

        assert!(matches!(
            error,
            ClientError::InputUtxoTreeMismatch { hash, utxo_tree, spend_tree }
                if hash == b && utxo_tree == other_tree && spend_tree == test_tree()
        ));
    }

    /// Auto-select must pick the largest utxo that actually divides into
    /// `parts`, not the largest overall: an indivisible larger utxo must not
    /// shadow a smaller splittable one.
    #[test]
    fn split_auto_select_skips_an_indivisible_larger_utxo() {
        let keypair = ShieldedKeypair::new_p256().unwrap();
        let mut wallet = sol_wallet(&keypair);
        push_utxo(&mut wallet, &keypair, 1001, [1u8; 31]);
        let divisible = push_utxo(&mut wallet, &keypair, 800, [2u8; 31]);

        let (input, per_output) = select_split_utxo(&wallet, test_tree(), SOL_MINT, 2, None)
            .expect("select the divisible utxo");

        assert_eq!(input.utxo_hash, divisible);
        assert_eq!(per_output, 400);
    }

    /// When plain utxos exist but none divide into `parts`, the error names the
    /// divisibility problem (on the largest candidate) rather than claiming an
    /// empty balance.
    #[test]
    fn split_auto_select_reports_indivisible_when_no_candidate_divides() {
        let keypair = ShieldedKeypair::new_p256().unwrap();
        let mut wallet = sol_wallet(&keypair);
        push_utxo(&mut wallet, &keypair, 1000, [1u8; 31]);

        let error = match select_split_utxo(&wallet, test_tree(), SOL_MINT, 3, None) {
            Err(error) => error,
            Ok(_) => panic!("an indivisible balance must be rejected"),
        };

        assert!(matches!(
            error,
            ClientError::SplitNotDivisible {
                amount: 1000,
                parts: 3
            }
        ));
    }

    const TEST_RING: Address = Address::new_from_array([7u8; 32]);

    fn bind_to_ring(wallet: &mut Wallet, hash: [u8; 32], tree_id: u16) {
        place_in_tree(wallet, hash, tree_id);
        wallet
            .utxos
            .iter_mut()
            .find(|entry| entry.utxo_hash == hash)
            .expect("pushed utxo")
            .utxo
            .ring_program_id = Some(TEST_RING);
    }

    fn wallet_with_ring_balance_on_another_tree(keypair: &ShieldedKeypair) -> Wallet {
        let mut wallet = sol_wallet(keypair);
        push_utxo(&mut wallet, keypair, 10, [1u8; 31]);
        let ring_bound = push_utxo(&mut wallet, keypair, 100, [2u8; 31]);
        bind_to_ring(&mut wallet, ring_bound, RING_TREE_ID);
        wallet
    }

    /// Registered, so the transfer takes the private path.
    fn registered_recipient_rpc(owner: Pubkey, recipient: &ShieldedKeypair) -> MockRpc {
        let (record_pda, bump) = user_record_pda(&owner);
        let record = UserRecord {
            owner: owner.to_bytes().into(),
            bump,
            owner_p256: Some(*recipient.signing_pubkey().as_p256().unwrap().as_bytes()),
            nullifier_pubkey: recipient.nullifier_key.pubkey().unwrap(),
            viewing_pubkey: *recipient.viewing_pubkey().as_bytes(),
            merging_enabled: false,
        };
        MockRpc {
            account: Some((
                Address::new_from_array(record_pda.to_bytes()),
                Account {
                    lamports: 1,
                    data: account_data(&record),
                    owner: user_registry_program_id(),
                    executable: false,
                    rent_epoch: 0,
                },
            )),
        }
    }

    #[test]
    fn select_inputs_leaves_ring_bound_utxos_to_the_ring_path() {
        let keypair = ShieldedKeypair::new_p256().unwrap();
        let mut wallet = sol_wallet(&keypair);
        push_utxo(&mut wallet, &keypair, 10, [1u8; 31]);
        let ring_bound = push_utxo(&mut wallet, &keypair, 100, [2u8; 31]);
        bind_to_ring(&mut wallet, ring_bound, TEST_TREE_ID);

        let selected = select_inputs(
            &wallet,
            &[test_tree()],
            SOL_MINT,
            10,
            is_default_ring_spendable,
        )
        .expect("a plain utxo covers the amount");
        assert_eq!(selected.len(), 1);
        assert!(selected
            .iter()
            .all(|input| input.utxo.ring_program_id.is_none()));

        assert!(matches!(
            select_inputs(
                &wallet,
                &[test_tree()],
                SOL_MINT,
                50,
                is_default_ring_spendable
            ),
            Err(ClientError::InsufficientBalance {
                requested: 50,
                available: 10
            })
        ));
    }

    #[test]
    fn select_spend_inputs_returns_transfer_ready_default_inputs() {
        let keypair = ShieldedKeypair::new_p256().unwrap();
        let mut wallet = sol_wallet(&keypair);
        push_utxo(&mut wallet, &keypair, 10, [1u8; 31]);
        push_utxo(&mut wallet, &keypair, 15, [3u8; 31]);
        let ring_bound = push_utxo(&mut wallet, &keypair, 100, [2u8; 31]);
        bind_to_ring(&mut wallet, ring_bound, RING_TREE_ID);
        for (index, note) in wallet.utxos.iter_mut().enumerate() {
            note.leaf_index = 100 + index as u64;
        }

        let selected = select_input_utxos_sync(
            SpendInputParams {
                wallet: &wallet,
                asset: SOL_MINT,
                amount: 20,
            },
            &keypair,
        )
        .expect("two plain utxos cover the amount");

        assert_eq!(selected.trees, vec![test_tree()]);
        assert_eq!(
            selected.inputs,
            vec![wallet.utxos[1].clone(), wallet.utxos[0].clone()]
        );
        assert!(selected
            .inputs
            .iter()
            .all(|input| input.utxo.ring_program_id.is_none() && input.ring_data_hash.is_none()));

        assert!(matches!(
            select_input_utxos_sync(
                SpendInputParams {
                    wallet: &wallet,
                    asset: SOL_MINT,
                    amount: 50,
                },
                &keypair
            ),
            Err(ClientError::InsufficientBalance {
                requested: 50,
                available: 25
            })
        ));
    }

    #[test]
    fn balances_split_ring_bound_notes_from_the_spendable_view() {
        let keypair = ShieldedKeypair::new_p256().unwrap();
        let mut wallet = sol_wallet(&keypair);
        push_utxo(&mut wallet, &keypair, 10, [1u8; 31]);
        let ring_bound = push_utxo(&mut wallet, &keypair, 100, [2u8; 31]);
        bind_to_ring(&mut wallet, ring_bound, RING_TREE_ID);

        let spendable = wallet.balances(true).expect("balances");
        assert_eq!(spendable.len(), 1);
        assert_eq!(spendable[0].amount, 10);

        let rings = wallet.ring_balances(true).expect("ring balances");
        assert_eq!(rings.len(), 1);
        assert_eq!(rings[0].ring_program_id, TEST_RING);
        assert_eq!(rings[0].assets.len(), 1);
        assert_eq!(rings[0].assets[0].amount, 100);
    }

    #[test]
    fn ring_balances_group_by_ring_in_address_order() {
        let keypair = ShieldedKeypair::new_p256().unwrap();
        let mut wallet = sol_wallet(&keypair);
        let first = push_utxo(&mut wallet, &keypair, 40, [1u8; 31]);
        bind_to_ring(&mut wallet, first, RING_TREE_ID);
        let second = push_utxo(&mut wallet, &keypair, 60, [2u8; 31]);
        bind_to_ring(&mut wallet, second, RING_TREE_ID);
        let other_ring = Address::new_from_array([3u8; 32]);
        wallet
            .utxos
            .iter_mut()
            .find(|entry| entry.utxo_hash == second)
            .expect("pushed utxo")
            .utxo
            .ring_program_id = Some(other_ring);

        let rings = wallet.ring_balances(true).expect("ring balances");
        assert_eq!(
            rings
                .iter()
                .map(|ring| (ring.ring_program_id, ring.assets[0].amount))
                .collect::<Vec<_>>(),
            vec![(other_ring, 60), (Address::new_from_array([7u8; 32]), 40),]
        );
    }

    /// Both balance views answer from the ids sync already resolved, so a note
    /// whose mint the registry does not name cannot break either of them. Asking
    /// about that mint by name is the one thing that still errors, because there
    /// is no note to read an id from.
    #[test]
    fn a_mint_the_registry_does_not_name_is_only_an_error_when_asked_for_by_name() {
        let keypair = ShieldedKeypair::new_p256().unwrap();
        let mut wallet = sol_wallet(&keypair);
        push_utxo(&mut wallet, &keypair, 10, [1u8; 31]);
        let ring_bound = push_utxo(&mut wallet, &keypair, 100, [2u8; 31]);
        bind_to_ring(&mut wallet, ring_bound, RING_TREE_ID);
        let unregistered = Address::new_from_array([8u8; 32]);

        let spendable = wallet.balances(true).expect("balances");
        assert_eq!(spendable.len(), 1);
        assert_eq!(spendable[0].amount, 10);
        let rings = wallet.ring_balances(true).expect("ring balances");
        assert_eq!(rings.len(), 1);
        assert_eq!(rings[0].assets[0].amount, 100);
        assert!(matches!(
            wallet.balance(unregistered, None),
            Err(TransactionError::UnknownMint(mint)) if mint == unregistered
        ));
    }

    /// A balance that straddles a tree rollover covers from both trees, and the
    /// selection reports them in declaration order.
    #[test]
    fn select_spend_inputs_spans_the_trees_holding_the_balance() {
        let keypair = ShieldedKeypair::new_p256().unwrap();
        let mut wallet = sol_wallet(&keypair);
        push_utxo(&mut wallet, &keypair, 10, [1u8; 31]);
        let elsewhere = push_utxo(&mut wallet, &keypair, 10, [2u8; 31]);
        place_in_tree(&mut wallet, elsewhere, RING_TREE_ID);

        let selected = select_input_utxos_sync(
            SpendInputParams {
                wallet: &wallet,
                asset: SOL_MINT,
                amount: 15,
            },
            &keypair,
        )
        .expect("both trees together cover the amount");

        assert_eq!(selected.trees, vec![test_tree(), pda::tree(RING_TREE_ID)]);
        assert_eq!(amounts(&selected.inputs), vec![10, 10]);
    }

    #[test]
    fn select_spend_inputs_groups_selected_notes_and_omits_unused_trees() {
        let keypair = ShieldedKeypair::new_p256().unwrap();
        let mut wallet = sol_wallet(&keypair);
        for (marker, amount, tree_id) in [(1, 40, 4), (2, 30, 1), (3, 20, 4), (4, 10, 2)] {
            let hash = push_utxo(&mut wallet, &keypair, amount, [marker; 31]);
            place_in_tree(&mut wallet, hash, tree_id);
        }

        for (amount, expected_trees, expected_inputs) in [
            (40, vec![4], vec![(4, 40)]),
            (90, vec![4, 1], vec![(4, 40), (4, 20), (1, 30)]),
        ] {
            let selected = select_input_utxos_sync(
                SpendInputParams {
                    wallet: &wallet,
                    asset: SOL_MINT,
                    amount,
                },
                &keypair,
            )
            .expect("only the selected trees count toward the limit");
            assert_eq!(
                selected.trees,
                expected_trees
                    .into_iter()
                    .map(pda::tree)
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                selected
                    .inputs
                    .iter()
                    .map(|input| (input.tree_id, input.utxo.amount))
                    .collect::<Vec<_>>(),
                expected_inputs
            );
        }
    }

    /// A selection that actually needs more than `MAX_INPUT_TREES` is rejected.
    #[test]
    fn select_spend_inputs_refuse_more_trees_than_the_program_limit() {
        let keypair = ShieldedKeypair::new_p256().unwrap();
        let mut wallet = sol_wallet(&keypair);
        for index in 0..=MAX_INPUT_TREES {
            let marker = u8::try_from(index).expect("utxo marker");
            let hash = push_utxo(&mut wallet, &keypair, 10, [marker + 1; 31]);
            place_in_tree(&mut wallet, hash, u16::from(marker) + 1);
        }

        assert!(matches!(
            select_input_utxos_sync(
                SpendInputParams {
                    wallet: &wallet,
                    asset: SOL_MINT,
                    amount: u64::try_from(MAX_INPUT_TREES).unwrap() * 10 + 1,
                }, &keypair),
            Err(ClientError::AmbiguousTree { tree_count, .. }) if tree_count == MAX_INPUT_TREES + 1
        ));
    }

    #[test]
    fn select_spend_inputs_skip_default_notes_carrying_ring_data() {
        let keypair = ShieldedKeypair::new_p256().unwrap();
        let mut wallet = sol_wallet(&keypair);
        let tainted = push_utxo(&mut wallet, &keypair, 50, [1u8; 31]);
        wallet
            .utxos
            .iter_mut()
            .find(|entry| entry.utxo_hash == tainted)
            .expect("pushed utxo")
            .ring_data_hash = Some([5u8; 32]);
        push_utxo(&mut wallet, &keypair, 20, [2u8; 31]);

        let selected = select_input_utxos_sync(
            SpendInputParams {
                wallet: &wallet,
                asset: SOL_MINT,
                amount: 20,
            },
            &keypair,
        )
        .expect("the clean note covers the amount");
        assert_eq!(amounts(&selected.inputs), vec![20]);

        assert!(matches!(
            select_input_utxos_sync(
                SpendInputParams {
                    wallet: &wallet,
                    asset: SOL_MINT,
                    amount: 60,
                },
                &keypair
            ),
            Err(ClientError::InsufficientBalance {
                requested: 60,
                available: 20
            })
        ));
    }

    #[test]
    fn select_spend_inputs_skips_spent_notes_and_stops_at_cover() {
        let keypair = ShieldedKeypair::new_p256().unwrap();
        let mut wallet = sol_wallet(&keypair);
        let spent = push_utxo(&mut wallet, &keypair, 10, [1u8; 31]);
        mark_spent(&mut wallet, spent);
        push_utxo(&mut wallet, &keypair, 15, [2u8; 31]);
        push_utxo(&mut wallet, &keypair, 20, [3u8; 31]);

        let selected = select_input_utxos_sync(
            SpendInputParams {
                wallet: &wallet,
                asset: SOL_MINT,
                amount: 15,
            },
            &keypair,
        )
        .expect("the unspent 20 covers the amount");

        assert_eq!(amounts(&selected.inputs), vec![20]);
    }

    #[test]
    fn select_spend_inputs_prefer_one_covering_note_over_fragments() {
        let keypair = ShieldedKeypair::new_p256().unwrap();
        let mut wallet = sol_wallet(&keypair);
        for index in 0..6u8 {
            push_utxo(&mut wallet, &keypair, 5, [index + 1; 31]);
        }
        push_utxo(&mut wallet, &keypair, 100, [10u8; 31]);

        let selected = select_input_utxos_sync(
            SpendInputParams {
                wallet: &wallet,
                asset: SOL_MINT,
                amount: 100,
            },
            &keypair,
        )
        .expect("the covering note input_utxos alone");
        assert_eq!(amounts(&selected.inputs), vec![100]);
    }

    #[test]
    fn select_spend_inputs_refuse_a_zero_amount() {
        let keypair = ShieldedKeypair::new_p256().unwrap();
        let mut wallet = sol_wallet(&keypair);
        push_utxo(&mut wallet, &keypair, 10, [1u8; 31]);

        assert!(matches!(
            select_input_utxos_sync(
                SpendInputParams {
                    wallet: &wallet,
                    asset: SOL_MINT,
                    amount: 0,
                },
                &keypair
            ),
            Err(ClientError::ZeroSpendAmount)
        ));
    }

    #[test]
    fn select_spend_inputs_refuse_a_cover_wider_than_the_shape() {
        let keypair = ShieldedKeypair::new_p256().unwrap();
        let mut wallet = sol_wallet(&keypair);
        for index in 0..6u8 {
            push_utxo(&mut wallet, &keypair, 5, [index + 1; 31]);
        }

        assert!(matches!(
            select_input_utxos_sync(
                SpendInputParams {
                    wallet: &wallet,
                    asset: SOL_MINT,
                    amount: 30,
                },
                &keypair
            ),
            Err(ClientError::TooManyInputs { got: 6, max: 5 })
        ));
    }

    /// An ineligible (ring-bound or data-carrying) utxo on a second tree must not
    /// make the split/merge spend tree ambiguous: eligibility filters tree
    /// resolution.
    #[test]
    fn resolve_spend_tree_ignores_ineligible_utxos_on_other_trees() {
        let keypair = ShieldedKeypair::new_p256().unwrap();
        let mut wallet = sol_wallet(&keypair);
        push_utxo(&mut wallet, &keypair, 10, [1u8; 31]);
        let ring_bound = push_utxo(&mut wallet, &keypair, 20, [2u8; 31]);
        bind_to_ring(&mut wallet, ring_bound, RING_TREE_ID);

        let tree = resolve_spend_tree(&wallet, SOL_MINT, is_plain_utxo)
            .expect("the ring utxo on another tree must not block a plain input_utxo");

        assert_eq!(tree, test_tree());
    }

    #[test]
    fn resolve_spend_tree_ignores_ring_bound_utxos_on_other_trees() {
        let keypair = ShieldedKeypair::new_p256().unwrap();
        let wallet = wallet_with_ring_balance_on_another_tree(&keypair);

        let tree = resolve_spend_tree(&wallet, SOL_MINT, is_default_ring_spendable)
            .expect("a ring balance on another tree must not make the input_utxo ambiguous");

        assert_eq!(tree, test_tree());
    }

    #[test]
    fn create_withdrawal_spends_the_plain_tree_when_a_ring_balance_sits_on_another() {
        let keypair = ShieldedKeypair::new_p256().unwrap();
        let wallet = wallet_with_ring_balance_on_another_tree(&keypair);

        let created = create_withdrawal(WithdrawalParams {
            wallet: &wallet,
            payer: Address::default(),
            legs: vec![WithdrawalLeg {
                recipient: Pubkey::new_unique(),
                asset: SOL_MINT,
                amount: 4,
                spl_token_program: None,
            }],
        })
        .expect("the plain tree covers the withdrawal");

        assert_eq!(created.transaction.tree(), test_tree());
        assert_eq!(created.transaction.input_count(), 1);
    }

    #[test]
    fn create_transfer_sync_public_withdrawal_ignores_a_ring_balance_on_another_tree() {
        let keypair = ShieldedKeypair::new_p256().unwrap();
        let wallet = wallet_with_ring_balance_on_another_tree(&keypair);
        let rpc = MockRpc { account: None };

        let created = create_transfer_sync(TransferParams {
            rpc: &rpc,
            wallet: &wallet,
            payer: Address::default(),
            recipient: Pubkey::new_unique(),
            asset: SOL_MINT,
            amount: 4,
        })
        .expect("the plain tree covers the withdrawal");

        assert!(matches!(
            created.recipient,
            TransferRecipient::PublicWithdrawal { .. }
        ));
        assert_eq!(created.transaction.tree(), test_tree());
        assert_eq!(created.transaction.input_count(), 1);
    }

    #[test]
    fn create_transfer_sync_ignores_a_ring_balance_on_another_tree() {
        let keypair = ShieldedKeypair::new_p256().unwrap();
        let recipient = ShieldedKeypair::new_p256().unwrap();
        let owner = Pubkey::new_unique();
        let wallet = wallet_with_ring_balance_on_another_tree(&keypair);
        let rpc = registered_recipient_rpc(owner, &recipient);

        let created = create_transfer_sync(TransferParams {
            rpc: &rpc,
            wallet: &wallet,
            payer: Address::default(),
            recipient: owner,
            asset: SOL_MINT,
            amount: 4,
        })
        .expect("the plain tree covers the transfer");

        assert!(matches!(
            created.recipient,
            TransferRecipient::Registered(resolved) if resolved.owner == owner
        ));
        assert_eq!(created.transaction.tree(), test_tree());
        assert_eq!(created.transaction.input_count(), 1);
    }

    #[test]
    fn create_withdrawal_reports_no_balance_when_all_of_it_is_ring_bound() {
        let keypair = ShieldedKeypair::new_p256().unwrap();
        let mut wallet = sol_wallet(&keypair);
        let ring_bound = push_utxo(&mut wallet, &keypair, 100, [1u8; 31]);
        bind_to_ring(&mut wallet, ring_bound, RING_TREE_ID);

        let error = withdrawal_error(create_withdrawal(WithdrawalParams {
            wallet: &wallet,
            payer: Address::default(),
            legs: vec![WithdrawalLeg {
                recipient: Pubkey::new_unique(),
                asset: SOL_MINT,
                amount: 4,
                spl_token_program: None,
            }],
        }));

        assert!(matches!(
            error,
            ClientError::InsufficientBalance { available: 0, .. }
        ));
    }

    #[test]
    fn create_merge_auto_sweep_reports_count_amount_and_tree() {
        let keypair = ShieldedKeypair::new_p256().unwrap();
        let mut wallet = sol_wallet(&keypair);
        for (index, amount) in [10u64, 20, 30].into_iter().enumerate() {
            push_utxo(&mut wallet, &keypair, amount, [index as u8 + 1; 31]);
        }

        let created = create_merge(MergeParams {
            wallet: &wallet,
            keypair: &keypair,
            asset: SOL_MINT,
            inputs: None,
        })
        .expect("merge");

        assert_eq!(created.num_inputs, 3);
        assert_eq!(created.merged_amount, 60);
        assert_eq!(created.tree, test_tree());
        assert_eq!(
            created.prepared.input_utxos.len(),
            MERGE_DEFAULT_INPUT_COUNT
        );
        assert_eq!(created.prepared.output_utxo.amount, 60);
    }
}
