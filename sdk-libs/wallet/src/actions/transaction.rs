use std::collections::BTreeSet;
use zolana_client::timing;

use solana_pubkey::Pubkey;
use zolana_interface::{
    instruction::{
        TransactInterfaceTransferAccounts, TransactSolTransferAccounts,
        TransactSplWithdrawalAccounts,
    },
    pda,
    shape::Shape,
    MAX_INTERFACE_TRANSFERS, SPL_TOKEN_2022_PROGRAM_ID, SPL_TOKEN_PROGRAM_ID,
};
use zolana_keypair::{shielded::ShieldedAddress, viewing_key::ViewTag, ShieldedKeypair};
use zolana_transaction::{
    instructions::{
        merge::{Merge, PreparedMerge, MERGE_INPUTS},
        transact::{
            ConfidentialSplit, ConfidentialTransfer, PreparedSplit, PreparedTransfer,
            SettlementTarget, SppProofInputs,
        },
        types::SppProofInputUtxo,
    },
    Address, AssetRegistry, TransactionError, Utxo, Wallet, WalletUtxo, SOL_MINT,
};

use solana_signer::Signer;
use solana_transaction::Transaction as SolanaTransaction;

use crate::{
    user_registry::{try_resolve_registered_address, try_resolve_registered_address_async},
    wallet_authority::{ApprovalRequest, SyncWalletAuthority, WalletAuthority},
};
use zolana_client::{
    client::ZolanaClient,
    error::ClientError,
    rpc::{AsyncRpc, Rpc},
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
    inputs: Vec<UnsignedSpendInput>,
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
struct UnsignedSpendInput {
    utxo: Utxo,
    utxo_hash: [u8; 32],
    nullifier: [u8; 32],
    data_hash: Option<[u8; 32]>,
    ring_data_hash: Option<[u8; 32]>,
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
    let tree = resolve_spend_tree(request.wallet, request.asset, |_| true)?;
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
    let inputs = select_inputs(request.wallet, tree, request.asset, request.amount)?;
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
    // `ConfidentialSplit::new` re-checks the same bound at sign time.
    let max_parts = Shape::IN1_OUT8.n_outputs() as u8;
    if !(2..=max_parts).contains(&request.parts) {
        return Err(TransactionError::SplitInvalidPartCount {
            num_outputs: request.parts,
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
) -> Result<(UnsignedSpendInput, u64), ClientError> {
    let parts_u64 = u64::from(parts);
    let candidate = match input {
        Some(hash) => {
            let entry = wallet
                .utxos
                .iter()
                .find(|entry| {
                    !entry.spent && entry.utxo.asset == asset && entry.output_context.hash == hash
                })
                .ok_or(ClientError::InputUtxoUnavailable { hash })?;
            // The utxo exists but lives on another tree: report the mismatch
            // rather than "unavailable", which the owner can see is untrue in
            // their own `wallet utxos` listing.
            if entry.output_context.tree != tree {
                return Err(ClientError::InputUtxoTreeMismatch {
                    hash,
                    utxo_tree: entry.output_context.tree,
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
            for entry in wallet.utxos.iter().filter(|entry| {
                !entry.spent
                    && entry.utxo.asset == asset
                    && entry.output_context.tree == tree
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

    let hash = candidate.output_context.hash;
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

    Ok((
        UnsignedSpendInput {
            utxo: candidate.utxo.clone(),
            utxo_hash: hash,
            nullifier: candidate.nullifier,
            data_hash: candidate.data_hash,
            ring_data_hash: candidate.ring_data_hash,
        },
        amount / parts_u64,
    ))
}

/// A prepared merge plus what a caller needs to report the outcome: how many real
/// utxos are consolidated, their summed amount, and the single spend tree the
/// merge binds.
pub struct CreatedMerge {
    pub prepared: PreparedMerge,
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

/// Build an up-to-8-in/1-out consolidation of same-owner, same-asset plain utxos
/// on one spend tree. Unlike a transfer, merge proves ownership in-circuit from
/// the keypair's nullifier secret and encrypts the single output to the owner's
/// viewing key, so it does not build an [`UnsignedPrivateTransaction`] or take an
/// authority signing step; the keypair is threaded straight to submission.
pub fn create_merge(request: MergeParams<'_>) -> Result<CreatedMerge, ClientError> {
    // Explicitly named inputs bind the spend to the first named utxo's tree
    // (the rest must match it), so `Merge::new` can report precise per-input
    // reasons; auto-sweep resolves the tree over the eligible (plain) utxos.
    let tree = match request.inputs.as_ref().and_then(|hashes| hashes.first()) {
        Some(&hash) => named_input_tree(request.wallet, request.asset, hash)?,
        None => resolve_spend_tree(request.wallet, request.asset, is_plain_utxo)?,
    };
    let inputs = select_merge_inputs(
        request.wallet,
        tree,
        request.asset,
        request.keypair,
        request.inputs,
    )?;
    let num_inputs = inputs.len();
    // `Merge::new` re-validates every input against the keypair (owner, nullifier
    // key, rail, asset), rejects ring-bound or data-carrying utxos, and sums the
    // inputs into the single output amount (same overflow error).
    let prepared = Merge::new(request.keypair, inputs)?.prepare();
    Ok(CreatedMerge {
        merged_amount: prepared.output.amount,
        prepared,
        num_inputs,
        tree,
    })
}

/// Whether a wallet utxo is plain: no ring binding and no attached data. Only
/// plain utxos are mergeable or splittable; building a spend input drops the
/// utxo's committed data hashes, which would desync the commitment from the tree
/// otherwise. Option semantics: a `Some(_)` hash counts as data regardless of the
/// hash value. Public so the CLI's `utxos` listing classifies `kind` with the
/// exact predicate split/merge enforce, and the two cannot drift.
pub fn is_plain_utxo(entry: &WalletUtxo) -> bool {
    entry.utxo.ring_program_id.is_none()
        && entry.ring_data_hash.is_none()
        && entry.data_hash.is_none()
        && entry.utxo.data.is_empty()
}

/// Build the spend input for a wallet utxo, preserving any committed data hashes
/// so `Merge::new` can reject a non-plain utxo by hash rather than silently
/// mismatching the tree commitment.
fn merge_spend_input(entry: &WalletUtxo, keypair: &ShieldedKeypair) -> SppProofInputUtxo {
    let mut spend = SppProofInputUtxo::new(entry.utxo.clone(), keypair);
    if let Some(data_hash) = entry.data_hash {
        spend = spend.with_data_hash(data_hash);
    }
    if let Some(ring_data_hash) = entry.ring_data_hash {
        spend = spend.with_ring_data_hash(ring_data_hash);
    }
    spend
}

/// Select the utxos a merge consolidates on `tree`. `None` auto-sweeps up to
/// [`MERGE_INPUTS`] of the smallest plain utxos of `asset` (ascending, dust
/// first). `Some(hashes)` takes exactly the named utxos: 2..=8 distinct, unspent
/// utxos of `asset` on `tree`; a non-plain named utxo is left for `Merge::new` to
/// reject with a precise reason.
fn select_merge_inputs(
    wallet: &Wallet,
    tree: Address,
    asset: Address,
    keypair: &ShieldedKeypair,
    inputs: Option<Vec<[u8; 32]>>,
) -> Result<Vec<SppProofInputUtxo>, ClientError> {
    match inputs {
        None => {
            let mut candidates: Vec<&WalletUtxo> = wallet
                .utxos
                .iter()
                .filter(|entry| {
                    !entry.spent
                        && entry.utxo.asset == asset
                        && entry.output_context.tree == tree
                        && is_plain_utxo(entry)
                })
                .collect();
            // Smallest first: a sweep clears dust and leaves large utxos intact.
            candidates.sort_by_key(|entry| entry.utxo.amount);
            candidates.truncate(MERGE_INPUTS);
            if candidates.len() < 2 {
                return Err(ClientError::NothingToMerge { asset });
            }
            Ok(candidates
                .into_iter()
                .map(|entry| merge_spend_input(entry, keypair))
                .collect())
        }
        Some(hashes) => {
            if hashes.len() > MERGE_INPUTS {
                return Err(ClientError::TooManyInputs {
                    got: hashes.len(),
                    max: MERGE_INPUTS,
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
                    .utxos
                    .iter()
                    .find(|entry| {
                        !entry.spent
                            && entry.utxo.asset == asset
                            && entry.output_context.hash == hash
                    })
                    .ok_or(ClientError::InputUtxoUnavailable { hash })?;
                // Distinguish a wrong-tree utxo from an unknown one; the owner
                // can see the hash in their own `wallet utxos` listing.
                if entry.output_context.tree != tree {
                    return Err(ClientError::InputUtxoTreeMismatch {
                        hash,
                        utxo_tree: entry.output_context.tree,
                        spend_tree: tree,
                    });
                }
                selected.push(merge_spend_input(entry, keypair));
            }
            Ok(selected)
        }
    }
}

pub async fn build_private_transaction<A: WalletAuthority + ?Sized, R: AsyncRpc>(
    transaction: UnsignedPrivateTransaction,
    wallet: &Wallet,
    authority: &A,
    client: &ZolanaClient<R>,
    fee_payer: Pubkey,
) -> Result<SolanaTransaction, ClientError> {
    let shielded = sign_shielded_transaction(transaction, wallet, authority).await?;
    let (blockhash, _) = client.rpc().get_latest_blockhash().await?;
    client
        .finish_submission_unsigned(&shielded, fee_payer, blockhash)
        .await
}

pub async fn sign_private_transaction<A: WalletAuthority + ?Sized, R: AsyncRpc>(
    transaction: UnsignedPrivateTransaction,
    wallet: &Wallet,
    authority: &A,
    client: &ZolanaClient<R>,
    fee_payer: &dyn Signer,
) -> Result<SolanaTransaction, ClientError> {
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
) -> Result<SolanaTransaction, ClientError> {
    let blockhash = client.rpc().get_latest_blockhash().await?.0;
    let shielded = sign_shielded_transaction(transaction, wallet, authority).await?;
    let mut native = client
        .finish_submission_unsigned(&shielded, fee_payer.pubkey(), blockhash)
        .await?;
    let mut signers = Vec::with_capacity(1 + additional_native_signers.len());
    signers.push(fee_payer);
    signers.extend_from_slice(additional_native_signers);
    native
        .try_sign(&signers, blockhash)
        .map_err(|err| ClientError::SolanaTransactionSigning(err.to_string()))?;
    Ok(native)
}

pub fn build_private_transaction_sync<A: SyncWalletAuthority + ?Sized, R: Rpc + Sync>(
    transaction: UnsignedPrivateTransaction,
    wallet: &Wallet,
    authority: &A,
    client: &ZolanaClient<R>,
    fee_payer: Pubkey,
) -> Result<SolanaTransaction, ClientError> {
    let shielded = sign_shielded_transaction_sync(transaction, wallet, authority)?;
    client.finish_submission_unsigned_sync(&shielded, fee_payer)
}

pub fn sign_private_transaction_sync<A: SyncWalletAuthority + ?Sized, R: Rpc + Sync>(
    transaction: UnsignedPrivateTransaction,
    wallet: &Wallet,
    authority: &A,
    client: &ZolanaClient<R>,
    fee_payer: &dyn Signer,
) -> Result<SolanaTransaction, ClientError> {
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
) -> Result<SolanaTransaction, ClientError> {
    let shielded = {
        let _t = timing::Phase::start("sign_shielded", 0);
        sign_shielded_transaction_sync(transaction, wallet, authority)?
    };
    let mut native = {
        let _t = timing::Phase::start("finish_submission", 0);
        client.finish_submission_unsigned_sync(&shielded, fee_payer.pubkey())?
    };
    // Whatever the built message carries: it is fetched after proving now, so
    // there is no separate blockhash here to keep in step with it.
    let blockhash = native.message.recent_blockhash;
    let mut signers = Vec::with_capacity(1 + additional_native_signers.len());
    signers.push(fee_payer);
    signers.extend_from_slice(additional_native_signers);
    native
        .try_sign(&signers, blockhash)
        .map_err(|err| ClientError::SolanaTransactionSigning(err.to_string()))?;
    Ok(native)
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
    let inputs = transaction
        .inputs
        .into_iter()
        .map(|input| SppProofInputUtxo {
            utxo: input.utxo,
            nullifier_key: nullifier_key.clone(),
            data_hash: input.data_hash,
            ring_data_hash: input.ring_data_hash,
        })
        .collect();
    let signed = match transaction.action {
        PrivateTransactionAction::Transfer {
            recipient,
            asset,
            amount,
        } => {
            let mut tx = ConfidentialTransfer::new(address, inputs, transaction.payer);
            tx.send(&recipient, asset, amount)?;
            let prepared = tx.prepare()?;
            sign_prepared(
                prepared,
                authority,
                &wallet.registry,
                transaction.approval_summary,
            )
            .await?
        }
        PrivateTransactionAction::Withdrawal { legs } => {
            let mut tx = ConfidentialTransfer::new(address, inputs, transaction.payer);
            for leg in legs {
                tx.withdraw(leg.asset, leg.amount, leg.target)?;
            }
            let prepared = tx.prepare()?;
            sign_prepared(
                prepared,
                authority,
                &wallet.registry,
                transaction.approval_summary,
            )
            .await?
        }
        PrivateTransactionAction::Split {
            asset,
            num_outputs,
            per_output_amount,
        } => {
            let input = inputs.into_iter().next().ok_or(ClientError::NoInputs)?;
            let split = ConfidentialSplit::new(
                address,
                input,
                asset,
                num_outputs,
                per_output_amount,
                transaction.payer,
            )?;
            let prepared = split.prepare()?;
            sign_prepared_split(
                prepared,
                authority,
                &wallet.registry,
                transaction.approval_summary,
            )
            .await?
        }
    };
    Ok(SignedPrivateTransaction {
        transaction: signed,
        settlement_transfers: transaction.settlement_transfers,
        input_tree: transaction.tree,
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

async fn sign_prepared<A: WalletAuthority + ?Sized>(
    prepared: PreparedTransfer,
    authority: &A,
    assets: &AssetRegistry,
    approval_summary: String,
) -> Result<SppProofInputs, ClientError> {
    let encrypted = authority
        .encrypt_confidential_transfer(&prepared.first_nullifier, &prepared.outputs, assets)
        .await?;
    authority
        .request_user_approval(ApprovalRequest {
            solana_pubkey: authority.solana_pubkey(),
            summary: approval_summary,
        })
        .await?;
    let proof_inputs =
        prepared.finalize(encrypted.tx_viewing_pk, encrypted.salt, encrypted.payload)?;
    Ok(proof_inputs)
}

async fn sign_prepared_split<A: WalletAuthority + ?Sized>(
    prepared: PreparedSplit,
    authority: &A,
    assets: &AssetRegistry,
    approval_summary: String,
) -> Result<SppProofInputs, ClientError> {
    let bundle = prepared.bundle_plaintext(assets)?;
    let view_tag = prepared.owner_view_tag()?;
    let encrypted = authority
        .encrypt_split(&prepared.first_nullifier, view_tag, &bundle)
        .await?;
    authority
        .request_user_approval(ApprovalRequest {
            solana_pubkey: authority.solana_pubkey(),
            summary: approval_summary,
        })
        .await?;
    let proof_inputs =
        prepared.finalize(encrypted.tx_viewing_pk, encrypted.salt, encrypted.payload)?;
    Ok(proof_inputs)
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
            spl_token_interface: Address::new_from_array(vault.to_bytes()),
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
) -> Result<(Address, Vec<UnsignedSpendInput>), ClientError> {
    let (first_asset, _) = required
        .first()
        .copied()
        .ok_or(TransactionError::NoInterfaceTransfers)?;
    let tree = resolve_spend_tree(wallet, first_asset, |_| true)?;
    let mut inputs = Vec::new();

    for (asset, amount) in required {
        let asset_tree = resolve_spend_tree(wallet, *asset, |_| true)?;
        if asset_tree != tree {
            let hash = wallet
                .utxos
                .iter()
                .find(|entry| {
                    !entry.spent
                        && entry.utxo.asset == *asset
                        && entry.output_context.tree == asset_tree
                })
                .map(|entry| entry.output_context.hash)
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
        inputs.extend(select_inputs(wallet, tree, *asset, *amount)?);
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
        .utxos
        .iter()
        .find(|entry| {
            !entry.spent && entry.utxo.asset == asset && entry.output_context.hash == hash
        })
        .map(|entry| entry.output_context.tree)
        .ok_or(ClientError::InputUtxoUnavailable { hash })
}

/// Resolve the single tree a spend of `asset` binds, considering only the utxos
/// `eligible` accepts. Transfers and withdrawals can spend any utxo; split and
/// merge only plain ones, so an ineligible ring-bound or data-carrying utxo
/// sitting on another tree must not make their spend tree ambiguous.
fn resolve_spend_tree(
    wallet: &Wallet,
    asset: Address,
    eligible: impl Fn(&WalletUtxo) -> bool,
) -> Result<Address, ClientError> {
    let trees: BTreeSet<Address> = wallet
        .utxos
        .iter()
        .filter(|entry| !entry.spent && entry.utxo.asset == asset && eligible(entry))
        .map(|entry| entry.output_context.tree)
        .collect();

    match trees.len() {
        0 => Err(ClientError::InsufficientBalance {
            requested: 1,
            available: 0,
        }),
        1 => Ok(*trees.iter().next().expect("single tree")),
        tree_count => Err(ClientError::AmbiguousTree { asset, tree_count }),
    }
}

fn select_inputs(
    wallet: &Wallet,
    tree: Address,
    asset: Address,
    amount: u64,
) -> Result<Vec<UnsignedSpendInput>, ClientError> {
    let mut selected = Vec::new();
    let mut available = 0u64;
    // A ring-bound utxo commits to its ring, and this circuit does not cover
    // that binding. Selecting one produces a witness the prover refuses, which
    // reads as a prover failure rather than a wrong input; spend it through the
    // ring's own path instead. Split and merge already refuse one by way of
    // `is_plain_utxo`.
    for entry in wallet.utxos.iter().filter(|entry| {
        !entry.spent
            && entry.utxo.asset == asset
            && entry.output_context.tree == tree
            && entry.utxo.ring_program_id.is_none()
    }) {
        selected.push(UnsignedSpendInput {
            utxo: entry.utxo.clone(),
            utxo_hash: entry.output_context.hash,
            nullifier: entry.nullifier,
            data_hash: entry.data_hash,
            ring_data_hash: entry.ring_data_hash,
        });
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
    inputs: &[UnsignedSpendInput],
) -> Result<(), ClientError> {
    for (index, input) in inputs.iter().enumerate() {
        let available = wallet.utxos.iter().any(|entry| {
            !entry.spent
                && entry.output_context.tree == tree
                && entry.output_context.hash == input.utxo_hash
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
    use zolana_keypair::{ShieldedKeypair, SigningKey};
    use zolana_transaction::{
        instructions::transact::SettlementTransfer, Data, DataRecord, Utxo, WalletUtxo,
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
            asset,
            amount,
            blinding,
            ring_program_id: None,
            data: Data::default(),
        };
        let nullifier_pk = keypair.nullifier_key.pubkey().expect("nullifier pubkey");
        let hash = utxo
            .hash(&nullifier_pk, &[0u8; 32], &[0u8; 32])
            .expect("utxo hash");
        let nullifier = utxo
            .nullifier(&hash, &keypair.nullifier_key)
            .expect("nullifier");
        wallet.utxos.push(WalletUtxo {
            utxo,
            output_context: zolana_transaction::instructions::transact::types::OutputContext {
                hash,
                tree: Address::default(),
                leaf_index: 0,
            },
            nullifier,
            data_hash: None,
            ring_data_hash: None,
            spent: false,
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
        let second_tree = Address::new_from_array([9u8; 32]);
        let mut spl_input = wallet_with_asset(sender, asset, 10)
            .utxos
            .into_iter()
            .next()
            .expect("SPL input");
        spl_input.output_context.tree = second_tree;
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
            } if utxo_tree == second_tree && spend_tree == Address::default()
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
        if let Some(entry) = wallet.utxos.first_mut() {
            entry.spent = true;
        }

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
            .hash(&nullifier_pubkey, &data_hash, &[0u8; 32])
            .unwrap();
        let nullifier = entry.utxo.nullifier(&hash, &sender.nullifier_key).unwrap();
        {
            let entry = wallet.utxos.first_mut().expect("wallet utxo");
            entry.output_context.hash = hash;
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
        let second_tree = Address::new_from_array([9u8; 32]);
        let mut wallet = wallet_with_sol(sender.clone(), 10);
        if let Some(entry) = wallet.utxos.first_mut() {
            entry.output_context.tree = second_tree;
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

        let tree = resolve_spend_tree(&wallet, SOL_MINT, |_| true).expect("infer tree");

        assert_eq!(tree, Address::default());
    }

    #[test]
    fn resolve_spend_tree_errors_when_balance_spans_multiple_trees() {
        let sender = ShieldedKeypair::new_p256().unwrap();
        let mut wallet = wallet_with_sol(sender.clone(), 4);
        let second_tree = Address::new_from_array([9u8; 32]);
        let mut second = wallet_with_sol(sender, 10).utxos.remove(0);
        second.output_context.tree = second_tree;
        wallet.utxos.push(second);

        let error = match resolve_spend_tree(&wallet, SOL_MINT, |_| true) {
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

        assert_eq!(created.transaction.tree(), Address::default());
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
        let hash = wallet
            .utxos
            .first()
            .expect("seeded utxo")
            .output_context
            .hash;
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
        let hash = wallet
            .utxos
            .first()
            .expect("seeded utxo")
            .output_context
            .hash;
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
            asset: SOL_MINT,
            amount,
            blinding: canonical_blinding,
            ring_program_id: None,
            data: Data::default(),
        };
        let nullifier_pk = keypair.nullifier_key.pubkey().expect("nullifier pubkey");
        let hash = utxo
            .hash(&nullifier_pk, &[0u8; 32], &[0u8; 32])
            .expect("utxo hash");
        let nullifier = utxo
            .nullifier(&hash, &keypair.nullifier_key)
            .expect("nullifier");
        wallet.utxos.push(WalletUtxo {
            utxo,
            output_context: zolana_transaction::instructions::transact::types::OutputContext {
                hash,
                tree: Address::default(),
                leaf_index: 0,
            },
            nullifier,
            data_hash: None,
            ring_data_hash: None,
            spent: false,
        });
        hash
    }

    fn amounts(selected: &[SppProofInputUtxo]) -> Vec<u64> {
        selected.iter().map(|spend| spend.utxo.amount).collect()
    }

    #[test]
    fn merge_auto_sweep_selects_smallest_plain_utxos_ascending() {
        let keypair = ShieldedKeypair::new_p256().unwrap();
        let mut wallet = sol_wallet(&keypair);
        for (index, amount) in [50u64, 10, 30].into_iter().enumerate() {
            push_utxo(&mut wallet, &keypair, amount, [index as u8 + 1; 31]);
        }

        let selected =
            select_merge_inputs(&wallet, Address::default(), SOL_MINT, &keypair, None).unwrap();

        assert_eq!(amounts(&selected), vec![10, 30, 50]);
    }

    #[test]
    fn merge_auto_sweep_caps_at_shape_keeping_the_smallest_utxos() {
        let keypair = ShieldedKeypair::new_p256().unwrap();
        let mut wallet = sol_wallet(&keypair);
        for step in 1..=9u64 {
            push_utxo(&mut wallet, &keypair, step * 10, [step as u8; 31]);
        }

        let selected =
            select_merge_inputs(&wallet, Address::default(), SOL_MINT, &keypair, None).unwrap();

        assert_eq!(selected.len(), MERGE_INPUTS);
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

        let selected =
            select_merge_inputs(&wallet, Address::default(), SOL_MINT, &keypair, None).unwrap();

        assert_eq!(amounts(&selected), vec![10, 20]);
    }

    #[test]
    fn merge_auto_sweep_needs_at_least_two_utxos() {
        let keypair = ShieldedKeypair::new_p256().unwrap();
        let mut wallet = sol_wallet(&keypair);
        push_utxo(&mut wallet, &keypair, 10, [1u8; 31]);

        let error = match select_merge_inputs(&wallet, Address::default(), SOL_MINT, &keypair, None)
        {
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

        let selected = select_merge_inputs(
            &wallet,
            Address::default(),
            SOL_MINT,
            &keypair,
            Some(vec![a, b]),
        )
        .unwrap();

        assert_eq!(amounts(&selected), vec![10, 20]);
    }

    #[test]
    fn merge_explicit_selection_rejects_duplicate_utxos() {
        let keypair = ShieldedKeypair::new_p256().unwrap();
        let mut wallet = sol_wallet(&keypair);
        let a = push_utxo(&mut wallet, &keypair, 10, [1u8; 31]);

        let error = match select_merge_inputs(
            &wallet,
            Address::default(),
            SOL_MINT,
            &keypair,
            Some(vec![a, a]),
        ) {
            Err(error) => error,
            Ok(_) => panic!("a repeated utxo must be rejected"),
        };

        assert!(matches!(error, ClientError::DuplicateInputUtxo { hash } if hash == a));
    }

    #[test]
    fn merge_explicit_selection_rejects_more_than_the_shape() {
        let keypair = ShieldedKeypair::new_p256().unwrap();
        let wallet = sol_wallet(&keypair);
        let hashes: Vec<[u8; 32]> = (0..9u8).map(|i| [i; 32]).collect();

        let error = match select_merge_inputs(
            &wallet,
            Address::default(),
            SOL_MINT,
            &keypair,
            Some(hashes),
        ) {
            Err(error) => error,
            Ok(_) => panic!("more than 8 inputs must be rejected"),
        };

        assert!(matches!(
            error,
            ClientError::TooManyInputs {
                got: 9,
                max: MERGE_INPUTS
            }
        ));
    }

    #[test]
    fn merge_explicit_selection_needs_at_least_two_utxos() {
        let keypair = ShieldedKeypair::new_p256().unwrap();
        let mut wallet = sol_wallet(&keypair);
        let a = push_utxo(&mut wallet, &keypair, 10, [1u8; 31]);

        let error = match select_merge_inputs(
            &wallet,
            Address::default(),
            SOL_MINT,
            &keypair,
            Some(vec![a]),
        ) {
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

        let error = match select_merge_inputs(
            &wallet,
            Address::default(),
            SOL_MINT,
            &keypair,
            Some(vec![a, missing]),
        ) {
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
        let other_tree = Address::new_from_array([9u8; 32]);
        wallet
            .utxos
            .iter_mut()
            .find(|entry| entry.output_context.hash == b)
            .expect("pushed utxo")
            .output_context
            .tree = other_tree;

        let error = match select_merge_inputs(
            &wallet,
            Address::default(),
            SOL_MINT,
            &keypair,
            Some(vec![a, b]),
        ) {
            Err(error) => error,
            Ok(_) => panic!("a wrong-tree utxo must be rejected"),
        };

        assert!(matches!(
            error,
            ClientError::InputUtxoTreeMismatch { hash, utxo_tree, spend_tree }
                if hash == b && utxo_tree == other_tree && spend_tree == Address::default()
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

        let (input, per_output) = select_split_utxo(&wallet, Address::default(), SOL_MINT, 2, None)
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

        let error = match select_split_utxo(&wallet, Address::default(), SOL_MINT, 3, None) {
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

    /// A ring-bound utxo commits to its ring; the default-ring circuit does not
    /// cover that binding. Selecting one builds a witness the prover refuses,
    /// which surfaces as a prover failure rather than a wrong input, so the
    /// balance has to look unavailable here instead.
    #[test]
    fn select_inputs_leaves_ring_bound_utxos_to_the_ring_path() {
        let keypair = ShieldedKeypair::new_p256().unwrap();
        let mut wallet = sol_wallet(&keypair);
        push_utxo(&mut wallet, &keypair, 10, [1u8; 31]);
        let ring_bound = push_utxo(&mut wallet, &keypair, 100, [2u8; 31]);
        let entry = wallet
            .utxos
            .iter_mut()
            .find(|entry| entry.output_context.hash == ring_bound)
            .expect("pushed utxo");
        entry.utxo.ring_program_id = Some(Address::new_from_array([7u8; 32]));

        // The plain utxo alone covers this.
        let selected = select_inputs(&wallet, Address::default(), SOL_MINT, 10)
            .expect("a plain utxo covers the amount");
        assert_eq!(selected.len(), 1);
        assert!(selected
            .iter()
            .all(|input| input.utxo.ring_program_id.is_none()));

        // The ring-bound 100 must not be reachable, even though it would cover
        // the amount on its own.
        assert!(matches!(
            select_inputs(&wallet, Address::default(), SOL_MINT, 50),
            Err(ClientError::InsufficientBalance {
                requested: 50,
                available: 10
            })
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
        let entry = wallet
            .utxos
            .iter_mut()
            .find(|entry| entry.output_context.hash == ring_bound)
            .expect("pushed utxo");
        entry.output_context.tree = Address::new_from_array([9u8; 32]);
        entry.utxo.ring_program_id = Some(Address::new_from_array([7u8; 32]));

        let tree = resolve_spend_tree(&wallet, SOL_MINT, is_plain_utxo)
            .expect("the ring utxo on another tree must not block a plain spend");

        assert_eq!(tree, Address::default());
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
        assert_eq!(created.tree, Address::default());
        assert_eq!(created.prepared.inputs.len(), MERGE_INPUTS);
        assert_eq!(created.prepared.output.amount, 60);
    }
}
