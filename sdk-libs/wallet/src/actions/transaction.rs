use std::collections::BTreeSet;

use solana_pubkey::Pubkey;
use zolana_interface::{
    instruction::{TransactSolWithdrawal, TransactSplWithdrawal, TransactWithdrawal},
    pda,
    shape::Shape,
    SPL_TOKEN_PROGRAM_ID,
};
use zolana_keypair::{
    shielded::ShieldedAddress, viewing_key::ViewTag, ShieldedKeypair, SignatureType,
};
use zolana_transaction::{
    instructions::{
        merge::{Merge, PreparedMerge, MERGE_INPUTS},
        transact::{
            ConfidentialSplit, ConfidentialTransfer, PreparedSplit, PreparedTransfer,
            SppProofInputs, WithdrawalTarget,
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
        withdrawal: TransactWithdrawal,
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

    pub fn withdrawal(&self) -> Option<&TransactWithdrawal> {
        match self {
            Self::Registered(_) => None,
            Self::PublicWithdrawal { withdrawal, .. } => Some(withdrawal),
        }
    }
}

#[derive(Clone)]
pub struct CreatedWithdrawal {
    pub transaction: UnsignedPrivateTransaction,
    pub withdrawal: TransactWithdrawal,
}

#[derive(Clone)]
pub struct UnsignedPrivateTransaction {
    payer: Address,
    tree: Address,
    inputs: Vec<UnsignedSpendInput>,
    action: PrivateTransactionAction,
    withdrawal: Option<TransactWithdrawal>,
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
}

#[derive(Clone)]
struct UnsignedSpendInput {
    utxo: Utxo,
    utxo_hash: [u8; 32],
    nullifier: [u8; 32],
    data_hash: Option<[u8; 32]>,
    zone_data_hash: Option<[u8; 32]>,
}

#[derive(Clone)]
enum PrivateTransactionAction {
    Transfer {
        recipient: ShieldedAddress,
        asset: Address,
        amount: u64,
    },
    Withdrawal {
        asset: Address,
        amount: u64,
        target: WithdrawalTarget,
    },
    Split {
        asset: Address,
        num_outputs: u8,
        per_output_amount: u64,
    },
}

pub struct TransferParams<'a, R> {
    pub rpc: &'a R,
    pub wallet: &'a Wallet,
    pub payer: Address,
    pub recipient: Pubkey,
    pub asset: Address,
    pub amount: u64,
}

pub struct WithdrawalParams<'a> {
    pub wallet: &'a Wallet,
    pub payer: Address,
    pub recipient: Pubkey,
    pub asset: Address,
    pub amount: u64,
}

pub async fn create_transfer<R: AsyncRpc>(
    request: TransferParams<'_, R>,
) -> Result<CreatedTransfer, ClientError> {
    let recipient = try_resolve_registered_address_async(request.rpc, request.recipient).await?;
    create_transfer_with_recipient(request, recipient)
}

pub fn create_transfer_sync<R: Rpc>(
    request: TransferParams<'_, R>,
) -> Result<CreatedTransfer, ClientError> {
    let recipient = try_resolve_registered_address(request.rpc, request.recipient)?;
    create_transfer_with_recipient(request, recipient)
}

fn create_transfer_with_recipient<R>(
    request: TransferParams<'_, R>,
    recipient: Option<ResolvedAddress>,
) -> Result<CreatedTransfer, ClientError> {
    let tree = resolve_spend_tree(request.wallet, request.asset)?;
    let Some(recipient) = recipient else {
        let withdrawal = create_withdrawal(WithdrawalParams {
            wallet: request.wallet,
            payer: request.payer,
            recipient: request.recipient,
            asset: request.asset,
            amount: request.amount,
        })?;
        return Ok(CreatedTransfer {
            transaction: withdrawal.transaction,
            recipient: TransferRecipient::PublicWithdrawal {
                recipient: request.recipient,
                withdrawal: withdrawal.withdrawal,
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
            withdrawal: None,
            approval_summary: format!(
                "private transaction transfer of {} to {}",
                request.amount, request.recipient
            ),
        },
        recipient: TransferRecipient::Registered(recipient),
    })
}

pub fn create_withdrawal(request: WithdrawalParams<'_>) -> Result<CreatedWithdrawal, ClientError> {
    let tree = resolve_spend_tree(request.wallet, request.asset)?;
    let inputs = select_inputs(request.wallet, tree, request.asset, request.amount)?;
    let (target, withdrawal) = withdrawal_target(request.recipient, request.asset)?;
    Ok(CreatedWithdrawal {
        transaction: UnsignedPrivateTransaction {
            payer: request.payer,
            tree,
            inputs,
            action: PrivateTransactionAction::Withdrawal {
                asset: request.asset,
                amount: request.amount,
                target,
            },
            withdrawal: Some(withdrawal),
            approval_summary: format!(
                "private transaction withdrawal of {} to {}",
                request.amount, request.recipient
            ),
        },
        withdrawal,
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
/// asset on the single spend tree. The utxo must be plain (no zone binding, no
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
    let tree = resolve_spend_tree(request.wallet, request.asset)?;
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
            withdrawal: None,
            approval_summary: format!(
                "private transaction split into {num_outputs} utxos of {per_output_amount}"
            ),
        },
        num_outputs,
        per_output_amount,
    })
}

/// Select and validate the single input utxo a split spends, returning it with
/// the per-output amount. Rejects utxos carrying zone bindings or data, and
/// amounts that do not divide evenly into `parts`.
fn select_split_utxo(
    wallet: &Wallet,
    tree: Address,
    asset: Address,
    parts: u8,
    input: Option<[u8; 32]>,
) -> Result<(UnsignedSpendInput, u64), ClientError> {
    let candidate = match input {
        Some(hash) => wallet
            .utxos
            .iter()
            .find(|entry| {
                !entry.spent
                    && entry.utxo.asset == asset
                    && entry.output_context.tree == tree
                    && entry.output_context.hash == hash
            })
            .ok_or(ClientError::InputUtxoUnavailable { hash })?,
        None => wallet
            .utxos
            .iter()
            .filter(|entry| {
                !entry.spent && entry.utxo.asset == asset && entry.output_context.tree == tree
            })
            .max_by_key(|entry| entry.utxo.amount)
            .ok_or(ClientError::InsufficientBalance {
                requested: 1,
                available: 0,
            })?,
    };

    let hash = candidate.output_context.hash;
    if candidate.utxo.zone_program_id.is_some() {
        return Err(ClientError::SplitInputZoneMismatch { hash });
    }
    if !is_plain_utxo(candidate) {
        return Err(ClientError::SplitInputHasData { hash });
    }

    let amount = candidate.utxo.amount;
    let parts_u64 = u64::from(parts);
    if parts == 0 || amount % parts_u64 != 0 {
        return Err(ClientError::SplitNotDivisible { amount, parts });
    }

    Ok((
        UnsignedSpendInput {
            utxo: candidate.utxo.clone(),
            utxo_hash: hash,
            nullifier: candidate.nullifier,
            data_hash: candidate.data_hash,
            zone_data_hash: candidate.zone_data_hash,
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
    let tree = resolve_spend_tree(request.wallet, request.asset)?;
    let inputs = select_merge_inputs(
        request.wallet,
        tree,
        request.asset,
        request.keypair,
        request.inputs,
    )?;
    let num_inputs = inputs.len();
    // `Merge::new` re-validates every input against the keypair (owner, nullifier
    // key, rail, asset), rejects zone-bound or data-carrying utxos, and sums the
    // inputs into the single output amount (same overflow error).
    let prepared = Merge::new(request.keypair, inputs)?.prepare();
    Ok(CreatedMerge {
        merged_amount: prepared.output.amount,
        prepared,
        num_inputs,
        tree,
    })
}

/// Whether a wallet utxo is plain: no zone binding and no attached data. Only
/// plain utxos are mergeable or splittable; building a spend input drops the
/// utxo's committed data hashes, which would desync the commitment from the tree
/// otherwise. Option semantics: a `Some(_)` hash counts as data regardless of the
/// hash value.
fn is_plain_utxo(entry: &WalletUtxo) -> bool {
    entry.utxo.zone_program_id.is_none()
        && entry.zone_data_hash.is_none()
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
    if let Some(zone_data_hash) = entry.zone_data_hash {
        spend = spend.with_zone_data_hash(zone_data_hash);
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
                            && entry.output_context.tree == tree
                            && entry.output_context.hash == hash
                    })
                    .ok_or(ClientError::InputUtxoUnavailable { hash })?;
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
    let blockhash = client.rpc().get_latest_blockhash().await?.0;
    let shielded = sign_shielded_transaction(transaction, wallet, authority).await?;
    let mut native = client
        .finish_submission_unsigned(&shielded, fee_payer.pubkey(), blockhash)
        .await?;
    native
        .try_sign(&[fee_payer], blockhash)
        .map_err(|err| ClientError::SolanaTransactionSigning(err.to_string()))?;
    Ok(native)
}

pub fn build_private_transaction_sync<A: SyncWalletAuthority + ?Sized, R: Rpc>(
    transaction: UnsignedPrivateTransaction,
    wallet: &Wallet,
    authority: &A,
    client: &ZolanaClient<R>,
    fee_payer: Pubkey,
) -> Result<SolanaTransaction, ClientError> {
    let shielded = sign_shielded_transaction_sync(transaction, wallet, authority)?;
    let (blockhash, _) = client.rpc().get_latest_blockhash()?;
    client.finish_submission_unsigned_sync(&shielded, fee_payer, blockhash)
}

pub fn sign_private_transaction_sync<A: SyncWalletAuthority + ?Sized, R: Rpc>(
    transaction: UnsignedPrivateTransaction,
    wallet: &Wallet,
    authority: &A,
    client: &ZolanaClient<R>,
    fee_payer: &dyn Signer,
) -> Result<SolanaTransaction, ClientError> {
    let shielded = sign_shielded_transaction_sync(transaction, wallet, authority)?;
    let (blockhash, _) = client.rpc().get_latest_blockhash()?;
    let mut native =
        client.finish_submission_unsigned_sync(&shielded, fee_payer.pubkey(), blockhash)?;
    native
        .try_sign(&[fee_payer], blockhash)
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
            zone_data_hash: input.zone_data_hash,
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
                &address,
                authority,
                &wallet.registry,
                transaction.approval_summary,
            )
            .await?
        }
        PrivateTransactionAction::Withdrawal {
            asset,
            amount,
            target,
        } => {
            let mut tx = ConfidentialTransfer::new(address, inputs, transaction.payer);
            tx.withdraw(asset, amount, target)?;
            let prepared = tx.prepare()?;
            sign_prepared(
                prepared,
                &address,
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
                &address,
                authority,
                &wallet.registry,
                transaction.approval_summary,
            )
            .await?
        }
    };
    Ok(SignedPrivateTransaction {
        transaction: signed,
        withdrawal: transaction.withdrawal,
        tree: transaction.tree,
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
    address: &ShieldedAddress,
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
    let mut proof_inputs =
        prepared.finalize(encrypted.tx_viewing_pk, encrypted.salt, encrypted.slots)?;
    apply_p256_signature(&mut proof_inputs, address, authority).await?;
    Ok(proof_inputs)
}

async fn sign_prepared_split<A: WalletAuthority + ?Sized>(
    prepared: PreparedSplit,
    address: &ShieldedAddress,
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
    let mut proof_inputs =
        prepared.finalize(encrypted.tx_viewing_pk, encrypted.salt, encrypted.bundle)?;
    apply_p256_signature(&mut proof_inputs, address, authority).await?;
    Ok(proof_inputs)
}

/// P256-rail signing tail shared by [`sign_prepared`] and [`sign_prepared_split`]:
/// when the owner's rail is P256, sign the proof inputs' message hash and pack the
/// r/s signature into the fixed 64-byte field. A no-op for the Solana rail.
async fn apply_p256_signature<A: WalletAuthority + ?Sized>(
    proof_inputs: &mut SppProofInputs,
    address: &ShieldedAddress,
    authority: &A,
) -> Result<(), ClientError> {
    if address.signing_pubkey.signature_type()? == SignatureType::P256 {
        let message_hash = proof_inputs.message_hash()?;
        let sig = authority.sign_p256(&message_hash).await?;
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&sig.sig_r);
        bytes[32..].copy_from_slice(&sig.sig_s);
        proof_inputs.p256_signature = Some(bytes);
    }
    Ok(())
}

fn withdrawal_target(
    recipient: Pubkey,
    asset: Address,
) -> Result<(WithdrawalTarget, TransactWithdrawal), ClientError> {
    if asset == SOL_MINT {
        return Ok((
            WithdrawalTarget::Sol {
                user_sol_account: Address::new_from_array(recipient.to_bytes()),
            },
            TransactWithdrawal::Sol(TransactSolWithdrawal { recipient }),
        ));
    }

    let mint = Pubkey::new_from_array(asset.to_bytes());
    let user_spl_token = pda::associated_token_address(&recipient, &mint);
    let vault = pda::spl_asset_vault(&mint);
    Ok((
        WithdrawalTarget::Spl {
            user_spl_token: Address::new_from_array(user_spl_token.to_bytes()),
            spl_token_interface: Address::new_from_array(vault.to_bytes()),
        },
        TransactWithdrawal::Spl(TransactSplWithdrawal {
            cpi_authority: Some(pda::shielded_pool_cpi_authority()),
            spl_token_interface: vault,
            recipient,
            user_token_account: user_spl_token,
            token_program: Pubkey::new_from_array(SPL_TOKEN_PROGRAM_ID),
        }),
    ))
}

fn resolve_spend_tree(wallet: &Wallet, asset: Address) -> Result<Address, ClientError> {
    let trees: BTreeSet<Address> = wallet
        .utxos
        .iter()
        .filter(|entry| !entry.spent && entry.utxo.asset == asset)
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
    for entry in wallet.utxos.iter().filter(|entry| {
        !entry.spent && entry.utxo.asset == asset && entry.output_context.tree == tree
    }) {
        selected.push(UnsignedSpendInput {
            utxo: entry.utxo.clone(),
            utxo_hash: entry.output_context.hash,
            nullifier: entry.nullifier,
            data_hash: entry.data_hash,
            zone_data_hash: entry.zone_data_hash,
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
                && entry.zone_data_hash == input.zone_data_hash
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
    use zolana_keypair::ShieldedKeypair;
    use zolana_transaction::{Data, DataRecord, Utxo, WalletUtxo};
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
        data
    }

    fn wallet_with_sol(keypair: ShieldedKeypair, amount: u64) -> Wallet {
        wallet_with_asset(keypair, SOL_MINT, amount)
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
        let utxo = Utxo {
            owner: keypair.signing_pubkey(),
            asset,
            amount,
            blinding: [7u8; 31],
            zone_program_id: None,
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
            zone_data_hash: None,
            spent: false,
        });
        wallet
    }

    #[test]
    fn create_transfer_sync_to_registered_recipient_builds_shielded_transfer() {
        let sender = ShieldedKeypair::new().unwrap();
        let recipient = ShieldedKeypair::new().unwrap();
        let owner = Pubkey::new_unique();
        let (record_pda, bump) = user_record_pda(&owner);
        let record = UserRecord {
            owner: owner.to_bytes().into(),
            bump,
            owner_p256: Some(*recipient.signing_pubkey().as_p256().unwrap().as_bytes()),
            nullifier_pubkey: recipient.nullifier_key.pubkey().unwrap(),
            viewing_pubkey: *recipient.viewing_pubkey().as_bytes(),
            sync_delegate: None,
            entries: Vec::new(),
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
        let wallet = wallet_with_sol(sender.clone(), 10);

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
        assert!(result.recipient.withdrawal().is_none());
    }

    #[tokio::test]
    async fn create_transfer_resolves_registered_recipient() {
        let sender = ShieldedKeypair::new().unwrap();
        let recipient = ShieldedKeypair::new().unwrap();
        let owner = Pubkey::new_unique();
        let (record_pda, bump) = user_record_pda(&owner);
        let record = UserRecord {
            owner: owner.to_bytes().into(),
            bump,
            owner_p256: Some(*recipient.signing_pubkey().as_p256().unwrap().as_bytes()),
            nullifier_pubkey: recipient.nullifier_key.pubkey().unwrap(),
            viewing_pubkey: *recipient.viewing_pubkey().as_bytes(),
            sync_delegate: None,
            entries: Vec::new(),
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
        let sender = ShieldedKeypair::new().unwrap();
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
                withdrawal: TransactWithdrawal::Sol(TransactSolWithdrawal { recipient }),
            } if pubkey == recipient
        ));
    }

    #[test]
    fn create_transfer_sync_to_unregistered_recipient_builds_spl_public_withdrawal() {
        let sender = ShieldedKeypair::new().unwrap();
        let mint = Pubkey::new_unique();
        let asset = Address::new_from_array(mint.to_bytes());
        let wallet = wallet_with_asset(sender.clone(), asset, 10);
        let rpc = MockRpc { account: None };
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
            result.recipient.withdrawal(),
            Some(&TransactWithdrawal::Spl(TransactSplWithdrawal {
                cpi_authority: Some(pda::shielded_pool_cpi_authority()),
                spl_token_interface: pda::spl_asset_vault(&mint),
                recipient,
                user_token_account: token_account,
                token_program: Pubkey::new_from_array(SPL_TOKEN_PROGRAM_ID),
            }))
        );
    }

    #[test]
    fn create_withdrawal_builds_spl_settlement_to_recipient_ata() {
        let sender = ShieldedKeypair::new().unwrap();
        let mint = Pubkey::new_unique();
        let asset = Address::new_from_array(mint.to_bytes());
        let wallet = wallet_with_asset(sender.clone(), asset, 10);
        let recipient = Pubkey::new_unique();
        let token_account = pda::associated_token_address(&recipient, &mint);

        let result = create_withdrawal(WithdrawalParams {
            wallet: &wallet,
            payer: Address::default(),
            recipient,
            asset,
            amount: 1,
        })
        .expect("withdrawal");

        assert_eq!(
            result.withdrawal,
            TransactWithdrawal::Spl(TransactSplWithdrawal {
                cpi_authority: Some(pda::shielded_pool_cpi_authority()),
                spl_token_interface: pda::spl_asset_vault(&mint),
                recipient,
                user_token_account: token_account,
                token_program: Pubkey::new_from_array(SPL_TOKEN_PROGRAM_ID),
            })
        );
    }

    #[test]
    fn signing_rejects_input_spent_after_creation() {
        let sender = ShieldedKeypair::new().unwrap();
        let authority =
            crate::wallet_authority::LocalWalletAuthority::new(Pubkey::default(), &sender);
        let mut wallet = wallet_with_sol(sender.clone(), 10);
        let unsigned = create_withdrawal(WithdrawalParams {
            wallet: &wallet,
            payer: Address::default(),
            recipient: Pubkey::new_unique(),
            asset: SOL_MINT,
            amount: 1,
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
        let sender = ShieldedKeypair::new().unwrap();
        let authority =
            crate::wallet_authority::LocalWalletAuthority::new(Pubkey::default(), &sender);
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
            recipient: Pubkey::new_unique(),
            asset: SOL_MINT,
            amount: 1,
        })
        .unwrap()
        .transaction;

        let signed = sign_shielded_transaction_sync(unsigned, &wallet, &authority).unwrap();

        let inputs = signed.transaction.input_utxo_hashes().unwrap();
        assert_eq!(inputs.first().expect("input").utxo_hash, hash);
    }

    #[test]
    fn input_selection_keeps_every_input_on_one_tree() {
        let sender = ShieldedKeypair::new().unwrap();
        let second_tree = Address::new_from_array([9u8; 32]);
        let mut wallet = wallet_with_sol(sender.clone(), 10);
        if let Some(entry) = wallet.utxos.first_mut() {
            entry.output_context.tree = second_tree;
        }

        let created = create_withdrawal(WithdrawalParams {
            wallet: &wallet,
            payer: Address::default(),
            recipient: Pubkey::new_unique(),
            asset: SOL_MINT,
            amount: 8,
        })
        .expect("tree with enough balance");

        assert_eq!(created.transaction.tree(), second_tree);
        assert_eq!(created.transaction.input_count(), 1);
    }

    #[test]
    fn resolve_spend_tree_infers_single_tree_balance() {
        let sender = ShieldedKeypair::new().unwrap();
        let wallet = wallet_with_sol(sender, 10);

        let tree = resolve_spend_tree(&wallet, SOL_MINT).expect("infer tree");

        assert_eq!(tree, Address::default());
    }

    #[test]
    fn resolve_spend_tree_errors_when_balance_spans_multiple_trees() {
        let sender = ShieldedKeypair::new().unwrap();
        let mut wallet = wallet_with_sol(sender.clone(), 4);
        let second_tree = Address::new_from_array([9u8; 32]);
        let mut second = wallet_with_sol(sender, 10).utxos.remove(0);
        second.output_context.tree = second_tree;
        wallet.utxos.push(second);

        let error = match resolve_spend_tree(&wallet, SOL_MINT) {
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
        let sender = ShieldedKeypair::new().unwrap();
        let wallet = wallet_with_sol(sender.clone(), 10);

        let created = create_withdrawal(WithdrawalParams {
            wallet: &wallet,
            payer: Address::default(),
            recipient: Pubkey::new_unique(),
            asset: SOL_MINT,
            amount: 1,
        })
        .expect("withdrawal");

        assert_eq!(created.transaction.tree(), Address::default());
    }

    #[test]
    fn create_split_accepts_plain_divisible_utxo() {
        let sender = ShieldedKeypair::new().unwrap();
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
        let sender = ShieldedKeypair::new().unwrap();
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
    fn create_split_rejects_utxo_carrying_data() {
        let sender = ShieldedKeypair::new().unwrap();
        let mut wallet = wallet_with_sol(sender, 800);
        if let Some(entry) = wallet.utxos.first_mut() {
            entry.utxo.data = Data::new(vec![DataRecord::Memo(b"utxo".to_vec())]);
        }

        let error = match create_split(SplitParams {
            wallet: &wallet,
            payer: Address::default(),
            asset: SOL_MINT,
            parts: 8,
            input: None,
        }) {
            Err(error) => error,
            Ok(_) => panic!("a utxo carrying data must be rejected"),
        };

        assert!(matches!(error, ClientError::SplitInputHasData { .. }));
    }

    #[test]
    fn create_split_rejects_zone_bound_utxo() {
        let sender = ShieldedKeypair::new().unwrap();
        let mut wallet = wallet_with_sol(sender, 800);
        if let Some(entry) = wallet.utxos.first_mut() {
            entry.utxo.zone_program_id = Some(Address::new_from_array([3u8; 32]));
        }

        let error = match create_split(SplitParams {
            wallet: &wallet,
            payer: Address::default(),
            asset: SOL_MINT,
            parts: 8,
            input: None,
        }) {
            Err(error) => error,
            Ok(_) => panic!("a zone-bound utxo must be rejected"),
        };

        assert!(matches!(error, ClientError::SplitInputZoneMismatch { .. }));
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
        let utxo = Utxo {
            owner: keypair.signing_pubkey(),
            asset: SOL_MINT,
            amount,
            blinding,
            zone_program_id: None,
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
            zone_data_hash: None,
            spent: false,
        });
        hash
    }

    fn amounts(selected: &[SppProofInputUtxo]) -> Vec<u64> {
        selected.iter().map(|spend| spend.utxo.amount).collect()
    }

    #[test]
    fn merge_auto_sweep_selects_smallest_plain_utxos_ascending() {
        let keypair = ShieldedKeypair::new().unwrap();
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
        let keypair = ShieldedKeypair::new().unwrap();
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
    fn merge_auto_sweep_skips_zone_and_data_utxos() {
        let keypair = ShieldedKeypair::new().unwrap();
        let mut wallet = sol_wallet(&keypair);
        push_utxo(&mut wallet, &keypair, 10, [1u8; 31]);
        push_utxo(&mut wallet, &keypair, 20, [2u8; 31]);
        // A zone-bound utxo and a data-carrying utxo must not be swept.
        push_utxo(&mut wallet, &keypair, 30, [3u8; 31]);
        if let Some(entry) = wallet.utxos.last_mut() {
            entry.utxo.zone_program_id = Some(Address::new_from_array([9u8; 32]));
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
        let keypair = ShieldedKeypair::new().unwrap();
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
        let keypair = ShieldedKeypair::new().unwrap();
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
        let keypair = ShieldedKeypair::new().unwrap();
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
        let keypair = ShieldedKeypair::new().unwrap();
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
        let keypair = ShieldedKeypair::new().unwrap();
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
        let keypair = ShieldedKeypair::new().unwrap();
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

    #[test]
    fn create_merge_auto_sweep_reports_count_amount_and_tree() {
        let keypair = ShieldedKeypair::new().unwrap();
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
