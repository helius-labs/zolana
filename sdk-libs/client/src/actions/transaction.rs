use std::collections::HashSet;

use solana_pubkey::Pubkey;
use zolana_interface::{
    instruction::{TransactSolWithdrawal, TransactSplWithdrawal, TransactWithdrawal},
    pda, SPL_TOKEN_PROGRAM_ID,
};
use zolana_keypair::{
    shielded::{ShieldedAddress, ShieldedKeypair},
    SignatureType,
};
use zolana_transaction::{
    instructions::{
        merge::{Merge, PreparedMerge, MERGE_INPUTS},
        transact::{
            PreparedSplit, PreparedTransaction, SignedTransaction, Transaction, WithdrawalTarget,
        },
        types::SpendUtxo,
    },
    Address, AssetRegistry, Wallet, SOL_MINT,
};

use crate::{
    error::ClientError,
    wallet_authority::{
        ApprovalRequest, ConfidentialRecipientSlot, SyncWalletAuthority, WalletAuthority,
    },
};

/// How [`select_inputs`] chooses which wallet notes to spend.
///
/// - [`InputSelection::Auto`] is the default largest-first scan: unspent notes of
///   the asset in descending amount order until the amount is covered.
/// - [`InputSelection::Explicit`] spends exactly the notes whose commitment hash
///   (see [`zolana_transaction::SpendableUtxo`]) is listed, in the listed order.
///   Every hash must name an unspent note of the asset, and the selected total
///   must cover the amount.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum InputSelection {
    #[default]
    Auto,
    Explicit(Vec<[u8; 32]>),
}

fn reject_duplicate_hashes(hashes: &[[u8; 32]]) -> Result<(), ClientError> {
    let mut seen = HashSet::with_capacity(hashes.len());
    for hash in hashes {
        if !seen.insert(*hash) {
            return Err(ClientError::DuplicateInputNote {
                hash: hex::encode(hash),
            });
        }
    }
    Ok(())
}

/// A private transfer prepared for submission.
///
/// The recipient is the exact shielded address used to build the output.
/// Registry aliases must be resolved before constructing [`CreateTransfer`].
#[derive(Clone)]
pub struct CreatedTransfer {
    pub signed: SignedTransaction,
    /// Committed hash of a real output note this transaction appends. The CLI
    /// waits for this hash to be indexed, which is robust under a shared view tag
    /// that has more than a page of outputs. See
    /// [`zolana_transaction::instructions::transact::PreparedTransaction::wait_output_hash`].
    pub wait_output_hash: [u8; 32],
    pub recipient: ShieldedAddress,
}

#[derive(Clone)]
pub struct CreatedWithdrawal {
    pub signed: SignedTransaction,
    /// Committed hash of the sender's change output note this withdrawal appends.
    pub wait_output_hash: [u8; 32],
    pub withdrawal: TransactWithdrawal,
}

#[derive(Clone)]
pub struct CreatedSplit {
    pub signed: SignedTransaction,
    /// Committed hash of one real self-split output note this split appends.
    pub wait_output_hash: [u8; 32],
    /// Number of self-owned notes the split produces.
    pub num_outputs: u8,
    /// Amount held by each produced note.
    pub per_output_amount: u64,
}

/// An unproven merge plan: the prepared 8-in/1-out consolidation and the metadata
/// the submit path reports. The single merged `output_hash` (what the CLI waits
/// on for indexing) is only known after the prover assembles the output, so it is
/// derived on the submit path from [`crate::MergeProofResult::output_hash`] rather
/// than carried here.
pub struct CreatedMerge {
    pub prepared: PreparedMerge,
    /// Number of real (non-dummy) notes this merge consolidates.
    pub num_inputs: usize,
    /// Total amount held by the single merged output note.
    pub merged_amount: u64,
}

/// Consolidate several small notes of `asset` into one. Merge proves ownership
/// in-circuit from the nullifier secret (no signing step), so it takes the
/// concrete [`ShieldedKeypair`] rather than a [`WalletAuthority`]: the authority
/// abstraction exposes only address, nullifier-key, and P256-signing hooks, none
/// of which cover the merge witness.
pub struct CreateMerge<'a> {
    pub wallet: &'a Wallet,
    pub keypair: &'a ShieldedKeypair,
    pub asset: Address,
    /// Which notes to consolidate. Defaults to [`InputSelection::Auto`], which
    /// picks up to [`MERGE_INPUTS`] unspent notes of `asset` smallest-first (so it
    /// sweeps dust and leaves large notes whole). `Explicit` consolidates exactly
    /// the listed notes (at most [`MERGE_INPUTS`]).
    pub selection: InputSelection,
}

pub struct CreateSplit<'a, A: ?Sized> {
    pub wallet: &'a Wallet,
    pub authority: &'a A,
    pub owner_pubkey: Pubkey,
    pub payer: Address,
    pub asset: Address,
    pub num_outputs: u8,
    pub per_output_amount: u64,
    pub assets: &'a AssetRegistry,
    /// Which note to spend. Defaults to [`InputSelection::Auto`]; a split spends a
    /// single input, so `Explicit` should name exactly one note.
    pub selection: InputSelection,
}

/// Build a private transfer to a concrete shielded address.
///
/// This action performs no user-registry lookup. Call
/// [`crate::resolve_registered_address`] first when the recipient is supplied as
/// a Solana pubkey, or use [`CreateWithdrawal`] for an explicit public
/// destination.
pub struct CreateTransfer<'a, A: ?Sized> {
    pub wallet: &'a Wallet,
    pub authority: &'a A,
    pub owner_pubkey: Pubkey,
    pub payer: Address,
    pub recipient: ShieldedAddress,
    pub asset: Address,
    pub amount: u64,
    pub assets: &'a AssetRegistry,
    /// Which notes to spend. Defaults to [`InputSelection::Auto`].
    pub selection: InputSelection,
}

pub struct CreateWithdrawal<'a, A: ?Sized> {
    pub wallet: &'a Wallet,
    pub authority: &'a A,
    pub owner_pubkey: Pubkey,
    pub payer: Address,
    pub recipient: Pubkey,
    pub asset: Address,
    pub amount: u64,
    pub assets: &'a AssetRegistry,
    /// Which notes to spend. Defaults to [`InputSelection::Auto`].
    pub selection: InputSelection,
}

pub async fn create_transfer<A: WalletAuthority + ?Sized>(
    request: CreateTransfer<'_, A>,
) -> Result<CreatedTransfer, ClientError> {
    let inputs = select_inputs(
        request.wallet,
        request.authority,
        request.owner_pubkey,
        request.asset,
        request.amount,
        &request.selection,
    )
    .await?;
    let address = request
        .authority
        .shielded_address(request.owner_pubkey)
        .await?;
    let mut tx = Transaction::new(address, inputs, request.payer);
    tx.send(&request.recipient, request.asset, request.amount)?;
    let prepared = tx.prepare(request.assets)?;
    let wait_output_hash = prepared.wait_output_hash()?;
    let signed = sign_prepared(
        prepared,
        &address,
        request.owner_pubkey,
        request.authority,
        request.assets,
        format!(
            "private transfer of {} to {}",
            request.amount, request.recipient
        ),
    )
    .await?;
    Ok(CreatedTransfer {
        signed,
        wait_output_hash,
        recipient: request.recipient,
    })
}

/// Blocking adapter for CLI and unit-test flows. Async hosts should call
/// [`create_transfer`] directly.
pub fn create_transfer_sync<A: SyncWalletAuthority + ?Sized>(
    request: CreateTransfer<'_, A>,
) -> Result<CreatedTransfer, ClientError> {
    futures::executor::block_on(create_transfer(request))
}

pub async fn create_withdrawal<A: WalletAuthority + ?Sized>(
    request: CreateWithdrawal<'_, A>,
) -> Result<CreatedWithdrawal, ClientError> {
    let inputs = select_inputs(
        request.wallet,
        request.authority,
        request.owner_pubkey,
        request.asset,
        request.amount,
        &request.selection,
    )
    .await?;
    // An SPL withdrawal fits fewer inputs than a shielded transfer before crossing
    // the packet limit (see [`MAX_SPL_WITHDRAWAL_INPUTS`]). Surface
    // `FragmentedBalance` so the caller consolidates first instead of building a
    // transaction the network rejects only after the proof is generated.
    if request.asset != SOL_MINT && inputs.len() > MAX_SPL_WITHDRAWAL_INPUTS {
        return Err(ClientError::FragmentedBalance {
            requested: request.amount,
            notes: inputs.len(),
            max_inputs: MAX_SPL_WITHDRAWAL_INPUTS,
        });
    }
    let (target, withdrawal) = withdrawal_target(request.recipient, request.asset)?;
    let address = request
        .authority
        .shielded_address(request.owner_pubkey)
        .await?;
    let mut tx = Transaction::new(address, inputs, request.payer);
    tx.withdraw(request.asset, request.amount, target)?;
    let prepared = tx.prepare(request.assets)?;
    let wait_output_hash = prepared.wait_output_hash()?;
    let signed = sign_prepared(
        prepared,
        &address,
        request.owner_pubkey,
        request.authority,
        request.assets,
        format!("withdraw {} to {}", request.amount, request.recipient),
    )
    .await?;
    Ok(CreatedWithdrawal {
        signed,
        wait_output_hash,
        withdrawal,
    })
}

/// Blocking adapter for CLI and unit-test flows. Async hosts should call
/// [`create_withdrawal`] directly.
pub fn create_withdrawal_sync<A: SyncWalletAuthority + ?Sized>(
    request: CreateWithdrawal<'_, A>,
) -> Result<CreatedWithdrawal, ClientError> {
    futures::executor::block_on(create_withdrawal(request))
}

/// Build a signed split: spend one selected input and fan it out into
/// `num_outputs` equal self-owned notes of `asset`, each holding
/// `per_output_amount`. The notes are encoded into a single [`Split`] bundle (not
/// per-recipient slots) and are re-decodable by `sync` as
/// `PrivateTransactionKind::Split`. The result is submittable via the same
/// proving/submit path as a transfer.
///
/// `num_outputs * per_output_amount` must equal the selected input's balance for
/// `asset` (a split conserves value and has no change).
pub async fn create_split<A: WalletAuthority + ?Sized>(
    request: CreateSplit<'_, A>,
) -> Result<CreatedSplit, ClientError> {
    let total = u64::from(request.num_outputs)
        .checked_mul(request.per_output_amount)
        .ok_or(ClientError::SelectedBalanceOverflow)?;
    let inputs = select_split_inputs(
        request.wallet,
        request.authority,
        request.owner_pubkey,
        request.asset,
        total,
        &request.selection,
    )
    .await?;
    let address = request
        .authority
        .shielded_address(request.owner_pubkey)
        .await?;

    let mut tx = Transaction::new(address, inputs, request.payer);
    tx.split(
        request.asset,
        request.num_outputs,
        request.per_output_amount,
    )?;
    let prepared = tx.prepare_split(request.assets)?;
    let wait_output_hash = prepared.wait_output_hash()?;
    let signed = sign_prepared_split(
        prepared,
        &address,
        request.owner_pubkey,
        request.authority,
        request.assets,
        format!(
            "split into {} notes of {}",
            request.num_outputs, request.per_output_amount
        ),
    )
    .await?;
    Ok(CreatedSplit {
        signed,
        wait_output_hash,
        num_outputs: request.num_outputs,
        per_output_amount: request.per_output_amount,
    })
}

/// Blocking adapter for CLI and unit-test flows. Async hosts should call
/// [`create_split`] directly.
pub fn create_split_sync<A: SyncWalletAuthority + ?Sized>(
    request: CreateSplit<'_, A>,
) -> Result<CreatedSplit, ClientError> {
    futures::executor::block_on(create_split(request))
}

/// Build an unproven merge plan: consolidate up to [`MERGE_INPUTS`] notes of
/// `asset` into one self-owned output. The result carries the [`PreparedMerge`]
/// the submit path folds into a merge proof; the merged output hash is derived
/// there from the built proof result (see [`CreatedMerge`]).
///
/// Unlike the transfer/split/withdrawal actions this is synchronous: it needs the
/// full [`ShieldedKeypair`] to build the merge witness, so there is no async
/// authority hop to await.
pub fn create_merge(request: CreateMerge<'_>) -> Result<CreatedMerge, ClientError> {
    let inputs = select_merge_inputs(
        request.wallet,
        request.keypair,
        request.asset,
        &request.selection,
    )?;
    let num_inputs = inputs.len();
    let merge = Merge::new(request.keypair, inputs)?.prepare();
    let merged_amount = merge.output.amount;
    Ok(CreatedMerge {
        prepared: merge,
        num_inputs,
        merged_amount,
    })
}

/// Select the notes a merge consolidates.
///
/// `Auto` picks up to [`MERGE_INPUTS`] unspent notes of `asset`, smallest-first,
/// so it sweeps dust and leaves large notes whole; it requires at least two real
/// notes (else [`ClientError::NothingToConsolidate`]). `Explicit` consolidates
/// exactly the listed notes: each hash must name an unspent note of `asset` (else
/// [`ClientError::InputNoteUnavailable`]), there must be at least two, and at most
/// [`MERGE_INPUTS`] (else [`ClientError::TooManyInputs`]).
fn select_merge_inputs(
    wallet: &Wallet,
    keypair: &ShieldedKeypair,
    asset: Address,
    selection: &InputSelection,
) -> Result<Vec<SpendUtxo>, ClientError> {
    let spend = |utxo: zolana_transaction::Utxo| SpendUtxo::from_keypair(utxo, keypair);

    let selected = match selection {
        InputSelection::Auto => {
            // Smallest-first so a bounded consolidation clears the most notes: the
            // dust is swept up while large notes stay whole for a later spend.
            let mut candidates: Vec<_> = wallet
                .utxos
                .iter()
                .filter(|entry| !entry.spent && entry.utxo.asset == asset)
                .collect();
            candidates.sort_by_key(|entry| entry.utxo.amount);
            candidates
                .into_iter()
                .take(MERGE_INPUTS)
                .map(|entry| spend(entry.utxo.clone()))
                .collect::<Vec<_>>()
        }
        InputSelection::Explicit(hashes) => {
            reject_duplicate_hashes(hashes)?;
            let mut selected = Vec::with_capacity(hashes.len());
            for hash in hashes {
                let entry = wallet
                    .utxos
                    .iter()
                    .find(|entry| {
                        !entry.spent
                            && entry.utxo.asset == asset
                            && &entry.output_context.hash == hash
                    })
                    .ok_or_else(|| ClientError::InputNoteUnavailable {
                        hash: hex::encode(hash),
                    })?;
                selected.push(spend(entry.utxo.clone()));
            }
            selected
        }
    };

    if selected.len() > MERGE_INPUTS {
        return Err(ClientError::TooManyInputs {
            got: selected.len(),
            max: MERGE_INPUTS,
        });
    }
    // A merge that consolidates fewer than two notes is a no-op: it would burn a
    // proof and a fee to reshape a single note into itself.
    if selected.len() < 2 {
        return Err(ClientError::NothingToConsolidate { asset });
    }
    Ok(selected)
}

/// Encrypt a prepared split's bundle through the authority, get approval, finalize
/// the signed transaction, and P256-sign it when the owner is on the P256 rail.
async fn sign_prepared_split<A: WalletAuthority + ?Sized>(
    prepared: PreparedSplit,
    address: &ShieldedAddress,
    owner_pubkey: Pubkey,
    authority: &A,
    assets: &AssetRegistry,
    approval_summary: String,
) -> Result<SignedTransaction, ClientError> {
    let view_tag = prepared.view_tag()?;
    let bundle = prepared.bundle_plaintext()?;
    let encrypted = authority
        .encrypt_split(owner_pubkey, &prepared.first_nullifier, view_tag, &bundle)
        .await?;
    authority
        .request_user_approval(ApprovalRequest {
            owner_pubkey,
            summary: approval_summary,
        })
        .await?;
    let mut signed = prepared.finalize(
        encrypted.tx_viewing_pk,
        encrypted.salt,
        encrypted.bundle,
        assets,
    )?;
    sign_p256_owner_if_needed(&mut signed, address, owner_pubkey, authority).await?;
    Ok(signed)
}

/// Sign a prepared transaction through a wallet authority (encrypt, approve,
/// P256-sign).
pub async fn sign_transaction<A: WalletAuthority + ?Sized>(
    tx: Transaction,
    wallet: &Wallet,
    owner_pubkey: Pubkey,
    authority: &A,
) -> Result<SignedTransaction, ClientError> {
    let address = authority.shielded_address(owner_pubkey).await?;
    let prepared = tx.prepare(&wallet.registry)?;
    sign_prepared(
        prepared,
        &address,
        owner_pubkey,
        authority,
        &wallet.registry,
        "private transaction".to_string(),
    )
    .await
}

/// Blocking adapter for CLI and unit-test flows. Async hosts should call
/// [`sign_transaction`] directly.
pub fn sign_transaction_sync<A: SyncWalletAuthority + ?Sized>(
    tx: Transaction,
    wallet: &Wallet,
    owner_pubkey: Pubkey,
    authority: &A,
) -> Result<SignedTransaction, ClientError> {
    futures::executor::block_on(sign_transaction(tx, wallet, owner_pubkey, authority))
}

fn recipient_slots(prepared: &PreparedTransaction) -> Vec<ConfidentialRecipientSlot> {
    prepared
        .recipients
        .iter()
        .map(|recipient| ConfidentialRecipientSlot {
            view_tag: recipient.view_tag,
            recipient_pubkey: recipient.recipient_pubkey,
            plaintext: recipient.plaintext.clone(),
        })
        .collect()
}

async fn sign_prepared<A: WalletAuthority + ?Sized>(
    prepared: PreparedTransaction,
    address: &ShieldedAddress,
    owner_pubkey: Pubkey,
    authority: &A,
    assets: &AssetRegistry,
    approval_summary: String,
) -> Result<SignedTransaction, ClientError> {
    let sender_tag = address.signing_pubkey.confidential_view_tag()?;
    let encrypted = authority
        .encrypt_confidential_transfer(
            owner_pubkey,
            &prepared.first_nullifier,
            sender_tag,
            &prepared.sender_plaintext,
            &recipient_slots(&prepared),
        )
        .await?;
    authority
        .request_user_approval(ApprovalRequest {
            owner_pubkey,
            summary: approval_summary,
        })
        .await?;
    let mut signed = prepared.finalize(
        encrypted.tx_viewing_pk,
        encrypted.salt,
        encrypted.slots,
        assets,
    )?;
    sign_p256_owner_if_needed(&mut signed, address, owner_pubkey, authority).await?;
    Ok(signed)
}

async fn sign_p256_owner_if_needed<A: WalletAuthority + ?Sized>(
    signed: &mut SignedTransaction,
    address: &ShieldedAddress,
    owner_pubkey: Pubkey,
    authority: &A,
) -> Result<(), ClientError> {
    if address.signing_pubkey.signature_type()? == SignatureType::P256 {
        let message_hash = signed.message_hash()?;
        let sig = authority.sign_p256(owner_pubkey, &message_hash).await?;
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&sig.sig_r);
        bytes[32..].copy_from_slice(&sig.sig_s);
        signed.p256_owner = Some(bytes);
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

/// Largest number of input notes a confidential transfer can spend in one
/// transaction: the `{5,3}` shape, the widest in
/// [`zolana_transaction::instructions::transact::SUPPORTED_SHAPES`]. Auto input
/// selection caps at this; a spend that would need more notes must be
/// consolidated (via `merge`) first, so it fails with
/// [`ClientError::FragmentedBalance`] instead of building an unsupported shape.
pub const MAX_TRANSFER_INPUTS: usize = 5;

/// Largest number of input notes an SPL withdrawal can spend in one transaction.
/// An SPL settlement appends five account keys to the instruction (see
/// [`zolana_interface::instruction::TransactSplWithdrawal`]), so it crosses
/// Solana's 1232-byte packet limit sooner than a shielded transfer: measured, the
/// `{3,3}` SPL withdrawal serializes to 1207 bytes but `{4,3}` to 1245. Spending
/// more SPL notes than this requires consolidating (via `merge`) first. SOL
/// withdrawals add only three account keys and stay within the limit at
/// [`MAX_TRANSFER_INPUTS`], so this cap applies to SPL only.
pub const MAX_SPL_WITHDRAWAL_INPUTS: usize = 3;

/// Select the notes to spend for `amount` of `asset`, honoring `selection`.
///
/// `Auto` scans unspent notes largest-first so the fewest inputs cover the
/// amount. `Explicit` spends exactly the listed notes (by commitment hash) in
/// order: each hash must name an unspent note of `asset` (else
/// [`ClientError::InputNoteUnavailable`]), and their total must cover `amount`
/// (else [`ClientError::InsufficientBalance`]).
async fn select_inputs<A: WalletAuthority + ?Sized>(
    wallet: &Wallet,
    authority: &A,
    owner_pubkey: Pubkey,
    asset: Address,
    amount: u64,
    selection: &InputSelection,
) -> Result<Vec<SpendUtxo>, ClientError> {
    if amount == 0 {
        return Err(ClientError::ZeroAmount);
    }
    let nullifier_key = authority.spend_nullifier_key(owner_pubkey).await?;
    let spend = |utxo: zolana_transaction::Utxo| SpendUtxo {
        utxo,
        nullifier_key: nullifier_key.clone(),
        data_hash: None,
        zone_data_hash: None,
    };

    match selection {
        InputSelection::Auto => {
            // Largest-first so the fewest notes cover the amount: this keeps the
            // proof shape small and the instruction within Solana's tx-size limit.
            // A balance spread across more than MAX_TRANSFER_INPUTS notes cannot be
            // spent in one transfer and must be consolidated (merge) first, so we
            // surface a precise error rather than build an unsupported shape.
            let mut candidates: Vec<_> = wallet
                .utxos
                .iter()
                .filter(|entry| !entry.spent && entry.utxo.asset == asset)
                .collect();
            candidates.sort_by_key(|entry| core::cmp::Reverse(entry.utxo.amount));

            let mut selected = Vec::new();
            let mut total = 0u64;
            for entry in candidates {
                if total >= amount {
                    break;
                }
                total = total
                    .checked_add(entry.utxo.amount)
                    .ok_or(ClientError::SelectedBalanceOverflow)?;
                selected.push(spend(entry.utxo.clone()));
            }
            if total < amount {
                return Err(ClientError::InsufficientBalance {
                    requested: amount,
                    available: total,
                });
            }
            if selected.len() > MAX_TRANSFER_INPUTS {
                return Err(ClientError::FragmentedBalance {
                    requested: amount,
                    notes: selected.len(),
                    max_inputs: MAX_TRANSFER_INPUTS,
                });
            }
            Ok(selected)
        }
        InputSelection::Explicit(hashes) => {
            reject_duplicate_hashes(hashes)?;
            let mut selected = Vec::with_capacity(hashes.len());
            let mut total = 0u64;
            for hash in hashes {
                let entry = wallet
                    .utxos
                    .iter()
                    .find(|entry| {
                        !entry.spent
                            && entry.utxo.asset == asset
                            && &entry.output_context.hash == hash
                    })
                    .ok_or_else(|| ClientError::InputNoteUnavailable {
                        hash: hex::encode(hash),
                    })?;
                selected.push(spend(entry.utxo.clone()));
                total = total
                    .checked_add(entry.utxo.amount)
                    .ok_or(ClientError::SelectedBalanceOverflow)?;
            }
            if total < amount {
                return Err(ClientError::InsufficientBalance {
                    requested: amount,
                    available: total,
                });
            }
            // Mirror the Auto branch: no transfer shape spends more than
            // MAX_TRANSFER_INPUTS notes, so surface the precise consolidation hint
            // rather than failing later with an opaque UnsupportedShape.
            if selected.len() > MAX_TRANSFER_INPUTS {
                return Err(ClientError::FragmentedBalance {
                    requested: amount,
                    notes: selected.len(),
                    max_inputs: MAX_TRANSFER_INPUTS,
                });
            }
            Ok(selected)
        }
    }
}

async fn select_split_inputs<A: WalletAuthority + ?Sized>(
    wallet: &Wallet,
    authority: &A,
    owner_pubkey: Pubkey,
    asset: Address,
    amount: u64,
    selection: &InputSelection,
) -> Result<Vec<SpendUtxo>, ClientError> {
    match selection {
        InputSelection::Explicit(_) => {
            select_inputs(wallet, authority, owner_pubkey, asset, amount, selection).await
        }
        InputSelection::Auto => {
            let nullifier_key = authority.spend_nullifier_key(owner_pubkey).await?;
            let mut available = 0u64;
            let mut exact = None;
            for entry in wallet
                .utxos
                .iter()
                .filter(|entry| !entry.spent && entry.utxo.asset == asset)
            {
                available = available
                    .checked_add(entry.utxo.amount)
                    .ok_or(ClientError::SelectedBalanceOverflow)?;
                if entry.utxo.amount == amount {
                    exact = Some(entry.utxo.clone());
                    break;
                }
            }
            let utxo = match exact {
                Some(utxo) => utxo,
                None if available < amount => {
                    return Err(ClientError::InsufficientBalance {
                        requested: amount,
                        available,
                    })
                }
                None => return Err(ClientError::SplitInputUnavailable { requested: amount }),
            };
            Ok(vec![SpendUtxo {
                utxo,
                nullifier_key,
                data_hash: None,
                zone_data_hash: None,
            }])
        }
    }
}

#[cfg(test)]
mod tests {
    use zolana_keypair::ShieldedKeypair;
    use zolana_transaction::{Data, TransactionError, Utxo, WalletUtxo};

    use super::*;

    fn wallet_with_sol(keypair: ShieldedKeypair, amount: u64) -> Wallet {
        wallet_with_asset(keypair, SOL_MINT, amount)
    }

    /// Push one unspent SOL note with a distinct blinding, returning its
    /// commitment hash (what `InputSelection::Explicit` matches against).
    fn push_sol_note(wallet: &Wallet, amount: u64, blinding: [u8; 31]) -> WalletUtxo {
        let utxo = Utxo {
            owner: wallet.keypair.signing_pubkey(),
            asset: SOL_MINT,
            amount,
            blinding,
            zone_program_id: None,
            data: Data::default(),
        };
        let nullifier_pk = wallet.keypair.nullifier_key.pubkey().expect("nullifier pk");
        let hash = utxo
            .hash(&nullifier_pk, &[0u8; 32], &[0u8; 32])
            .expect("utxo hash");
        let nullifier = utxo
            .nullifier(&hash, &wallet.keypair.nullifier_key)
            .expect("nullifier");
        WalletUtxo {
            utxo,
            output_context: zolana_transaction::instructions::transact::types::OutputContext {
                hash,
                tree: Address::default(),
                leaf_index: 0,
            },
            nullifier,
            spent: false,
        }
    }

    fn wallet_with_notes(keypair: ShieldedKeypair, amounts: &[(u64, [u8; 31])]) -> Wallet {
        let mut wallet = Wallet::new(keypair, AssetRegistry::default()).expect("wallet");
        for (amount, blinding) in amounts {
            let note = push_sol_note(&wallet, *amount, *blinding);
            wallet.utxos.push(note);
        }
        wallet
    }

    fn wallet_with_asset(keypair: ShieldedKeypair, asset: Address, amount: u64) -> Wallet {
        wallet_with_asset_notes(keypair, asset, &[(amount, [7u8; 31])])
    }

    fn wallet_with_asset_notes(
        keypair: ShieldedKeypair,
        asset: Address,
        amounts: &[(u64, [u8; 31])],
    ) -> Wallet {
        let registry = if asset == SOL_MINT {
            AssetRegistry::default()
        } else {
            AssetRegistry::new([(2, asset)]).expect("asset registry")
        };
        let mut wallet = Wallet::new(keypair.clone(), registry).expect("wallet");
        for (amount, blinding) in amounts {
            let utxo = Utxo {
                owner: keypair.signing_pubkey(),
                asset,
                amount: *amount,
                blinding: *blinding,
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
                spent: false,
            });
        }
        wallet
    }

    #[test]
    fn create_transfer_uses_the_supplied_shielded_address() {
        let sender = ShieldedKeypair::new().unwrap();
        let recipient = ShieldedKeypair::new().unwrap();
        let recipient = recipient.shielded_address().expect("recipient address");
        let wallet = wallet_with_sol(sender.clone(), 10);

        let result = create_transfer_sync(CreateTransfer {
            wallet: &wallet,
            authority: &sender,
            owner_pubkey: Pubkey::default(),
            payer: Address::default(),
            recipient,
            asset: SOL_MINT,
            amount: 1,
            assets: &AssetRegistry::default(),
            selection: InputSelection::Auto,
        })
        .expect("transfer");

        assert_eq!(result.recipient, recipient);
        assert_eq!(result.signed.public_amounts.sol, [0u8; 32]);
        assert_eq!(result.signed.public_amounts.spl, [0u8; 32]);
    }

    #[test]
    fn create_withdrawal_builds_spl_settlement_to_recipient_ata() {
        let sender = ShieldedKeypair::new().unwrap();
        let mint = Pubkey::new_unique();
        let asset = Address::new_from_array(mint.to_bytes());
        let wallet = wallet_with_asset(sender.clone(), asset, 10);
        let recipient = Pubkey::new_unique();
        let token_account = pda::associated_token_address(&recipient, &mint);

        let result = create_withdrawal_sync(CreateWithdrawal {
            wallet: &wallet,
            authority: &sender,
            owner_pubkey: Pubkey::default(),
            payer: Address::default(),
            recipient,
            asset,
            amount: 1,
            assets: &AssetRegistry::new([(2, asset)]).expect("asset registry"),
            selection: InputSelection::Auto,
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
    fn spendable_utxos_expose_selectable_hashes() {
        let keypair = ShieldedKeypair::new().unwrap();
        let wallet = wallet_with_notes(keypair, &[(30, [1u8; 31]), (70, [2u8; 31])]);
        let spendable = wallet.spendable_utxos(SOL_MINT);
        assert_eq!(spendable.len(), 2);
        let amounts: Vec<_> = spendable.iter().map(|note| note.amount).collect();
        assert_eq!(amounts, vec![30, 70]);
        // The exposed hash equals the note's commitment and is what Explicit matches.
        for (spendable, entry) in spendable.iter().zip(wallet.utxos.iter()) {
            assert_eq!(spendable.hash, entry.output_context.hash);
        }
    }

    #[test]
    fn explicit_selection_picks_named_note() {
        let sender = ShieldedKeypair::new().unwrap();
        let wallet = wallet_with_notes(sender.clone(), &[(30, [1u8; 31]), (70, [2u8; 31])]);
        let target = wallet
            .spendable_utxos(SOL_MINT)
            .get(1)
            .copied()
            .expect("target note");

        let selected = match futures::executor::block_on(select_inputs(
            &wallet,
            &sender,
            Pubkey::default(),
            SOL_MINT,
            50,
            &InputSelection::Explicit(vec![target.hash]),
        )) {
            Ok(selected) => selected,
            Err(err) => panic!("explicit selection failed: {err}"),
        };
        assert_eq!(selected.len(), 1);
        let selected = selected.first().expect("selected note");
        assert_eq!(selected.utxo.amount, 70);
        assert_eq!(selected.utxo.blinding, [2u8; 31]);
    }

    #[test]
    fn explicit_selection_rejects_missing_note() {
        let sender = ShieldedKeypair::new().unwrap();
        let wallet = wallet_with_notes(sender.clone(), &[(30, [1u8; 31])]);
        let err = match futures::executor::block_on(select_inputs(
            &wallet,
            &sender,
            Pubkey::default(),
            SOL_MINT,
            10,
            &InputSelection::Explicit(vec![[9u8; 32]]),
        )) {
            Ok(_) => panic!("missing note must error"),
            Err(err) => err,
        };
        assert!(matches!(err, ClientError::InputNoteUnavailable { .. }));
    }

    #[test]
    fn explicit_selection_rejects_duplicate_note() {
        let sender = ShieldedKeypair::new().unwrap();
        let wallet = wallet_with_notes(sender.clone(), &[(30, [1u8; 31])]);
        let hash = wallet
            .spendable_utxos(SOL_MINT)
            .first()
            .expect("spendable note")
            .hash;
        let err = match futures::executor::block_on(select_inputs(
            &wallet,
            &sender,
            Pubkey::default(),
            SOL_MINT,
            50,
            &InputSelection::Explicit(vec![hash, hash]),
        )) {
            Ok(_) => panic!("duplicate explicit input must error"),
            Err(err) => err,
        };
        assert!(matches!(err, ClientError::DuplicateInputNote { .. }));
    }

    #[test]
    fn explicit_selection_rejects_spent_note() {
        let sender = ShieldedKeypair::new().unwrap();
        let mut wallet = wallet_with_notes(sender.clone(), &[(30, [1u8; 31])]);
        let hash = wallet
            .spendable_utxos(SOL_MINT)
            .first()
            .expect("spendable note")
            .hash;
        wallet.utxos.first_mut().expect("wallet note").spent = true;
        let err = match futures::executor::block_on(select_inputs(
            &wallet,
            &sender,
            Pubkey::default(),
            SOL_MINT,
            10,
            &InputSelection::Explicit(vec![hash]),
        )) {
            Ok(_) => panic!("spent note must error"),
            Err(err) => err,
        };
        assert!(matches!(err, ClientError::InputNoteUnavailable { .. }));
    }

    #[test]
    fn explicit_selection_rejects_insufficient_total() {
        let sender = ShieldedKeypair::new().unwrap();
        let wallet = wallet_with_notes(sender.clone(), &[(30, [1u8; 31])]);
        let hash = wallet
            .spendable_utxos(SOL_MINT)
            .first()
            .expect("spendable note")
            .hash;
        let err = match futures::executor::block_on(select_inputs(
            &wallet,
            &sender,
            Pubkey::default(),
            SOL_MINT,
            100,
            &InputSelection::Explicit(vec![hash]),
        )) {
            Ok(_) => panic!("insufficient explicit total must error"),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            ClientError::InsufficientBalance {
                requested: 100,
                available: 30
            }
        ));
    }

    #[test]
    fn auto_selection_prefers_largest_note() {
        let sender = ShieldedKeypair::new().unwrap();
        // Largest-first: one 70-note covers 60, so a smaller/older note is not
        // dragged in and the shape stays as small as possible.
        let wallet = wallet_with_notes(
            sender.clone(),
            &[(30, [1u8; 31]), (70, [2u8; 31]), (50, [3u8; 31])],
        );
        let selected = futures::executor::block_on(select_inputs(
            &wallet,
            &sender,
            Pubkey::default(),
            SOL_MINT,
            60,
            &InputSelection::Auto,
        ))
        .expect("auto selection");
        assert_eq!(selected.len(), 1);
        assert_eq!(selected.first().expect("selected note").utxo.amount, 70);
    }

    #[test]
    fn auto_selection_accumulates_largest_first() {
        let sender = ShieldedKeypair::new().unwrap();
        let wallet = wallet_with_notes(
            sender.clone(),
            &[(30, [1u8; 31]), (40, [2u8; 31]), (20, [3u8; 31])],
        );
        let selected = futures::executor::block_on(select_inputs(
            &wallet,
            &sender,
            Pubkey::default(),
            SOL_MINT,
            60,
            &InputSelection::Auto,
        ))
        .expect("auto selection");
        // 40 + 30 covers 60; taken in descending order, the 20-note is untouched.
        let amounts: Vec<u64> = selected.iter().map(|s| s.utxo.amount).collect();
        assert_eq!(amounts, vec![40, 30]);
    }

    #[test]
    fn auto_selection_allows_up_to_five_notes() {
        let sender = ShieldedKeypair::new().unwrap();
        let notes = [
            (10, [1u8; 31]),
            (10, [2u8; 31]),
            (10, [3u8; 31]),
            (10, [4u8; 31]),
            (10, [5u8; 31]),
        ];
        let wallet = wallet_with_notes(sender.clone(), &notes);
        // Exactly MAX_TRANSFER_INPUTS notes needed to cover 45 -> the {5,3} shape.
        let selected = futures::executor::block_on(select_inputs(
            &wallet,
            &sender,
            Pubkey::default(),
            SOL_MINT,
            45,
            &InputSelection::Auto,
        ))
        .expect("auto selection at the input ceiling");
        assert_eq!(selected.len(), MAX_TRANSFER_INPUTS);
    }

    #[test]
    fn auto_selection_rejects_balance_spread_over_more_than_five_notes() {
        let sender = ShieldedKeypair::new().unwrap();
        let notes = [
            (10, [1u8; 31]),
            (10, [2u8; 31]),
            (10, [3u8; 31]),
            (10, [4u8; 31]),
            (10, [5u8; 31]),
            (10, [6u8; 31]),
        ];
        let wallet = wallet_with_notes(sender.clone(), &notes);
        // Balance (60) is sufficient but needs six notes to cover 55; a transfer
        // spends at most five, so this must fail with a consolidation hint rather
        // than build an unsupported shape.
        let err = match futures::executor::block_on(select_inputs(
            &wallet,
            &sender,
            Pubkey::default(),
            SOL_MINT,
            55,
            &InputSelection::Auto,
        )) {
            Ok(_) => panic!("too-fragmented balance must error"),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            ClientError::FragmentedBalance {
                requested: 55,
                notes: 6,
                max_inputs: 5,
            }
        ));
    }

    #[test]
    fn auto_selection_rejects_insufficient_total() {
        let sender = ShieldedKeypair::new().unwrap();
        let wallet = wallet_with_notes(sender.clone(), &[(10, [1u8; 31]), (10, [2u8; 31])]);
        let err = match futures::executor::block_on(select_inputs(
            &wallet,
            &sender,
            Pubkey::default(),
            SOL_MINT,
            100,
            &InputSelection::Auto,
        )) {
            Ok(_) => panic!("insufficient total must error"),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            ClientError::InsufficientBalance {
                requested: 100,
                available: 20
            }
        ));
    }

    #[test]
    fn selection_rejects_zero_amount() {
        let sender = ShieldedKeypair::new().unwrap();
        let wallet = wallet_with_notes(sender.clone(), &[(10, [1u8; 31])]);
        let err = match futures::executor::block_on(select_inputs(
            &wallet,
            &sender,
            Pubkey::default(),
            SOL_MINT,
            0,
            &InputSelection::Auto,
        )) {
            Ok(_) => panic!("zero amount must error"),
            Err(err) => err,
        };
        assert!(matches!(err, ClientError::ZeroAmount));
    }

    #[test]
    fn create_split_produces_split_bundle() {
        use borsh::BorshDeserialize;
        use zolana_event::OutputData;

        let sender = ShieldedKeypair::new().unwrap();
        // One 400-lamport note split into four 100-lamport notes.
        let wallet = wallet_with_notes(sender.clone(), &[(400, [3u8; 31])]);

        let split = match create_split_sync(CreateSplit {
            wallet: &wallet,
            authority: &sender,
            owner_pubkey: Pubkey::default(),
            payer: Address::default(),
            asset: SOL_MINT,
            num_outputs: 4,
            per_output_amount: 100,
            assets: &AssetRegistry::default(),
            selection: InputSelection::Auto,
        }) {
            Ok(split) => split,
            Err(err) => panic!("split failed: {err}"),
        };

        assert_eq!(split.num_outputs, 4);
        assert_eq!(split.per_output_amount, 100);
        let external = &split.signed.external_data;
        // Emitted shape is {1, 8} so the on-chain verifier finds the
        // transfer_confidential_1_8 key: 4 real notes + 4 commitment-only dummies.
        assert_eq!(split.signed.shape.n_inputs, 1);
        assert_eq!(split.signed.shape.n_outputs, 8);
        assert_eq!(external.output_utxo_hashes.len(), 8);
        // One Split bundle at slot 0 plus one aligned dummy ciphertext per padding
        // output (not four confidential recipient slots).
        assert_eq!(external.output_ciphertexts.len(), 1 + (8 - 4));
        let bundle = external
            .output_ciphertexts
            .first()
            .expect("split bundle ciphertext");
        let blob = match OutputData::try_from_slice(&bundle.data).unwrap() {
            OutputData::Encrypted(blob) => blob,
            other => panic!("split bundle must be Encrypted, got {other:?}"),
        };
        assert_eq!(
            blob.first().copied(),
            Some(zolana_transaction::EncryptedScheme::Split.as_byte())
        );
    }

    #[test]
    fn create_split_explicit_input_selects_that_note() {
        let sender = ShieldedKeypair::new().unwrap();
        let wallet = wallet_with_notes(sender.clone(), &[(50, [4u8; 31]), (400, [5u8; 31])]);
        let target = wallet
            .spendable_utxos(SOL_MINT)
            .get(1)
            .copied()
            .expect("target note");

        let split = match create_split_sync(CreateSplit {
            wallet: &wallet,
            authority: &sender,
            owner_pubkey: Pubkey::default(),
            payer: Address::default(),
            asset: SOL_MINT,
            num_outputs: 4,
            per_output_amount: 100,
            assets: &AssetRegistry::default(),
            selection: InputSelection::Explicit(vec![target.hash]),
        }) {
            Ok(split) => split,
            Err(err) => panic!("split from explicit note failed: {err}"),
        };
        // The split spends the 400-note (index 1) and emits the {1, 8} shape.
        assert_eq!(split.signed.external_data.output_utxo_hashes.len(), 8);
        assert_eq!(split.signed.shape.n_outputs, 8);
    }

    #[test]
    fn create_split_auto_selects_exact_matching_note() {
        let sender = ShieldedKeypair::new().unwrap();
        let wallet = wallet_with_notes(sender.clone(), &[(700, [4u8; 31]), (400, [5u8; 31])]);

        let split = match create_split_sync(CreateSplit {
            wallet: &wallet,
            authority: &sender,
            owner_pubkey: Pubkey::default(),
            payer: Address::default(),
            asset: SOL_MINT,
            num_outputs: 4,
            per_output_amount: 100,
            assets: &AssetRegistry::default(),
            selection: InputSelection::Auto,
        }) {
            Ok(split) => split,
            Err(err) => panic!("split auto should pick the 400-note: {err}"),
        };

        assert_eq!(split.num_outputs, 4);
        assert_eq!(split.per_output_amount, 100);
    }

    #[test]
    fn create_split_auto_rejects_when_no_exact_note_matches_total() {
        let sender = ShieldedKeypair::new().unwrap();
        let wallet = wallet_with_notes(sender.clone(), &[(300, [4u8; 31]), (300, [5u8; 31])]);

        let err = match create_split_sync(CreateSplit {
            wallet: &wallet,
            authority: &sender,
            owner_pubkey: Pubkey::default(),
            payer: Address::default(),
            asset: SOL_MINT,
            num_outputs: 4,
            per_output_amount: 100,
            assets: &AssetRegistry::default(),
            selection: InputSelection::Auto,
        }) {
            Ok(_) => panic!("split auto must require one exact input"),
            Err(err) => err,
        };

        assert!(matches!(
            err,
            ClientError::SplitInputUnavailable { requested: 400 }
        ));
    }

    #[test]
    fn merge_auto_selection_picks_smallest_first_capped_at_eight() {
        let sender = ShieldedKeypair::new().unwrap();
        // Ten dust notes of distinct amounts; Auto should sweep the eight smallest.
        let notes = [
            (90, [1u8; 31]),
            (10, [2u8; 31]),
            (80, [3u8; 31]),
            (20, [4u8; 31]),
            (70, [5u8; 31]),
            (30, [6u8; 31]),
            (60, [7u8; 31]),
            (40, [8u8; 31]),
            (50, [9u8; 31]),
            (100, [10u8; 31]),
        ];
        let wallet = wallet_with_notes(sender.clone(), &notes);

        let selected = match select_merge_inputs(&wallet, &sender, SOL_MINT, &InputSelection::Auto)
        {
            Ok(selected) => selected,
            Err(e) => panic!("merge auto selection failed: {e}"),
        };

        assert_eq!(selected.len(), MERGE_INPUTS);
        let amounts: Vec<u64> = selected.iter().map(|s| s.utxo.amount).collect();
        // Smallest eight, in ascending order; the two largest (90, 100) are untouched.
        assert_eq!(amounts, vec![10, 20, 30, 40, 50, 60, 70, 80]);
    }

    #[test]
    fn merge_auto_selection_consolidates_all_notes_below_the_cap() {
        let sender = ShieldedKeypair::new().unwrap();
        let wallet = wallet_with_notes(
            sender.clone(),
            &[(30, [1u8; 31]), (10, [2u8; 31]), (20, [3u8; 31])],
        );

        let selected = match select_merge_inputs(&wallet, &sender, SOL_MINT, &InputSelection::Auto)
        {
            Ok(selected) => selected,
            Err(e) => panic!("merge auto selection failed: {e}"),
        };

        let amounts: Vec<u64> = selected.iter().map(|s| s.utxo.amount).collect();
        assert_eq!(amounts, vec![10, 20, 30]);
    }

    #[test]
    fn merge_auto_selection_rejects_single_note() {
        let sender = ShieldedKeypair::new().unwrap();
        let wallet = wallet_with_notes(sender.clone(), &[(30, [1u8; 31])]);

        let err = match select_merge_inputs(&wallet, &sender, SOL_MINT, &InputSelection::Auto) {
            Ok(_) => panic!("single note must not be consolidatable"),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            ClientError::NothingToConsolidate { asset } if asset == SOL_MINT
        ));
    }

    #[test]
    fn merge_auto_selection_rejects_empty_wallet() {
        let sender = ShieldedKeypair::new().unwrap();
        let wallet = Wallet::new(sender.clone(), AssetRegistry::default()).expect("wallet");

        let err = match select_merge_inputs(&wallet, &sender, SOL_MINT, &InputSelection::Auto) {
            Ok(_) => panic!("empty wallet must not be consolidatable"),
            Err(err) => err,
        };
        assert!(matches!(err, ClientError::NothingToConsolidate { .. }));
    }

    #[test]
    fn merge_explicit_selection_picks_named_notes() {
        let sender = ShieldedKeypair::new().unwrap();
        let wallet = wallet_with_notes(
            sender.clone(),
            &[(30, [1u8; 31]), (70, [2u8; 31]), (50, [3u8; 31])],
        );
        let spendable = wallet.spendable_utxos(SOL_MINT);
        let hashes = vec![
            spendable.first().expect("first note").hash,
            spendable.get(2).expect("third note").hash,
        ];

        let selected = match select_merge_inputs(
            &wallet,
            &sender,
            SOL_MINT,
            &InputSelection::Explicit(hashes),
        ) {
            Ok(selected) => selected,
            Err(e) => panic!("merge explicit selection failed: {e}"),
        };
        // Kept in the listed order (not re-sorted), spending notes 0 and 2.
        let amounts: Vec<u64> = selected.iter().map(|s| s.utxo.amount).collect();
        assert_eq!(amounts, vec![30, 50]);
    }

    #[test]
    fn merge_explicit_selection_rejects_missing_note() {
        let sender = ShieldedKeypair::new().unwrap();
        let wallet = wallet_with_notes(sender.clone(), &[(30, [1u8; 31]), (70, [2u8; 31])]);
        let hash = wallet
            .spendable_utxos(SOL_MINT)
            .first()
            .expect("spendable note")
            .hash;

        let err = match select_merge_inputs(
            &wallet,
            &sender,
            SOL_MINT,
            &InputSelection::Explicit(vec![hash, [9u8; 32]]),
        ) {
            Ok(_) => panic!("missing note must error"),
            Err(err) => err,
        };
        assert!(matches!(err, ClientError::InputNoteUnavailable { .. }));
    }

    #[test]
    fn merge_explicit_selection_rejects_duplicate_note() {
        let sender = ShieldedKeypair::new().unwrap();
        let wallet = wallet_with_notes(sender.clone(), &[(30, [1u8; 31]), (70, [2u8; 31])]);
        let hash = wallet
            .spendable_utxos(SOL_MINT)
            .first()
            .expect("spendable note")
            .hash;

        let err = match select_merge_inputs(
            &wallet,
            &sender,
            SOL_MINT,
            &InputSelection::Explicit(vec![hash, hash]),
        ) {
            Ok(_) => panic!("duplicate merge note must error"),
            Err(err) => err,
        };
        assert!(matches!(err, ClientError::DuplicateInputNote { .. }));
    }

    #[test]
    fn merge_explicit_selection_rejects_more_than_eight_notes() {
        let sender = ShieldedKeypair::new().unwrap();
        let notes = [
            (10, [1u8; 31]),
            (11, [2u8; 31]),
            (12, [3u8; 31]),
            (13, [4u8; 31]),
            (14, [5u8; 31]),
            (15, [6u8; 31]),
            (16, [7u8; 31]),
            (17, [8u8; 31]),
            (18, [9u8; 31]),
        ];
        let wallet = wallet_with_notes(sender.clone(), &notes);
        let hashes: Vec<[u8; 32]> = wallet
            .spendable_utxos(SOL_MINT)
            .iter()
            .map(|note| note.hash)
            .collect();

        let err = match select_merge_inputs(
            &wallet,
            &sender,
            SOL_MINT,
            &InputSelection::Explicit(hashes),
        ) {
            Ok(_) => panic!("nine explicit notes must exceed the merge cap"),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            ClientError::TooManyInputs {
                got: 9,
                max: MERGE_INPUTS,
            }
        ));
    }

    #[test]
    fn merge_explicit_selection_rejects_single_note() {
        let sender = ShieldedKeypair::new().unwrap();
        let wallet = wallet_with_notes(sender.clone(), &[(30, [1u8; 31]), (70, [2u8; 31])]);
        let hash = wallet
            .spendable_utxos(SOL_MINT)
            .first()
            .expect("spendable note")
            .hash;

        let err = match select_merge_inputs(
            &wallet,
            &sender,
            SOL_MINT,
            &InputSelection::Explicit(vec![hash]),
        ) {
            Ok(_) => panic!("one explicit note must not be consolidatable"),
            Err(err) => err,
        };
        assert!(matches!(err, ClientError::NothingToConsolidate { .. }));
    }

    #[test]
    fn create_merge_builds_prepared_plan_over_smallest_notes() {
        let sender = ShieldedKeypair::new().unwrap();
        let wallet = wallet_with_notes(
            sender.clone(),
            &[(30, [1u8; 31]), (70, [2u8; 31]), (20, [3u8; 31])],
        );

        let merged = match create_merge(CreateMerge {
            wallet: &wallet,
            keypair: &sender,
            asset: SOL_MINT,
            selection: InputSelection::Auto,
        }) {
            Ok(merged) => merged,
            Err(e) => panic!("create_merge failed: {e}"),
        };

        assert_eq!(merged.num_inputs, 3);
        assert_eq!(merged.merged_amount, 120);
        // The plan pads to MERGE_INPUTS with dummy inputs; only the three real
        // notes yield input commitments.
        assert_eq!(merged.prepared.inputs.len(), MERGE_INPUTS);
        let commitments = merged
            .prepared
            .input_commitments()
            .expect("input commitments");
        assert_eq!(commitments.len(), 3);
    }

    #[test]
    fn create_split_rejects_value_mismatch() {
        let sender = ShieldedKeypair::new().unwrap();
        // 400-lamport note but requesting 4 x 90 = 360 != 400.
        let wallet = wallet_with_notes(sender.clone(), &[(400, [6u8; 31])]);
        let hash = wallet
            .spendable_utxos(SOL_MINT)
            .first()
            .expect("spendable note")
            .hash;
        let err = match create_split_sync(CreateSplit {
            wallet: &wallet,
            authority: &sender,
            owner_pubkey: Pubkey::default(),
            payer: Address::default(),
            asset: SOL_MINT,
            num_outputs: 4,
            per_output_amount: 90,
            assets: &AssetRegistry::default(),
            selection: InputSelection::Explicit(vec![hash]),
        }) {
            Ok(_) => panic!("value mismatch must error"),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            ClientError::Transaction(TransactionError::SplitAmountMismatch {
                requested: 360,
                available: 400
            })
        ));
    }

    fn withdraw_auto(
        wallet: &Wallet,
        sender: &ShieldedKeypair,
        asset: Address,
        amount: u64,
        assets: &AssetRegistry,
    ) -> Result<CreatedWithdrawal, ClientError> {
        create_withdrawal_sync(CreateWithdrawal {
            wallet,
            authority: sender,
            owner_pubkey: Pubkey::default(),
            payer: Address::default(),
            recipient: Pubkey::new_unique(),
            asset,
            amount,
            assets,
            selection: InputSelection::Auto,
        })
    }

    #[test]
    fn spl_withdrawal_rejects_more_than_three_notes() {
        let sender = ShieldedKeypair::new().unwrap();
        let asset = Address::new_from_array([2u8; 32]);
        // Four SPL notes; withdrawing the whole balance needs all four inputs, one
        // over the SPL packet cap ({4,3} SPL serializes to 1245 > 1232).
        let wallet = wallet_with_asset_notes(
            sender.clone(),
            asset,
            &[
                (10, [1u8; 31]),
                (10, [2u8; 31]),
                (10, [3u8; 31]),
                (10, [4u8; 31]),
            ],
        );
        let assets = AssetRegistry::new([(2, asset)]).expect("asset registry");
        let err = withdraw_auto(&wallet, &sender, asset, 40, &assets)
            .err()
            .expect("four-note SPL withdrawal must exceed the packet cap");
        assert!(matches!(
            err,
            ClientError::FragmentedBalance {
                requested: 40,
                notes: 4,
                max_inputs: MAX_SPL_WITHDRAWAL_INPUTS,
            }
        ));
    }

    #[test]
    fn spl_withdrawal_allows_three_notes() {
        let sender = ShieldedKeypair::new().unwrap();
        let asset = Address::new_from_array([2u8; 32]);
        let wallet = wallet_with_asset_notes(
            sender.clone(),
            asset,
            &[(10, [1u8; 31]), (10, [2u8; 31]), (10, [3u8; 31])],
        );
        let assets = AssetRegistry::new([(2, asset)]).expect("asset registry");
        withdraw_auto(&wallet, &sender, asset, 30, &assets)
            .expect("three-note SPL withdrawal is within the packet cap");
    }

    #[test]
    fn sol_withdrawal_is_not_capped_at_three_notes() {
        let sender = ShieldedKeypair::new().unwrap();
        // SOL withdrawals add fewer settlement accounts, so they stay within the
        // packet limit at the full MAX_TRANSFER_INPUTS and are not SPL-capped.
        let wallet = wallet_with_notes(
            sender.clone(),
            &[
                (10, [1u8; 31]),
                (10, [2u8; 31]),
                (10, [3u8; 31]),
                (10, [4u8; 31]),
                (10, [5u8; 31]),
            ],
        );
        withdraw_auto(&wallet, &sender, SOL_MINT, 50, &AssetRegistry::default())
            .expect("five-note SOL withdrawal is allowed");
    }
}
