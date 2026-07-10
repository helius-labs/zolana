use std::collections::HashSet;

use solana_pubkey::Pubkey;
use zolana_interface::{
    instruction::{TransactSolWithdrawal, TransactSplWithdrawal, TransactWithdrawal},
    pda, SPL_TOKEN_PROGRAM_ID,
};
use zolana_keypair::{shielded::ShieldedAddress, SignatureType};
use zolana_transaction::{
    instructions::{
        transact::{PreparedTransaction, SignedTransaction, Transaction, WithdrawalTarget},
        types::SpendUtxo,
    },
    Address, AssetRegistry, Wallet, SOL_MINT,
};

/// How a private spend chooses wallet notes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum InputSelection {
    /// Choose the fewest notes by scanning unspent notes largest-first.
    #[default]
    Auto,
    /// Spend exactly these commitment hashes, in the supplied order.
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

use crate::{
    error::ClientError,
    wallet_authority::{
        ApprovalRequest, ConfidentialRecipientSlot, SyncWalletAuthority, WalletAuthority,
    },
};

#[derive(Clone)]
pub struct CreatedTransfer {
    pub signed: SignedTransaction,
    /// Committed output hash used to confirm indexer progress.
    pub wait_output_hash: [u8; 32],
    pub recipient: ShieldedAddress,
}

#[derive(Clone)]
pub struct CreatedWithdrawal {
    pub signed: SignedTransaction,
    /// Committed output hash used to confirm indexer progress.
    pub wait_output_hash: [u8; 32],
    pub withdrawal: TransactWithdrawal,
}

/// Build a private transfer to a concrete shielded address.
///
/// This action performs no user-registry lookup. Resolve an optional registry
/// alias before constructing this request, or use [`CreateWithdrawal`] for an
/// explicit public destination.
pub struct CreateTransfer<'a, A: ?Sized> {
    pub wallet: &'a Wallet,
    pub authority: &'a A,
    pub owner_pubkey: Pubkey,
    pub payer: Address,
    pub recipient: ShieldedAddress,
    pub asset: Address,
    pub amount: u64,
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
    let prepared = tx.prepare(&request.wallet.registry)?;
    let wait_output_hash = prepared.wait_output_hash()?;
    let signed = sign_prepared(
        prepared,
        &address,
        request.owner_pubkey,
        request.authority,
        &request.wallet.registry,
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
    let prepared = tx.prepare(&request.wallet.registry)?;
    let wait_output_hash = prepared.wait_output_hash()?;
    let signed = sign_prepared(
        prepared,
        &address,
        request.owner_pubkey,
        request.authority,
        &request.wallet.registry,
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
    if address.signing_pubkey.signature_type()? == SignatureType::P256 {
        let message_hash = signed.message_hash()?;
        let sig = authority.sign_p256(owner_pubkey, &message_hash).await?;
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&sig.sig_r);
        bytes[32..].copy_from_slice(&sig.sig_s);
        signed.p256_owner = Some(bytes);
    }
    Ok(signed)
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

/// Maximum regular private-transfer input count. `{5,3}` is the widest enabled
/// packet-safe shape.
pub const MAX_TRANSFER_INPUTS: usize = 5;

/// SPL settlement adds more account keys than a shielded transfer or SOL
/// withdrawal. `{3,3}` fits the packet limit; `{4,3}` does not.
const MAX_SPL_WITHDRAWAL_INPUTS: usize = 3;

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

#[cfg(test)]
mod tests {
    use zolana_keypair::ShieldedKeypair;
    use zolana_transaction::{Data, Utxo, WalletUtxo};

    use super::*;

    fn wallet_with_sol(keypair: ShieldedKeypair, amount: u64) -> Wallet {
        wallet_with_asset(keypair, SOL_MINT, amount)
    }

    fn wallet_with_asset(keypair: ShieldedKeypair, asset: Address, amount: u64) -> Wallet {
        wallet_with_asset_notes(keypair, asset, &[(amount, [7u8; 31])])
    }

    fn wallet_with_notes(keypair: ShieldedKeypair, notes: &[(u64, [u8; 31])]) -> Wallet {
        wallet_with_asset_notes(keypair, SOL_MINT, notes)
    }

    fn wallet_with_asset_notes(
        keypair: ShieldedKeypair,
        asset: Address,
        notes: &[(u64, [u8; 31])],
    ) -> Wallet {
        let registry = if asset == SOL_MINT {
            AssetRegistry::default()
        } else {
            AssetRegistry::new([(2, asset)]).expect("asset registry")
        };
        let mut wallet = Wallet::new(keypair.clone(), registry).expect("wallet");
        for (amount, blinding) in notes {
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
            selection: InputSelection::Auto,
        })
        .expect("transfer");

        assert_eq!(result.recipient, recipient);
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

    fn selected(
        wallet: &Wallet,
        sender: &ShieldedKeypair,
        asset: Address,
        amount: u64,
        selection: &InputSelection,
    ) -> Result<Vec<SpendUtxo>, ClientError> {
        futures::executor::block_on(select_inputs(
            wallet,
            sender,
            Pubkey::default(),
            asset,
            amount,
            selection,
        ))
    }

    #[test]
    fn spendable_utxos_expose_selectable_hashes() {
        let keypair = ShieldedKeypair::new().unwrap();
        let wallet = wallet_with_notes(keypair, &[(30, [1u8; 31]), (70, [2u8; 31])]);
        let spendable = wallet.spendable_utxos(SOL_MINT);

        assert_eq!(
            spendable.iter().map(|note| note.amount).collect::<Vec<_>>(),
            vec![30, 70]
        );
        for (note, entry) in spendable.iter().zip(&wallet.utxos) {
            assert_eq!(note.hash, entry.output_context.hash);
        }
    }

    #[test]
    fn explicit_selection_picks_named_note() {
        let sender = ShieldedKeypair::new().unwrap();
        let wallet = wallet_with_notes(sender.clone(), &[(30, [1u8; 31]), (70, [2u8; 31])]);
        let target = wallet.spendable_utxos(SOL_MINT)[1];

        let inputs = selected(
            &wallet,
            &sender,
            SOL_MINT,
            50,
            &InputSelection::Explicit(vec![target.hash]),
        )
        .expect("explicit selection");

        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].utxo.amount, 70);
    }

    #[test]
    fn explicit_selection_rejects_missing_and_duplicate_notes() {
        let sender = ShieldedKeypair::new().unwrap();
        let wallet = wallet_with_notes(sender.clone(), &[(30, [1u8; 31])]);
        let hash = wallet.spendable_utxos(SOL_MINT)[0].hash;

        let missing = selected(
            &wallet,
            &sender,
            SOL_MINT,
            10,
            &InputSelection::Explicit(vec![[9u8; 32]]),
        )
        .err()
        .expect("missing note");
        assert!(matches!(missing, ClientError::InputNoteUnavailable { .. }));

        let duplicate = selected(
            &wallet,
            &sender,
            SOL_MINT,
            10,
            &InputSelection::Explicit(vec![hash, hash]),
        )
        .err()
        .expect("duplicate note");
        assert!(matches!(duplicate, ClientError::DuplicateInputNote { .. }));
    }

    #[test]
    fn auto_selection_is_largest_first_and_allows_five_inputs() {
        let sender = ShieldedKeypair::new().unwrap();
        let wallet = wallet_with_notes(
            sender.clone(),
            &[(30, [1u8; 31]), (70, [2u8; 31]), (50, [3u8; 31])],
        );
        let inputs =
            selected(&wallet, &sender, SOL_MINT, 60, &InputSelection::Auto).expect("largest first");
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].utxo.amount, 70);

        let five = wallet_with_notes(
            sender.clone(),
            &[
                (10, [1u8; 31]),
                (10, [2u8; 31]),
                (10, [3u8; 31]),
                (10, [4u8; 31]),
                (10, [5u8; 31]),
            ],
        );
        assert_eq!(
            selected(&five, &sender, SOL_MINT, 50, &InputSelection::Auto)
                .expect("five inputs")
                .len(),
            MAX_TRANSFER_INPUTS
        );
    }

    #[test]
    fn auto_and_explicit_selection_reject_six_inputs() {
        let sender = ShieldedKeypair::new().unwrap();
        let wallet = wallet_with_notes(
            sender.clone(),
            &[
                (10, [1u8; 31]),
                (10, [2u8; 31]),
                (10, [3u8; 31]),
                (10, [4u8; 31]),
                (10, [5u8; 31]),
                (10, [6u8; 31]),
            ],
        );

        let auto = selected(&wallet, &sender, SOL_MINT, 60, &InputSelection::Auto)
            .err()
            .expect("six auto inputs");
        assert!(matches!(
            auto,
            ClientError::FragmentedBalance {
                notes: 6,
                max_inputs: MAX_TRANSFER_INPUTS,
                ..
            }
        ));

        let hashes = wallet
            .spendable_utxos(SOL_MINT)
            .into_iter()
            .map(|note| note.hash)
            .collect();
        let explicit = selected(
            &wallet,
            &sender,
            SOL_MINT,
            60,
            &InputSelection::Explicit(hashes),
        )
        .err()
        .expect("six explicit inputs");
        assert!(matches!(
            explicit,
            ClientError::FragmentedBalance {
                notes: 6,
                max_inputs: MAX_TRANSFER_INPUTS,
                ..
            }
        ));
    }

    #[test]
    fn selection_rejects_zero_amount() {
        let sender = ShieldedKeypair::new().unwrap();
        let wallet = wallet_with_sol(sender.clone(), 10);
        assert!(matches!(
            selected(&wallet, &sender, SOL_MINT, 0, &InputSelection::Auto),
            Err(ClientError::ZeroAmount)
        ));
    }

    fn withdraw_auto(
        wallet: &Wallet,
        sender: &ShieldedKeypair,
        asset: Address,
        amount: u64,
    ) -> Result<CreatedWithdrawal, ClientError> {
        create_withdrawal_sync(CreateWithdrawal {
            wallet,
            authority: sender,
            owner_pubkey: Pubkey::default(),
            payer: Address::default(),
            recipient: Pubkey::new_unique(),
            asset,
            amount,
            selection: InputSelection::Auto,
        })
    }

    #[test]
    fn spl_withdrawal_caps_at_three_inputs_while_sol_allows_five() {
        let sender = ShieldedKeypair::new().unwrap();
        let asset = Address::new_from_array([2u8; 32]);
        let four_spl = wallet_with_asset_notes(
            sender.clone(),
            asset,
            &[
                (10, [1u8; 31]),
                (10, [2u8; 31]),
                (10, [3u8; 31]),
                (10, [4u8; 31]),
            ],
        );
        assert!(matches!(
            withdraw_auto(&four_spl, &sender, asset, 40),
            Err(ClientError::FragmentedBalance {
                notes: 4,
                max_inputs: MAX_SPL_WITHDRAWAL_INPUTS,
                ..
            })
        ));

        let three_spl = wallet_with_asset_notes(
            sender.clone(),
            asset,
            &[(10, [1u8; 31]), (10, [2u8; 31]), (10, [3u8; 31])],
        );
        withdraw_auto(&three_spl, &sender, asset, 30).expect("three SPL inputs");

        let five_sol = wallet_with_notes(
            sender.clone(),
            &[
                (10, [1u8; 31]),
                (10, [2u8; 31]),
                (10, [3u8; 31]),
                (10, [4u8; 31]),
                (10, [5u8; 31]),
            ],
        );
        withdraw_auto(&five_sol, &sender, SOL_MINT, 50).expect("five SOL inputs");
    }
}
