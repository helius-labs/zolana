use std::collections::HashSet;

use solana_pubkey::Pubkey;
use zolana_interface::{
    instruction::{TransactSolWithdrawal, TransactSplWithdrawal, TransactWithdrawal},
    pda, SPL_TOKEN_PROGRAM_ID,
};
use zolana_keypair::{shielded::ShieldedAddress, viewing_key::ViewTag, SignatureType};
use zolana_transaction::{
    instructions::{
        transact::{
            PreparedTransaction, SignedTransaction, Transaction, WithdrawalTarget,
            SENDER_SLOT_COUNT,
        },
        types::SpendUtxo,
    },
    Address, AssetRegistry, Wallet, WalletUtxo,
};

use crate::{
    canonical_shape,
    error::ClientError,
    user_registry::TransferRecipient,
    wallet_authority::{
        ApprovalRequest, ConfidentialRecipientSlot, SyncWalletAuthority, WalletAuthority,
    },
};

/// A recipient resolved to its registered private wallet: the owner's Solana
/// pubkey plus the shielded address and view tag a private transfer is built
/// against. The [`TransferRecipient::Private`] payload of
/// [`resolve_recipient`](crate::user_registry::resolve_recipient).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedAddress {
    pub owner: Pubkey,
    pub address: ShieldedAddress,
    pub view_tag: ViewTag,
}

/// A built and signed private transfer, awaiting its proof. Pass it to
/// `rpc.send(payer).execute(&transfer)` to prove, send, and wait for indexing.
#[derive(Clone)]
pub struct CreatedTransfer {
    pub signed: SignedTransaction,
    pub wait_tag: ViewTag,
    pub recipient: TransferRecipient,
    /// Public settlement routing, present when the recipient resolved to
    /// [`TransferRecipient::Public`] and the transfer became a withdrawal.
    pub withdrawal: Option<TransactWithdrawal>,
}

#[derive(Clone)]
pub struct CreatedWithdrawal {
    pub signed: SignedTransaction,
    pub wait_tag: ViewTag,
    pub withdrawal: TransactWithdrawal,
}

/// A private transfer, built and signed locally.
///
/// No network happens here: the one chain read a transfer needs is the
/// explicit [`resolve_recipient`](crate::user_registry::resolve_recipient)
/// step that produces the `destination` field. A destination that resolved to
/// [`TransferRecipient::Public`] makes the transfer settle as a
/// private-to-public withdrawal instead. Finish with
/// [`PrivateTransfer::create`] (async; custody hosts whose signing crosses a
/// network boundary) or [`PrivateTransfer::instruction`] (blocking; local
/// keys and tests).
pub struct PrivateTransfer<'a, A: ?Sized> {
    pub source: &'a Wallet,
    pub destination: TransferRecipient,
    /// The asset's mint; [`SOL_MINT`](crate::SOL_MINT) for SOL.
    pub asset: Pubkey,
    pub amount: u64,
    pub authority: &'a A,
    pub payer: Pubkey,
    /// Free-form note for the recipient, encrypted into their output
    /// ciphertext and not committed into any hash. It lengthens that
    /// ciphertext, so its presence and byte length are visible onchain; the
    /// contents are not. Ignored when the transfer settles as a public
    /// withdrawal (public funds carry no ciphertext).
    pub memo: Option<Vec<u8>>,
}

/// A private-to-public withdrawal, built and signed locally. Finish with
/// [`Withdrawal::create`] (async; custody hosts whose signing crosses a
/// network boundary) or [`Withdrawal::instruction`] (blocking; local keys and
/// tests).
pub struct Withdrawal<'a, A: ?Sized> {
    pub source: &'a Wallet,
    pub destination: Pubkey,
    /// The asset's mint; [`SOL_MINT`](crate::SOL_MINT) for SOL.
    pub asset: Pubkey,
    pub amount: u64,
    pub authority: &'a A,
    pub payer: Pubkey,
}

impl<A: ?Sized> PrivateTransfer<'_, A> {
    /// Build and sign the transfer through the async [`WalletAuthority`] —
    /// the builder for embedded and custody hosts whose signing, encryption,
    /// or approval crosses a network boundary (enclaves, passkeys, remote
    /// signers). Hosts managing many users' wallets scope their
    /// [`MultiWalletAuthority`](crate::wallet_authority::MultiWalletAuthority)
    /// per user with [`Scoped::new`](crate::wallet_authority::Scoped::new)
    /// and pass the result as `authority`.
    ///
    /// Returns a signed payload awaiting its proof, not a composable Solana
    /// `Instruction`; pass it to `rpc.send(payer).execute(&transfer)`. No
    /// network happens here; the chain read lives in `resolve_recipient`.
    pub async fn create(self) -> Result<CreatedTransfer, ClientError>
    where
        A: WalletAuthority,
    {
        create_transfer(self).await
    }

    /// Blocking twin of [`PrivateTransfer::create`] for local-key authorities
    /// (a [`SyncWalletAuthority`], such as a `ShieldedKeypair`) — the
    /// convenience for CLI flows and tests.
    pub fn instruction(self) -> Result<CreatedTransfer, ClientError>
    where
        A: SyncWalletAuthority,
    {
        create_transfer_sync(self)
    }
}

impl<A: ?Sized> Withdrawal<'_, A> {
    /// Build and sign the withdrawal through the async [`WalletAuthority`] —
    /// the builder for embedded and custody hosts whose signing, encryption,
    /// or approval crosses a network boundary (enclaves, passkeys, remote
    /// signers). Hosts managing many users' wallets scope their
    /// [`MultiWalletAuthority`](crate::wallet_authority::MultiWalletAuthority)
    /// per user with [`Scoped::new`](crate::wallet_authority::Scoped::new)
    /// and pass the result as `authority`.
    ///
    /// Returns a signed payload awaiting its proof, not a composable Solana
    /// `Instruction`; pass it to `rpc.send(payer).execute(&withdrawal)`. No
    /// network happens here.
    pub async fn create(self) -> Result<CreatedWithdrawal, ClientError>
    where
        A: WalletAuthority,
    {
        create_withdrawal(self).await
    }

    /// Blocking twin of [`Withdrawal::create`] for local-key authorities
    /// (a [`SyncWalletAuthority`], such as a `ShieldedKeypair`) — the
    /// convenience for CLI flows and tests.
    pub fn instruction(self) -> Result<CreatedWithdrawal, ClientError>
    where
        A: SyncWalletAuthority,
    {
        create_withdrawal_sync(self)
    }
}

pub async fn create_transfer<A: WalletAuthority + ?Sized>(
    request: PrivateTransfer<'_, A>,
) -> Result<CreatedTransfer, ClientError> {
    let recipient = request.destination;
    let resolved = match recipient {
        TransferRecipient::Private(resolved) => resolved,
        // Unregistered recipient: settle publicly. The resolve step already
        // made the degradation visible; here it is just routing.
        TransferRecipient::Public(recipient_pubkey) => {
            let created = create_withdrawal(Withdrawal {
                source: request.source,
                destination: recipient_pubkey,
                asset: request.asset,
                amount: request.amount,
                authority: request.authority,
                payer: request.payer,
            })
            .await?;
            return Ok(CreatedTransfer {
                signed: created.signed,
                wait_tag: created.wait_tag,
                recipient,
                withdrawal: Some(created.withdrawal),
            });
        }
    };
    let asset = Address::new_from_array(request.asset.to_bytes());
    let payer = Address::new_from_array(request.payer.to_bytes());
    let inputs = select_inputs(request.source, request.authority, asset, request.amount).await?;
    let address = request.authority.shielded_address().await?;
    let wait_tag = address.signing_pubkey.confidential_view_tag()?;
    let mut tx = Transaction::new(address, inputs, payer);
    tx.send_with_memo(&resolved.address, asset, request.amount, request.memo)?;
    let prepared = tx.prepare(&request.source.registry)?;
    let signed = sign_prepared(
        prepared,
        &address,
        request.authority,
        &request.source.registry,
        format!(
            "private transfer of {} to {}",
            request.amount, resolved.owner
        ),
    )
    .await?;
    Ok(CreatedTransfer {
        signed,
        wait_tag,
        recipient,
        withdrawal: None,
    })
}

/// Blocking adapter for CLI and unit-test flows. Async hosts should call
/// [`create_transfer`] directly.
pub fn create_transfer_sync<A: SyncWalletAuthority + ?Sized>(
    request: PrivateTransfer<'_, A>,
) -> Result<CreatedTransfer, ClientError> {
    futures::executor::block_on(create_transfer(request))
}

pub async fn create_withdrawal<A: WalletAuthority + ?Sized>(
    request: Withdrawal<'_, A>,
) -> Result<CreatedWithdrawal, ClientError> {
    let asset = Address::new_from_array(request.asset.to_bytes());
    let payer = Address::new_from_array(request.payer.to_bytes());
    let inputs = select_inputs(request.source, request.authority, asset, request.amount).await?;
    let (target, withdrawal) = withdrawal_target(request.destination, request.asset)?;
    let address = request.authority.shielded_address().await?;
    let wait_tag = address.signing_pubkey.confidential_view_tag()?;
    let mut tx = Transaction::new(address, inputs, payer);
    tx.withdraw(asset, request.amount, target)?;
    let prepared = tx.prepare(&request.source.registry)?;
    let signed = sign_prepared(
        prepared,
        &address,
        request.authority,
        &request.source.registry,
        format!("withdraw {} to {}", request.amount, request.destination),
    )
    .await?;
    Ok(CreatedWithdrawal {
        signed,
        wait_tag,
        withdrawal,
    })
}

/// Blocking adapter for CLI and unit-test flows. Async hosts should call
/// [`create_withdrawal`] directly.
pub fn create_withdrawal_sync<A: SyncWalletAuthority + ?Sized>(
    request: Withdrawal<'_, A>,
) -> Result<CreatedWithdrawal, ClientError> {
    futures::executor::block_on(create_withdrawal(request))
}

/// Sign a prepared transaction through a wallet authority (encrypt, approve,
/// P256-sign).
pub async fn sign_transaction<A: WalletAuthority + ?Sized>(
    tx: Transaction,
    wallet: &Wallet,
    authority: &A,
) -> Result<SignedTransaction, ClientError> {
    let address = authority.shielded_address().await?;
    let prepared = tx.prepare(&wallet.registry)?;
    sign_prepared(
        prepared,
        &address,
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
    authority: &A,
) -> Result<SignedTransaction, ClientError> {
    futures::executor::block_on(sign_transaction(tx, wallet, authority))
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
    authority: &A,
    assets: &AssetRegistry,
    approval_summary: String,
) -> Result<SignedTransaction, ClientError> {
    let sender_tag = address.signing_pubkey.confidential_view_tag()?;
    let encrypted = authority
        .encrypt_confidential_transfer(
            &prepared.first_nullifier,
            sender_tag,
            &prepared.sender_plaintext,
            &recipient_slots(&prepared),
        )
        .await?;
    authority
        .request_user_approval(ApprovalRequest {
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
        let sig = authority.sign_p256(&message_hash).await?;
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&sig.sig_r);
        bytes[32..].copy_from_slice(&sig.sig_s);
        signed.p256_owner = Some(bytes);
    }
    Ok(signed)
}

fn withdrawal_target(
    recipient: Pubkey,
    asset: Pubkey,
) -> Result<(WithdrawalTarget, TransactWithdrawal), ClientError> {
    if asset == crate::SOL_MINT {
        return Ok((
            WithdrawalTarget::Sol {
                user_sol_account: Address::new_from_array(recipient.to_bytes()),
            },
            TransactWithdrawal::Sol(TransactSolWithdrawal { recipient }),
        ));
    }

    let mint = asset;
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

async fn select_inputs<A: WalletAuthority + ?Sized>(
    wallet: &Wallet,
    authority: &A,
    asset: Address,
    amount: u64,
) -> Result<Vec<SpendUtxo>, ClientError> {
    let nullifier_key = authority.spend_nullifier_key().await?;
    let mut selected = Vec::new();
    let mut total = 0u64;
    for entry in &wallet.utxos {
        if entry.spent || entry.utxo.asset != asset {
            continue;
        }
        selected.push(SpendUtxo {
            utxo: entry.utxo.clone(),
            nullifier_key: nullifier_key.clone(),
            data_hash: None,
            zone_data_hash: None,
        });
        total = total
            .checked_add(entry.utxo.amount)
            .ok_or(ClientError::SelectedBalanceOverflow)?;
        if total >= amount {
            break;
        }
    }
    if total < amount {
        return Err(ClientError::InsufficientBalance {
            requested: amount,
            available: total,
        });
    }
    Ok(selected)
}

/// UTXO count ceiling for a single shaped transaction: the largest input arity
/// any supported transfer shape provides.
pub const MAX_SELECTABLE_INPUTS: usize = 5;

/// Select the fewest unlocked UTXOs of `asset` whose combined value covers
/// `amount`, such that the resulting transaction — `selected` inputs against
/// [`SENDER_SLOT_COUNT`] sender-change slots plus `output_count` recipient
/// outputs — fits a [supported shape](crate::SUPPORTED_SHAPES) within
/// [`MAX_SELECTABLE_INPUTS`].
///
/// Unlike the greedy [`select_inputs`] behind the high-level transfer, this is
/// shape- and lock-aware: `output_count` is the number of recipient outputs the
/// caller intends to add (the builder always reserves [`SENDER_SLOT_COUNT`]
/// change slots on top), and `excluded` holds the commitment hashes
/// (`WalletUtxo::output_context.hash`) of UTXOs already locked in flight, which
/// are skipped so concurrent transactions spend disjoint sets.
///
/// Picks largest-first to reach `amount` in the fewest inputs, and separates two
/// failures a caller handles differently:
/// - [`ClientError::InsufficientBalance`] — the total unlocked balance is below
///   `amount`; the wallet simply lacks the funds.
/// - [`ClientError::ShapeExceeded`] — the balance covers `amount` but is too
///   fragmented (or `output_count` is too large) for any subset of at most
///   [`MAX_SELECTABLE_INPUTS`] UTXOs to fit a supported shape; the caller should
///   consolidate/denominate before retrying.
pub async fn select_inputs_for_shape<A: WalletAuthority + ?Sized>(
    wallet: &Wallet,
    authority: &A,
    asset: Address,
    amount: u64,
    output_count: usize,
    excluded: &HashSet<[u8; 32]>,
) -> Result<Vec<SpendUtxo>, ClientError> {
    let nullifier_key = authority.spend_nullifier_key().await?;
    let required_outputs = SENDER_SLOT_COUNT + output_count;

    // Spendable UTXOs of this asset, largest first, so the running sum reaches
    // `amount` in the fewest inputs.
    let mut available: Vec<&WalletUtxo> = wallet
        .utxos
        .iter()
        .filter(|entry| {
            !entry.spent
                && entry.utxo.asset == asset
                && !excluded.contains(&entry.output_context.hash)
        })
        .collect();
    available.sort_by_key(|entry| std::cmp::Reverse(entry.utxo.amount));

    let mut total = 0u64;
    for entry in &available {
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

    let mut selected = Vec::new();
    let mut running = 0u64;
    for entry in available.iter().take(MAX_SELECTABLE_INPUTS) {
        selected.push(SpendUtxo {
            utxo: entry.utxo.clone(),
            nullifier_key: nullifier_key.clone(),
            data_hash: None,
            zone_data_hash: None,
        });
        // Bounded by `total`, which was overflow-checked above.
        running += entry.utxo.amount;
        if running >= amount && canonical_shape(selected.len(), required_outputs).is_ok() {
            return Ok(selected);
        }
    }

    Err(ClientError::ShapeExceeded {
        requested: amount,
        available: total,
        max_inputs: MAX_SELECTABLE_INPUTS,
    })
}

#[cfg(test)]
mod tests {
    use borsh::to_vec;
    use solana_account::Account;
    use zolana_keypair::ShieldedKeypair;
    use zolana_transaction::{Data, Utxo, WalletUtxo, SOL_MINT};
    use zolana_user_registry_interface::{user_record_pda, user_registry_program_id, UserRecord};

    use super::*;
    use crate::{rpc::Rpc, user_registry::resolve_recipient};

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
        let mut wallet = Wallet::new(keypair.clone(), registry).expect("wallet");
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
            spent: false,
        });
        wallet
    }

    #[test]
    fn private_transfer_to_resolved_recipient_builds_shielded_transfer() {
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

        let resolved = resolve_recipient(&rpc, owner).expect("resolve");
        assert!(!resolved.is_public());
        let result = PrivateTransfer {
            source: &wallet,
            destination: resolved,
            asset: crate::SOL_MINT,
            amount: 1,
            authority: &sender,
            payer: Pubkey::default(),
            memo: None,
        }
        .instruction()
        .expect("transfer");

        assert_eq!(result.recipient, resolved);
        assert_eq!(result.recipient.pubkey(), owner);
        assert!(result.withdrawal.is_none());
    }

    #[test]
    fn private_transfer_to_unregistered_recipient_settles_as_public_withdrawal() {
        let sender = ShieldedKeypair::new().unwrap();
        let wallet = wallet_with_sol(sender.clone(), 10);
        let recipient = Pubkey::new_unique();
        let rpc = MockRpc { account: None };

        let resolved = resolve_recipient(&rpc, recipient).expect("resolve");
        assert_eq!(resolved, TransferRecipient::Public(recipient));

        let result = PrivateTransfer {
            source: &wallet,
            destination: resolved,
            asset: crate::SOL_MINT,
            amount: 1,
            authority: &sender,
            payer: Pubkey::default(),
            memo: None,
        }
        .instruction()
        .expect("public withdrawal fallback");

        assert!(result.recipient.is_public());
        assert_eq!(
            result.withdrawal,
            Some(TransactWithdrawal::Sol(TransactSolWithdrawal { recipient }))
        );
    }

    fn wallet_with_amounts(keypair: ShieldedKeypair, asset: Address, amounts: &[u64]) -> Wallet {
        let registry = if asset == SOL_MINT {
            AssetRegistry::default()
        } else {
            AssetRegistry::new([(2, asset)]).expect("asset registry")
        };
        let mut wallet = Wallet::new(keypair.clone(), registry).expect("wallet");
        let nullifier_pk = keypair.nullifier_key.pubkey().expect("nullifier pubkey");
        for (i, &amount) in amounts.iter().enumerate() {
            let utxo = Utxo {
                owner: keypair.signing_pubkey(),
                asset,
                amount,
                blinding: [(i + 1) as u8; 31],
                zone_program_id: None,
                data: Data::default(),
            };
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
                    leaf_index: i as u64,
                },
                nullifier,
                spent: false,
            });
        }
        wallet
    }

    fn select(
        wallet: &Wallet,
        keypair: &ShieldedKeypair,
        amount: u64,
        output_count: usize,
        excluded: &HashSet<[u8; 32]>,
    ) -> Result<Vec<SpendUtxo>, ClientError> {
        futures::executor::block_on(select_inputs_for_shape(
            wallet,
            keypair,
            SOL_MINT,
            amount,
            output_count,
            excluded,
        ))
    }

    fn selected_amounts(selected: &[SpendUtxo]) -> Vec<u64> {
        selected.iter().map(|s| s.utxo.amount).collect()
    }

    #[test]
    fn shape_selector_picks_fewest_inputs_largest_first() {
        let keypair = ShieldedKeypair::new().unwrap();
        let wallet = wallet_with_amounts(keypair.clone(), SOL_MINT, &[100, 50, 30]);

        let selected = select(&wallet, &keypair, 120, 1, &HashSet::new()).expect("selection");

        assert_eq!(selected.len(), 2);
        assert_eq!(selected_amounts(&selected), vec![100, 50]);
    }

    #[test]
    fn shape_selector_skips_locked_utxos() {
        let keypair = ShieldedKeypair::new().unwrap();
        let wallet = wallet_with_amounts(keypair.clone(), SOL_MINT, &[100, 50, 30]);
        let locked_hash = wallet.utxos[0].output_context.hash;
        let excluded = HashSet::from([locked_hash]);

        let selected = select(&wallet, &keypair, 60, 1, &excluded).expect("selection");

        assert_eq!(selected.len(), 2);
        assert_eq!(selected_amounts(&selected), vec![50, 30]);
        assert!(selected.iter().all(|s| s.utxo.amount != 100));
    }

    #[test]
    fn shape_selector_reports_insufficient_balance() {
        let keypair = ShieldedKeypair::new().unwrap();
        let wallet = wallet_with_amounts(keypair.clone(), SOL_MINT, &[10, 10]);

        match select(&wallet, &keypair, 100, 1, &HashSet::new())
            .err()
            .expect("should fail")
        {
            ClientError::InsufficientBalance {
                requested,
                available,
            } => assert_eq!((requested, available), (100, 20)),
            other => panic!("expected InsufficientBalance, got {other:?}"),
        }
    }

    #[test]
    fn shape_selector_reports_shape_exceeded_when_fragmented() {
        let keypair = ShieldedKeypair::new().unwrap();
        // Six UTXOs of 10 cover 60, but no <= 5-input subset does.
        let wallet = wallet_with_amounts(keypair.clone(), SOL_MINT, &[10, 10, 10, 10, 10, 10]);

        match select(&wallet, &keypair, 60, 1, &HashSet::new())
            .err()
            .expect("should fail")
        {
            ClientError::ShapeExceeded {
                requested,
                available,
                max_inputs,
            } => assert_eq!((requested, available, max_inputs), (60, 60, 5)),
            other => panic!("expected ShapeExceeded, got {other:?}"),
        }
    }

    #[test]
    fn shape_selector_reports_shape_exceeded_when_output_count_caps_inputs() {
        let keypair = ShieldedKeypair::new().unwrap();
        // Balance is ample, but six recipient outputs force the (1,8) shape, so
        // only a single input is admissible and one 50 UTXO cannot cover 60.
        let wallet = wallet_with_amounts(keypair.clone(), SOL_MINT, &[50, 50]);

        match select(&wallet, &keypair, 60, 6, &HashSet::new())
            .err()
            .expect("should fail")
        {
            ClientError::ShapeExceeded {
                requested,
                available,
                max_inputs,
            } => assert_eq!((requested, available, max_inputs), (60, 100, 5)),
            other => panic!("expected ShapeExceeded, got {other:?}"),
        }
    }

    #[test]
    fn withdrawal_builds_spl_settlement_to_recipient_ata() {
        let sender = ShieldedKeypair::new().unwrap();
        let mint = Pubkey::new_unique();
        let asset = Address::new_from_array(mint.to_bytes());
        let wallet = wallet_with_asset(sender.clone(), asset, 10);
        let recipient = Pubkey::new_unique();
        let token_account = pda::associated_token_address(&recipient, &mint);

        let result = Withdrawal {
            source: &wallet,
            destination: recipient,
            asset: mint,
            amount: 1,
            authority: &sender,
            payer: Pubkey::default(),
        }
        .instruction()
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
}
