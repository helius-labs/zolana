use std::collections::BTreeSet;

use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature as EcdsaSignature, VerifyingKey};
use solana_pubkey::Pubkey;
use zolana_interface::{
    instruction::{TransactSolWithdrawal, TransactSplWithdrawal, TransactWithdrawal},
    pda, SPL_TOKEN_PROGRAM_ID,
};
use zolana_keypair::{shielded::ShieldedAddress, viewing_key::ViewTag, SignatureType};
use zolana_transaction::{
    instructions::{
        transact::{ConfidentialTransfer, PreparedTransfer, SppProofInputs, WithdrawalTarget},
        types::SppProofInputUtxo,
    },
    Address, AssetRegistry, Utxo, Wallet, SOL_MINT,
};

#[cfg(feature = "indexer-api")]
use solana_signer::Signer;
#[cfg(feature = "indexer-api")]
use solana_transaction::Transaction as SolanaTransaction;

use crate::{
    error::ClientError,
    rpc::{AsyncRpc, Rpc},
    user_registry::{try_resolve_registered_address, try_resolve_registered_address_async},
    wallet_authority::{ApprovalRequest, SyncWalletAuthority, WalletAuthority},
};

#[cfg(feature = "indexer-api")]
use crate::client::ZolanaClient;

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

#[doc(hidden)]
pub struct SignedPrivateTransaction {
    pub transaction: SppProofInputs,
    pub withdrawal: Option<TransactWithdrawal>,
    pub tree: Address,
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

#[cfg(feature = "indexer-api")]
pub async fn build_private_transaction<A: WalletAuthority + ?Sized, R: AsyncRpc>(
    transaction: UnsignedPrivateTransaction,
    wallet: &Wallet,
    authority: &A,
    client: &ZolanaClient<R>,
    fee_payer: Pubkey,
) -> Result<SolanaTransaction, ClientError> {
    let shielded = sign_shielded_transaction(transaction, wallet, authority).await?;
    client
        .finish_submission_unsigned(&shielded, fee_payer)
        .await
}

#[cfg(feature = "indexer-api")]
pub async fn sign_private_transaction<A: WalletAuthority + ?Sized, R: AsyncRpc>(
    transaction: UnsignedPrivateTransaction,
    wallet: &Wallet,
    authority: &A,
    client: &ZolanaClient<R>,
    fee_payer: &dyn Signer,
) -> Result<SolanaTransaction, ClientError> {
    let shielded = sign_shielded_transaction(transaction, wallet, authority).await?;
    let mut native = client
        .finish_submission_unsigned(&shielded, fee_payer.pubkey())
        .await?;
    let blockhash = native.message.recent_blockhash;
    native
        .try_sign(&[fee_payer], blockhash)
        .map_err(|err| ClientError::SolanaTransactionSigning(err.to_string()))?;
    Ok(native)
}

#[cfg(feature = "indexer-api")]
pub fn build_private_transaction_sync<A: SyncWalletAuthority + ?Sized, R: Rpc>(
    transaction: UnsignedPrivateTransaction,
    wallet: &Wallet,
    authority: &A,
    client: &ZolanaClient<R>,
    fee_payer: Pubkey,
) -> Result<SolanaTransaction, ClientError> {
    let shielded = sign_shielded_transaction_sync(transaction, wallet, authority)?;
    client.finish_submission_unsigned_sync(&shielded, fee_payer)
}

#[cfg(feature = "indexer-api")]
pub fn sign_private_transaction_sync<A: SyncWalletAuthority + ?Sized, R: Rpc>(
    transaction: UnsignedPrivateTransaction,
    wallet: &Wallet,
    authority: &A,
    client: &ZolanaClient<R>,
    fee_payer: &dyn Signer,
) -> Result<SolanaTransaction, ClientError> {
    let shielded = sign_shielded_transaction_sync(transaction, wallet, authority)?;
    let mut native = client.finish_submission_unsigned_sync(&shielded, fee_payer.pubkey())?;
    let blockhash = native.message.recent_blockhash;
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
    if address != wallet.identity {
        return Err(zolana_transaction::TransactionError::WalletAuthorityMismatch.into());
    }
    let nullifier_key = authority.spend_nullifier_key().await?;
    if nullifier_key.pubkey()? != address.nullifier_pubkey {
        return Err(zolana_transaction::TransactionError::WalletAuthorityMismatch.into());
    }
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
    let mut tx = ConfidentialTransfer::new(address, inputs, transaction.payer);
    match transaction.action {
        PrivateTransactionAction::Transfer {
            recipient,
            asset,
            amount,
        } => {
            tx.send(&recipient, asset, amount)?;
        }
        PrivateTransactionAction::Withdrawal {
            asset,
            amount,
            target,
        } => {
            tx.withdraw(asset, amount, target)?;
        }
    }
    let prepared = tx.prepare()?;
    let signed = sign_prepared(
        prepared,
        &address,
        authority,
        &wallet.registry,
        transaction.approval_summary,
    )
    .await?;
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
    if address.signing_pubkey.signature_type()? == SignatureType::P256 {
        let message_hash = proof_inputs.message_hash()?;
        let sig = authority.sign_p256(&message_hash).await?;
        if sig.pubkey != address.signing_pubkey.as_p256()? {
            return Err(zolana_transaction::TransactionError::WalletAuthorityMismatch.into());
        }
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&sig.sig_r);
        bytes[32..].copy_from_slice(&sig.sig_s);
        verify_p256_signature(&sig.pubkey, &message_hash, &bytes)?;
        proof_inputs.p256_signature = Some(bytes);
    }
    Ok(proof_inputs)
}

fn verify_p256_signature(
    pubkey: &zolana_keypair::P256Pubkey,
    message_hash: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), ClientError> {
    let verifying_key = VerifyingKey::from_sec1_bytes(pubkey.as_bytes())
        .map_err(|err| ClientError::P256Signature(err.to_string()))?;
    let signature = EcdsaSignature::from_slice(signature)
        .map_err(|err| ClientError::P256Signature(err.to_string()))?;
    verifying_key
        .verify_prehash(message_hash, &signature)
        .map_err(|err| ClientError::P256Signature(err.to_string()))
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
    use zolana_transaction::{Data, Utxo, WalletUtxo};
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
}
