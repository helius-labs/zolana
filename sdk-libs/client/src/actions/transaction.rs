use solana_pubkey::Pubkey;
use zolana_interface::{
    instruction::{TransactSolWithdrawal, TransactSplWithdrawal, TransactWithdrawal},
    pda, SPL_TOKEN_PROGRAM_ID,
};
use zolana_keypair::shielded::{ShieldedAddress, ShieldedKeypair};
use zolana_keypair::viewing_key::ViewTag;
use zolana_transaction::{Address, AssetRegistry, Wallet, SOL_MINT};

use crate::error::ClientError;
use crate::private_transaction::{SignedTransaction, SpendUtxo, Transaction, WithdrawalTarget};
use crate::rpc::Rpc;
use crate::user_registry::try_resolve_registered_address;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedAddress {
    pub owner: Pubkey,
    pub address: ShieldedAddress,
    pub view_tag: ViewTag,
}

#[derive(Clone)]
pub struct CreatedTransfer {
    pub signed: SignedTransaction,
    pub wait_tag: ViewTag,
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
    pub signed: SignedTransaction,
    pub wait_tag: ViewTag,
    pub withdrawal: TransactWithdrawal,
}

pub struct CreateTransfer<'a, R: Rpc> {
    pub rpc: &'a R,
    pub wallet: &'a Wallet,
    pub keypair: &'a ShieldedKeypair,
    pub payer: Address,
    pub recipient_owner: Pubkey,
    pub asset: Address,
    pub amount: u64,
    pub assets: &'a AssetRegistry,
}

pub struct CreateWithdrawal<'a> {
    pub wallet: &'a Wallet,
    pub keypair: &'a ShieldedKeypair,
    pub payer: Address,
    pub recipient: Pubkey,
    pub asset: Address,
    pub amount: u64,
    pub assets: &'a AssetRegistry,
}

pub fn create_transfer<R: Rpc>(
    request: CreateTransfer<'_, R>,
) -> Result<CreatedTransfer, ClientError> {
    let Some(recipient) = try_resolve_registered_address(request.rpc, request.recipient_owner)?
    else {
        let withdrawal = create_withdrawal(CreateWithdrawal {
            wallet: request.wallet,
            keypair: request.keypair,
            payer: request.payer,
            recipient: request.recipient_owner,
            asset: request.asset,
            amount: request.amount,
            assets: request.assets,
        })?;
        return Ok(CreatedTransfer {
            signed: withdrawal.signed,
            wait_tag: withdrawal.wait_tag,
            recipient: TransferRecipient::PublicWithdrawal {
                recipient: request.recipient_owner,
                withdrawal: withdrawal.withdrawal,
            },
        });
    };
    let wait_tag = next_sender_view_tag(request.wallet, request.keypair)?;
    let inputs = select_inputs(
        request.wallet,
        request.keypair,
        request.asset,
        request.amount,
    )?;
    let mut tx = Transaction::new(request.keypair.shielded_address()?, inputs, request.payer);
    tx.send(
        &recipient.address,
        request.asset,
        request.amount,
        recipient.view_tag,
    )?;
    let signed = tx.sign(request.keypair, request.assets, wait_tag)?;
    Ok(CreatedTransfer {
        signed,
        wait_tag,
        recipient: TransferRecipient::Registered(recipient),
    })
}

pub fn create_withdrawal(request: CreateWithdrawal<'_>) -> Result<CreatedWithdrawal, ClientError> {
    let wait_tag = next_sender_view_tag(request.wallet, request.keypair)?;
    let inputs = select_inputs(
        request.wallet,
        request.keypair,
        request.asset,
        request.amount,
    )?;
    let (target, withdrawal) = withdrawal_target(request.recipient, request.asset)?;
    let mut tx = Transaction::new(request.keypair.shielded_address()?, inputs, request.payer);
    tx.withdraw(request.asset, request.amount, target)?;
    let signed = tx.sign(request.keypair, request.assets, wait_tag)?;
    Ok(CreatedWithdrawal {
        signed,
        wait_tag,
        withdrawal,
    })
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
            vault,
            recipient,
            user_token_account: user_spl_token,
            token_program: Pubkey::new_from_array(SPL_TOKEN_PROGRAM_ID),
        }),
    ))
}

fn select_inputs(
    wallet: &Wallet,
    keypair: &ShieldedKeypair,
    asset: Address,
    amount: u64,
) -> Result<Vec<SpendUtxo>, ClientError> {
    let mut selected = Vec::new();
    let mut total = 0u64;
    for entry in &wallet.utxos {
        if entry.spent || entry.utxo.asset != asset {
            continue;
        }
        selected.push(SpendUtxo::from((entry.utxo.clone(), keypair)));
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

fn next_sender_view_tag(
    wallet: &Wallet,
    keypair: &ShieldedKeypair,
) -> Result<ViewTag, ClientError> {
    let entry = wallet
        .viewing_key_history
        .last()
        .ok_or(ClientError::WalletViewingHistoryMissing)?;
    Ok(keypair.get_sender_view_tag(entry.tx_count)?)
}

#[cfg(test)]
mod tests {
    use borsh::to_vec;
    use solana_account::Account;
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

    fn account_data(record: &UserRecord) -> Vec<u8> {
        let mut data = vec![UserRecord::DISCRIMINATOR];
        data.extend_from_slice(&to_vec(record).expect("serialize user record"));
        data
    }

    fn wallet_with_sol(keypair: ShieldedKeypair, amount: u64) -> Wallet {
        wallet_with_asset(keypair, SOL_MINT, amount)
    }

    fn wallet_with_asset(keypair: ShieldedKeypair, asset: Address, amount: u64) -> Wallet {
        let mut wallet = Wallet::new(keypair.clone()).expect("wallet");
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
            hash,
            nullifier,
            spent: false,
        });
        wallet
    }

    #[test]
    fn create_transfer_to_registered_recipient_builds_shielded_transfer() {
        let sender = ShieldedKeypair::new().unwrap();
        let recipient = ShieldedKeypair::new().unwrap();
        let owner = Pubkey::new_unique();
        let (record_pda, bump) = user_record_pda(&owner);
        let record = UserRecord {
            owner: owner.to_bytes(),
            bump,
            owner_p256: Some(*recipient.signing_pubkey().as_p256().unwrap().as_bytes()),
            nullifier_pubkey: recipient.nullifier_key.pubkey().unwrap(),
            viewing_pubkey: *recipient.viewing_pubkey().as_bytes(),
            sync_delegate: None,
            entries: Vec::new(),
            merge_service: false,
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

        let result = create_transfer(CreateTransfer {
            rpc: &rpc,
            wallet: &wallet,
            keypair: &sender,
            payer: Address::default(),
            recipient_owner: owner,
            asset: SOL_MINT,
            amount: 1,
            assets: &AssetRegistry::default(),
        })
        .expect("transfer");

        assert!(matches!(
            result.recipient,
            TransferRecipient::Registered(resolved) if resolved.owner == owner
        ));
        assert!(result.recipient.withdrawal().is_none());
    }

    #[test]
    fn create_transfer_to_unregistered_recipient_builds_public_withdrawal() {
        let sender = ShieldedKeypair::new().unwrap();
        let wallet = wallet_with_sol(sender.clone(), 10);
        let recipient = Pubkey::new_unique();
        let rpc = MockRpc { account: None };

        let result = create_transfer(CreateTransfer {
            rpc: &rpc,
            wallet: &wallet,
            keypair: &sender,
            payer: Address::default(),
            recipient_owner: recipient,
            asset: SOL_MINT,
            amount: 1,
            assets: &AssetRegistry::default(),
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
    fn create_transfer_to_unregistered_recipient_builds_spl_public_withdrawal() {
        let sender = ShieldedKeypair::new().unwrap();
        let mint = Pubkey::new_unique();
        let asset = Address::new_from_array(mint.to_bytes());
        let wallet = wallet_with_asset(sender.clone(), asset, 10);
        let rpc = MockRpc { account: None };
        let recipient = Pubkey::new_unique();
        let token_account = pda::associated_token_address(&recipient, &mint);

        let result = create_transfer(CreateTransfer {
            rpc: &rpc,
            wallet: &wallet,
            keypair: &sender,
            payer: Address::default(),
            recipient_owner: recipient,
            asset,
            amount: 1,
            assets: &AssetRegistry::new([(2, asset)]).expect("asset registry"),
        })
        .expect("public withdrawal fallback");

        assert_eq!(
            result.recipient.withdrawal(),
            Some(&TransactWithdrawal::Spl(TransactSplWithdrawal {
                cpi_authority: Some(pda::shielded_pool_cpi_authority()),
                vault: pda::spl_asset_vault(&mint),
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

        let result = create_withdrawal(CreateWithdrawal {
            wallet: &wallet,
            keypair: &sender,
            payer: Address::default(),
            recipient,
            asset,
            amount: 1,
            assets: &AssetRegistry::new([(2, asset)]).expect("asset registry"),
        })
        .expect("withdrawal");

        assert_eq!(
            result.withdrawal,
            TransactWithdrawal::Spl(TransactSplWithdrawal {
                cpi_authority: Some(pda::shielded_pool_cpi_authority()),
                vault: pda::spl_asset_vault(&mint),
                recipient,
                user_token_account: token_account,
                token_program: Pubkey::new_from_array(SPL_TOKEN_PROGRAM_ID),
            })
        );
    }
}
