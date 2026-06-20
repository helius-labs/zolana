use solana_pubkey::Pubkey;
use zolana_interface::instruction::{TransactSolWithdrawal, TransactWithdrawal};
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
    pub withdrawal: Option<TransactWithdrawal>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferRecipient {
    Registered(ResolvedAddress),
    PublicWithdrawal(Pubkey),
}

impl TransferRecipient {
    pub fn pubkey(self) -> Pubkey {
        match self {
            Self::Registered(recipient) => recipient.owner,
            Self::PublicWithdrawal(recipient) => recipient,
        }
    }

    pub fn is_public_withdrawal(self) -> bool {
        matches!(self, Self::PublicWithdrawal(_))
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

pub fn create_transfer<R: Rpc>(
    request: CreateTransfer<'_, R>,
) -> Result<CreatedTransfer, ClientError> {
    let Some(recipient) = try_resolve_registered_address(request.rpc, request.recipient_owner)?
    else {
        let withdrawal = create_withdrawal(
            request.wallet,
            request.keypair,
            request.payer,
            request.recipient_owner,
            request.asset,
            request.amount,
            request.assets,
        )?;
        return Ok(CreatedTransfer {
            signed: withdrawal.signed,
            wait_tag: withdrawal.wait_tag,
            recipient: TransferRecipient::PublicWithdrawal(request.recipient_owner),
            withdrawal: Some(withdrawal.withdrawal),
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
        withdrawal: None,
    })
}

pub fn create_withdrawal(
    wallet: &Wallet,
    keypair: &ShieldedKeypair,
    payer: Address,
    destination: Pubkey,
    asset: Address,
    amount: u64,
    assets: &AssetRegistry,
) -> Result<CreatedWithdrawal, ClientError> {
    if asset != SOL_MINT {
        return Err(ClientError::UnsupportedWithdrawalAsset);
    }
    let wait_tag = next_sender_view_tag(wallet, keypair)?;
    let inputs = select_inputs(wallet, keypair, asset, amount)?;
    let target = WithdrawalTarget::Sol {
        user_sol_account: Address::new_from_array(destination.to_bytes()),
    };
    let mut tx = Transaction::new(keypair.shielded_address()?, inputs, payer);
    tx.withdraw(asset, amount, target)?;
    let signed = tx.sign(keypair, assets, wait_tag)?;
    Ok(CreatedWithdrawal {
        signed,
        wait_tag,
        withdrawal: TransactWithdrawal::Sol(TransactSolWithdrawal {
            recipient: destination,
        }),
    })
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
    use zolana_interface::user_registry::{user_record_pda, user_registry_program_id, UserRecord};
    use zolana_transaction::{Data, Utxo, WalletUtxo};

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
        let mut wallet = Wallet::new(keypair.clone()).expect("wallet");
        let utxo = Utxo {
            owner: keypair.signing_pubkey(),
            asset: SOL_MINT,
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

        assert_eq!(result.withdrawal, None);
        assert!(matches!(
            result.recipient,
            TransferRecipient::Registered(resolved) if resolved.owner == owner
        ));
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
            TransferRecipient::PublicWithdrawal(pubkey) if pubkey == recipient
        ));
        assert_eq!(
            result.withdrawal,
            Some(TransactWithdrawal::Sol(TransactSolWithdrawal { recipient }))
        );
    }

    #[test]
    fn create_transfer_to_unregistered_recipient_rejects_non_sol_public_withdrawal() {
        let sender = ShieldedKeypair::new().unwrap();
        let wallet = wallet_with_sol(sender.clone(), 10);
        let rpc = MockRpc { account: None };
        let asset = Address::new_from_array([9u8; 32]);

        let result = create_transfer(CreateTransfer {
            rpc: &rpc,
            wallet: &wallet,
            keypair: &sender,
            payer: Address::default(),
            recipient_owner: Pubkey::new_unique(),
            asset,
            amount: 1,
            assets: &AssetRegistry::default(),
        });

        assert!(matches!(
            result,
            Err(ClientError::UnsupportedWithdrawalAsset)
        ));
    }

    #[test]
    fn create_withdrawal_rejects_non_sol_assets() {
        let sender = ShieldedKeypair::new().unwrap();
        let wallet = Wallet::new(ShieldedKeypair::new().unwrap()).unwrap();
        let asset = Address::new_from_array([7u8; 32]);

        let result = create_withdrawal(
            &wallet,
            &sender,
            Address::default(),
            Pubkey::new_unique(),
            asset,
            1,
            &AssetRegistry::default(),
        );

        assert!(matches!(
            result,
            Err(ClientError::UnsupportedWithdrawalAsset)
        ));
    }
}
