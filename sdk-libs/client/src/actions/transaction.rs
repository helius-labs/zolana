use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use zolana_interface::{
    instruction::{TransactSolWithdrawal, TransactSplWithdrawal, TransactWithdrawal},
    pda, SPL_TOKEN_PROGRAM_ID,
};
use zolana_keypair::{shielded::ShieldedAddress, viewing_key::ViewTag, SignatureType};
use zolana_transaction::{
    instructions::{
        transact::{PreparedTransaction, SignedTransaction, Transaction, WithdrawalTarget},
        types::SpendUtxo,
    },
    Address, AssetRegistry, Wallet, SOL_MINT,
};

use crate::{
    actions::submit::Submit,
    error::ClientError,
    prover::ProverClient,
    rpc::Rpc,
    user_registry::try_resolve_registered_address,
    wallet_authority::{
        ApprovalRequest, ConfidentialRecipientSlot, SyncWalletAuthority, WalletAuthority,
    },
};

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

impl CreatedTransfer {
    /// Prove and submit this transfer in one call, mirroring [`super::Deposit::send`].
    ///
    /// The public-withdrawal settlement is derived internally — a transfer to an
    /// unregistered recipient falls back to a public withdrawal — so the caller
    /// cannot mismatch it. `cu_limit` of `None` uses [`super::DEFAULT_TRANSACT_CU_LIMIT`].
    pub fn submit<R: Rpc>(
        self,
        rpc: &R,
        prover: &ProverClient,
        payer: &Keypair,
        tree: Pubkey,
        cu_limit: Option<u32>,
    ) -> Result<Signature, ClientError> {
        Submit {
            signed: self.signed,
            withdrawal: self.recipient.withdrawal().cloned(),
            cu_limit,
        }
        .execute(rpc, prover, payer, tree)
    }
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

impl CreatedWithdrawal {
    /// Prove and submit this withdrawal in one call, mirroring [`super::Deposit::send`].
    /// `cu_limit` of `None` uses [`super::DEFAULT_TRANSACT_CU_LIMIT`].
    pub fn submit<R: Rpc>(
        self,
        rpc: &R,
        prover: &ProverClient,
        payer: &Keypair,
        tree: Pubkey,
        cu_limit: Option<u32>,
    ) -> Result<Signature, ClientError> {
        Submit {
            signed: self.signed,
            withdrawal: Some(self.withdrawal),
            cu_limit,
        }
        .execute(rpc, prover, payer, tree)
    }
}

pub struct CreateTransfer<'a, R: Rpc, A: ?Sized> {
    pub rpc: &'a R,
    pub wallet: &'a Wallet,
    pub authority: &'a A,
    pub owner_pubkey: Pubkey,
    pub payer: Address,
    pub recipient_owner: Pubkey,
    pub asset: Address,
    pub amount: u64,
}

pub struct CreateWithdrawal<'a, A: ?Sized> {
    pub wallet: &'a Wallet,
    pub authority: &'a A,
    pub owner_pubkey: Pubkey,
    pub payer: Address,
    pub recipient: Pubkey,
    pub asset: Address,
    pub amount: u64,
}

pub async fn create_transfer<R: Rpc, A: WalletAuthority + ?Sized>(
    request: CreateTransfer<'_, R, A>,
) -> Result<CreatedTransfer, ClientError> {
    let Some(recipient) = try_resolve_registered_address(request.rpc, request.recipient_owner)?
    else {
        let withdrawal = create_withdrawal(CreateWithdrawal {
            wallet: request.wallet,
            authority: request.authority,
            owner_pubkey: request.owner_pubkey,
            payer: request.payer,
            recipient: request.recipient_owner,
            asset: request.asset,
            amount: request.amount,
        })
        .await?;
        return Ok(CreatedTransfer {
            signed: withdrawal.signed,
            wait_tag: withdrawal.wait_tag,
            recipient: TransferRecipient::PublicWithdrawal {
                recipient: request.recipient_owner,
                withdrawal: withdrawal.withdrawal,
            },
        });
    };
    let inputs = select_inputs(
        request.wallet,
        request.authority,
        request.owner_pubkey,
        request.asset,
        request.amount,
    )
    .await?;
    let address = request
        .authority
        .shielded_address(request.owner_pubkey)
        .await?;
    let wait_tag = address.signing_pubkey.confidential_view_tag()?;
    let mut tx = Transaction::new(address, inputs, request.payer);
    tx.send(&recipient.address, request.asset, request.amount)?;
    let prepared = tx.prepare(&request.wallet.registry)?;
    let signed = sign_prepared(
        prepared,
        &address,
        request.owner_pubkey,
        request.authority,
        &request.wallet.registry,
        format!(
            "private transfer of {} to {}",
            request.amount, request.recipient_owner
        ),
    )
    .await?;
    Ok(CreatedTransfer {
        signed,
        wait_tag,
        recipient: TransferRecipient::Registered(recipient),
    })
}

/// Blocking adapter for CLI and unit-test flows. Async hosts should call
/// [`create_transfer`] directly.
pub fn create_transfer_sync<R: Rpc, A: SyncWalletAuthority + ?Sized>(
    request: CreateTransfer<'_, R, A>,
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
    )
    .await?;
    let (target, withdrawal) = withdrawal_target(request.recipient, request.asset)?;
    let address = request
        .authority
        .shielded_address(request.owner_pubkey)
        .await?;
    let wait_tag = address.signing_pubkey.confidential_view_tag()?;
    let mut tx = Transaction::new(address, inputs, request.payer);
    tx.withdraw(request.asset, request.amount, target)?;
    let prepared = tx.prepare(&request.wallet.registry)?;
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
        wait_tag,
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

async fn select_inputs<A: WalletAuthority + ?Sized>(
    wallet: &Wallet,
    authority: &A,
    owner_pubkey: Pubkey,
    asset: Address,
    amount: u64,
) -> Result<Vec<SpendUtxo>, ClientError> {
    let nullifier_key = authority.spend_nullifier_key(owner_pubkey).await?;
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

        // Echo an inclusion proof for every requested leaf so `get_spend_proofs`
        // (and thus `Submit::prepare`) resolves without a live indexer.
        fn get_merkle_proofs(
            &self,
            tree_account: Address,
            leaves: Vec<[u8; 32]>,
        ) -> Result<crate::rpc::GetMerkleProofsResponse, ClientError> {
            Ok(crate::rpc::GetMerkleProofsResponse {
                context: crate::rpc::Context { slot: 0 },
                proofs: leaves
                    .into_iter()
                    .map(|leaf| crate::rpc::MerkleProof {
                        leaf,
                        merkle_context: crate::rpc::MerkleContext {
                            tree_type: 0,
                            tree: tree_account,
                        },
                        path: vec![[0u8; 32]; crate::rpc::STATE_TREE_HEIGHT],
                        leaf_index: 0,
                        root: [0u8; 32],
                        root_seq: 0,
                        root_index: 0,
                    })
                    .collect(),
            })
        }

        fn get_non_inclusion_proofs(
            &self,
            tree_account: Address,
            leaves: Vec<[u8; 32]>,
        ) -> Result<crate::rpc::GetNonInclusionProofsResponse, ClientError> {
            Ok(crate::rpc::GetNonInclusionProofsResponse {
                context: crate::rpc::Context { slot: 0 },
                proofs: leaves
                    .into_iter()
                    .map(|leaf| crate::rpc::NonInclusionProof {
                        leaf,
                        merkle_context: crate::rpc::MerkleContext {
                            tree_type: 0,
                            tree: tree_account,
                        },
                        path: vec![[0u8; 32]; crate::rpc::NULLIFIER_TREE_HEIGHT],
                        low_element: [0u8; 32],
                        low_element_index: 0,
                        high_element: [0u8; 32],
                        high_element_index: 0,
                        root: [0u8; 32],
                        root_seq: 0,
                        root_index: 0,
                    })
                    .collect(),
            })
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
    fn create_transfer_to_registered_recipient_builds_shielded_transfer() {
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

        let result = create_transfer_sync(CreateTransfer {
            rpc: &rpc,
            wallet: &wallet,
            authority: &sender,
            owner_pubkey: Pubkey::default(),
            payer: Address::default(),
            recipient_owner: owner,
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

    #[test]
    fn submit_prepare_fetches_proofs_and_assembles_the_witness() {
        // Build a real signed transfer, then drive the network-free prefix of
        // `Submit::execute` (proof fetch + witness assembly) against a mock that
        // echoes proofs. The prove/send tail needs a live prover and is covered by
        // the BDD harness; this asserts the SDK wires fetch→assemble correctly.
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

        let created = create_transfer_sync(CreateTransfer {
            rpc: &rpc,
            wallet: &wallet,
            authority: &sender,
            owner_pubkey: Pubkey::default(),
            payer: Address::default(),
            recipient_owner: owner,
            asset: SOL_MINT,
            amount: 1,
        })
        .expect("transfer");

        let submit = crate::actions::submit::Submit {
            signed: created.signed,
            withdrawal: created.recipient.withdrawal().cloned(),
            cu_limit: None,
        };
        // Uses the echo-proof MockRpc above; `prepare` must fetch a spend proof for
        // each input commitment and assemble a witness without a prover.
        let assembled = submit
            .prepare(&rpc, Pubkey::default())
            .expect("prepare assembles the witness");
        // Assembling produces a rail-specific witness and a non-zero public input
        // hash committing to the transaction; the concrete rail depends on the
        // input's ownership and is exercised end-to-end by the BDD harness.
        assert!(matches!(
            assembled.prover_inputs,
            crate::prover::transact::witness::ProverInputs::Eddsa(_)
                | crate::prover::transact::witness::ProverInputs::P256(_)
        ));
        assert_ne!(assembled.public_input_hash, [0u8; 32]);
    }

    #[test]
    fn create_transfer_to_unregistered_recipient_builds_public_withdrawal() {
        let sender = ShieldedKeypair::new().unwrap();
        let wallet = wallet_with_sol(sender.clone(), 10);
        let recipient = Pubkey::new_unique();
        let rpc = MockRpc { account: None };

        let result = create_transfer_sync(CreateTransfer {
            rpc: &rpc,
            wallet: &wallet,
            authority: &sender,
            owner_pubkey: Pubkey::default(),
            payer: Address::default(),
            recipient_owner: recipient,
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
    fn create_transfer_to_unregistered_recipient_builds_spl_public_withdrawal() {
        let sender = ShieldedKeypair::new().unwrap();
        let mint = Pubkey::new_unique();
        let asset = Address::new_from_array(mint.to_bytes());
        let wallet = wallet_with_asset(sender.clone(), asset, 10);
        let rpc = MockRpc { account: None };
        let recipient = Pubkey::new_unique();
        let token_account = pda::associated_token_address(&recipient, &mint);

        let result = create_transfer_sync(CreateTransfer {
            rpc: &rpc,
            wallet: &wallet,
            authority: &sender,
            owner_pubkey: Pubkey::default(),
            payer: Address::default(),
            recipient_owner: recipient,
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

        let result = create_withdrawal_sync(CreateWithdrawal {
            wallet: &wallet,
            authority: &sender,
            owner_pubkey: Pubkey::default(),
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
}
