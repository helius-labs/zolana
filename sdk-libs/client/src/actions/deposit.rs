//! Proofless shield action.

use solana_address::Address;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::Transaction as SolanaTransaction;
use zolana_interface::{
    instruction::{Deposit as DepositInstruction, DepositIxData, DepositSplAccounts},
    pda, SPL_TOKEN_PROGRAM_ID,
};
use zolana_keypair::{random_blinding, ShieldedAddress};
use zolana_transaction::{ProofInputUtxo, SOL_MINT};

use crate::{
    error::ClientError,
    rpc::{AsyncRpc, Rpc},
};

/// Prepared direct proofless SOL shield.
///
/// This owns the recipient-derived deposit material so callers do not need to
/// manually coordinate salt, blinding, owner commitment, and UTXO hash rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Deposit {
    pub data: DepositIxData,
    pub utxo_hash: [u8; 32],
    pub asset: Address,
    pub spl: Option<DepositSplAccounts>,
}

pub struct DepositParams<'a> {
    pub recipient: &'a ShieldedAddress,
    pub asset: Address,
    pub amount: u64,
    pub spl_token_account: Option<Pubkey>,
    /// Optional free-form memo emitted in the clear with the deposit.
    pub memo: Option<Vec<u8>>,
}

impl Deposit {
    pub fn new(request: DepositParams<'_>) -> Result<Self, ClientError> {
        // Fresh blinding is sent in the clear; the recipient `owner` commitment
        // is derived from public address material, so a third-party depositor
        // needs no shared secret and the recipient spends the note directly.
        let owner = request.recipient.owner_hash()?;
        let blinding = random_blinding();
        let view_tag = request.recipient.viewing_pubkey.x();
        let utxo_hash =
            ProofInputUtxo::new(owner, &request.asset, request.amount, &blinding)?.hash()?;
        let spl = spl_accounts(request.asset, request.spl_token_account)?;
        Ok(Self {
            data: DepositIxData {
                view_tag,
                owner,
                blinding,
                amount: request.amount,
                utxo_data: None,
                memo: request.memo,
            },
            utxo_hash,
            asset: request.asset,
            spl,
        })
    }

    pub fn instruction(&self, tree: Pubkey, depositor: Pubkey) -> Instruction {
        deposit_instruction(tree, depositor, self.spl, &self.data)
    }

    /// Build an unsigned deposit transaction for one or more external signers.
    pub async fn build_transaction<R: AsyncRpc>(
        &self,
        rpc: &R,
        payer: Pubkey,
        tree: Pubkey,
        depositor: Pubkey,
    ) -> Result<SolanaTransaction, ClientError> {
        build_deposit_transaction(rpc, payer, tree, depositor, self).await
    }

    /// Blocking adapter for building an unsigned deposit transaction.
    pub fn build_transaction_sync<R: Rpc>(
        &self,
        rpc: &R,
        payer: Pubkey,
        tree: Pubkey,
        depositor: Pubkey,
    ) -> Result<SolanaTransaction, ClientError> {
        build_deposit_transaction_sync(rpc, payer, tree, depositor, self)
    }

    pub fn send<R: Rpc>(
        &self,
        rpc: &R,
        payer: &Keypair,
        tree: Pubkey,
        depositor: &Keypair,
    ) -> Result<Signature, ClientError> {
        deposit(rpc, payer, tree, depositor, self.spl, &self.data)
    }

    pub fn view_tag(&self) -> [u8; 32] {
        self.data.view_tag
    }
}

pub fn create_deposit(request: DepositParams<'_>) -> Result<Deposit, ClientError> {
    Deposit::new(request)
}

pub async fn build_deposit_transaction<R: AsyncRpc>(
    rpc: &R,
    payer: Pubkey,
    tree: Pubkey,
    depositor: Pubkey,
    deposit: &Deposit,
) -> Result<SolanaTransaction, ClientError> {
    let (blockhash, _) = rpc.get_latest_blockhash().await?;
    Ok(unsigned_deposit_transaction(
        payer,
        deposit.instruction(tree, depositor),
        blockhash,
    ))
}

pub fn build_deposit_transaction_sync<R: Rpc>(
    rpc: &R,
    payer: Pubkey,
    tree: Pubkey,
    depositor: Pubkey,
    deposit: &Deposit,
) -> Result<SolanaTransaction, ClientError> {
    let (blockhash, _) = rpc.get_latest_blockhash()?;
    Ok(unsigned_deposit_transaction(
        payer,
        deposit.instruction(tree, depositor),
        blockhash,
    ))
}

/// Build and send a direct (non-zone) proofless shield: a public deposit
/// that appends a recipient-hidden UTXO without a proof.
///
/// `payer` funds the transaction fee; `depositor` signs the deposit and is the
/// public funding source for the shielded amount (they may be the same key).
/// Returns the transaction signature; event indexing is the caller's concern.
pub fn deposit<R: Rpc>(
    rpc: &R,
    payer: &Keypair,
    tree: Pubkey,
    depositor: &Keypair,
    spl: Option<DepositSplAccounts>,
    data: &DepositIxData,
) -> Result<Signature, ClientError> {
    let ix = deposit_instruction(tree, depositor.pubkey(), spl, data);
    let mut signers: Vec<&Keypair> = vec![payer];
    if depositor.pubkey() != payer.pubkey() {
        signers.push(depositor);
    }
    let payer_address = Address::new_from_array(payer.pubkey().to_bytes());
    rpc.create_and_send_transaction(&[ix], payer_address, &signers)
}

fn deposit_instruction(
    tree: Pubkey,
    depositor: Pubkey,
    spl: Option<DepositSplAccounts>,
    data: &DepositIxData,
) -> Instruction {
    DepositInstruction {
        tree,
        depositor,
        spl,
        view_tag: data.view_tag,
        owner: data.owner,
        blinding: data.blinding,
        amount: data.amount,
        utxo_data: data.utxo_data.clone(),
        memo: data.memo.clone(),
    }
    .instruction()
}

fn unsigned_deposit_transaction(
    payer: Pubkey,
    instruction: Instruction,
    blockhash: solana_hash::Hash,
) -> SolanaTransaction {
    let mut message = Message::new(&[instruction], Some(&payer));
    message.recent_blockhash = blockhash;
    SolanaTransaction::new_unsigned(message)
}

fn spl_accounts(
    asset: Address,
    spl_token_account: Option<Pubkey>,
) -> Result<Option<DepositSplAccounts>, ClientError> {
    if asset == SOL_MINT {
        return Ok(None);
    }
    let mint = Pubkey::new_from_array(asset.to_bytes());
    let user_token = spl_token_account.ok_or(ClientError::MissingSplTokenAccount { mint })?;
    Ok(Some(DepositSplAccounts {
        user_token,
        spl_token_interface: pda::spl_asset_vault(&mint),
        registry: pda::spl_asset_registry(&mint),
        token_program: Pubkey::new_from_array(SPL_TOKEN_PROGRAM_ID),
    }))
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use solana_hash::Hash;
    use solana_transaction::Transaction;
    use zolana_keypair::ShieldedKeypair;

    use super::*;

    /// Minimal `Rpc` backend that records the transaction the action sends, so
    /// we can assert the action builds and submits the interface instruction
    /// without a live validator.
    #[derive(Default)]
    struct MockRpc {
        sent: RefCell<Option<Transaction>>,
    }

    impl Rpc for MockRpc {
        fn get_latest_blockhash(&self) -> Result<(Hash, u64), ClientError> {
            Ok((Hash::default(), 0))
        }

        fn send_transaction(&self, transaction: &Transaction) -> Result<Signature, ClientError> {
            *self.sent.borrow_mut() = Some(transaction.clone());
            Ok(Signature::default())
        }
    }

    struct AsyncMockRpc;

    #[async_trait::async_trait]
    impl AsyncRpc for AsyncMockRpc {
        async fn get_latest_blockhash(&self) -> Result<(Hash, u64), ClientError> {
            Ok((Hash::new_from_array([7u8; 32]), 1))
        }
    }

    #[test]
    fn deposit_sends_the_interface_instruction() {
        let rpc = MockRpc::default();
        let payer = Keypair::new();
        let depositor = Keypair::new();
        let tree = Pubkey::new_unique();
        let data = DepositIxData {
            view_tag: [1u8; 32],
            owner: [2u8; 32],
            blinding: [3u8; 31],
            amount: 1_000,
            utxo_data: None,
            memo: Some(b"thanks".to_vec()),
        };

        deposit(&rpc, &payer, tree, &depositor, None, &data).expect("action");

        let sent = rpc.sent.borrow().clone().expect("transaction recorded");
        let expected = DepositInstruction {
            tree,
            depositor: depositor.pubkey(),
            spl: None,
            view_tag: data.view_tag,
            owner: data.owner,
            blinding: data.blinding,
            amount: data.amount,
            utxo_data: data.utxo_data.clone(),
            memo: data.memo.clone(),
        }
        .instruction();
        assert_eq!(sent.message.instructions.len(), 1);
        assert_eq!(sent.message.instructions[0].data, expected.data);
        assert!(sent.message.account_keys.contains(&payer.pubkey()));
        assert!(sent.message.account_keys.contains(&depositor.pubkey()));
    }

    #[test]
    fn prepared_sol_deposit_derives_consistent_material() {
        let recipient = ShieldedKeypair::new().unwrap();
        let recipient_address = recipient.shielded_address().unwrap();
        let prepared = create_deposit(DepositParams {
            recipient: &recipient_address,
            asset: SOL_MINT,
            amount: 1_000,
            spl_token_account: None,
            memo: None,
        })
        .expect("prepared deposit");

        assert_eq!(prepared.data.view_tag, recipient.viewing_pubkey().x());
        assert_eq!(prepared.data.amount, 1_000);
        assert_ne!(prepared.data.blinding, [0u8; 31]);
        assert_ne!(prepared.data.owner, [0u8; 32]);
        assert_ne!(prepared.utxo_hash, [0u8; 32]);
    }

    #[tokio::test]
    async fn deposit_builder_returns_sendable_unsigned_transaction() {
        let recipient = ShieldedKeypair::new().expect("recipient");
        let prepared = create_deposit(DepositParams {
            recipient: &recipient.shielded_address().expect("shielded address"),
            asset: SOL_MINT,
            amount: 1_000,
            spl_token_account: None,
            memo: None,
        })
        .expect("prepared deposit");
        let payer = Pubkey::new_unique();
        let tree = Pubkey::new_unique();
        let future = prepared.build_transaction(&AsyncMockRpc, payer, tree, payer);
        fn assert_send<T: Send>(value: T) -> T {
            value
        }
        let transaction = assert_send(future).await.expect("unsigned deposit");

        assert_eq!(transaction.message.account_keys[0], payer);
        assert_eq!(
            transaction.message.recent_blockhash,
            Hash::new_from_array([7u8; 32])
        );
        assert_eq!(transaction.signatures, vec![Signature::default()]);
    }

    #[test]
    fn prepared_spl_deposit_carries_settlement_accounts() {
        let recipient = ShieldedKeypair::new().unwrap();
        let recipient_address = recipient.shielded_address().unwrap();
        let mint = Pubkey::new_unique();
        let user_token = Pubkey::new_unique();
        let asset = Address::new_from_array(mint.to_bytes());

        let prepared = create_deposit(DepositParams {
            recipient: &recipient_address,
            asset,
            amount: 1_000,
            memo: None,
            spl_token_account: Some(user_token),
        })
        .expect("prepared deposit");

        assert_eq!(prepared.asset, asset);
        assert_eq!(prepared.data.amount, 1_000);
        assert_eq!(
            prepared.spl,
            Some(DepositSplAccounts {
                user_token,
                spl_token_interface: pda::spl_asset_vault(&mint),
                registry: pda::spl_asset_registry(&mint),
                token_program: Pubkey::new_from_array(SPL_TOKEN_PROGRAM_ID),
            })
        );
    }
}
