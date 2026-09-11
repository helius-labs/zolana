//! Proofless shield action.

use solana_address::Address;
use solana_instruction::Instruction;
use solana_message::VersionedMessage;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_interface::instruction::{
    AssetDeposit, Deposit as DepositInstruction, DepositAsset, DepositSplAccounts,
};
use zolana_keypair::ShieldedAddress;
use zolana_transaction::SOL_MINT;

use zolana_client::{
    error::ClientError,
    rpc::{compile_message, AsyncRpc, ComputeBudgetConfig, Rpc},
};

/// Prepared direct proofless SOL shield.
///
/// This owns the recipient-derived deposit material, so callers coordinate no
/// owner-commitment or UTXO-hash rules themselves. The blinding comes from the
/// leaf index the output lands at, so read the indexed UTXO to spend it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Deposit {
    pub deposit: AssetDeposit,
    pub asset: Address,
}

pub struct DepositParams<'a> {
    pub recipient: &'a ShieldedAddress,
    pub asset: Address,
    pub amount: u64,
    pub spl_token_account: Option<Pubkey>,
    /// SPL Token or Token-2022 program for non-SOL assets.
    pub spl_token_program: Option<Pubkey>,
    /// Optional free-form memo emitted in the clear with the deposit.
    pub memo: Option<Vec<u8>>,
}

impl Deposit {
    pub fn new(request: DepositParams<'_>) -> Result<Self, ClientError> {
        // The recipient `owner` commitment is public address material, so a
        // third-party depositor shares no secret with the recipient.
        let owner = request.recipient.owner_hash()?;
        let view_tag = request.recipient.viewing_pubkey.x();
        Ok(Self {
            deposit: AssetDeposit {
                asset: deposit_asset(
                    request.asset,
                    request.spl_token_account,
                    request.spl_token_program,
                )?,
                view_tag,
                owner,
                amount: request.amount,
                utxo_data: None,
                memo: request.memo,
            },
            asset: request.asset,
        })
    }

    pub fn instruction(&self, tree: Pubkey, depositor: Pubkey) -> Result<Instruction, ClientError> {
        deposit_instruction(tree, depositor, &self.deposit)
    }

    /// Build the unsigned v1 deposit message for one or more external signers.
    pub async fn build_transaction<R: AsyncRpc>(
        &self,
        rpc: &R,
        payer: Pubkey,
        tree: Pubkey,
        depositor: Pubkey,
    ) -> Result<VersionedMessage, ClientError> {
        build_deposit_transaction(rpc, payer, tree, depositor, self).await
    }

    /// Blocking adapter for building the unsigned v1 deposit message.
    pub fn build_transaction_sync<R: Rpc>(
        &self,
        rpc: &R,
        payer: Pubkey,
        tree: Pubkey,
        depositor: Pubkey,
    ) -> Result<VersionedMessage, ClientError> {
        build_deposit_transaction_sync(rpc, payer, tree, depositor, self)
    }

    pub fn send<R: Rpc>(
        &self,
        rpc: &R,
        payer: &dyn Signer,
        tree: Pubkey,
        depositor: &dyn Signer,
    ) -> Result<Signature, ClientError> {
        deposit(rpc, payer, tree, depositor, &self.deposit)
    }

    pub fn view_tag(&self) -> [u8; 32] {
        self.deposit.view_tag
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
) -> Result<VersionedMessage, ClientError> {
    let (blockhash, _) = rpc.get_latest_blockhash().await?;
    unsigned_deposit_message(payer, deposit.instruction(tree, depositor)?, blockhash)
}

pub fn build_deposit_transaction_sync<R: Rpc>(
    rpc: &R,
    payer: Pubkey,
    tree: Pubkey,
    depositor: Pubkey,
    deposit: &Deposit,
) -> Result<VersionedMessage, ClientError> {
    let (blockhash, _) = rpc.get_latest_blockhash()?;
    unsigned_deposit_message(payer, deposit.instruction(tree, depositor)?, blockhash)
}

/// Build and send a direct (non-ring) proofless shield: a public deposit
/// that appends a recipient-hidden UTXO without a proof.
///
/// `payer` funds the transaction fee; `depositor` signs the deposit and is the
/// public funding source for the shielded amount (they may be the same key).
/// Returns the transaction signature; event indexing is the caller's concern.
pub fn deposit<R: Rpc>(
    rpc: &R,
    payer: &dyn Signer,
    tree: Pubkey,
    depositor: &dyn Signer,
    deposit_fields: &AssetDeposit,
) -> Result<Signature, ClientError> {
    let ix = deposit_instruction(tree, depositor.pubkey(), deposit_fields)?;
    let mut signers: Vec<&dyn Signer> = vec![payer];
    if depositor.pubkey() != payer.pubkey() {
        signers.push(depositor);
    }
    let payer_address = Address::new_from_array(payer.pubkey().to_bytes());
    rpc.create_and_send_transaction(
        core::slice::from_ref(&ix),
        payer_address,
        &signers,
        ComputeBudgetConfig::for_instruction_count(1),
    )
}

fn deposit_instruction(
    tree: Pubkey,
    depositor: Pubkey,
    deposit: &AssetDeposit,
) -> Result<Instruction, ClientError> {
    Ok(DepositInstruction {
        tree,
        depositor,
        deposits: vec![deposit.clone()],
    }
    .instruction()?)
}

fn unsigned_deposit_message(
    payer: Pubkey,
    instruction: Instruction,
    blockhash: solana_hash::Hash,
) -> Result<VersionedMessage, ClientError> {
    compile_message(
        &payer,
        core::slice::from_ref(&instruction),
        blockhash,
        ComputeBudgetConfig::for_instruction_count(1),
    )
}

fn deposit_asset(
    asset: Address,
    spl_token_account: Option<Pubkey>,
    spl_token_program: Option<Pubkey>,
) -> Result<DepositAsset, ClientError> {
    if asset == SOL_MINT {
        return Ok(DepositAsset::Sol);
    }
    let mint = Pubkey::new_from_array(asset.to_bytes());
    let user_token = spl_token_account.ok_or(ClientError::MissingSplTokenAccount { mint })?;
    let token_program = spl_token_program.ok_or(ClientError::MissingSplTokenProgram { mint })?;
    Ok(DepositAsset::Spl(DepositSplAccounts {
        mint,
        user_token,
        token_program,
    }))
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use solana_hash::Hash;
    use solana_keypair::Keypair;
    use solana_transaction::versioned::VersionedTransaction;
    use zolana_keypair::ShieldedKeypair;

    use super::*;

    /// Minimal `Rpc` backend that records the transaction the action sends, so
    /// we can assert the action builds and submits the interface instruction
    /// without a live validator.
    #[derive(Default)]
    struct MockRpc {
        sent: RefCell<Option<VersionedTransaction>>,
    }

    impl Rpc for MockRpc {
        fn get_latest_blockhash(&self) -> Result<(Hash, u64), ClientError> {
            Ok((Hash::default(), 0))
        }

        fn process_transaction(
            &self,
            transaction: VersionedTransaction,
        ) -> Result<Signature, ClientError> {
            *self.sent.borrow_mut() = Some(transaction);
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
        let entry = AssetDeposit {
            asset: DepositAsset::Sol,
            view_tag: [1u8; 32],
            owner: [2u8; 32],
            amount: 1_000,
            utxo_data: None,
            memo: Some(b"thanks".to_vec()),
        };

        deposit(&rpc, &payer, tree, &depositor, &entry).expect("action");

        let sent = rpc.sent.borrow().clone().expect("transaction recorded");
        let expected = DepositInstruction {
            tree,
            depositor: depositor.pubkey(),
            deposits: vec![entry.clone()],
        }
        .instruction()
        .expect("valid deposit");
        assert!(matches!(sent.message, VersionedMessage::V1(_)));
        let instructions = sent.message.instructions();
        assert_eq!(instructions.len(), 1);
        assert_eq!(
            instructions.first().expect("the only instruction").data,
            expected.data
        );
        let account_keys = sent.message.static_account_keys();
        assert!(account_keys.contains(&payer.pubkey()));
        assert!(account_keys.contains(&depositor.pubkey()));
    }

    #[test]
    fn prepared_sol_deposit_derives_consistent_material() {
        let recipient = ShieldedKeypair::new_p256().unwrap();
        let recipient_address = recipient.shielded_address().unwrap();
        let prepared = create_deposit(DepositParams {
            recipient: &recipient_address,
            asset: SOL_MINT,
            amount: 1_000,
            spl_token_account: None,
            spl_token_program: Some(zolana_interface::pda::spl_token_program_id()),
            memo: None,
        })
        .expect("prepared deposit");

        assert_eq!(prepared.deposit.view_tag, recipient.viewing_pubkey().x());
        assert_eq!(prepared.deposit.amount, 1_000);
        assert_ne!(prepared.deposit.owner, [0u8; 32]);
    }

    #[tokio::test]
    async fn deposit_builder_returns_sendable_unsigned_message() {
        let recipient = ShieldedKeypair::new_p256().expect("recipient");
        let prepared = create_deposit(DepositParams {
            recipient: &recipient.shielded_address().expect("shielded address"),
            asset: SOL_MINT,
            amount: 1_000,
            spl_token_account: None,
            spl_token_program: Some(zolana_interface::pda::spl_token_program_id()),
            memo: None,
        })
        .expect("prepared deposit");
        let payer = Pubkey::new_unique();
        let tree = Pubkey::new_unique();
        let future = prepared.build_transaction(&AsyncMockRpc, payer, tree, payer);
        fn assert_send<T: Send>(value: T) -> T {
            value
        }
        let message = assert_send(future).await.expect("unsigned deposit");

        assert!(matches!(message, VersionedMessage::V1(_)));
        assert_eq!(
            message.static_account_keys().first().copied(),
            Some(payer),
            "the fee payer is the first account key"
        );
        assert_eq!(*message.recent_blockhash(), Hash::new_from_array([7u8; 32]));
    }

    #[test]
    fn prepared_spl_deposit_carries_settlement_accounts() {
        let recipient = ShieldedKeypair::new_p256().unwrap();
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
            spl_token_program: Some(zolana_interface::pda::spl_token_program_id()),
        })
        .expect("prepared deposit");

        assert_eq!(prepared.asset, asset);
        assert_eq!(prepared.deposit.amount, 1_000);
        assert_eq!(
            prepared.deposit.asset,
            DepositAsset::Spl(DepositSplAccounts {
                mint,
                user_token,
                token_program: zolana_interface::pda::spl_token_program_id(),
            })
        );
    }
}
