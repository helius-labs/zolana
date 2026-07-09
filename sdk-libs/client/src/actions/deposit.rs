//! Proofless shield action.

use std::{
    thread::sleep,
    time::{Duration, Instant},
};

use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::Instruction;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_interface::{
    instruction::{Deposit as DepositInstruction, DepositIxData, DepositSplAccounts},
    pda, SPL_TOKEN_PROGRAM_ID,
};
use zolana_keypair::{random_blinding, ShieldedAddress};
use zolana_transaction::{owner_utxo_hash, utxo_hash, Wallet, SOL_MINT};

use crate::{error::ClientError, rpc::Rpc, wallet_sync::sync_wallet};

/// Compute-unit ceiling [`deposit`] is submitted with. Benchmarked deposits run
/// ~34k CU (`program-tests/shielded-pool/CU_BENCHMARK.md`), but a live devnet
/// SPL deposit was observed exceeding 40k, so the ceiling leaves headroom.
pub const DEFAULT_DEPOSIT_CU_LIMIT: u32 = 80_000;

/// How long [`CreatedDeposit::wait_until_synced`] waits for the indexer to
/// pick up the deposited UTXO before giving up.
const INDEXER_TIMEOUT: Duration = Duration::from_secs(120);
/// Delay between indexer polls.
const INDEXER_POLL: Duration = Duration::from_millis(500);

/// A prepared deposit, ready to send. Deposits enter the pool without a proof.
///
/// This owns the recipient-derived deposit material so callers do not need to
/// manually coordinate salt, blinding, owner commitment, and UTXO hash rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreatedDeposit {
    pub data: DepositIxData,
    pub utxo_hash: [u8; 32],
    pub asset: Address,
    pub spl: Option<DepositSplAccounts>,
}

/// A public-to-private deposit into the pool. No proof is needed to enter;
/// [`create_deposit`] prepares it, then [`CreatedDeposit::send`] submits.
pub struct Deposit<'a> {
    pub destination: &'a ShieldedAddress,
    /// The asset's mint; [`SOL_MINT`](crate::SOL_MINT) for SOL.
    pub asset: Pubkey,
    pub amount: u64,
    pub spl_token_account: Option<Pubkey>,
    /// Optional free-form memo emitted in the clear with the deposit.
    pub memo: Option<Vec<u8>>,
}

impl CreatedDeposit {
    pub fn new(request: Deposit<'_>) -> Result<Self, ClientError> {
        let asset = Address::new_from_array(request.asset.to_bytes());
        // Fresh blinding is sent in the clear; the recipient `owner` commitment
        // is derived from public address material, so a third-party depositor
        // needs no shared secret and the recipient spends the note directly.
        let owner = request.destination.owner_hash()?;
        let blinding = random_blinding();
        let view_tag = request.destination.viewing_pubkey.x();
        let owner_utxo_hash = owner_utxo_hash(&owner, &blinding)?;
        let utxo_hash = utxo_hash(
            asset,
            request.amount,
            &[0u8; 32],
            &[0u8; 32],
            None,
            &owner_utxo_hash,
        )?;
        let spl = spl_accounts(asset, request.spl_token_account)?;
        Ok(Self {
            data: DepositIxData {
                view_tag,
                owner,
                blinding,
                public_amount: Some(request.amount),
                utxo_data: None,
                memo: request.memo,
            },
            utxo_hash,
            asset,
            spl,
        })
    }

    pub fn instruction(&self, tree: Pubkey, depositor: Pubkey) -> Instruction {
        deposit_instruction(tree, depositor, self.spl, &self.data)
    }

    /// Send the deposit. The recipient's wallet sees the deposited UTXO only
    /// after a sync; a recipient who needs to block until it is visible calls
    /// [`CreatedDeposit::wait_until_synced`].
    pub fn send<R: Rpc>(
        &self,
        rpc: &R,
        payer: &dyn Signer,
        tree: Pubkey,
        depositor: &dyn Signer,
    ) -> Result<Signature, ClientError> {
        deposit(rpc, payer, tree, depositor, self.spl, &self.data)
    }

    /// Sync `wallet` until the deposited UTXO is visible: the recipient-side
    /// read-your-write step after [`CreatedDeposit::send`], for callers that
    /// spend or display the balance immediately.
    ///
    /// `wallet` must be the deposit recipient's (a self-deposit, or an
    /// app-held recipient wallet). A wallet that is not the recipient can
    /// never see the UTXO: the call waits the full 120s and returns
    /// [`ClientError::DepositNotIndexed`] even though the deposit succeeded.
    /// For a deposit to a third party there is nothing to wait for on the
    /// sender side — the recipient's own sync discovers the UTXO.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use solana_pubkey::Pubkey;
    /// use solana_signer::Signer;
    /// use zolana_client::{create_deposit, ClientError, Deposit, Rpc, SOL_MINT};
    /// use zolana_keypair::ShieldedAddress;
    /// use zolana_transaction::Wallet;
    ///
    /// fn deposit_sol<R: Rpc, I: Rpc>(
    ///     rpc: &R,
    ///     indexer: &I,
    ///     payer: &dyn Signer,
    ///     tree: Pubkey,
    ///     recipient: &ShieldedAddress,
    ///     wallet: &mut Wallet,
    /// ) -> Result<(), ClientError> {
    ///     let prepared = create_deposit(Deposit {
    ///         destination: recipient,
    ///         asset: SOL_MINT,
    ///         amount: 1_000_000,
    ///         spl_token_account: None,
    ///         memo: None,
    ///     })?;
    ///     let signature = prepared.send(rpc, payer, tree, payer)?;
    ///     prepared.wait_until_synced(wallet, indexer, signature)?;
    ///     Ok(())
    /// }
    /// ```
    pub fn wait_until_synced<I: Rpc>(
        &self,
        wallet: &mut Wallet,
        indexer: &I,
        signature: Signature,
    ) -> Result<(), ClientError> {
        wait_for_deposited_utxo(wallet, indexer, self.utxo_hash, signature)
    }

    pub fn view_tag(&self) -> [u8; 32] {
        self.data.view_tag
    }
}

/// Poll [`sync_wallet`] until the wallet holds the UTXO with `utxo_hash`, or
/// [`INDEXER_TIMEOUT`] elapses.
fn wait_for_deposited_utxo<I: Rpc>(
    wallet: &mut Wallet,
    indexer: &I,
    utxo_hash: [u8; 32],
    signature: Signature,
) -> Result<(), ClientError> {
    let started = Instant::now();
    loop {
        sync_wallet(wallet, indexer)?;
        if wallet
            .utxos
            .iter()
            .any(|utxo| utxo.output_context.hash == utxo_hash)
        {
            return Ok(());
        }
        if started.elapsed() >= INDEXER_TIMEOUT {
            return Err(ClientError::DepositNotIndexed {
                utxo_hash,
                signature,
            });
        }
        sleep(INDEXER_POLL);
    }
}

pub fn create_deposit(request: Deposit<'_>) -> Result<CreatedDeposit, ClientError> {
    CreatedDeposit::new(request)
}

/// Build and send a direct (non-zone) proofless shield: a public deposit
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
    spl: Option<DepositSplAccounts>,
    data: &DepositIxData,
) -> Result<Signature, ClientError> {
    let cu_ix = ComputeBudgetInstruction::set_compute_unit_limit(DEFAULT_DEPOSIT_CU_LIMIT);
    let ix = deposit_instruction(tree, depositor.pubkey(), spl, data);
    let mut signers: Vec<&dyn Signer> = vec![payer];
    if depositor.pubkey() != payer.pubkey() {
        signers.push(depositor);
    }
    let payer_address = Address::new_from_array(payer.pubkey().to_bytes());
    rpc.create_and_send_transaction(&[cu_ix, ix], payer_address, &signers)
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
        public_amount: data.public_amount,
        utxo_data: data.utxo_data.clone(),
        memo: data.memo.clone(),
    }
    .instruction()
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
    use solana_keypair::Keypair;
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
            public_amount: Some(1_000),
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
            public_amount: data.public_amount,
            utxo_data: data.utxo_data.clone(),
            memo: data.memo.clone(),
        }
        .instruction();
        let cu_expected =
            ComputeBudgetInstruction::set_compute_unit_limit(DEFAULT_DEPOSIT_CU_LIMIT);
        assert_eq!(sent.message.instructions.len(), 2);
        assert_eq!(sent.message.instructions[0].data, cu_expected.data);
        assert_eq!(sent.message.instructions[1].data, expected.data);
        assert!(sent.message.account_keys.contains(&payer.pubkey()));
        assert!(sent.message.account_keys.contains(&depositor.pubkey()));
    }

    #[test]
    fn prepared_sol_deposit_derives_consistent_material() {
        let recipient = ShieldedKeypair::new().unwrap();
        let recipient_address = recipient.shielded_address().unwrap();
        let prepared = create_deposit(Deposit {
            destination: &recipient_address,
            asset: crate::SOL_MINT,
            amount: 1_000,
            spl_token_account: None,
            memo: None,
        })
        .expect("prepared deposit");

        assert_eq!(prepared.data.view_tag, recipient.viewing_pubkey().x());
        assert_eq!(prepared.data.public_amount, Some(1_000));
        assert_ne!(prepared.data.blinding, [0u8; 31]);
        assert_ne!(prepared.data.owner, [0u8; 32]);
        assert_ne!(prepared.utxo_hash, [0u8; 32]);
    }

    #[test]
    fn prepared_spl_deposit_carries_settlement_accounts() {
        let recipient = ShieldedKeypair::new().unwrap();
        let recipient_address = recipient.shielded_address().unwrap();
        let mint = Pubkey::new_unique();
        let user_token = Pubkey::new_unique();

        let prepared = create_deposit(Deposit {
            destination: &recipient_address,
            asset: mint,
            amount: 1_000,
            memo: None,
            spl_token_account: Some(user_token),
        })
        .expect("prepared deposit");

        assert_eq!(prepared.asset, Address::new_from_array(mint.to_bytes()));
        assert_eq!(prepared.data.public_amount, Some(1_000));
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
