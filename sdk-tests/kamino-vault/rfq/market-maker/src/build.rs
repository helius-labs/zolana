use std::sync::Arc;

use solana_address::Address;
use solana_signature::Signature;
use zolana_interface::pda;
use zolana_keypair::{ShieldedAddress, ShieldedKeypair};
use zolana_program::instruction::{
    TransactInterfaceTransferAccounts, TransactSplWithdrawalAccounts,
};
use zolana_transaction::{
    instructions::transact::{ConfidentialTransaction, SppProofInputs},
    keys::DeriveRequest,
    Mint, ShieldedKeys, SppProofOutputUtxo, TransactionError, Utxo, WalletUtxo,
};

use super::{error::MakerError, scheduler::transfer::TransferPlan};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WithdrawalTarget {
    pub owner: Address,
    pub token_program: Address,
}

impl WithdrawalTarget {
    pub fn token_account(&self, mint: &Address) -> Address {
        pda::associated_token_address_with_program(&self.owner, mint, &self.token_program)
    }

    pub fn spl_accounts(&self, mint: Address) -> TransactSplWithdrawalAccounts {
        TransactSplWithdrawalAccounts {
            mint,
            spl_interface: pda::spl_interface(&mint),
            user_token_account: self.token_account(&mint),
            token_program: self.token_program,
        }
    }

    pub fn accounts(&self, mint: Address) -> TransactInterfaceTransferAccounts {
        TransactInterfaceTransferAccounts::SplWithdrawal(self.spl_accounts(mint))
    }
}

#[derive(Clone)]
pub struct BuiltTransfer {
    pub proof_inputs: SppProofInputs,
    pub interface_accounts: Vec<TransactInterfaceTransferAccounts>,
    pub expected_outputs: Vec<WalletUtxo>,
}

#[derive(Clone)]
pub struct TransferBuild {
    pub plan: TransferPlan,
    pub own: ShieldedAddress,
    pub payer: Address,
    pub tree_id: u16,
    pub withdrawal: Option<WithdrawalTarget>,
}

impl TransferBuild {
    pub async fn run(self, keys: Arc<ShieldedKeypair>) -> Result<BuiltTransfer, MakerError> {
        tokio::task::spawn_blocking(move || self.build(keys.as_ref()))
            .await
            .map_err(|error| MakerError::BlockingTask(error.to_string()))?
    }

    fn build<K: ShieldedKeys + ?Sized>(self, keys: &K) -> Result<BuiltTransfer, MakerError> {
        let wallets: Vec<WalletUtxo> = self
            .plan
            .selection
            .inputs
            .iter()
            .map(|input| input.wallet())
            .collect();
        let asset = wallets
            .first()
            .map(|wallet| wallet.utxo.asset)
            .ok_or(TransactionError::NoInputs)?;

        let mut transaction =
            ConfidentialTransaction::new(wallets, self.payer)?.with_output_tree_id(self.tree_id)?;
        if let Some((recipient, amount)) = self.plan.recipient {
            pay_to(&mut transaction, asset, &recipient, amount)?;
        }
        let mut interface_accounts = Vec::new();
        if let Some(target) = self.withdrawal.filter(|_| self.plan.withdrawal > 0) {
            transaction.withdraw(
                asset.asset,
                self.plan.withdrawal,
                target.token_account(&asset.asset),
            )?;
            interface_accounts.push(target.accounts(asset.asset));
        }
        for amount in &self.plan.own_parts {
            pay_to(&mut transaction, asset, &self.own, *amount)?;
        }
        transaction.pad_utxos(self.plan.shape, &self.own)?;
        let proof_inputs = transaction.encrypt(keys)?;

        let mut expected_outputs = Vec::new();
        for (position, output) in proof_inputs.output_utxos.iter().enumerate() {
            if output.owner_address == Some(self.own) && output.amount > 0 {
                expected_outputs.push(expected_output(
                    &self.own,
                    output,
                    output.hash(self.tree_id)?,
                    self.tree_id,
                    position,
                )?);
            }
        }
        assign_nullifiers(keys, &mut expected_outputs)?;
        Ok(BuiltTransfer {
            proof_inputs,
            interface_accounts,
            expected_outputs,
        })
    }
}

fn pay_to(
    transaction: &mut ConfidentialTransaction,
    asset: Mint,
    recipient: &ShieldedAddress,
    amount: u64,
) -> Result<(), TransactionError> {
    if asset == Mint::SOL {
        transaction.transfer_sol(recipient, amount)?;
    } else {
        transaction.transfer(recipient, asset.asset, amount)?;
    }
    Ok(())
}

fn expected_output(
    own: &ShieldedAddress,
    output: &SppProofOutputUtxo,
    utxo_hash: [u8; 32],
    tree_id: u16,
    position: usize,
) -> Result<WalletUtxo, MakerError> {
    let slot_index =
        u32::try_from(position).map_err(|_| MakerError::OutputPositionOutOfRange { position })?;
    let utxo = Utxo {
        owner: own.signing_pubkey,
        asset: output.asset,
        amount: output.amount,
        blinding: output.blinding,
        ring_program_id: output.ring_program_id,
        data: output.data.clone(),
    };
    if utxo.hash(&own.nullifier_pubkey, &[0; 32], &[0; 32], tree_id)? != utxo_hash {
        return Err(TransactionError::InputCommitmentMismatch { index: position }.into());
    }
    Ok(WalletUtxo {
        utxo,
        nullifier_pubkey: own.nullifier_pubkey,
        utxo_hash,
        nullifier: [0; 32],
        data_hash: None,
        ring_data_hash: None,
        tree_id,
        leaf_index: 0,
        slot: 0,
        tx_signature: Signature::default(),
        slot_index,
    })
}

fn assign_nullifiers<K: ShieldedKeys + ?Sized>(
    keys: &K,
    outputs: &mut [WalletUtxo],
) -> Result<(), MakerError> {
    let requests: Vec<DeriveRequest> = outputs
        .iter()
        .map(|output| DeriveRequest::Nullifier {
            utxo_hash: output.utxo_hash,
            blinding: output.utxo.blinding,
        })
        .collect();
    let nullifiers = keys.derive(&requests)?;
    if nullifiers.len() != outputs.len() {
        return Err(TransactionError::IncompleteDerivation {
            got: nullifiers.len(),
            want: outputs.len(),
        }
        .into());
    }
    for (output, nullifier) in outputs.iter_mut().zip(nullifiers) {
        output.nullifier = nullifier;
    }
    Ok(())
}
