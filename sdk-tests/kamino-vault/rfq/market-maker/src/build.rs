use std::{collections::HashMap, sync::Arc};

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

use super::{
    error::MakerError,
    scheduler::payment::TransferPlan,
    tracker::{CacheSlot, SpendPath},
};

#[derive(Clone)]
pub struct CacheWrites {
    pub cache: Address,
    pub slots: Vec<u8>,
}

impl CacheWrites {
    fn slot(&self, position: usize) -> Option<CacheSlot> {
        self.slots.get(position).map(|index| CacheSlot {
            cache: self.cache,
            index: *index,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WithdrawalTarget {
    pub owner: Address,
    pub token_program: Address,
}

impl WithdrawalTarget {
    pub fn token_account(&self, mint: &Address) -> Address {
        pda::associated_token_address_with_program(&self.owner, mint, &self.token_program)
    }

    pub fn accounts(&self, mint: Address) -> TransactInterfaceTransferAccounts {
        TransactInterfaceTransferAccounts::SplWithdrawal(TransactSplWithdrawalAccounts {
            mint,
            spl_interface: pda::spl_interface(&mint),
            user_token_account: self.token_account(&mint),
            token_program: self.token_program,
        })
    }
}

#[derive(Clone)]
pub struct PredictedUtxo {
    pub wallet: WalletUtxo,
    pub cache_slot: Option<CacheSlot>,
}

#[derive(Clone)]
pub struct BuiltTransfer {
    pub proof_inputs: SppProofInputs,
    pub interface_accounts: Vec<TransactInterfaceTransferAccounts>,
    pub own_outputs: Vec<PredictedUtxo>,
}

#[derive(Clone)]
pub struct TransferBuild {
    pub plan: TransferPlan,
    pub own: ShieldedAddress,
    pub payer: Address,
    pub tree_id: u16,
    pub writes: Option<CacheWrites>,
    pub withdrawal: Option<WithdrawalTarget>,
}

impl TransferBuild {
    pub async fn run(self, keys: Arc<ShieldedKeypair>) -> Result<BuiltTransfer, MakerError> {
        tokio::task::spawn_blocking(move || self.build(keys.as_ref()))
            .await
            .map_err(|error| MakerError::BlockingTask(error.to_string()))?
    }

    fn build<K: ShieldedKeys + ?Sized>(self, keys: &K) -> Result<BuiltTransfer, MakerError> {
        let cached: HashMap<[u8; 32], u8> = self
            .plan
            .selection
            .inputs
            .iter()
            .filter_map(|input| match input.path {
                SpendPath::CachedRead(slot) => Some((input.utxo.utxo_hash(), slot.index)),
                SpendPath::MerklePath(_) => None,
            })
            .collect();
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
        for amount in &self.plan.own_splits {
            pay_to(&mut transaction, asset, &self.own, *amount)?;
        }
        transaction.pad_utxos(self.plan.shape, &self.own)?;
        let mut proof_inputs = transaction.encrypt(keys)?;

        for input in proof_inputs.input_utxos.iter_mut() {
            if let Some(index) = cached.get(&input.utxo_hash) {
                *input = input.clone().with_cache_slot(*index)?;
            }
        }
        if let Some(cache) = self.plan.selection.read_cache {
            proof_inputs = proof_inputs.with_read_cache(cache);
        }

        let own_positions: Vec<usize> = proof_inputs
            .output_utxos
            .iter()
            .enumerate()
            .filter(|(_, output)| output.owner_address == Some(self.own) && output.amount > 0)
            .map(|(position, _)| position)
            .collect();
        if let Some(writes) = &self.writes {
            if writes.slots.len() != own_positions.len() {
                return Err(MakerError::CacheSlotCountMismatch {
                    slots: writes.slots.len(),
                    outputs: own_positions.len(),
                });
            }
            for (position, index) in own_positions.iter().zip(&writes.slots) {
                let output = proof_inputs
                    .output_utxos
                    .get_mut(*position)
                    .ok_or(TransactionError::TooManyOutputs)?;
                *output = output.clone().with_cache_slot(*index)?;
            }
            proof_inputs = proof_inputs.with_write_cache(writes.cache);
        }

        let mut own_outputs = Vec::with_capacity(own_positions.len());
        for (write_position, position) in own_positions.iter().enumerate() {
            let output = proof_inputs
                .output_utxos
                .get(*position)
                .ok_or(TransactionError::TooManyOutputs)?;
            own_outputs.push(PredictedUtxo {
                wallet: predict(
                    &self.own,
                    output,
                    output.hash(self.tree_id)?,
                    self.tree_id,
                    *position,
                )?,
                cache_slot: self
                    .writes
                    .as_ref()
                    .and_then(|writes| writes.slot(write_position)),
            });
        }
        assign_nullifiers(keys, &mut own_outputs)?;
        Ok(BuiltTransfer {
            proof_inputs,
            interface_accounts,
            own_outputs,
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

fn predict(
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
    predicted: &mut [PredictedUtxo],
) -> Result<(), MakerError> {
    let requests: Vec<DeriveRequest> = predicted
        .iter()
        .map(|entry| DeriveRequest::Nullifier {
            utxo_hash: entry.wallet.utxo_hash,
            blinding: entry.wallet.utxo.blinding,
        })
        .collect();
    let nullifiers = keys.derive(&requests)?;
    if nullifiers.len() != predicted.len() {
        return Err(TransactionError::IncompleteDerivation {
            got: nullifiers.len(),
            want: predicted.len(),
        }
        .into());
    }
    for (entry, nullifier) in predicted.iter_mut().zip(nullifiers) {
        entry.wallet.nullifier = nullifier;
    }
    Ok(())
}
