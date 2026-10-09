use std::sync::Arc;

use solana_address::Address;
use solana_instruction::Instruction;
use solana_signature::Signature;
use zolana_client::Shape;
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

use k_lend_rfq_sdk::pair::VaultState;

use super::{
    budget::smallest_shape,
    coordinator::Coordinator,
    steps::{FillTransfer, OperationId, ProofWork, Step, StepId, StepKind},
};
use crate::{error::MakerError, inventory::balance::select::Selection};

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
pub struct TransferPlan {
    pub selection: Selection,
    pub recipient: Option<(ShieldedAddress, u64)>,
    pub withdrawal: u64,
    pub own_parts: Vec<u64>,
    pub shape: Shape,
}

impl TransferPlan {
    fn new(
        selection: Selection,
        recipient: Option<(ShieldedAddress, u64)>,
        withdrawal: u64,
        own_parts: Vec<u64>,
    ) -> Result<Self, MakerError> {
        let spent = recipient
            .map(|(_, amount)| amount)
            .unwrap_or(0)
            .saturating_add(withdrawal);
        let own_value = own_value(&selection, spent)?;
        let planned: u64 = own_parts.iter().sum();
        if planned != own_value {
            return Err(MakerError::OwnPartsMismatch { planned, own_value });
        }
        let outputs = usize::from(recipient.is_some()) + own_parts.len();
        let inputs = selection.inputs.len();
        let shape = smallest_shape(inputs, outputs)
            .ok_or(MakerError::NoSupportedShape { inputs, outputs })?;
        Ok(Self {
            selection,
            recipient,
            withdrawal,
            own_parts,
            shape,
        })
    }
}

pub fn own_value(selection: &Selection, spent: u64) -> Result<u64, MakerError> {
    selection
        .total
        .checked_sub(spent)
        .ok_or(MakerError::InsufficientBalance {
            asset: selection
                .inputs
                .first()
                .map(|input| input.utxo.asset())
                .unwrap_or_default(),
            available: selection.total,
            requested: spent,
        })
}

pub fn plan_transfer(
    selection: Selection,
    recipient: ShieldedAddress,
    amount: u64,
    own_parts: Vec<u64>,
) -> Result<TransferPlan, MakerError> {
    TransferPlan::new(selection, Some((recipient, amount)), 0, own_parts)
}

pub fn plan_consolidate(
    selection: Selection,
    withdrawal: u64,
    own_parts: Vec<u64>,
) -> Result<TransferPlan, MakerError> {
    TransferPlan::new(selection, None, withdrawal, own_parts)
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

pub struct TransferStep {
    pub kind: StepKind,
    pub asset: Address,
    pub operation: Option<OperationId>,
    pub plan: TransferPlan,
    pub withdrawal: Option<WithdrawalTarget>,
    pub tail: Vec<Instruction>,
    pub vault_before: Option<VaultState>,
    pub fill: Option<FillTransfer>,
}

impl Coordinator {
    pub async fn schedule_transfer(
        &mut self,
        transfer: TransferStep,
    ) -> Result<StepId, MakerError> {
        let TransferStep {
            kind,
            asset,
            operation,
            plan,
            withdrawal,
            tail,
            vault_before,
            fill,
        } = transfer;
        let inputs = plan.selection.hashes();
        let built = TransferBuild {
            plan,
            own: self.identity.own,
            payer: self.identity.payer,
            tree_id: self.identity.tree_id,
            withdrawal,
        }
        .run(self.identity.keys.clone())
        .await?;
        let id = self.steps.next_id();
        let mut step = Step::new(
            id,
            kind,
            Some(ProofWork {
                inputs: built.proof_inputs,
                interface_accounts: built.interface_accounts,
            }),
        );
        step.asset = Some(asset);
        step.operation = operation;
        step.inputs = inputs;
        step.tail = tail;
        step.vault_before = vault_before;
        step.fill = fill;
        step.expected_outputs = built.expected_outputs;
        self.admit(step)?;
        Ok(id)
    }

    fn admit(&mut self, step: Step) -> Result<(), MakerError> {
        self.services
            .pending
            .reservations
            .reserve(step.id, &step.inputs)?;
        if let Some(asset) = step.asset {
            let incoming = step
                .expected_outputs
                .iter()
                .map(|output| output.utxo.amount)
                .sum();
            self.services.pending.expect(step.id, asset, incoming);
        }
        let id = step.id;
        self.steps.insert(step);
        self.spawn_prove(id);
        Ok(())
    }

    pub fn other_utxos(&self, asset: &Address, selection: &Selection) -> Vec<u64> {
        let selected = selection.hashes();
        self.services
            .pending
            .reservations
            .utxos(asset)
            .into_iter()
            .filter(|utxo| !selected.contains(&utxo.utxo_hash))
            .map(|utxo| utxo.amount)
            .collect()
    }

    pub fn waits_for_utxos(&self, asset: &Address) -> bool {
        let reservations = &self.services.pending.reservations;
        reservations.in_flight(asset) || reservations.unindexed(asset)
    }
}
