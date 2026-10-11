use std::{
    collections::BTreeSet,
    sync::PoisonError,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_hash::Hash;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::VersionedMessage;
use solana_signature::Signature;
use zolana_client::{compile_message, AsyncRpc, ComputeBudgetConfig};
use zolana_interface::{
    instruction::{tag, TransactIxData},
    pda, PROGRAM_ID_PUBKEY,
};
use zolana_keypair::ShieldedAddress;
use zolana_transaction::WalletUtxo;

use k_lend_rfq_sdk::{
    pair::Pair,
    swap::{Fill, Quote, SwapError, SwapRequest},
    transfer::Receiver,
};

use crate::{
    api::Inner,
    error::MakerError,
    inventory::balance::{
        pending::{Inflow, UserInput},
        select::select,
    },
    transactions::budget::USER_OUTPUTS,
    transactions::{
        confirm::Retry,
        coordinator::{Coordinator, Operation, OperationOutcome, ScheduleOutcome},
        kvault::read_vault,
        steps::{FillTransfer, OperationId, StepId, StepKind, StepState},
        transfer::{assign_nullifiers, own_value, plan_transfer, TransferStep},
    },
};

pub const SWAP_COMPUTE_BUDGET: ComputeBudgetConfig = ComputeBudgetConfig::new(1_400_000);

pub struct MakerFill {
    pub fill: Fill,
    pub spent: Vec<[u8; 32]>,
    pub change: Vec<WalletUtxo>,
}

pub struct FillOrder {
    pub asset: Address,
    pub amount: u64,
    pub recipient: ShieldedAddress,
    pub user_transfer: Instruction,
    pub inflow: Inflow,
    pub receipts: Vec<WalletUtxo>,
    pub user_inputs: Vec<UserInput>,
    pub user_signer: Address,
    pub ttl: Duration,
}

struct UserPayment {
    inflow: Inflow,
    receipts: Vec<WalletUtxo>,
    inputs: Vec<UserInput>,
    signer: Address,
}

impl Inner {
    pub async fn fill(&self, pair: &Pair, request: &SwapRequest) -> Result<MakerFill> {
        let quotes = {
            let settings = self.settings();
            settings.serves(pair)?;
            settings.quotes
        };
        let rate = read_vault(self.services.rpc.as_ref(), pair.vault).await?;
        let quote = Quote::price(
            &rate,
            request.quote.direction,
            request.quote.amount_in,
            quotes.fee_bps,
        )?;
        // No slippage is configured: the requested payout must match our fresh price.
        if request.quote.amount_out != quote.amount_out {
            return Err(SwapError::QuoteMismatch {
                expected: quote.amount_out,
                requested: request.quote.amount_out,
            }
            .into());
        }
        let (asset_in, asset_out) = quote.direction.assets(pair);
        let payment = self.check_user_transfer(asset_in, request).await?;
        let outcome = self
            .operation(Operation::Fill(Box::new(FillOrder {
                asset: asset_out,
                amount: quote.amount_out,
                recipient: request.user,
                user_transfer: request.transfer.clone(),
                inflow: payment.inflow,
                receipts: payment.receipts,
                user_inputs: payment.inputs,
                user_signer: payment.signer,
                ttl: quotes.ttl,
            })))
            .await
            .map_err(|error| match error {
                MakerError::InsufficientBalance {
                    asset,
                    available,
                    requested,
                } => anyhow::Error::from(SwapError::InsufficientInventory {
                    asset,
                    required: requested,
                    available,
                }),
                MakerError::Swap(error) => anyhow::Error::from(error),
                other => anyhow::Error::from(other),
            })?;
        match outcome {
            OperationOutcome::Filled(fill) => Ok(fill),
            _ => Err(MakerError::UnexpectedOutcome { expected: "fill" }.into()),
        }
    }

    async fn check_user_transfer(
        &self,
        asset_in: Address,
        request: &SwapRequest,
    ) -> Result<UserPayment> {
        let user_data = transact_data(&request.transfer)?;
        if !user_data.interface_transfers.is_empty() {
            return Err(SwapError::PublicTransfer {
                count: user_data.interface_transfers.len(),
            }
            .into());
        }
        let max = self.max_user_inputs;
        if user_data.inputs.len() > max {
            return Err(SwapError::UserTransferTooWide {
                inputs: user_data.inputs.len(),
                max,
            }
            .into());
        }
        if user_data.outputs.len() != USER_OUTPUTS {
            return Err(SwapError::UserTransferOutputs {
                outputs: user_data.outputs.len(),
                expected: USER_OUTPUTS,
            }
            .into());
        }
        let signer = Address::new_from_array(request.user.signing_pubkey.as_ed25519()?);
        let inputs = user_inputs(
            &request.transfer,
            &user_data,
            self.identity.payer,
            signer,
            self.identity.tree,
        )?;
        self.check_user_inputs(&inputs).await?;
        let registry = self
            .registry
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let outputs: Vec<_> = Receiver {
            keypair: &self.identity.keys,
            registry: &registry,
            tree_id: self.identity.tree_id,
        }
        .received_outputs(&user_data)?
        .into_iter()
        .filter(|(utxo, _)| utxo.asset.asset == asset_in && utxo.amount > 0)
        .collect();
        let received = outputs.iter().try_fold(0u64, |amount, (utxo, _)| {
            amount
                .checked_add(utxo.amount)
                .ok_or(SwapError::UnexpectedTransaction)
        })?;
        if received != request.quote.amount_in {
            return Err(SwapError::Underpaid {
                expected: request.quote.amount_in,
                received,
            }
            .into());
        }
        if outputs.len() != 1 {
            return Err(SwapError::UserPaymentOutputs {
                received: outputs.len(),
            }
            .into());
        }
        let utxo_hash = outputs
            .first()
            .map(|(_, hash)| *hash)
            .ok_or(SwapError::Underpaid {
                expected: request.quote.amount_in,
                received,
            })?;
        let mut receipts: Vec<_> = outputs
            .into_iter()
            .map(|(utxo, hash)| WalletUtxo {
                utxo,
                nullifier_pubkey: self.identity.own.nullifier_pubkey,
                utxo_hash: hash,
                nullifier: [0; 32],
                data_hash: None,
                ring_data_hash: None,
                tree_id: self.identity.tree_id,
                leaf_index: 0,
                slot: 0,
                tx_signature: Signature::default(),
                slot_index: 0,
            })
            .collect();
        assign_nullifiers(self.identity.keys.as_ref(), &mut receipts)?;
        Ok(UserPayment {
            inflow: Inflow {
                asset: asset_in,
                amount: received,
                utxo_hash,
            },
            receipts,
            inputs,
            signer,
        })
    }

    async fn check_user_inputs(&self, inputs: &[UserInput]) -> Result<()> {
        for input in inputs {
            if self
                .services
                .pending
                .reservations
                .is_spent(&input.nullifier)
            {
                return Err(SwapError::UserInputSpent {
                    nullifier: input.nullifier,
                }
                .into());
            }
        }
        let addresses = inputs
            .iter()
            .map(|input| pda::nullifier_pda(&input.tree, &input.nullifier).0)
            .collect();
        let accounts = self.services.rpc.get_multiple_accounts(addresses).await?;
        if accounts.len() != inputs.len() {
            return Err(SwapError::UnexpectedTransaction.into());
        }
        for (input, account) in inputs.iter().zip(accounts) {
            if account.is_some_and(|account| {
                account.owner != Address::default() || !account.data.is_empty()
            }) {
                return Err(SwapError::UserInputSpent {
                    nullifier: input.nullifier,
                }
                .into());
            }
        }
        // Closed nullifier PDAs are absent; the indexer retains their confirmed spends.
        let spent = self
            .services
            .indexer
            .get_shielded_transactions_by_nullifiers(
                inputs.iter().map(|input| input.nullifier).collect(),
                None,
                Some(1),
                None,
            )
            .await?;
        for input in inputs {
            if spent
                .transactions
                .iter()
                .any(|tx| tx.nullifiers.contains(&input.nullifier))
            {
                return Err(SwapError::UserInputSpent {
                    nullifier: input.nullifier,
                }
                .into());
            }
        }
        Ok(())
    }
}

fn user_inputs(
    instruction: &Instruction,
    data: &TransactIxData,
    payer: Address,
    signer: Address,
    output_tree: Address,
) -> Result<Vec<UserInput>> {
    let invalid = || SwapError::UserTransferSigner { expected: signer };
    let owner_start = 4usize
        .checked_add(data.tree_contexts.len())
        .and_then(|offset| offset.checked_add(data.inputs.len()))
        .ok_or_else(invalid)?;
    let owners = instruction
        .accounts
        .get(owner_start..)
        .ok_or_else(invalid)?;
    let [owner] = owners else {
        return Err(invalid().into());
    };
    if signer == payer
        || owner.pubkey != signer
        || !owner.is_signer
        || data.inputs.is_empty()
        || data.tree_contexts.is_empty()
        || data.circuit.cache_access().is_some()
        || instruction
            .accounts
            .first()
            .is_none_or(|account| account.pubkey != payer || !account.is_signer)
    {
        return Err(invalid().into());
    }
    let [payer_meta, tree_meta, program_meta, system_meta] = instruction
        .accounts
        .get(..4)
        .ok_or(SwapError::UnexpectedTransaction)?
    else {
        return Err(SwapError::UnexpectedTransaction.into());
    };
    if !payer_meta.is_writable
        || tree_meta.pubkey != output_tree
        || !tree_meta.is_writable
        || tree_meta.is_signer
        || program_meta.pubkey != PROGRAM_ID_PUBKEY
        || program_meta.is_signer
        || system_meta.pubkey != Address::default()
        || system_meta.is_signer
    {
        return Err(SwapError::UnexpectedTransaction.into());
    }
    let trees = instruction
        .accounts
        .get(4..4 + data.tree_contexts.len())
        .ok_or(SwapError::UnexpectedTransaction)?;
    for tree in trees {
        if tree.is_signer || !tree.is_writable {
            return Err(SwapError::UnexpectedTransaction.into());
        }
    }
    data.inputs
        .iter()
        .enumerate()
        .map(|(position, input)| {
            let tree = trees
                .get(usize::from(input.tree_index))
                .ok_or(SwapError::UnexpectedTransaction)?
                .pubkey;
            let nullifier = pda::nullifier_pda(&tree, &input.nullifier_hash).0;
            let account = instruction
                .accounts
                .get(4 + trees.len() + position)
                .ok_or(SwapError::UnexpectedTransaction)?;
            if account.pubkey != nullifier || account.is_signer {
                return Err(SwapError::UnexpectedTransaction.into());
            }
            Ok(UserInput {
                tree,
                nullifier: input.nullifier_hash,
            })
        })
        .collect()
}

impl Coordinator {
    pub async fn schedule_fill(&mut self, id: OperationId, order: &FillOrder) -> ScheduleOutcome {
        let available = self.services.pending.reservations.available(&order.asset);
        let max_inputs = match self.services.budget.max_maker_inputs(&order.user_transfer) {
            Ok(max_inputs) => max_inputs,
            Err(error) => return ScheduleOutcome::Rejected(error.into()),
        };
        let Some(selection) = select(&available, order.amount, max_inputs) else {
            return self
                .unschedulable(order.asset, order.amount, max_inputs)
                .await;
        };
        let max_outputs = match self
            .services
            .budget
            .max_maker_outputs(&order.user_transfer, selection.inputs.len())
        {
            Ok(max_outputs) => max_outputs,
            Err(error) => return ScheduleOutcome::Rejected(error.into()),
        };
        let change = match own_value(&selection, order.amount) {
            Ok(change) => change,
            Err(error) => return ScheduleOutcome::Rejected(error),
        };
        let change_parts = self.config.profile(&order.asset).parts(
            change,
            &self.other_utxos(&order.asset, &selection),
            max_outputs.saturating_sub(1),
        );
        let spends = selection
            .inputs
            .iter()
            .map(|input| input.utxo.wallet.nullifier)
            .collect();
        let plan = match plan_transfer(selection, order.recipient, order.amount, change_parts) {
            Ok(plan) => plan,
            Err(error) => return ScheduleOutcome::Rejected(error),
        };
        let fill = FillTransfer {
            user_transfer: order.user_transfer.clone(),
            user_signer: order.user_signer,
            receipts: order.receipts.clone(),
            ttl: order.ttl,
            spends,
            message: None,
            last_valid_block_height: 0,
            expires_at: None,
            transaction: None,
            settle: None,
        };
        self.schedule_transfer(TransferStep {
            kind: StepKind::Fill,
            asset: order.asset,
            operation: Some(id),
            plan,
            withdrawal: None,
            tail: Vec::new(),
            vault_before: None,
            fill: Some(fill),
        })
        .await
        .into()
    }

    async fn unschedulable(
        &mut self,
        asset: Address,
        amount: u64,
        max_inputs: usize,
    ) -> ScheduleOutcome {
        if self.preempt_upkeep(&asset).await {
            return ScheduleOutcome::Retry;
        }
        if self.waits_for_utxos(&asset) {
            return ScheduleOutcome::Backlogged;
        }
        ScheduleOutcome::Rejected(MakerError::FragmentedInventory {
            asset,
            available: self.services.pending.reservations.balance(&asset),
            requested: amount,
            max_inputs,
        })
    }

    pub async fn offer_fill(&mut self, id: StepId) {
        let transfers = self.steps.get(id).and_then(|step| {
            let fill = step.fill.as_ref()?;
            Some([fill.user_transfer.clone(), step.instruction.clone()?])
        });
        let Some(transfers) = transfers else {
            return;
        };
        if let Err(error) = self.services.budget.check(&transfers) {
            self.abort(id, error.into(), Retry::Fail).await;
            return;
        }
        let (blockhash, last_valid_block_height) =
            match self.services.sender.latest_blockhash().await {
                Ok(latest) => latest,
                Err(error) => {
                    self.abort(id, error, Retry::Requeue).await;
                    return;
                }
            };
        let message = match compile_message(
            &self.identity.payer,
            &transfers,
            blockhash,
            SWAP_COMPUTE_BUDGET,
        ) {
            Ok(message) => message,
            Err(error) => {
                self.abort(id, error.into(), Retry::Fail).await;
                return;
            }
        };
        let Some(step) = self.steps.get_mut(id) else {
            return;
        };
        let Some(fill) = step.fill.as_mut() else {
            return;
        };
        let expires_at = Instant::now() + fill.ttl;
        fill.message = Some(message.clone());
        fill.last_valid_block_height = last_valid_block_height;
        fill.expires_at = Some(expires_at);
        step.state = StepState::AwaitingSignature;
        let transfer = MakerFill {
            fill: Fill {
                message,
                expires_at,
            },
            spent: fill.spends.clone(),
            change: step.expected_outputs.clone(),
        };
        let operation = step
            .operation
            .and_then(|operation| self.scheduled.remove(&operation));
        self.spawn_expiry(id, expires_at);
        let delivered = operation.is_some_and(|operation| {
            operation
                .reply
                .send(Ok(OperationOutcome::Filled(transfer)))
                .is_ok()
        });
        if !delivered {
            self.discard(id, MakerError::ReservationExpired { step: id }, Retry::Fail)
                .await;
            self.try_schedule().await;
        }
    }
}

pub fn swap_message(
    fee_payer: &Address,
    transfers: [Instruction; 2],
    blockhash: Hash,
) -> Result<VersionedMessage> {
    Ok(compile_message(
        fee_payer,
        &transfers,
        blockhash,
        SWAP_COMPUTE_BUDGET,
    )?)
}

pub fn instructions(message: &VersionedMessage) -> Result<Vec<Instruction>> {
    let keys = message.static_account_keys();
    let key = |index: u8| -> Result<Address> {
        Ok(*keys
            .get(usize::from(index))
            .ok_or(SwapError::UnexpectedTransaction)?)
    };
    message
        .instructions()
        .iter()
        .map(|compiled| {
            let accounts = compiled
                .accounts
                .iter()
                .map(|&index| {
                    Ok(AccountMeta {
                        pubkey: key(index)?,
                        is_signer: message.is_signer(usize::from(index)),
                        is_writable: message.is_maybe_writable_with_reserved_addresses(
                            usize::from(index),
                            None::<&BTreeSet<Address>>,
                        ),
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(Instruction {
                program_id: key(compiled.program_id_index)?,
                accounts,
                data: compiled.data.clone(),
            })
        })
        .collect()
}

pub fn transact_data(instruction: &Instruction) -> Result<TransactIxData> {
    if instruction.program_id != PROGRAM_ID_PUBKEY {
        return Err(SwapError::UnexpectedTransaction.into());
    }
    let Some((&tag::TRANSACT, payload)) = instruction.data.split_first() else {
        return Err(SwapError::UnexpectedTransaction.into());
    };
    TransactIxData::deserialize(payload).map_err(|e| anyhow!("decode transact: {e}"))
}

pub fn transfers(message: &VersionedMessage) -> Result<Vec<TransactIxData>> {
    instructions(message)?.iter().map(transact_data).collect()
}
