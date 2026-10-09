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
use zolana_client::{compile_message, ComputeBudgetConfig};
use zolana_interface::{
    instruction::{tag, TransactIxData},
    PROGRAM_ID_PUBKEY,
};
use zolana_keypair::ShieldedAddress;
use zolana_transaction::WalletUtxo;

use k_lend_rfq_sdk::{
    pair::Pair,
    swap::{Fill, SwapError, SwapRequest},
    transfer::Receiver,
};

use crate::{
    api::Inner,
    error::MakerError,
    inventory::balance::{pending::Inflow, select::select},
    transactions::budget::USER_OUTPUTS,
    transactions::{
        confirm::Retry,
        coordinator::{Coordinator, Operation, OperationOutcome, ScheduleOutcome},
        steps::{FillTransfer, OperationId, StepId, StepKind, StepState},
        transfer::{own_value, plan_transfer, TransferStep},
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
    pub ttl: Duration,
}

impl Inner {
    pub async fn fill(&self, pair: &Pair, request: &SwapRequest) -> Result<MakerFill> {
        let ttl = {
            let settings = self.settings();
            settings.serves(pair)?;
            settings.quotes.ttl
        };
        let quote = request.quote;
        let (asset_in, asset_out) = quote.direction.assets(pair);
        let inflow = self.check_user_transfer(asset_in, request).await?;
        let outcome = self
            .operation(Operation::Fill(FillOrder {
                asset: asset_out,
                amount: quote.amount_out,
                recipient: request.user,
                user_transfer: request.transfer.clone(),
                inflow,
                ttl,
            }))
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
    ) -> Result<Inflow> {
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
        .filter(|(utxo, _)| utxo.asset.asset == asset_in)
        .collect();
        let received: u64 = outputs.iter().map(|(utxo, _)| utxo.amount).sum();
        if received != request.quote.amount_in {
            return Err(SwapError::Underpaid {
                expected: request.quote.amount_in,
                received,
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
        Ok(Inflow {
            asset: asset_in,
            amount: received,
            utxo_hash,
        })
    }
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
