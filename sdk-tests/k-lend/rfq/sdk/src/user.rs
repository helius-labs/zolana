use std::{cmp::Reverse, collections::BTreeSet};

use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::VersionedMessage;
use zolana_client::{Rpc, ZolanaClient};
use zolana_interface::{
    instruction::{tag, TransactIxData},
    PROGRAM_ID_PUBKEY,
};
use zolana_keypair::ShieldedKeypair;
use zolana_transaction::{Utxo, WalletUtxo};

use crate::{
    pair::{Pair, VaultState},
    swap::{Offer, Order, Quote, SwapError, SwapRequest},
    transfer::{Receiver, Transfer},
};

pub fn select_inputs(
    utxos: Vec<WalletUtxo>,
    asset: Address,
    amount: u64,
    max_inputs: usize,
) -> Result<Vec<WalletUtxo>, SwapError> {
    let mut candidates: Vec<WalletUtxo> = utxos
        .into_iter()
        .filter(|utxo| utxo.utxo.asset.asset == asset)
        .collect();
    candidates.sort_by_key(|utxo| Reverse(utxo.utxo.amount));
    let mut inputs = Vec::new();
    let mut total = 0u64;
    for utxo in candidates {
        if total >= amount {
            break;
        }
        total = total.saturating_add(utxo.utxo.amount);
        inputs.push(utxo);
    }
    if total < amount {
        return Err(SwapError::InsufficientFunds {
            asset,
            required: amount,
        });
    }
    if inputs.len() > max_inputs {
        return Err(SwapError::TooManyInputs {
            needed: inputs.len(),
            max: max_inputs,
        });
    }
    Ok(inputs)
}

pub struct UserOrder {
    pub offer: Offer,
    pub inputs: Vec<WalletUtxo>,
    pub width: Option<usize>,
    pub tree: Address,
    pub tree_id: u16,
}

impl UserOrder {
    pub fn prove<R: Rpc>(
        self,
        client: &ZolanaClient<R>,
        keypair: &ShieldedKeypair,
    ) -> Result<Order> {
        let UserOrder {
            offer,
            inputs,
            width,
            tree,
            tree_id,
        } = self;
        if inputs.len() > offer.max_user_inputs {
            return Err(SwapError::TooManyInputs {
                needed: inputs.len(),
                max: offer.max_user_inputs,
            }
            .into());
        }
        let quote = offer.quote;
        let transfer = Transfer {
            inputs: inputs.clone(),
            width: width.unwrap_or(inputs.len()),
            amount: quote.amount_in,
            recipient: offer.maker,
            payer: offer.fee_payer,
            tree,
            tree_id,
        }
        .prove(client, keypair)?;
        Ok(Order {
            offer,
            inputs,
            request: SwapRequest {
                quote,
                user: keypair.shielded_address()?,
                transfer: transfer.instruction,
            },
        })
    }
}

pub struct QuoteCheck<'a> {
    pub order: &'a Order,
    pub message: &'a VersionedMessage,
    pub pair: &'a Pair,
    pub rate: &'a VaultState,
    pub fee_bps: u64,
}

impl QuoteCheck<'_> {
    pub fn verify(&self, receiver: &Receiver) -> Result<()> {
        let order = self.order;
        if self.message.static_account_keys().first() != Some(&order.offer.fee_payer) {
            return Err(SwapError::UnexpectedTransaction.into());
        }
        let instructions = instructions(self.message)?;
        let [user_transfer, maker_transfer] = instructions.as_slice() else {
            return Err(SwapError::UnexpectedTransaction.into());
        };
        if *user_transfer != order.request.transfer {
            return Err(SwapError::UserTransferAltered.into());
        }
        let user_data = transact_data(user_transfer)?;
        let maker_data = transact_data(maker_transfer)?;
        let count = user_data.interface_transfers.len() + maker_data.interface_transfers.len();
        if count != 0 {
            return Err(SwapError::PublicTransfer { count }.into());
        }
        let (_, asset_out) = order.offer.quote.direction.assets(self.pair);
        let received: Vec<Utxo> = receiver
            .received(&maker_data)?
            .into_iter()
            .filter(|utxo| utxo.asset.asset == asset_out)
            .collect();
        let [utxo] = received.as_slice() else {
            return Err(SwapError::UnexpectedOutputs {
                received: received.len(),
            }
            .into());
        };
        let expected = Quote::price(
            self.rate,
            order.offer.quote.direction,
            order.offer.quote.amount_in,
            self.fee_bps,
        )?;
        if utxo.amount < expected.amount_out {
            return Err(SwapError::BelowRate {
                expected: expected.amount_out,
                offered: utxo.amount,
            }
            .into());
        }
        Ok(())
    }
}

fn instructions(message: &VersionedMessage) -> Result<Vec<Instruction>> {
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

fn transact_data(instruction: &Instruction) -> Result<TransactIxData> {
    if instruction.program_id != PROGRAM_ID_PUBKEY {
        return Err(SwapError::UnexpectedTransaction.into());
    }
    let Some((&tag::TRANSACT, payload)) = instruction.data.split_first() else {
        return Err(SwapError::UnexpectedTransaction.into());
    };
    TransactIxData::deserialize(payload).map_err(|e| anyhow!("decode transact: {e}"))
}
