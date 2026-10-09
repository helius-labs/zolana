use anyhow::{anyhow, Result};
use borsh::BorshDeserialize;
use solana_address::Address;
use solana_instruction::Instruction;
use solana_message::VersionedMessage;
use zolana_client::{Rpc, ZolanaClient};
use zolana_event::OutputDataEncoding;
use zolana_interface::instruction::TransactIxData;
use zolana_keypair::{constants::P256_PUBKEY_LEN, P256Pubkey, ShieldedAddress, ShieldedKeypair};
use zolana_program::instruction::Transact;
use zolana_transaction::{
    instructions::transact::ConfidentialTransaction,
    serialization::confidential::{Confidential, ConfidentialOutputPlaintext},
    AssetRegistry, EncryptedScheme, Utxo, WalletUtxo,
};

use crate::{
    budget::{smallest_shape, USER_OUTPUTS},
    kvault::{Pair, VaultState},
    swap::{instructions, transact_data, Offer, Order, Quote, SwapError, SwapRequest},
};

pub struct Transfer {
    pub inputs: Vec<WalletUtxo>,
    pub width: usize,
    pub amount: u64,
    pub recipient: ShieldedAddress,
    pub payer: Address,
    pub tree: Address,
    pub tree_id: u16,
}

pub struct TransferInstruction {
    pub instruction: Instruction,
    pub nullifiers: Vec<[u8; 32]>,
}

impl Transfer {
    pub fn prove<R: Rpc>(
        self,
        client: &ZolanaClient<R>,
        keypair: &ShieldedKeypair,
    ) -> Result<TransferInstruction> {
        let Transfer {
            inputs,
            width,
            amount,
            recipient,
            payer,
            tree,
            tree_id,
        } = self;
        let asset = inputs
            .first()
            .map(|input| input.utxo.asset.asset)
            .ok_or_else(|| anyhow!("transfer without inputs"))?;
        let shape = smallest_shape(width.max(inputs.len()), USER_OUTPUTS).ok_or(
            SwapError::NoSupportedShape {
                inputs: width,
                outputs: USER_OUTPUTS,
            },
        )?;
        let identity = keypair.shielded_address()?;
        let mut transaction =
            ConfidentialTransaction::new(inputs, payer)?.with_output_tree_id(tree_id)?;
        transaction.transfer(&recipient, asset, amount)?;
        transaction.pad_utxos(shape, &identity)?;
        let proof_inputs = transaction.encrypt(keypair)?;
        let nullifiers = proof_inputs
            .input_utxos
            .iter()
            .filter(|input| !input.is_dummy())
            .map(|input| input.nullifier)
            .collect();
        let owner_signers = proof_inputs.owner_signer_pubkeys()?;
        let data = client
            .prove_transact(proof_inputs, None, keypair)
            .map_err(|e| anyhow!("prove transfer: {e:?}"))?;
        let instruction = Transact {
            payer,
            input_trees: vec![tree],
            output_tree: tree,
            owner_signers,
            interface_transfer_accounts: Vec::new(),
            data,
        }
        .instruction();
        Ok(TransferInstruction {
            instruction,
            nullifiers,
        })
    }
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

pub struct Receiver<'a> {
    pub keypair: &'a ShieldedKeypair,
    pub registry: &'a AssetRegistry,
    pub tree_id: u16,
}

impl Receiver<'_> {
    pub fn received(&self, data: &TransactIxData) -> Result<Vec<Utxo>> {
        Ok(self
            .received_outputs(data)?
            .into_iter()
            .map(|(utxo, _)| utxo)
            .collect())
    }

    pub fn received_outputs(&self, data: &TransactIxData) -> Result<Vec<(Utxo, [u8; 32])>> {
        let identity = self.keypair.shielded_address()?;
        let mut received = Vec::new();
        for (slot, output) in data.outputs.iter().enumerate() {
            let Some(plaintext) =
                self.decrypt_output(&identity, output.data.as_deref(), data, slot)?
            else {
                continue;
            };
            let utxo = plaintext.into_utxo(identity.signing_pubkey, self.registry)?;
            let hash = utxo.hash(&identity.nullifier_pubkey, &[0; 32], &[0; 32], self.tree_id)?;
            if hash != output.utxo_hash {
                return Err(SwapError::CommitmentMismatch { slot }.into());
            }
            received.push((utxo, hash));
        }
        Ok(received)
    }

    fn decrypt_output(
        &self,
        identity: &ShieldedAddress,
        output: Option<&[u8]>,
        data: &TransactIxData,
        slot: usize,
    ) -> Result<Option<ConfidentialOutputPlaintext>> {
        let Some(output) = output else {
            return Ok(None);
        };
        let Ok(OutputDataEncoding::Encrypted(blob)) = OutputDataEncoding::try_from_slice(output)
        else {
            return Ok(None);
        };
        let Some((&scheme, body)) = blob.split_first() else {
            return Ok(None);
        };
        if scheme != EncryptedScheme::Confidential.as_byte()
            || Confidential::embedded_viewing_pk(body)? != identity.viewing_pubkey
        {
            return Ok(None);
        }
        let ciphertext = body
            .get(P256_PUBKEY_LEN..)
            .ok_or_else(|| anyhow!("output {slot} ciphertext is truncated"))?;
        let bytes = self.keypair.decrypt_utxo(
            ciphertext,
            &P256Pubkey::from_bytes(data.tx_viewing_pk)?,
            data.salt,
            u32::try_from(slot)?,
        )?;
        Ok(Some(ConfidentialOutputPlaintext::deserialize(&bytes)?))
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
