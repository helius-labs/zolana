use anyhow::{anyhow, Result};
use borsh::BorshDeserialize;
use solana_address::Address;
use solana_instruction::Instruction;
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

use zolana_client::{Shape, SPP_SUPPORTED_SHAPES};

use crate::swap::SwapError;

const USER_OUTPUTS: usize = 2;

fn smallest_shape(inputs: usize, outputs: usize) -> Option<Shape> {
    SPP_SUPPORTED_SHAPES
        .into_iter()
        .filter(|shape| shape.n_inputs() >= inputs && shape.n_outputs() >= outputs)
        .min_by_key(|shape| (shape.n_inputs(), shape.n_outputs()))
}

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
