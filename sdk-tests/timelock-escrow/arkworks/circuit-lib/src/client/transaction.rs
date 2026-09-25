use anyhow::{anyhow, bail, Result};
use solana_address::Address;
use zolana_hasher::{hash_chain::create_hash_chain_4_from_slice, Hasher, Poseidon};
use zolana_interface::instruction::instruction_data::transact::{OwnerTag, TransactOutput};
use zolana_keypair::{
    constants::SALT_LEN, random_blinding, random_salt, ViewingKey, ViewingKeyTrait,
};
use zolana_transaction::{
    instructions::transact::{ExternalData, SppProofInputs},
    serialization::{
        confidential::{Confidential, ConfidentialEncode, ConfidentialOutputPlaintext},
        UtxoSerialization,
    },
    utxo::{derive_output_blinding_seed, derive_transact_output_blinding, SppProofInputUtxo},
    SppProofOutputUtxo,
};

use super::{DataUtxo, OutputTokenUtxo, State, TokenUtxo};
use crate::convert::tx_context;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxContext {
    pub first_nullifier: [u8; 32],
    pub blinding_seed: [u8; 32],
    pub output_tree_id: u16,
}

impl TxContext {
    pub fn circuit(&self) -> Result<crate::TxContext> {
        Ok(tx_context(
            &self.first_nullifier,
            &self.blinding_seed,
            self.output_tree_id,
        )?)
    }
}

pub trait PublicInputs {
    fn hash(&self, private_tx_hash: &[u8; 32]) -> Result<[u8; 32]>;
}

#[must_use]
pub struct ConfidentialTransaction<'a, P, const IN: usize, const OUT: usize> {
    payer: Address,
    output_tree_id: u16,
    expiry_unix_ts: u64,
    blinding_seed: Option<[u8; 32]>,
    public: &'a P,
    inputs: Vec<SppProofInputUtxo>,
    outputs: Vec<SppProofOutputUtxo>,
    error: Option<anyhow::Error>,
}

impl<'a, P: PublicInputs, const IN: usize, const OUT: usize>
    ConfidentialTransaction<'a, P, IN, OUT>
{
    pub fn new(payer: Address, output_tree_id: u16, public: &'a P) -> Self {
        Self {
            payer,
            output_tree_id,
            expiry_unix_ts: u64::MAX,
            blinding_seed: None,
            public,
            inputs: Vec::with_capacity(IN),
            outputs: Vec::with_capacity(OUT),
            error: None,
        }
    }

    pub fn with_expiry(mut self, expiry_unix_ts: u64) -> Self {
        self.expiry_unix_ts = expiry_unix_ts;
        self
    }

    pub fn with_blinding_seed(mut self, blinding_seed: [u8; 32]) -> Self {
        self.blinding_seed = Some(blinding_seed);
        self
    }

    pub fn with_token_utxos<const N: usize>(mut self, token: TokenUtxo<N>) -> Self {
        self.inputs.extend(token.inputs().iter().cloned());
        match token.change() {
            Ok(Some(change)) => self.outputs.push(change),
            Ok(None) => {}
            Err(error) => self.record(error),
        }
        self
    }

    pub fn with_output_token_utxo(mut self, output: OutputTokenUtxo) -> Self {
        match output.output() {
            Ok(output) => self.outputs.push(output),
            Err(error) => self.record(error),
        }
        self
    }

    pub fn with_data_utxo<S: State>(mut self, utxo: DataUtxo<S>) -> Self {
        if let Some(input) = utxo.input() {
            self.inputs.push(input.clone());
        }
        match utxo.output() {
            Ok(Some(output)) => self.outputs.push(output),
            Ok(None) => {}
            Err(error) => self.record(error),
        }
        self
    }

    pub fn build(self, viewing_key: &impl ViewingKeyTrait) -> Result<BuiltTransaction<IN, OUT>> {
        if let Some(error) = self.error {
            return Err(error);
        }
        let input_utxos = padded_inputs::<IN>(self.inputs)?;
        let first_nullifier = input_utxos
            .first()
            .map(|input| input.nullifier)
            .ok_or_else(|| anyhow!("a transaction needs an input"))?;
        let tx_context = TxContext {
            first_nullifier,
            blinding_seed: self.blinding_seed.unwrap_or_else(random_blinding),
            output_tree_id: self.output_tree_id,
        };
        let output_utxos = blinded_outputs::<OUT>(self.outputs, &tx_context)?;

        let transaction_viewing_key = viewing_key.get_transaction_viewing_key(&first_nullifier)?;
        let salt = random_salt();
        let mut transact_outputs = Vec::with_capacity(OUT);
        let mut owner_tags = Vec::with_capacity(OUT);
        let mut output_hashes = Vec::with_capacity(OUT);
        for (slot, output) in output_utxos.iter().enumerate() {
            let utxo_hash = output.hash(self.output_tree_id)?;
            let (owner_tag, data) = match output.owner_address {
                Some(owner) => {
                    let owner_tag = owner.signing_pubkey.confidential_view_tag()?;
                    let data = ciphertext(
                        output,
                        owner_tag,
                        &transaction_viewing_key,
                        salt,
                        u32::try_from(slot)?,
                    )?;
                    (owner_tag, Some(data))
                }
                None => ([0u8; 32], None),
            };
            transact_outputs.push(TransactOutput {
                utxo_hash,
                owner_tag: OwnerTag::Inline(owner_tag),
                data,
            });
            owner_tags.push(owner_tag);
            output_hashes.push(if output.is_dummy() {
                [0u8; 32]
            } else {
                utxo_hash
            });
        }
        let mut external_data = ExternalData::new(
            *transaction_viewing_key.pubkey().as_bytes(),
            salt,
            transact_outputs,
            owner_tags,
            Vec::new(),
        );
        external_data.expiry_unix_ts = self.expiry_unix_ts;

        let input_hashes: Vec<[u8; 32]> = input_utxos
            .iter()
            .map(|input| {
                if input.is_dummy() {
                    [0u8; 32]
                } else {
                    input.utxo_hash
                }
            })
            .collect();
        let spp_proof_inputs = SppProofInputs {
            input_utxos,
            output_utxos,
            blinding_seed: tx_context.blinding_seed,
            output_tree_id: self.output_tree_id,
            external_data,
            payer: self.payer,
            cache_accounts: Default::default(),
        };
        spp_proof_inputs.check_shape()?;
        let private_tx_hash = Poseidon::hashv(&[
            create_hash_chain_4_from_slice(&input_hashes)?.as_slice(),
            create_hash_chain_4_from_slice(&output_hashes)?.as_slice(),
            create_hash_chain_4_from_slice(&[[0u8; 32]; IN])?.as_slice(),
            spp_proof_inputs.private_tx_blinding()?.as_slice(),
        ])?;
        let public_hash = self.public.hash(&private_tx_hash)?;

        Ok(BuiltTransaction {
            spp_proof_inputs,
            tx_context,
            input_hashes: array(input_hashes)?,
            output_hashes: array(output_hashes)?,
            private_tx_hash,
            public_hash,
        })
    }

    fn record(&mut self, error: anyhow::Error) {
        self.error.get_or_insert(error);
    }
}

#[derive(Clone)]
pub struct BuiltTransaction<const IN: usize, const OUT: usize> {
    pub spp_proof_inputs: SppProofInputs,
    pub tx_context: TxContext,
    pub input_hashes: [[u8; 32]; IN],
    pub output_hashes: [[u8; 32]; OUT],
    pub private_tx_hash: [u8; 32],
    pub public_hash: [u8; 32],
}

fn padded_inputs<const IN: usize>(
    mut inputs: Vec<SppProofInputUtxo>,
) -> Result<Vec<SppProofInputUtxo>> {
    if inputs.len() > IN {
        bail!("input slot {IN} is outside the transaction");
    }
    let first = inputs
        .first()
        .ok_or_else(|| anyhow!("a transaction needs a real input"))?;
    if first.is_dummy() {
        bail!("input slot 0 must hold a real input: it is the first nullifier");
    }
    let padding_tree_id = inputs
        .iter()
        .rev()
        .find(|input| !input.is_dummy())
        .map(|input| input.tree_id)
        .unwrap_or(first.tree_id);
    while inputs.len() < IN {
        inputs.push(SppProofInputUtxo::dummy(padding_tree_id)?);
    }
    Ok(inputs)
}

fn blinded_outputs<const OUT: usize>(
    mut outputs: Vec<SppProofOutputUtxo>,
    tx_context: &TxContext,
) -> Result<Vec<SppProofOutputUtxo>> {
    if outputs.len() > OUT {
        bail!("output slot {OUT} is outside the transaction");
    }
    outputs.resize_with(OUT, SppProofOutputUtxo::default);
    let output_blinding_seed =
        derive_output_blinding_seed(&tx_context.first_nullifier, &tx_context.blinding_seed)?;
    for (slot, output) in outputs.iter_mut().enumerate() {
        output.blinding = derive_transact_output_blinding(
            &tx_context.first_nullifier,
            &output_blinding_seed,
            u32::try_from(slot)?,
        )?;
    }
    Ok(outputs)
}

fn array<const N: usize>(hashes: Vec<[u8; 32]>) -> Result<[[u8; 32]; N]> {
    let len = hashes.len();
    hashes
        .try_into()
        .map_err(|_| anyhow!("expected {N} slot hashes, got {len}"))
}

fn ciphertext(
    output: &SppProofOutputUtxo,
    owner_tag: [u8; 32],
    transaction_viewing_key: &ViewingKey,
    salt: [u8; SALT_LEN],
    slot_index: u32,
) -> Result<Vec<u8>> {
    let recipient = output
        .owner_address
        .ok_or_else(|| anyhow!("output has no owner"))?;
    let message = Confidential::encode_plaintext(
        &ConfidentialOutputPlaintext {
            asset_id: output.asset.asset_id,
            amount: output.amount,
            blinding: output.blinding,
            ring_program_id: None,
            data: output.data.clone(),
        },
        owner_tag,
        &ConfidentialEncode {
            tx: transaction_viewing_key.clone(),
            recipient_pubkey: recipient.viewing_pubkey,
            salt,
            slot_index,
        },
    )?;
    Ok(message.data)
}
