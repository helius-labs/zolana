use anyhow::{anyhow, bail, Result};
use solana_address::Address;
use timelock_escrow_prover::TransactionProofInputs;
use zolana_client::ProofInputUtxo;
use zolana_interface::instruction::instruction_data::transact::{OwnerTag, TransactOutput};
use zolana_keypair::{
    constants::SALT_LEN, random_blinding, random_salt, ViewingKey, ViewingKeyTrait,
};
use zolana_transaction::{
    instructions::transact::{ExternalData, PrivateTxHash, SppProofInputs},
    serialization::{
        confidential::{Confidential, ConfidentialEncode, ConfidentialOutputPlaintext},
        UtxoSerialization,
    },
    utxo::{derive_output_blinding_seed, derive_transact_output_blinding, SppProofInputUtxo},
    SppProofOutputUtxo,
};

use super::{NewProgramUtxo, ProgramState, ProgramUtxo};
use crate::err;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OutputEncoding {
    #[default]
    Encrypted,
    HashOnly,
}

#[derive(Clone, Debug)]
struct PlannedOutput {
    utxo: SppProofOutputUtxo,
    encoding: OutputEncoding,
}

#[derive(Clone)]
pub struct ProgramTransaction<const IN: usize, const OUT: usize> {
    payer: Address,
    output_tree_id: u16,
    expiry_unix_ts: u64,
    blinding_seed: Option<[u8; 32]>,
    inputs: [Option<SppProofInputUtxo>; IN],
    outputs: [Option<PlannedOutput>; OUT],
    program_signers: Vec<Address>,
}

impl<const IN: usize, const OUT: usize> ProgramTransaction<IN, OUT> {
    pub fn new(payer: Address, output_tree_id: u16) -> Self {
        Self {
            payer,
            output_tree_id,
            expiry_unix_ts: u64::MAX,
            blinding_seed: None,
            inputs: std::array::from_fn(|_| None),
            outputs: std::array::from_fn(|_| None),
            program_signers: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_expiry(mut self, expiry_unix_ts: u64) -> Self {
        self.expiry_unix_ts = expiry_unix_ts;
        self
    }

    #[must_use]
    pub fn with_blinding_seed(mut self, blinding_seed: [u8; 32]) -> Self {
        self.blinding_seed = Some(blinding_seed);
        self
    }

    pub fn with_input(mut self, slot: usize, input: SppProofInputUtxo) -> Result<Self> {
        if input.is_dummy() {
            bail!("input slot {slot}: dummy inputs are added by build");
        }
        let entry = self
            .inputs
            .get_mut(slot)
            .ok_or_else(|| anyhow!("input slot {slot} is outside a transaction of {IN} inputs"))?;
        if entry.is_some() {
            bail!("input slot {slot} is set twice");
        }
        *entry = Some(input);
        Ok(self)
    }

    pub fn with_output(self, slot: usize, output: SppProofOutputUtxo) -> Result<Self> {
        if output.is_dummy() {
            bail!("output slot {slot}: an output needs an owner");
        }
        self.set_output(slot, output)
    }

    pub fn with_program_output<S: ProgramState>(
        mut self,
        slot: usize,
        program_utxo: &NewProgramUtxo<S>,
    ) -> Result<Self> {
        let output = program_utxo.output([0u8; 32])?;
        let pda = *program_utxo.owner.pda();
        if !self.program_signers.contains(&pda) {
            self.program_signers.push(pda);
        }
        self.set_output(slot, output)
    }

    pub fn with_output_encoding(mut self, slot: usize, encoding: OutputEncoding) -> Result<Self> {
        let planned = self
            .outputs
            .get_mut(slot)
            .and_then(Option::as_mut)
            .ok_or_else(|| anyhow!("output slot {slot} is unset"))?;
        planned.encoding = encoding;
        Ok(self)
    }

    fn set_output(mut self, slot: usize, utxo: SppProofOutputUtxo) -> Result<Self> {
        let entry = self.outputs.get_mut(slot).ok_or_else(|| {
            anyhow!("output slot {slot} is outside a transaction of {OUT} outputs")
        })?;
        if entry.is_some() {
            bail!("output slot {slot} is set twice");
        }
        *entry = Some(PlannedOutput {
            utxo,
            encoding: OutputEncoding::default(),
        });
        Ok(self)
    }

    pub fn build(self, viewing_key: &impl ViewingKeyTrait) -> Result<BuiltTransaction<IN, OUT>> {
        let Self {
            payer,
            output_tree_id,
            expiry_unix_ts,
            blinding_seed,
            inputs,
            outputs,
            program_signers,
        } = self;

        let input_utxos = pad_inputs(inputs)?;
        let first_nullifier = input_utxos
            .first()
            .ok_or_else(|| anyhow!("a transaction needs an input"))?
            .nullifier;
        let blinding_seed = blinding_seed.unwrap_or_else(random_blinding);
        let output_blinding_seed =
            derive_output_blinding_seed(&first_nullifier, &blinding_seed).map_err(err)?;

        let mut planned_outputs = Vec::with_capacity(OUT);
        for (slot, planned) in outputs.into_iter().enumerate() {
            let mut planned = planned.ok_or_else(|| anyhow!("output slot {slot} is unset"))?;
            let slot_index = u32::try_from(slot).map_err(err)?;
            planned.utxo.blinding = derive_transact_output_blinding(
                &first_nullifier,
                &output_blinding_seed,
                slot_index,
            )
            .map_err(err)?;
            planned_outputs.push(planned);
        }

        let transaction_viewing_key = viewing_key
            .get_transaction_viewing_key(&first_nullifier)
            .map_err(err)?;
        let salt = random_salt();
        let mut transact_outputs = Vec::with_capacity(OUT);
        let mut resolved_owner_tags = Vec::with_capacity(OUT);
        let mut output_hashes = Vec::with_capacity(OUT);
        for (slot, planned) in planned_outputs.iter().enumerate() {
            let owner_tag = planned
                .utxo
                .owner_address
                .ok_or_else(|| anyhow!("output slot {slot} has no owner"))?
                .signing_pubkey
                .confidential_view_tag()
                .map_err(err)?;
            let utxo_hash = planned.utxo.hash(output_tree_id).map_err(err)?;
            let data = match planned.encoding {
                OutputEncoding::Encrypted => Some(confidential_ciphertext(
                    &planned.utxo,
                    owner_tag,
                    &transaction_viewing_key,
                    salt,
                    u32::try_from(slot).map_err(err)?,
                )?),
                OutputEncoding::HashOnly => None,
            };
            transact_outputs.push(TransactOutput {
                utxo_hash,
                owner_tag: OwnerTag::Inline(owner_tag),
                data,
            });
            resolved_owner_tags.push(owner_tag);
            output_hashes.push(utxo_hash);
        }

        let mut external_data = ExternalData::new(
            *transaction_viewing_key.pubkey().as_bytes(),
            salt,
            transact_outputs,
            resolved_owner_tags,
            Vec::new(),
        );
        external_data.expiry_unix_ts = expiry_unix_ts;

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
            output_utxos: planned_outputs
                .into_iter()
                .map(|planned| planned.utxo)
                .collect(),
            blinding_seed,
            output_tree_id,
            external_data,
            payer,
            cache_accounts: Default::default(),
            program_signers,
        };
        spp_proof_inputs.check_shape().map_err(err)?;

        let external_data_hash = spp_proof_inputs.external_data.hash().map_err(err)?;
        let private_tx_blinding = spp_proof_inputs.private_tx_blinding().map_err(err)?;
        let private_tx_hash = PrivateTxHash::new(
            &input_hashes,
            &output_hashes,
            &external_data_hash,
            &private_tx_blinding,
        )
        .hash()
        .map_err(err)?;
        if zolana_keypair::hash::sha256(&private_tx_hash)
            != spp_proof_inputs.message_hash().map_err(err)?
        {
            bail!("private tx hash does not match the SPP transaction");
        }

        Ok(BuiltTransaction {
            spp_proof_inputs,
            input_hashes: to_array(input_hashes)?,
            output_hashes: to_array(output_hashes)?,
            external_data_hash,
            private_tx_blinding,
            private_tx_hash,
        })
    }
}

fn pad_inputs<const IN: usize>(
    inputs: [Option<SppProofInputUtxo>; IN],
) -> Result<Vec<SppProofInputUtxo>> {
    let padding_tree_id = inputs
        .iter()
        .flatten()
        .last()
        .map(|input| input.tree_id)
        .ok_or_else(|| anyhow!("a transaction needs a real input"))?;
    if inputs.first().and_then(Option::as_ref).is_none() {
        bail!("input slot 0 must hold a real input: it is the first nullifier");
    }
    inputs
        .into_iter()
        .map(|input| match input {
            Some(input) => Ok(input),
            None => SppProofInputUtxo::dummy(padding_tree_id).map_err(err),
        })
        .collect()
}

fn to_array<const N: usize>(hashes: Vec<[u8; 32]>) -> Result<[[u8; 32]; N]> {
    let len = hashes.len();
    hashes
        .try_into()
        .map_err(|_| anyhow!("expected {N} slot hashes, got {len}"))
}

fn confidential_ciphertext(
    output: &SppProofOutputUtxo,
    owner_tag: [u8; 32],
    transaction_viewing_key: &ViewingKey,
    salt: [u8; SALT_LEN],
    slot_index: u32,
) -> Result<Vec<u8>> {
    if output.ring_program_id.is_some() {
        bail!("ring outputs are not supported");
    }
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
    )
    .map_err(err)?;
    Ok(message.data)
}

#[derive(Clone)]
pub struct BuiltTransaction<const IN: usize, const OUT: usize> {
    spp_proof_inputs: SppProofInputs,
    input_hashes: [[u8; 32]; IN],
    output_hashes: [[u8; 32]; OUT],
    external_data_hash: [u8; 32],
    private_tx_blinding: [u8; 32],
    private_tx_hash: [u8; 32],
}

impl<const IN: usize, const OUT: usize> BuiltTransaction<IN, OUT> {
    pub fn spp_proof_inputs(&self) -> SppProofInputs {
        self.spp_proof_inputs.clone()
    }

    pub fn private_tx_hash(&self) -> &[u8; 32] {
        &self.private_tx_hash
    }

    pub fn external_data_hash(&self) -> &[u8; 32] {
        &self.external_data_hash
    }

    pub fn private_tx_blinding(&self) -> &[u8; 32] {
        &self.private_tx_blinding
    }

    pub fn payer(&self) -> &Address {
        &self.spp_proof_inputs.payer
    }

    pub fn output_tree_id(&self) -> u16 {
        self.spp_proof_inputs.output_tree_id
    }

    pub fn first_nullifier(&self) -> Result<[u8; 32]> {
        self.spp_proof_inputs.first_nullifier().map_err(err)
    }

    pub fn blinding_seed(&self) -> &[u8; 32] {
        &self.spp_proof_inputs.blinding_seed
    }

    pub fn transaction_proof_inputs(&self) -> Result<TransactionProofInputs> {
        Ok(TransactionProofInputs {
            external_data_hash: self.external_data_hash,
            first_nullifier: self.first_nullifier()?,
            blinding_seed: *self.blinding_seed(),
            output_tree_id: self.output_tree_id(),
        })
    }

    pub fn input(&self, slot: usize) -> Result<&SppProofInputUtxo> {
        self.spp_proof_inputs
            .input_utxos
            .get(slot)
            .ok_or_else(|| anyhow!("input slot {slot} is outside a transaction of {IN} inputs"))
    }

    pub fn input_hash(&self, slot: usize) -> Result<&[u8; 32]> {
        self.input_hashes
            .get(slot)
            .ok_or_else(|| anyhow!("input slot {slot} is outside a transaction of {IN} inputs"))
    }

    pub fn input_proof_inputs(&self, slot: usize) -> Result<ProofInputUtxo> {
        ProofInputUtxo::try_from(self.input(slot)?).map_err(err)
    }

    pub fn output(&self, slot: usize) -> Result<&SppProofOutputUtxo> {
        self.spp_proof_inputs
            .output_utxos
            .get(slot)
            .ok_or_else(|| anyhow!("output slot {slot} is outside a transaction of {OUT} outputs"))
    }

    pub fn output_hash(&self, slot: usize) -> Result<&[u8; 32]> {
        self.output_hashes
            .get(slot)
            .ok_or_else(|| anyhow!("output slot {slot} is outside a transaction of {OUT} outputs"))
    }

    pub fn output_proof_inputs(&self, slot: usize) -> Result<ProofInputUtxo> {
        ProofInputUtxo::try_from((self.output(slot)?, self.output_tree_id())).map_err(err)
    }

    pub fn created<S: ProgramState>(
        &self,
        slot: usize,
        program_utxo: NewProgramUtxo<S>,
    ) -> Result<ProgramUtxo<S>> {
        let blinding = self.output(slot)?.blinding;
        let created = program_utxo.created(blinding, self.output_tree_id());
        if created.hash()? != *self.output_hash(slot)? {
            bail!("output slot {slot} does not hold this program utxo");
        }
        Ok(created)
    }

    pub fn external_data(&self) -> &ExternalData {
        &self.spp_proof_inputs.external_data
    }

    pub fn owner_signers(&self) -> Result<Vec<Address>> {
        self.spp_proof_inputs.owner_signer_pubkeys().map_err(err)
    }

    pub(super) fn input_nullifiers(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.spp_proof_inputs
            .input_utxos
            .iter()
            .map(|input| &input.nullifier)
    }

    pub(super) fn input_tree_ids(&self) -> Vec<u16> {
        let mut tree_ids = Vec::new();
        for input in self
            .spp_proof_inputs
            .input_utxos
            .iter()
            .filter(|input| !input.is_dummy())
        {
            if !tree_ids.contains(&input.tree_id) {
                tree_ids.push(input.tree_id);
            }
        }
        tree_ids
    }
}
