use anyhow::{bail, Result};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use swap_prover::CreateProofInputs;
use zolana_interface::instruction::instruction_data::transact::{OutputData, TransactIxData};
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{
    instructions::{
        transact::{OutputUtxo, SppProofInputs},
        types::SppProofInputUtxo,
    },
    TransactionError,
};

use crate::{
    err, escrow_authority_pda,
    order::{BlindingField, DataHash, OrderUtxo},
    program_id_pubkey, spp_program_meta, tag, CreateProof, CreateSwapIxData, MarkerData,
};

pub struct SppTxHashes {
    pub source_input_hash: [u8; 32],
    pub external_data_hash: [u8; 32],
}

impl SppTxHashes {
    pub fn new(spp_proof_inputs: &SppProofInputs) -> Result<Self> {
        let source_input = spp_proof_inputs
            .input_utxos
            .first()
            .ok_or_else(|| err("missing source input"))?;
        Ok(Self {
            source_input_hash: source_input.hash().map_err(err)?,
            external_data_hash: spp_proof_inputs.external_data.hash().map_err(err)?,
        })
    }
}

pub struct CreateSwapProofInputParams {
    pub escrow: OrderUtxo,
    pub change: OutputUtxo,
    pub spp_tx_hashes: SppTxHashes,
}

impl CreateSwapProofInputParams {
    pub fn into_proof_inputs(&self) -> Result<CreateProofInputs> {
        let terms = &self.escrow.terms;
        if self.change.owner_address != Some(terms.destination) {
            bail!("change owner does not match order destination");
        }
        if self.change.asset != self.escrow.source_mint {
            bail!("change asset does not match order source mint");
        }
        if self.change.data_hash.is_some()
            || self.change.zone_data_hash.is_some()
            || self.change.zone_program_id.is_some()
        {
            bail!("change output must not carry data or zone commitments");
        }
        Ok(CreateProofInputs {
            source_mint: *self.escrow.source_mint.as_array(),
            source_amount: self.escrow.source_amount,
            escrow_authority: *escrow_authority_pda().as_array(),
            escrow_blinding: self.escrow.blinding.to_field(),
            destination_mint: *terms.destination_mint.as_array(),
            destination_amount: terms.destination_amount,
            maker_owner_hash: terms.destination.owner_hash().map_err(err)?,
            maker_viewing_pk: *terms.destination.viewing_pubkey.as_bytes(),
            expiry: terms.expiry,
            taker_pk_fe: terms.taker.data_hash()?,
            fill_mode: terms.fill_mode,
            external_data_hash: self.spp_tx_hashes.external_data_hash,
            source_input_hash: self.spp_tx_hashes.source_input_hash,
            change_amount: self.change.amount,
            change_blinding: self.change.blinding.to_field(),
        })
    }
}

pub fn input_sum(inputs: &[SppProofInputUtxo], asset: &Address) -> i128 {
    inputs
        .iter()
        .filter(|spend| &spend.utxo.asset == asset)
        .map(|spend| i128::from(spend.utxo.amount))
        .sum()
}

pub struct OrderMarker {
    pub escrow_utxo_hash: [u8; 32],
    pub maker_pubkey: Pubkey,
    pub taker_address: ShieldedAddress,
}

impl OrderMarker {
    pub fn message(self) -> Result<OutputData, TransactionError> {
        Ok(OutputData {
            view_tag: self.taker_address.signing_pubkey.confidential_view_tag()?,
            data: borsh::to_vec(&MarkerData {
                escrow_utxo_hash: self.escrow_utxo_hash,
                maker_pubkey: self.maker_pubkey.to_bytes(),
            })
            .expect("MarkerData serialization is infallible"),
        })
    }
}

pub struct CreateSwap {
    pub payer: Pubkey,
    pub tree: Pubkey,
    pub create_swap_proof: CreateProof,
    pub spp_proof: TransactIxData,
}

impl CreateSwap {
    pub fn instruction(self) -> Result<Instruction> {
        let Self {
            payer,
            tree,
            create_swap_proof,
            mut spp_proof,
        } = self;

        if let Some(marker) = spp_proof.messages.first_mut() {
            marker.data = Vec::new();
        }

        let data = wincode::serialize(&CreateSwapIxData {
            proof: create_swap_proof,
            transact: spp_proof,
        })
        .map_err(err)?;

        let accounts = vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(payer, true),
            AccountMeta::new(tree, false),
            spp_program_meta(),
        ];
        let mut instruction_data = vec![tag::CREATE_SWAP];
        instruction_data.extend_from_slice(&data);
        Ok(Instruction {
            program_id: program_id_pubkey(),
            accounts,
            data: instruction_data,
        })
    }
}

#[cfg(test)]
mod tests {
    use zolana_keypair::{constants::BLINDING_LEN, shielded::ShieldedKeypair};
    use zolana_transaction::{
        instructions::{
            transact::{
                encrypt_transaction_data, get_transaction_viewing_key, ExternalData, OutputUtxo,
                PrivateTxHash, Shape, SppProofInputs,
            },
            types::SppProofInputUtxo,
        },
        utxo::Utxo,
        AssetRegistry, Data, SOL_MINT,
    };

    use super::*;

    fn data_hash_fe(byte: u8) -> [u8; 32] {
        let mut out = [byte; 32];
        out[0] = 0;
        out
    }

    #[test]
    fn sign_escrow_create_layout() {
        let owner_keypair = ShieldedKeypair::from_seed_ed25519(&[7u8; 32]).expect("owner keypair");
        let order_keypair = ShieldedKeypair::from_seed_ed25519(&[9u8; 32]).expect("order keypair");
        let taker_keypair =
            ShieldedKeypair::from_seed_ed25519(&[13u8; 32]).expect("market maker keypair");
        let assets = AssetRegistry::default();

        let input_amount = 1_000_000u64;
        let escrow_amount = 400_000u64;

        let input_utxo = Utxo {
            owner: owner_keypair.signing_pubkey(),
            asset: SOL_MINT,
            amount: input_amount,
            blinding: [5u8; BLINDING_LEN],
            zone_program_id: None,
            data: Data::default(),
        };
        let spend = SppProofInputUtxo::new(input_utxo, &owner_keypair);

        let escrow = OutputUtxo {
            owner_address: Some(order_keypair.shielded_address().expect("order address")),
            asset: SOL_MINT,
            amount: escrow_amount,
            blinding: [11u8; BLINDING_LEN],
            ..Default::default()
        }
        .with_utxo_data(vec![1, 2, 3, 4], data_hash_fe(0xAB));

        let taker_address = taker_keypair
            .shielded_address()
            .expect("market maker address");
        let owner_address = owner_keypair.shielded_address().expect("owner address");

        let escrow_utxo_hash = escrow.hash().expect("escrow hash");
        let change_amount = input_amount - escrow_amount;
        let change =
            OutputUtxo::new(SOL_MINT, change_amount, owner_address).expect("change output");
        let marker_message = OrderMarker {
            escrow_utxo_hash,
            maker_pubkey: Pubkey::default(),
            taker_address,
        }
        .message()
        .expect("marker message");
        let expected_marker_bytes = borsh::to_vec(&MarkerData {
            escrow_utxo_hash,
            maker_pubkey: Pubkey::default().to_bytes(),
        })
        .expect("marker bytes");
        let input_utxos = vec![spend, SppProofInputUtxo::new_dummy()];
        let transaction_viewing_key = get_transaction_viewing_key(&owner_keypair, &input_utxos)
            .expect("transaction viewing key");

        let encoded =
            encrypt_transaction_data(&[change, escrow], &assets, &transaction_viewing_key)
                .expect("encode slots");

        let external_data = ExternalData::new(
            *transaction_viewing_key.pubkey().as_bytes(),
            encoded.salt,
            encoded.outputs,
            encoded.resolved_owner_tags,
            vec![marker_message],
        );
        let spp_proof_inputs = SppProofInputs::new(
            input_utxos,
            encoded.output_utxos,
            external_data,
            Address::default(),
        );

        assert_eq!(spp_proof_inputs.shape().expect("shape"), Shape::IN2_OUT2);
        assert_eq!(spp_proof_inputs.output_utxos.len(), 2);

        let change = spp_proof_inputs
            .output_utxos
            .first()
            .expect("change output");
        assert!(!change.is_dummy());
        assert_eq!(change.amount, input_amount - escrow_amount);
        let escrow_out = spp_proof_inputs.output_utxos.get(1).expect("escrow output");
        assert!(!escrow_out.is_dummy());

        let change_hash = change.hash().expect("change hash");
        let output_hashes: Vec<[u8; 32]> = spp_proof_inputs
            .external_data
            .outputs
            .iter()
            .map(|output| output.utxo_hash)
            .collect();
        assert_eq!(output_hashes, vec![change_hash, escrow_utxo_hash]);

        let marker = spp_proof_inputs
            .external_data
            .messages
            .first()
            .expect("marker message");
        assert_eq!(spp_proof_inputs.external_data.messages.len(), 1);
        assert_eq!(marker.data, expected_marker_bytes);

        assert_eq!(spp_proof_inputs.input_utxos.len(), 2);
        let spend = spp_proof_inputs.input_utxos.first().expect("input");
        assert!(!spend.is_dummy());
        assert!(spp_proof_inputs
            .input_utxos
            .get(1)
            .expect("dummy input")
            .is_dummy());
        let source_input_hash = spend.hash().expect("source input hash");

        let external_data_hash = spp_proof_inputs
            .external_data
            .hash()
            .expect("external data hash");
        let expected = PrivateTxHash::new(
            &[source_input_hash, [0u8; 32]],
            &[change_hash, escrow_utxo_hash],
            &external_data_hash,
        )
        .hash()
        .expect("private tx hash");
        assert_eq!(
            zolana_keypair::hash::sha256(&expected),
            spp_proof_inputs.message_hash().expect("message hash")
        );
        assert_eq!(spp_proof_inputs.p256_signature, None);
    }

    #[test]
    fn sign_escrow_create_zero_change_note() {
        let owner_keypair = ShieldedKeypair::from_seed_ed25519(&[3u8; 32]).expect("owner keypair");
        let order_keypair = ShieldedKeypair::from_seed_ed25519(&[4u8; 32]).expect("order keypair");
        let taker_keypair =
            ShieldedKeypair::from_seed_ed25519(&[14u8; 32]).expect("market maker keypair");
        let assets = AssetRegistry::default();

        let amount = 250_000u64;
        let input_utxo = Utxo {
            owner: owner_keypair.signing_pubkey(),
            asset: SOL_MINT,
            amount,
            blinding: [6u8; BLINDING_LEN],
            zone_program_id: None,
            data: Data::default(),
        };
        let spend = SppProofInputUtxo::new(input_utxo, &owner_keypair);

        let escrow = OutputUtxo {
            owner_address: Some(order_keypair.shielded_address().expect("order address")),
            asset: SOL_MINT,
            amount,
            blinding: [12u8; BLINDING_LEN],
            ..Default::default()
        }
        .with_utxo_data(vec![9, 9], data_hash_fe(0xCD));

        let taker_address = taker_keypair
            .shielded_address()
            .expect("market maker address");
        let owner_address = owner_keypair.shielded_address().expect("owner address");

        let escrow_utxo_hash = escrow.hash().expect("escrow hash");
        let change = OutputUtxo::new(SOL_MINT, 0, owner_address).expect("change output");
        let marker_message = OrderMarker {
            escrow_utxo_hash,
            maker_pubkey: Pubkey::default(),
            taker_address,
        }
        .message()
        .expect("marker message");
        let input_utxos = vec![spend, SppProofInputUtxo::new_dummy()];
        let transaction_viewing_key = get_transaction_viewing_key(&owner_keypair, &input_utxos)
            .expect("transaction viewing key");

        let encoded =
            encrypt_transaction_data(&[change, escrow], &assets, &transaction_viewing_key)
                .expect("encode slots");

        let external_data = ExternalData::new(
            *transaction_viewing_key.pubkey().as_bytes(),
            encoded.salt,
            encoded.outputs,
            encoded.resolved_owner_tags,
            vec![marker_message],
        );
        let spp_proof_inputs = SppProofInputs::new(
            input_utxos,
            encoded.output_utxos,
            external_data,
            Address::default(),
        );

        let change = spp_proof_inputs
            .output_utxos
            .first()
            .expect("change output");
        assert!(!change.is_dummy());
        assert_eq!(change.amount, 0);

        let escrow_out = spp_proof_inputs.output_utxos.get(1).expect("escrow output");
        let external_data_hash = spp_proof_inputs
            .external_data
            .hash()
            .expect("external data hash");
        let spend = spp_proof_inputs.input_utxos.first().expect("input");
        let source_input_hash = spend.hash().expect("source input hash");
        let expected = PrivateTxHash::new(
            &[source_input_hash, [0u8; 32]],
            &[
                change.hash().expect("change hash"),
                escrow_out.hash().expect("escrow hash"),
            ],
            &external_data_hash,
        )
        .hash()
        .expect("private tx hash");
        let message_hash = spp_proof_inputs.message_hash().expect("message hash");
        assert_eq!(zolana_keypair::hash::sha256(&expected), message_hash);
    }
}
