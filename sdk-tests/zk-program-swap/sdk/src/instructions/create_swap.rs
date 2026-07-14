use anyhow::Result;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use swap_prover::CreateProofInputs;
use zolana_interface::instruction::instruction_data::transact::{OutputData, TransactIxData};
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{
    instructions::{
        transact::{OutputUtxo, PrebuiltSlot},
        types::SppProofInputUtxo,
    },
    utxo::Blinding,
    TransactionError,
};

use crate::{
    err, escrow_authority_pda,
    order::{BlindingField, DataHash, OrderUtxo},
    program_id_pubkey, spp_program_meta, tag, CreateProof, MarkerData,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateSwapIxData {
    pub proof: CreateProof,
    pub transact: TransactIxData,
}
// TODO: check why we need manual serialization at all.
impl CreateSwapIxData {
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = borsh::to_vec(&self.proof).expect("CreateProof serialization is infallible");
        data.extend_from_slice(
            &self
                .transact
                .serialize()
                .expect("transact serialization is infallible"),
        );
        data
    }
}

pub struct CreateSwapProofInputParams {
    pub escrow: OrderUtxo,
    pub taker_address: ShieldedAddress,
    pub source_input_hash: [u8; 32],
    pub change_amount: u64,
    pub change_blinding: Blinding,
    pub external_data_hash: [u8; 32],
}

impl CreateSwapProofInputParams {
    pub fn into_proof_inputs(&self) -> Result<CreateProofInputs> {
        let terms = &self.escrow.terms;
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
            external_data_hash: self.external_data_hash,
            source_input_hash: self.source_input_hash,
            change_amount: self.change_amount,
            change_blinding: self.change_blinding.to_field(),
            marker_owner_hash: self.taker_address.owner_hash().map_err(err)?,
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

pub struct MarkerEncrypt {
    pub marker: OutputUtxo,
    pub escrow_utxo_hash: [u8; 32],
    pub payer: Pubkey,
}

impl MarkerEncrypt {
    pub fn encrypt(self) -> Result<PrebuiltSlot, TransactionError> {
        let marker_address = self
            .marker
            .owner_address
            .ok_or(TransactionError::MissingOutput)?;
        Ok(PrebuiltSlot {
            ciphertext: OutputData {
                view_tag: marker_address.signing_pubkey.confidential_view_tag()?,
                data: borsh::to_vec(&MarkerData {
                    escrow_utxo_hash: self.escrow_utxo_hash,
                    maker_pubkey: self.payer.to_bytes(),
                })
                .expect("MarkerData serialization is infallible"),
            },
            output: self.marker,
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

        if let Some(marker) = spp_proof.outputs.last_mut() {
            marker.data = None;
        }

        let data = CreateSwapIxData {
            proof: create_swap_proof,
            transact: spp_proof,
        }
        .serialize();

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
            transact::{no_address_hashes, private_tx_hash, ConfidentialSlot, Shape, SlotTransact},
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
        let spend = SppProofInputUtxo::new(input_utxo, &owner_keypair.nullifier_key);

        let escrow = OutputUtxo {
            owner_address: Some(order_keypair.shielded_address().expect("order address")),
            asset: SOL_MINT,
            amount: escrow_amount,
            blinding: [11u8; BLINDING_LEN],
            ..Default::default()
        }
        .with_utxo_data(vec![1, 2, 3, 4], data_hash_fe(0xAB));

        let marker = OutputUtxo {
            owner_address: Some(
                taker_keypair
                    .shielded_address()
                    .expect("market maker address"),
            ),
            asset: SOL_MINT,
            amount: 0,
            blinding: [17u8; BLINDING_LEN],
            ..Default::default()
        };

        let owner_address = owner_keypair.shielded_address().expect("owner address");

        let escrow_utxo_hash = escrow.hash().expect("escrow hash");
        let marker_hash = marker.hash().expect("marker hash");
        let change_amount = input_amount - escrow_amount;
        let change_slot = ConfidentialSlot::new(
            OutputUtxo {
                owner_address: Some(owner_address),
                asset: SOL_MINT,
                amount: change_amount,
                blinding: [21u8; BLINDING_LEN],
                ..Default::default()
            },
            &assets,
        )
        .expect("change slot");
        let escrow_slot = ConfidentialSlot::new(escrow, &assets).expect("escrow slot");
        let marker_slot = MarkerEncrypt {
            marker,
            escrow_utxo_hash,
            payer: Pubkey::default(),
        }
        .encrypt()
        .expect("marker slot");
        let input_utxos = vec![spend, SppProofInputUtxo::new_dummy()];
        let spp_proof_inputs = SlotTransact {
            input_utxos,
            payer: Address::default(),
            expiry_unix_ts: u64::MAX,
        }
        .sign(&[&change_slot, &escrow_slot, &marker_slot], &owner_keypair)
        .expect("escrow create");

        assert_eq!(spp_proof_inputs.shape, Shape::new(2, 3));
        assert_eq!(spp_proof_inputs.output_utxos.len(), 3);

        let change = spp_proof_inputs
            .output_utxos
            .first()
            .expect("change output");
        assert!(!change.is_dummy());
        assert_eq!(change.amount, input_amount - escrow_amount);
        let escrow_out = spp_proof_inputs.output_utxos.get(1).expect("escrow output");
        assert!(!escrow_out.is_dummy());
        let marker_out = spp_proof_inputs.output_utxos.get(2).expect("marker output");
        assert!(!marker_out.is_dummy());
        assert_eq!(marker_out.amount, 0);

        let change_hash = change.hash().expect("change hash");
        let output_hashes: Vec<[u8; 32]> = spp_proof_inputs
            .external_data
            .outputs
            .iter()
            .map(|output| output.utxo_hash)
            .collect();
        assert_eq!(
            output_hashes,
            vec![change_hash, escrow_utxo_hash, marker_hash]
        );

        assert_eq!(spp_proof_inputs.input_utxos.len(), 2);
        let spend = spp_proof_inputs.input_utxos.first().expect("input");
        assert!(!spend.is_dummy());
        assert!(spp_proof_inputs
            .input_utxos
            .get(1)
            .expect("dummy input")
            .is_dummy());
        let nullifier_pubkey = spend.nullifier_key.pubkey().expect("nullifier pubkey");
        let source_input_hash = spend
            .utxo
            .hash(
                &nullifier_pubkey,
                &spend.data_hash.unwrap_or([0u8; 32]),
                &spend.zone_data_hash.unwrap_or([0u8; 32]),
            )
            .expect("source input hash");

        let external_data_hash = spp_proof_inputs
            .external_data
            .hash()
            .expect("external data hash");
        let expected = private_tx_hash(
            &[source_input_hash, [0u8; 32]],
            &[change_hash, escrow_utxo_hash, marker_hash],
            &no_address_hashes(2),
            &external_data_hash,
        )
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
        let spend = SppProofInputUtxo::new(input_utxo, &owner_keypair.nullifier_key);

        let escrow = OutputUtxo {
            owner_address: Some(order_keypair.shielded_address().expect("order address")),
            asset: SOL_MINT,
            amount,
            blinding: [12u8; BLINDING_LEN],
            ..Default::default()
        }
        .with_utxo_data(vec![9, 9], data_hash_fe(0xCD));

        let marker = OutputUtxo {
            owner_address: Some(
                taker_keypair
                    .shielded_address()
                    .expect("market maker address"),
            ),
            asset: SOL_MINT,
            amount: 0,
            blinding: [18u8; BLINDING_LEN],
            ..Default::default()
        };

        let owner_address = owner_keypair.shielded_address().expect("owner address");

        let escrow_utxo_hash = escrow.hash().expect("escrow hash");
        let change_slot = ConfidentialSlot::new(
            OutputUtxo {
                owner_address: Some(owner_address),
                asset: SOL_MINT,
                amount: 0,
                blinding: [22u8; BLINDING_LEN],
                ..Default::default()
            },
            &assets,
        )
        .expect("change slot");
        let escrow_slot = ConfidentialSlot::new(escrow, &assets).expect("escrow slot");
        let marker_slot = MarkerEncrypt {
            marker,
            escrow_utxo_hash,
            payer: Pubkey::default(),
        }
        .encrypt()
        .expect("marker slot");
        let input_utxos = vec![spend, SppProofInputUtxo::new_dummy()];
        let spp_proof_inputs = SlotTransact {
            input_utxos,
            payer: Address::default(),
            expiry_unix_ts: u64::MAX,
        }
        .sign(&[&change_slot, &escrow_slot, &marker_slot], &owner_keypair)
        .expect("escrow create");

        let change = spp_proof_inputs
            .output_utxos
            .first()
            .expect("change output");
        assert!(!change.is_dummy());
        assert_eq!(change.amount, 0);

        let escrow_out = spp_proof_inputs.output_utxos.get(1).expect("escrow output");
        let marker_out = spp_proof_inputs.output_utxos.get(2).expect("marker output");
        let external_data_hash = spp_proof_inputs
            .external_data
            .hash()
            .expect("external data hash");
        let spend = spp_proof_inputs.input_utxos.first().expect("input");
        let nullifier_pubkey = spend.nullifier_key.pubkey().expect("nullifier pubkey");
        let source_input_hash = spend
            .utxo
            .hash(&nullifier_pubkey, &[0u8; 32], &[0u8; 32])
            .expect("source input hash");
        let expected = private_tx_hash(
            &[source_input_hash, [0u8; 32]],
            &[
                change.hash().expect("change hash"),
                escrow_out.hash().expect("escrow hash"),
                marker_out.hash().expect("marker hash"),
            ],
            &no_address_hashes(2),
            &external_data_hash,
        )
        .expect("private tx hash");
        let message_hash = spp_proof_inputs.message_hash().expect("message hash");
        assert_eq!(zolana_keypair::hash::sha256(&expected), message_hash);
    }
}
