use anyhow::Result;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use zolana_interface::{
    instruction::instruction_data::transact::{MessageData, TransactIxData},
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::ShieldedAddress;
use zolana_transaction::TransactionError;

use crate::{err, tag, MakeIxData, MakeProof, MarkerData};

pub struct OrderMarker {
    pub order_utxo_hash: [u8; 32],
    pub maker_pubkey: Pubkey,
    pub taker_address: ShieldedAddress,
}

impl OrderMarker {
    pub fn message(self) -> Result<MessageData, TransactionError> {
        Ok(MessageData {
            view_tag: self.taker_address.signing_pubkey.confidential_view_tag()?,
            data: borsh::to_vec(&MarkerData {
                order_utxo_hash: self.order_utxo_hash,
                maker_pubkey: self.maker_pubkey.to_bytes(),
            })
            .map_err(|e| TransactionError::Serialize(e.to_string()))?,
        })
    }
}

pub struct Make {
    pub payer: Pubkey,
    pub tree: Pubkey,
    pub make_proof: MakeProof,
    pub spp_proof: TransactIxData,
}

impl Make {
    pub fn instruction(self) -> Result<Instruction> {
        let Self {
            payer,
            tree,
            make_proof,
            mut spp_proof,
        } = self;

        if let Some(marker) = spp_proof.messages.first_mut() {
            marker.data = Vec::new();
        }

        let serialized_ix = wincode::serialize(&MakeIxData {
            proof: make_proof,
            transact: spp_proof,
        })
        .map_err(err)?;

        let accounts = vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(payer, true),
            AccountMeta::new(tree, false),
            AccountMeta::new_readonly(Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID), false),
        ];
        let mut instruction_data = vec![tag::MAKE];
        instruction_data.extend_from_slice(&serialized_ix);
        Ok(Instruction {
            program_id: swap_program::ID,
            accounts,
            data: instruction_data,
        })
    }
}

#[cfg(test)]
mod tests {
    use solana_address::Address;
    use solana_keypair::Keypair;
    use zolana_keypair::{constants::BLINDING_LEN, shielded::ShieldedKeypair};
    use zolana_transaction::{
        instructions::{
            transact::{
                encrypt_transaction_data, get_transaction_viewing_key, ExternalData, PrivateTxHash,
                Shape, SppProofInputs, SppProofOutputUtxo,
            },
            types::SppProofInputUtxo,
        },
        utxo::Utxo,
        AssetRegistry, Data, SOL_MINT,
    };

    use super::*;

    fn data_hash_bytes(byte: u8) -> [u8; 32] {
        let mut out = [byte; 32];
        out[0] = 0;
        out
    }

    #[test]
    fn sign_order_utxo_make_layout() {
        let owner_keypair =
            ShieldedKeypair::from_solana_keypair(&Keypair::new_from_array([7u8; 32]))
                .expect("owner keypair");
        let order_keypair =
            ShieldedKeypair::from_solana_keypair(&Keypair::new_from_array([9u8; 32]))
                .expect("order keypair");
        let taker_keypair =
            ShieldedKeypair::from_solana_keypair(&Keypair::new_from_array([13u8; 32]))
                .expect("market maker keypair");
        let assets = AssetRegistry::default();

        let input_amount = 1_000_000u64;
        let order_utxo_amount = 400_000u64;

        let input_utxo = Utxo {
            owner: owner_keypair.signing_pubkey(),
            asset: SOL_MINT,
            amount: input_amount,
            blinding: [5u8; BLINDING_LEN],
            zone_program_id: None,
            data: Data::default(),
        };
        let spend = SppProofInputUtxo::new(input_utxo, &owner_keypair);

        let order_utxo = SppProofOutputUtxo {
            owner_address: Some(order_keypair.shielded_address().expect("order address")),
            asset: SOL_MINT,
            amount: order_utxo_amount,
            blinding: [11u8; BLINDING_LEN],
            ..Default::default()
        }
        .with_utxo_data(vec![1, 2, 3, 4], data_hash_bytes(0xAB));

        let taker_address = taker_keypair
            .shielded_address()
            .expect("market maker address");
        let owner_address = owner_keypair.shielded_address().expect("owner address");

        let order_utxo_hash = order_utxo.hash().expect("order hash");
        let change_amount = input_amount - order_utxo_amount;
        let change =
            SppProofOutputUtxo::new(SOL_MINT, change_amount, owner_address).expect("change output");
        let marker_message = OrderMarker {
            order_utxo_hash,
            maker_pubkey: Pubkey::default(),
            taker_address,
        }
        .message()
        .expect("marker message");
        let expected_marker_bytes = borsh::to_vec(&MarkerData {
            order_utxo_hash,
            maker_pubkey: Pubkey::default().to_bytes(),
        })
        .expect("marker bytes");
        let input_utxos = vec![spend, SppProofInputUtxo::new_dummy()];
        let transaction_viewing_key = get_transaction_viewing_key(&owner_keypair, &input_utxos)
            .expect("transaction viewing key");

        let encoded =
            encrypt_transaction_data(&[change, order_utxo], &assets, &transaction_viewing_key)
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

        assert_eq!(
            spp_proof_inputs.check_shape().expect("shape"),
            Shape::IN2_OUT2
        );
        assert_eq!(spp_proof_inputs.output_utxos.len(), 2);

        let change = spp_proof_inputs
            .output_utxos
            .first()
            .expect("change output");
        assert!(!change.is_dummy());
        assert_eq!(change.amount, input_amount - order_utxo_amount);
        let order_output_utxo = spp_proof_inputs.output_utxos.get(1).expect("order output");
        assert!(!order_output_utxo.is_dummy());

        let change_hash = change.hash().expect("change hash");
        let output_hashes: Vec<[u8; 32]> = spp_proof_inputs
            .external_data
            .outputs
            .iter()
            .map(|output| output.utxo_hash)
            .collect();
        assert_eq!(output_hashes, vec![change_hash, order_utxo_hash]);

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
            &[change_hash, order_utxo_hash],
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
    fn sign_order_utxo_make_zero_change_utxo() {
        let owner_keypair =
            ShieldedKeypair::from_solana_keypair(&Keypair::new_from_array([3u8; 32]))
                .expect("owner keypair");
        let order_keypair =
            ShieldedKeypair::from_solana_keypair(&Keypair::new_from_array([4u8; 32]))
                .expect("order keypair");
        let taker_keypair =
            ShieldedKeypair::from_solana_keypair(&Keypair::new_from_array([14u8; 32]))
                .expect("market maker keypair");
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

        let order_utxo = SppProofOutputUtxo {
            owner_address: Some(order_keypair.shielded_address().expect("order address")),
            asset: SOL_MINT,
            amount,
            blinding: [12u8; BLINDING_LEN],
            ..Default::default()
        }
        .with_utxo_data(vec![9, 9], data_hash_bytes(0xCD));

        let taker_address = taker_keypair
            .shielded_address()
            .expect("market maker address");
        let owner_address = owner_keypair.shielded_address().expect("owner address");

        let order_utxo_hash = order_utxo.hash().expect("order hash");
        let change = SppProofOutputUtxo::new(SOL_MINT, 0, owner_address).expect("change output");
        let marker_message = OrderMarker {
            order_utxo_hash,
            maker_pubkey: Pubkey::default(),
            taker_address,
        }
        .message()
        .expect("marker message");
        let input_utxos = vec![spend, SppProofInputUtxo::new_dummy()];
        let transaction_viewing_key = get_transaction_viewing_key(&owner_keypair, &input_utxos)
            .expect("transaction viewing key");

        let encoded =
            encrypt_transaction_data(&[change, order_utxo], &assets, &transaction_viewing_key)
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

        let order_output_utxo = spp_proof_inputs.output_utxos.get(1).expect("order output");
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
                order_output_utxo.hash().expect("order hash"),
            ],
            &external_data_hash,
        )
        .hash()
        .expect("private tx hash");
        let message_hash = spp_proof_inputs.message_hash().expect("message hash");
        assert_eq!(zolana_keypair::hash::sha256(&expected), message_hash);
    }
}
