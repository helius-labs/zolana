use anyhow::Result;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use swap_prover::CreateProofInputs;
use zolana_interface::instruction::instruction_data::transact::{OutputCiphertext, TransactIxData};
use zolana_keypair::{ShieldedAddress, ShieldedKeypairTrait, ViewingKeyTrait};
use zolana_transaction::{
    derive_blinding,
    instructions::{
        transact::{
            OutputCiphertextSlot, OutputUtxo, RecipientSlot, SenderSlot, SignedTransaction,
            Transaction,
        },
        types::SpendUtxo,
    },
    serialization::confidential::TransferSenderPlaintext,
    AssetRegistry, Data, TransactionError, SOL_MINT,
};

use crate::{
    err, escrow_authority_pda,
    order::{BlindingField, DataHash, Escrow},
    program_id_pubkey, spp_program_meta, tag, CreateProof, MarkerData,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateSwapIxData {
    pub proof: CreateProof,
    pub transact: TransactIxData,
}

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
    pub escrow: Escrow,
    pub taker_address: ShieldedAddress,
    pub source_input_hash: [u8; 32],
    pub change_output_utxo: OutputUtxo,
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
            change_amount: self.change_output_utxo.amount,
            change_blinding: self.change_output_utxo.blinding.to_field(),
            marker_owner_hash: self.taker_address.owner_hash().map_err(err)?,
        })
    }
}

const CHANGE_POSITION: u8 = 1;

pub struct EscrowCreate {
    pub tx: Transaction,
    pub escrow: OutputUtxo,
    pub marker: OutputUtxo,
    /// The maker's 32-byte owner pubkey (the create tx fee payer / user-registry
    /// key). Written into the marker so the taker can look the maker up; the
    /// on-chain program reconstructs the same value from the payer signer.
    pub payer: Pubkey,
}

impl EscrowCreate {
    pub fn sign<K: ShieldedKeypairTrait + ViewingKeyTrait>(
        self,
        keypair: &K,
        assets: &AssetRegistry,
    ) -> Result<SignedTransaction, TransactionError> {
        let Self {
            mut tx,
            escrow,
            marker,
            payer,
        } = self;
        if tx.inputs.len() != 1 {
            return Err(TransactionError::TooManyInputs {
                got: tx.inputs.len(),
                max: 1,
            });
        }
        let escrow_address = escrow
            .owner_address
            .ok_or(TransactionError::MissingOutput)?;
        let marker_address = marker
            .owner_address
            .ok_or(TransactionError::MissingOutput)?;
        // Change is denominated in the escrow (source) asset: the single real input
        // spends `source_amount` into the escrow and returns the remainder to the
        // maker. SOL rides `sol_amount`; any other asset rides `spl_amount` with its
        // registered `spl_asset_id`.
        let escrow_asset = escrow.asset;
        let leftover = input_sum(&tx, &escrow_asset)
            .checked_sub(i128::from(escrow.amount))
            .ok_or(TransactionError::SelectedBalanceOverflow)?;
        if leftover < 0 {
            return Err(TransactionError::InsufficientBalance {
                requested: (-leftover) as u64,
                available: 0,
            });
        }
        let change_amount = leftover as u64;
        let (sol_change, spl_change, spl_asset_id) = if escrow_asset == SOL_MINT {
            (change_amount, 0, 0)
        } else {
            (0, change_amount, assets.asset_id(&escrow_asset)?)
        };

        let change = if change_amount > 0 {
            OutputUtxo {
                owner_address: Some(tx.owner),
                asset: escrow_asset,
                amount: change_amount,
                blinding: derive_blinding(&tx.blinding_seed, CHANGE_POSITION),
                ..Default::default()
            }
        } else {
            OutputUtxo {
                blinding: derive_blinding(&tx.blinding_seed, CHANGE_POSITION),
                owner_tag: Some(tx.owner.signing_pubkey.confidential_view_tag()?),
                ..Default::default()
            }
        };

        let sender_slot = SenderSlot {
            plaintext: TransferSenderPlaintext {
                owner_pubkey: tx.owner.signing_pubkey,
                spl_asset_id,
                spl_amount: spl_change,
                sol_amount: sol_change,
                blinding_seed: tx.blinding_seed,
                recipient_viewing_pks: vec![escrow_address.viewing_pubkey],
                spl_data: Data::default(),
                sol_data: Data::default(),
            },
            output: change,
        };
        let escrow_utxo_hash = escrow.hash()?;
        let escrow_slot = RecipientSlot::new(escrow, assets)?;

        let marker_slot = OutputCiphertextSlot {
            output: marker,
            ciphertext: OutputCiphertext {
                view_tag: marker_address.signing_pubkey.confidential_view_tag()?,
                data: borsh::to_vec(&MarkerData {
                    escrow_utxo_hash,
                    maker_pubkey: payer.to_bytes(),
                })
                .expect("MarkerData serialization is infallible"),
            },
        };

        // Pad to the 2x3 shape: 1 real input + 1 dummy, outputs [change, escrow, marker].
        tx.inputs.push(SpendUtxo::new_dummy());
        tx.sign_with_slots(&[&sender_slot, &escrow_slot, &marker_slot], keypair)
    }
}

fn input_sum(tx: &Transaction, asset: &Address) -> i128 {
    tx.inputs
        .iter()
        .filter(|spend| &spend.utxo.asset == asset)
        .map(|spend| i128::from(spend.utxo.amount))
        .sum()
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

        if let Some(marker) = spp_proof.output_ciphertexts.last_mut() {
            marker.data = Vec::new();
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
            transact::{no_address_hashes, private_tx_hash, Shape},
            types::SpendUtxo,
        },
        utxo::Utxo,
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
        let spend = SpendUtxo::from_keypair(input_utxo, &owner_keypair);

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

        let tx = Transaction::new(
            owner_keypair.shielded_address().expect("owner address"),
            vec![spend],
            Address::default(),
        );

        let escrow_utxo_hash = escrow.hash().expect("escrow hash");
        let marker_hash = marker.hash().expect("marker hash");
        let signed = EscrowCreate {
            tx,
            escrow,
            marker,
            payer: Pubkey::default(),
        }
        .sign(&owner_keypair, &assets)
        .expect("escrow create");

        assert_eq!(signed.shape, Shape::new(2, 3));
        assert_eq!(signed.outputs.len(), 3);

        let change = signed.outputs.first().expect("change output");
        assert!(!change.is_dummy());
        assert_eq!(change.amount, input_amount - escrow_amount);
        let escrow_out = signed.outputs.get(1).expect("escrow output");
        assert!(!escrow_out.is_dummy());
        let marker_out = signed.outputs.get(2).expect("marker output");
        assert!(!marker_out.is_dummy());
        assert_eq!(marker_out.amount, 0);

        let change_hash = change.hash().expect("change hash");
        assert_eq!(
            signed.external_data.output_utxo_hashes,
            vec![change_hash, escrow_utxo_hash, marker_hash]
        );

        assert_eq!(signed.inputs.len(), 2);
        let spend = signed.inputs.first().expect("input");
        assert!(!spend.is_dummy());
        assert!(signed.inputs.get(1).expect("dummy input").is_dummy());
        let nullifier_pubkey = spend.nullifier_key.pubkey().expect("nullifier pubkey");
        let source_input_hash = spend
            .utxo
            .hash(
                &nullifier_pubkey,
                &spend.data_hash.unwrap_or([0u8; 32]),
                &spend.zone_data_hash.unwrap_or([0u8; 32]),
            )
            .expect("source input hash");

        let external_data_hash = signed.external_data.hash().expect("external data hash");
        let expected = private_tx_hash(
            &[source_input_hash, [0u8; 32]],
            &[change_hash, escrow_utxo_hash, marker_hash],
            &no_address_hashes(2),
            &external_data_hash,
        )
        .expect("private tx hash");
        assert_eq!(
            zolana_keypair::hash::sha256(&expected),
            signed.message_hash().expect("message hash")
        );
        assert_eq!(signed.p256_owner, None);
    }

    #[test]
    fn sign_escrow_create_zero_change_dummy() {
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
        let spend = SpendUtxo::from_keypair(input_utxo, &owner_keypair);

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

        let tx = Transaction::new(
            owner_keypair.shielded_address().expect("owner address"),
            vec![spend],
            Address::default(),
        );

        let signed = EscrowCreate {
            tx,
            escrow,
            marker,
            payer: Pubkey::default(),
        }
        .sign(&owner_keypair, &assets)
        .expect("escrow create");

        let change = signed.outputs.first().expect("change output");
        assert!(change.is_dummy());
        assert_eq!(change.amount, 0);

        let escrow_out = signed.outputs.get(1).expect("escrow output");
        let marker_out = signed.outputs.get(2).expect("marker output");
        let external_data_hash = signed.external_data.hash().expect("external data hash");
        let spend = signed.inputs.first().expect("input");
        let nullifier_pubkey = spend.nullifier_key.pubkey().expect("nullifier pubkey");
        let source_input_hash = spend
            .utxo
            .hash(&nullifier_pubkey, &[0u8; 32], &[0u8; 32])
            .expect("source input hash");
        let expected = private_tx_hash(
            &[source_input_hash, [0u8; 32]],
            &[
                [0u8; 32],
                escrow_out.hash().expect("escrow hash"),
                marker_out.hash().expect("marker hash"),
            ],
            &no_address_hashes(2),
            &external_data_hash,
        )
        .expect("private tx hash");
        let message_hash = signed.message_hash().expect("message hash");
        assert_eq!(zolana_keypair::hash::sha256(&expected), message_hash);
    }
}
