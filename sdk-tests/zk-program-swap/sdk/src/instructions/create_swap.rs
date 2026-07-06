use anyhow::Result;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use swap_prover::CreateProofInputs;
use zolana_client::{ProverClient, SpendProof};
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
    utxo::Blinding,
    AssetRegistry, Data, TransactionError, SOL_MINT,
};

use crate::{
    check_private_tx_hash, err, escrow_authority_pda, lifecycle_instruction,
    order::{marker_output, sdk_private_tx_hash, BlindingField, Escrow, OrderTerms},
    prover::{create_proof_ix, prove_transact},
    spp_program_meta, tag, CreateProof, MarkerData,
};

/// Wire layout for an order-lifecycle instruction's body: a Borsh proof-struct
/// prefix (no enum tag byte), then the create-only `source_asset_id`, then the
/// wincode-encoded `transact` bytes to the end. The two encodings are
/// concatenated rather than nested because `TransactIxData` is wincode (not
/// Borsh); keeping the `transact` bytes contiguous lets the program forward
/// them to the SPP CPI verbatim without a re-serialization round trip.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateSwapIxData {
    pub proof: CreateProof,
    pub source_asset_id: u64,
    pub maker_address: [u8; 65],
    pub transact: TransactIxData,
}

impl CreateSwapIxData {
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = borsh::to_vec(&self.proof).expect("CreateProof serialization is infallible");
        data.extend_from_slice(
            &borsh::to_vec(&self.source_asset_id).expect("u64 serialization is infallible"),
        );
        data.extend_from_slice(
            &borsh::to_vec(&self.maker_address).expect("maker address serialization is infallible"),
        );
        data.extend_from_slice(
            &self
                .transact
                .serialize()
                .expect("transact serialization is infallible"),
        );
        data
    }
}

pub fn create_swap(
    payer: Pubkey,
    spp_accounts: Vec<AccountMeta>,
    proof: CreateProof,
    source_asset_id: u64,
    maker_address: [u8; 65],
    mut transact: TransactIxData,
) -> Instruction {
    // The marker payload `{ maker_address, escrow_utxo_hash }` is reconstructable by the
    // create program (maker_address from instruction data, escrow_utxo_hash from
    // `output_utxo_hashes[1]`), so the client clears it before sending and the program
    // refills it before the SPP CPI. The proofs were already committed over the filled payload.
    if let Some(marker) = transact.output_ciphertexts.last_mut() {
        marker.data = Vec::new();
    }
    let data = CreateSwapIxData {
        proof,
        source_asset_id,
        maker_address,
        transact,
    }
    .serialize();
    lifecycle_instruction(tag::CREATE_SWAP, payer, spp_accounts, data)
}

pub struct CreateSharedInputs {
    pub terms: OrderTerms,
    pub escrow_blinding: Blinding,
    pub taker_address: ShieldedAddress,
    pub source_input_hash: [u8; 32],
    pub change_amount: u64,
    pub change_blinding: [u8; 32],
    pub external_data_hash: [u8; 32],
}

impl CreateSharedInputs {
    pub fn create_proof_inputs(&self, source_mint: Address) -> Result<CreateProofInputs> {
        Ok(CreateProofInputs {
            source_asset_id: self.terms.source_asset_id,
            source_mint: *source_mint.as_array(),
            source_amount: self.terms.source_amount,
            escrow_authority: *escrow_authority_pda().as_array(),
            escrow_blinding: self.escrow_blinding.to_field(),
            destination_mint: *self.terms.destination_mint.as_array(),
            destination_amount: self.terms.destination_amount,
            maker_owner_hash: self.terms.maker_owner_hash,
            maker_viewing_pk: self.terms.maker_viewing_pk,
            expiry: self.terms.expiry,
            taker_pk_fe: self.terms.taker_pk_fe,
            fill_mode: self.terms.fill_mode,
            external_data_hash: self.external_data_hash,
            source_input_hash: self.source_input_hash,
            change_amount: self.change_amount,
            change_blinding: self.change_blinding,
            marker_output_hash: self.marker_output_hash()?,
        })
    }

    pub fn change_output_hash(&self, source_mint: Address) -> Result<[u8; 32]> {
        self.create_proof_inputs(source_mint)?
            .change_output_hash()
            .map_err(err)
    }

    pub fn escrow_output(&self, source_mint: Address) -> Result<OutputUtxo> {
        Escrow {
            terms: self.terms.clone(),
            blinding: self.escrow_blinding,
            source_mint,
        }
        .output(self.taker_address.viewing_pubkey)
    }

    pub fn marker_output(&self) -> OutputUtxo {
        marker_output(self.taker_address)
    }

    pub fn marker_output_hash(&self) -> Result<[u8; 32]> {
        self.marker_output().hash().map_err(err)
    }

    pub fn sdk_private_tx_hash(&self, source_mint: Address) -> Result<[u8; 32]> {
        let escrow_hash = self.escrow_output(source_mint)?.hash().map_err(err)?;
        let marker_hash = self.marker_output_hash()?;
        let change_hash = self.change_output_hash(source_mint)?;
        // Padded 2x3 chains: one dummy input contributes 0; outputs are
        // [change, escrow, marker]; addresses are two zeros.
        sdk_private_tx_hash(
            &[self.source_input_hash, [0u8; 32]],
            &[change_hash, escrow_hash, marker_hash],
            &self.external_data_hash,
        )
    }
}

const SOL_CHANGE_POSITION: u8 = 1;

pub struct EscrowCreate {
    pub tx: Transaction,
    pub escrow: OutputUtxo,
    pub marker: OutputUtxo,
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
        if escrow.asset != SOL_MINT {
            return Err(TransactionError::UnsupportedShape { n_in: 2, n_out: 3 });
        }

        let sol_leftover = input_sum(&tx, &SOL_MINT)
            .checked_sub(i128::from(escrow.amount))
            .ok_or(TransactionError::SelectedBalanceOverflow)?;
        if sol_leftover < 0 {
            return Err(TransactionError::InsufficientBalance {
                requested: (-sol_leftover) as u64,
                available: 0,
            });
        }
        let sol_change = sol_leftover as u64;

        let change = if sol_change > 0 {
            OutputUtxo {
                owner_address: Some(tx.owner),
                asset: SOL_MINT,
                amount: sol_change,
                blinding: derive_blinding(&tx.blinding_seed, SOL_CHANGE_POSITION),
                ..Default::default()
            }
        } else {
            OutputUtxo {
                blinding: derive_blinding(&tx.blinding_seed, SOL_CHANGE_POSITION),
                owner_tag: Some(tx.owner.signing_pubkey.confidential_view_tag()?),
                ..Default::default()
            }
        };

        let sender_slot = SenderSlot {
            plaintext: TransferSenderPlaintext {
                owner_pubkey: tx.owner.signing_pubkey,
                spl_asset_id: 0,
                spl_amount: 0,
                sol_amount: sol_change,
                blinding_seed: tx.blinding_seed,
                recipient_viewing_pks: vec![escrow_address.viewing_pubkey],
                spl_data: Data::default(),
                sol_data: Data::default(),
            },
            output: change,
        };
        let mut maker_compressed_address = [0u8; 65];
        maker_compressed_address[0..32].copy_from_slice(&tx.owner.owner_hash()?);
        maker_compressed_address[32..65].copy_from_slice(tx.owner.viewing_pubkey.as_bytes());
        let escrow_hash = escrow.hash()?;
        let escrow_slot = RecipientSlot::new(escrow, assets)?;

        let marker_slot = OutputCiphertextSlot {
            output: marker,
            ciphertext: OutputCiphertext {
                view_tag: marker_address.signing_pubkey.confidential_view_tag()?,
                data: borsh::to_vec(&MarkerData {
                    maker_address: maker_compressed_address,
                    escrow_utxo_hash: escrow_hash,
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
    pub inputs: CreateSharedInputs,
    pub signed: SignedTransaction,
    pub source_mint: Address,
    pub payer: Pubkey,
    pub tree: Pubkey,
}

impl CreateSwap {
    pub fn instruction(
        self,
        spend_proofs: &[SpendProof],
        prover: &ProverClient,
    ) -> Result<Instruction> {
        let Self {
            inputs,
            signed,
            source_mint,
            payer,
            tree,
        } = self;
        let expected = inputs.sdk_private_tx_hash(source_mint)?;
        let transact = prove_transact(signed, spend_proofs, prover)?;
        check_private_tx_hash("transact", transact.private_tx_hash, expected)?;
        let create_result = inputs
            .create_proof_inputs(source_mint)?
            .prove()
            .map_err(err)?;
        check_private_tx_hash("create proof", create_result.private_tx_hash, expected)?;
        let spp_accounts = vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(tree, false),
            spp_program_meta(),
        ];
        let mut maker_address = [0u8; 65];
        maker_address[0..32].copy_from_slice(&inputs.terms.maker_owner_hash);
        maker_address[32..65].copy_from_slice(&inputs.terms.maker_viewing_pk);
        Ok(create_swap(
            payer,
            spp_accounts,
            create_proof_ix(&create_result.proof),
            inputs.terms.source_asset_id,
            maker_address,
            transact,
        ))
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

        let escrow_hash = escrow.hash().expect("escrow hash");
        let marker_hash = marker.hash().expect("marker hash");
        let signed = EscrowCreate { tx, escrow, marker }
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
            vec![change_hash, escrow_hash, marker_hash]
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
            &[change_hash, escrow_hash, marker_hash],
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

        let signed = EscrowCreate { tx, escrow, marker }
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
