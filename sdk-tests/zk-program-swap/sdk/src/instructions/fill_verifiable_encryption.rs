use anyhow::Result;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use swap_prover::FillVerifiableEncryptionProofInputs;
use zolana_interface::instruction::instruction_data::transact::{OutputCiphertext, TransactIxData};
use zolana_keypair::{P256Pubkey, ShieldedAddress, ShieldedKeypairTrait, ViewingKeyTrait};
use zolana_transaction::{
    instructions::transact::{
        OutputCiphertextSlot, OutputUtxo, SenderSlot, SignedTransaction, Transaction,
    },
    serialization::confidential::TransferSenderPlaintext,
    utxo::Blinding,
    AssetRegistry, Data, TransactionError, SOL_MINT, VIEW_TAG_LEN,
};

use crate::{
    err, escrow_authority_pda,
    order::{BlindingField, DataHash, OrderUtxo, Recipient},
    program_id_pubkey, spp_program_meta, tag, FillVerifiableEncryptionProof,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FillVerifiableEncryptionIxData {
    pub proof: FillVerifiableEncryptionProof,
    pub transact: TransactIxData,
}

impl FillVerifiableEncryptionIxData {
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = borsh::to_vec(&self.proof)
            .expect("FillVerifiableEncryptionProof serialization is infallible");
        data.extend_from_slice(
            &self
                .transact
                .serialize()
                .expect("transact serialization is infallible"),
        );
        data
    }
}

pub struct FillVerifiableEncryptionProofInputParams {
    pub escrow: OrderUtxo,
    pub taker_in_blinding: Blinding,
    pub destination_output_blinding: Blinding,
    pub source_output_blinding: Blinding,
    pub external_data_hash: [u8; 32],
    pub maker_recipient: ShieldedAddress,
    pub taker_recipient: ShieldedAddress,
}

impl FillVerifiableEncryptionProofInputParams {
    pub fn into_proof_inputs(&self) -> Result<FillVerifiableEncryptionProofInputs> {
        let terms = &self.escrow.terms;
        Ok(FillVerifiableEncryptionProofInputs {
            source_mint: *self.escrow.source_mint.as_array(),
            destination_mint: *terms.destination_mint.as_array(),
            source_amount: self.escrow.source_amount,
            escrow_authority: *escrow_authority_pda().as_array(),
            escrow_blinding: self.escrow.blinding.to_field(),
            destination_amount: terms.destination_amount,
            maker_owner_hash: terms.destination.owner_hash().map_err(err)?,
            maker_viewing_pk: *terms.destination.viewing_pubkey.as_bytes(),
            expiry: terms.expiry,
            taker_pk_fe: terms.taker.data_hash()?,
            taker_nullifier_pk: self.taker_recipient.nullifier_pubkey,
            taker_in_blinding: self.taker_in_blinding.to_field(),
            destination_output_blinding: self.destination_output_blinding.to_field(),
            source_output_blinding: self.source_output_blinding.to_field(),
            external_data_hash: self.external_data_hash,
        })
    }

    pub fn destination_output(&self) -> OutputUtxo {
        Recipient {
            address: self.maker_recipient,
            amount: self.escrow.terms.destination_amount,
            blinding: self.destination_output_blinding,
            mint: self.escrow.terms.destination_mint,
        }
        .output()
    }

    pub fn source_output(&self) -> OutputUtxo {
        Recipient {
            address: self.taker_recipient,
            amount: self.escrow.source_amount,
            blinding: self.source_output_blinding,
            mint: self.escrow.source_mint,
        }
        .output()
    }
}

pub struct EscrowFillVerifiableEncryption {
    pub tx: Transaction,
    pub source_output: OutputUtxo,
    pub destination_output: OutputUtxo,
    pub destination_ciphertext: Vec<u8>,
    pub destination_view_tag: [u8; VIEW_TAG_LEN],
    pub destination_recipient_viewing_pk: P256Pubkey,
}

impl EscrowFillVerifiableEncryption {
    pub fn sign<K: ShieldedKeypairTrait + ViewingKeyTrait>(
        self,
        keypair: &K,
        assets: &AssetRegistry,
    ) -> Result<SignedTransaction, TransactionError> {
        let Self {
            tx,
            source_output,
            destination_output,
            destination_ciphertext,
            destination_view_tag,
            destination_recipient_viewing_pk,
        } = self;
        if tx.inputs.len() != 2 {
            return Err(TransactionError::TooManyInputs {
                got: tx.inputs.len(),
                max: 2,
            });
        }

        let source_asset_id = asset_id(assets, &source_output.asset)?;
        let (sol_amount, spl_asset_id, spl_amount) = if source_output.asset == SOL_MINT {
            (source_output.amount, 0, 0)
        } else {
            (0, source_asset_id, source_output.amount)
        };
        let sender_slot = SenderSlot {
            plaintext: TransferSenderPlaintext {
                owner_pubkey: tx.owner.signing_pubkey,
                spl_asset_id,
                spl_amount,
                sol_amount,
                blinding_seed: tx.blinding_seed,
                recipient_viewing_pks: vec![destination_recipient_viewing_pk],
                spl_data: Data::default(),
                sol_data: Data::default(),
            },
            output: source_output,
        };
        let destination_slot = OutputCiphertextSlot {
            output: destination_output,
            ciphertext: OutputCiphertext {
                view_tag: destination_view_tag,
                data: destination_ciphertext,
            },
        };

        tx.sign_with_slots(&[&sender_slot, &destination_slot], keypair)
    }
}

fn asset_id(assets: &AssetRegistry, asset: &Address) -> Result<u64, TransactionError> {
    if asset == &SOL_MINT {
        Ok(zolana_transaction::SOL_ASSET_ID)
    } else {
        Ok(assets.asset_id(asset)?)
    }
}

pub struct FillVerifiableEncryption {
    pub payer: Pubkey,
    pub tree: Pubkey,
    pub fill_proof: FillVerifiableEncryptionProof,
    pub spp_proof: TransactIxData,
}

/// The escrow (input 0) is owned by the escrow-authority PDA appended readonly
/// after `tree`; the swap program signs for it via `invoke_signed`. The taker
/// input is signed by the SPP payer (account index 0). The signer index
/// selects the account whose pubkey the SPP proof's input_owner_pk_hash must
/// match; it is not itself a proof public input, so overriding it post-proof is
/// safe.
const ESCROW_AUTHORITY_SIGNER_INDEX: u8 = 2;

impl FillVerifiableEncryption {
    pub fn instruction(self) -> Result<Instruction> {
        let Self {
            payer,
            tree,
            fill_proof,
            mut spp_proof,
        } = self;
        if let Some(escrow_input) = spp_proof.inputs.get_mut(0) {
            escrow_input.eddsa_signer_index = ESCROW_AUTHORITY_SIGNER_INDEX;
        }

        let data = FillVerifiableEncryptionIxData {
            proof: fill_proof,
            transact: spp_proof,
        }
        .serialize();

        let accounts = vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(payer, true),
            AccountMeta::new(tree, false),
            AccountMeta::new_readonly(escrow_authority_pda(), false),
            spp_program_meta(),
        ];
        let mut instruction_data = vec![tag::FILL_VERIFIABLE_ENCRYPTION];
        instruction_data.extend_from_slice(&data);
        Ok(Instruction {
            program_id: program_id_pubkey(),
            accounts,
            data: instruction_data,
        })
    }
}
