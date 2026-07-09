use anyhow::Result;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use swap_prover::{FillVerifiableEncryptionProofInputs, FillVerifiableEncryptionProofResult};
use zolana_client::{ProverClient, SpendProof};
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
    check_private_tx_hash, err, escrow_authority_pda, lifecycle_instruction,
    order::{sdk_private_tx_hash, BlindingField, DataHash, Escrow, OrderTerms, Recipient},
    prover::{prove_transact, SwapProverClient},
    spp_program_meta, tag, FillVerifiableEncryptionProof,
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

pub fn fill_verifiable_encryption(
    payer: Pubkey,
    spp_accounts: Vec<AccountMeta>,
    proof: FillVerifiableEncryptionProof,
    transact: TransactIxData,
) -> Instruction {
    let data = FillVerifiableEncryptionIxData { proof, transact }.serialize();
    lifecycle_instruction(tag::FILL_VERIFIABLE_ENCRYPTION, payer, spp_accounts, data)
}

pub struct FillVerifiableEncryptionSharedInputs {
    pub terms: OrderTerms,
    pub source_mint: Address,
    pub destination_mint: Address,
    pub escrow_blinding: Blinding,
    pub taker_in_blinding: Blinding,
    pub destination_output_blinding: Blinding,
    pub source_output_blinding: Blinding,
    pub external_data_hash: [u8; 32],
    pub maker_recipient: ShieldedAddress,
    pub taker_recipient: ShieldedAddress,
}

impl FillVerifiableEncryptionSharedInputs {
    pub fn fill_proof_inputs(&self) -> Result<FillVerifiableEncryptionProofInputs> {
        Ok(FillVerifiableEncryptionProofInputs {
            source_asset_id: self.terms.source_asset_id,
            source_mint: *self.source_mint.as_array(),
            destination_mint: *self.destination_mint.as_array(),
            source_amount: self.terms.source_amount,
            escrow_authority: *escrow_authority_pda().as_array(),
            escrow_blinding: self.escrow_blinding.to_field(),
            destination_amount: self.terms.destination_amount,
            maker_owner_hash: self.terms.destination.owner_hash().map_err(err)?,
            maker_viewing_pk: *self.terms.destination.viewing_pubkey.as_bytes(),
            expiry: self.terms.expiry,
            taker_pk_fe: self.terms.taker.data_hash()?,
            taker_nullifier_pk: self.taker_recipient.nullifier_pubkey,
            taker_in_blinding: self.taker_in_blinding.to_field(),
            destination_output_blinding: self.destination_output_blinding.to_field(),
            source_output_blinding: self.source_output_blinding.to_field(),
            external_data_hash: self.external_data_hash,
        })
    }

    pub fn escrow_output(&self) -> Result<OutputUtxo> {
        Escrow {
            terms: self.terms.clone(),
            blinding: self.escrow_blinding,
            source_mint: self.source_mint,
        }
        .output_utxo(self.taker_recipient.viewing_pubkey)
    }

    pub fn taker_utxo(&self) -> OutputUtxo {
        Recipient {
            address: self.taker_recipient,
            amount: self.terms.destination_amount,
            blinding: self.taker_in_blinding,
            mint: self.destination_mint,
        }
        .output()
    }

    pub fn destination_output(&self) -> OutputUtxo {
        Recipient {
            address: self.maker_recipient,
            amount: self.terms.destination_amount,
            blinding: self.destination_output_blinding,
            mint: self.destination_mint,
        }
        .output()
    }

    pub fn source_output(&self) -> OutputUtxo {
        Recipient {
            address: self.taker_recipient,
            amount: self.terms.source_amount,
            blinding: self.source_output_blinding,
            mint: self.source_mint,
        }
        .output()
    }

    pub fn sdk_private_tx_hash(&self) -> Result<[u8; 32]> {
        let escrow_hash = self.escrow_output()?.hash().map_err(err)?;
        let taker_utxo_hash = self.taker_utxo().hash().map_err(err)?;
        let destination_output_hash = self.destination_output().hash().map_err(err)?;
        let source_output_hash = self.source_output().hash().map_err(err)?;
        sdk_private_tx_hash(
            &[escrow_hash, taker_utxo_hash],
            &[source_output_hash, destination_output_hash],
            &self.external_data_hash,
        )
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
    pub inputs: FillVerifiableEncryptionSharedInputs,
    pub signed: SignedTransaction,
    pub payer: Pubkey,
    pub tree: Pubkey,
}

/// The escrow (input 0) is owned by the escrow-authority PDA appended readonly
/// after `tree`; the swap program signs for it via `invoke_signed`. The taker
/// input is signed by the SPP payer (account index 0). The signer index
/// selects the account whose pubkey the SPP proof's input_owner_pk_hash must
/// match; it is not itself a proof public input, so overriding it post-proof is
/// safe.
const ESCROW_AUTHORITY_SIGNER_INDEX: u8 = 2;

impl FillVerifiableEncryption {
    pub fn instruction(
        self,
        spend_proofs: &[SpendProof],
        prover: &ProverClient,
        swap_prover: &SwapProverClient,
    ) -> Result<(Instruction, FillVerifiableEncryptionProofResult)> {
        let Self {
            inputs,
            signed,
            payer,
            tree,
        } = self;
        let expected = inputs.sdk_private_tx_hash()?;
        let mut transact = prove_transact(signed, spend_proofs, prover)?;
        if let Some(escrow_input) = transact.inputs.get_mut(0) {
            escrow_input.eddsa_signer_index = ESCROW_AUTHORITY_SIGNER_INDEX;
        }
        check_private_tx_hash("transact", transact.private_tx_hash, expected)?;
        let fill_result = swap_prover.prove_fill_verifiable_encryption(&inputs)?;
        check_private_tx_hash("fill proof", fill_result.private_tx_hash, expected)?;
        let spp_accounts = vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(tree, false),
            AccountMeta::new_readonly(escrow_authority_pda(), false),
            spp_program_meta(),
        ];
        let ix = fill_verifiable_encryption(
            payer,
            spp_accounts,
            fill_result.proof.into(),
            transact,
        );
        Ok((ix, fill_result))
    }
}
