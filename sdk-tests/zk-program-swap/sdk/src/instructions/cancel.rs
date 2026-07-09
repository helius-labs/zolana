use anyhow::Result;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use swap_prover::CancelProofInputs;
use zolana_interface::instruction::instruction_data::transact::TransactIxData;
use zolana_keypair::{P256Pubkey, ShieldedAddress, ShieldedKeypairTrait, ViewingKeyTrait};
use zolana_transaction::{
    instructions::transact::{OutputUtxo, RecipientSlot, SignedTransaction, Transaction},
    utxo::Blinding,
    AssetRegistry, TransactionError,
};

use crate::{
    err, escrow_authority_pda,
    order::{BlindingField, DataHash, Escrow, Recipient},
    program_id_pubkey, spp_program_meta, tag, CancelProof,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CancelIxData {
    pub proof: CancelProof,
    /// The committed order `expiry` the cancel proof reveals as a public input.
    /// Carried separately from `transact.expiry_unix_ts` (the SPP relayer
    /// deadline): cancel requires `now > order_expiry`, which is necessarily in
    /// the past, whereas SPP rejects a `transact` whose `expiry_unix_ts` is in the
    /// past. The proof binds `order_expiry` to the escrow's committed terms.
    pub order_expiry: u64,
    pub transact: TransactIxData,
}

impl CancelIxData {
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = borsh::to_vec(&self.proof).expect("CancelProof serialization is infallible");
        data.extend_from_slice(
            &borsh::to_vec(&self.order_expiry).expect("u64 serialization is infallible"),
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

pub struct CancelProofInputParams {
    pub escrow: Escrow,
    pub taker_viewing_pk: P256Pubkey,
    pub source_output_blinding: Blinding,
    pub external_data_hash: [u8; 32],
    pub maker_recipient: ShieldedAddress,
}

impl CancelProofInputParams {
    pub fn into_proof_inputs(&self) -> Result<CancelProofInputs> {
        let terms = &self.escrow.terms;
        Ok(CancelProofInputs {
            source_mint: *self.escrow.source_mint.as_array(),
            source_amount: self.escrow.source_amount,
            escrow_authority: *escrow_authority_pda().as_array(),
            escrow_blinding: self.escrow.blinding.to_field(),
            destination_mint: *terms.destination_mint.as_array(),
            destination_amount: terms.destination_amount,
            maker_owner_hash: terms.destination.owner_hash().map_err(err)?,
            maker_owner_pk_field: self
                .maker_recipient
                .signing_pubkey
                .owner_pk_field()
                .map_err(err)?,
            maker_nullifier_pk: self.maker_recipient.nullifier_pubkey,
            maker_viewing_pk: *terms.destination.viewing_pubkey.as_bytes(),
            expiry: terms.expiry,
            taker_pk_fe: terms.taker.data_hash()?,
            fill_mode: terms.fill_mode,
            source_output_blinding: self.source_output_blinding.to_field(),
            external_data_hash: self.external_data_hash,
        })
    }

    pub fn source_output(&self) -> OutputUtxo {
        Recipient {
            address: self.maker_recipient,
            amount: self.escrow.source_amount,
            blinding: self.source_output_blinding,
            mint: self.escrow.source_mint,
        }
        .output()
    }
}

pub struct EscrowCancel {
    pub tx: Transaction,
    pub source_output: OutputUtxo,
}

impl EscrowCancel {
    pub fn sign<K: ShieldedKeypairTrait + ViewingKeyTrait>(
        self,
        keypair: &K,
        assets: &AssetRegistry,
    ) -> Result<SignedTransaction, TransactionError> {
        let Self { tx, source_output } = self;
        if tx.inputs.len() != 1 {
            return Err(TransactionError::TooManyInputs {
                got: tx.inputs.len(),
                max: 1,
            });
        }
        let slot = RecipientSlot::new(source_output, assets)?;
        tx.sign_with_slots(&[&slot], keypair)
    }
}

pub struct Cancel {
    /// The maker's ed25519 pubkey, a dedicated readonly signer the swap program
    /// binds the cancel proof's committed maker to.
    pub maker: Pubkey,
    pub payer: Pubkey,
    pub tree: Pubkey,
    pub cancel_proof: CancelProof,
    pub order_expiry: u64,
    pub spp_proof: TransactIxData,
}

/// The escrow (input 0) is owned by the escrow-authority PDA appended readonly
/// after `tree`; the swap program signs for it via `invoke_signed`. The signer
/// index selects the account whose pubkey the SPP proof's input_owner_pk_hash
/// must match; it is not itself a proof public input, so overriding it post-proof
/// is safe.
const ESCROW_AUTHORITY_SIGNER_INDEX: u8 = 2;

impl Cancel {
    pub fn instruction(self) -> Result<Instruction> {
        let Self {
            maker,
            payer,
            tree,
            cancel_proof,
            order_expiry,
            mut spp_proof,
        } = self;
        if let Some(escrow_input) = spp_proof.inputs.get_mut(0) {
            escrow_input.eddsa_signer_index = ESCROW_AUTHORITY_SIGNER_INDEX;
        }

        let data = CancelIxData {
            proof: cancel_proof,
            order_expiry,
            transact: spp_proof,
        }
        .serialize();

        // The maker is a dedicated readonly signer after the fee payer; the swap
        // program reads its pubkey to bind the cancel proof to the escrow's maker.
        let accounts = vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(maker, true),
            AccountMeta::new(payer, true),
            AccountMeta::new(tree, false),
            AccountMeta::new_readonly(escrow_authority_pda(), false),
            spp_program_meta(),
        ];
        let mut instruction_data = vec![tag::CANCEL];
        instruction_data.extend_from_slice(&data);
        Ok(Instruction {
            program_id: program_id_pubkey(),
            accounts,
            data: instruction_data,
        })
    }
}
