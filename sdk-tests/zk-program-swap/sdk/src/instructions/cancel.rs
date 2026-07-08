use anyhow::Result;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use swap_prover::CancelProofInputs;
use zolana_client::{ProverClient, SpendProof};
use zolana_interface::instruction::instruction_data::transact::TransactIxData;
use zolana_keypair::{P256Pubkey, ShieldedAddress, ShieldedKeypairTrait, ViewingKeyTrait};
use zolana_transaction::{
    instructions::transact::{OutputUtxo, RecipientSlot, SignedTransaction, Transaction},
    utxo::Blinding,
    AssetRegistry, TransactionError,
};

use crate::{
    check_private_tx_hash, err, escrow_authority_pda,
    order::{sdk_private_tx_hash, BlindingField, Escrow, OrderTerms, Recipient},
    program_id_pubkey,
    prover::prove_transact,
    spp_program_meta, tag, CancelProof,
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

pub fn cancel(
    payer: Pubkey,
    maker_signer: Pubkey,
    spp_accounts: Vec<AccountMeta>,
    proof: CancelProof,
    order_expiry: u64,
    transact: TransactIxData,
) -> Instruction {
    let body = CancelIxData {
        proof,
        order_expiry,
        transact,
    }
    .serialize();
    // The maker is a dedicated readonly signer after the fee payer; the swap
    // program reads its pubkey to bind the cancel proof to the escrow's maker.
    let mut accounts = vec![
        AccountMeta::new(payer, true),
        AccountMeta::new_readonly(maker_signer, true),
    ];
    accounts.extend(spp_accounts);
    let mut data = vec![tag::CANCEL];
    data.extend_from_slice(&body);
    Instruction {
        program_id: program_id_pubkey(),
        accounts,
        data,
    }
}

pub struct CancelSharedInputs {
    pub terms: OrderTerms,
    pub escrow_blinding: Blinding,
    pub taker_viewing_pk: P256Pubkey,
    pub source_output_blinding: Blinding,
    pub external_data_hash: [u8; 32],
    pub maker_recipient: ShieldedAddress,
}

impl CancelSharedInputs {
    pub fn cancel_proof_inputs(&self, source_mint: Address) -> Result<CancelProofInputs> {
        Ok(CancelProofInputs {
            source_asset_id: self.terms.source_asset_id,
            source_mint: *source_mint.as_array(),
            source_amount: self.terms.source_amount,
            escrow_authority: *escrow_authority_pda().as_array(),
            escrow_blinding: self.escrow_blinding.to_field(),
            destination_mint: *self.terms.destination_mint.as_array(),
            destination_amount: self.terms.destination_amount,
            maker_owner_hash: self.terms.maker_owner_hash,
            maker_owner_pk_field: self
                .maker_recipient
                .signing_pubkey
                .owner_pk_field()
                .map_err(err)?,
            maker_nullifier_pk: self.maker_recipient.nullifier_pubkey,
            maker_viewing_pk: self.terms.maker_viewing_pk,
            expiry: self.terms.expiry,
            taker_pk_fe: self.terms.taker_pk_fe,
            fill_mode: self.terms.fill_mode,
            source_output_blinding: self.source_output_blinding.to_field(),
            external_data_hash: self.external_data_hash,
        })
    }

    pub fn escrow_output(&self, source_mint: Address) -> Result<OutputUtxo> {
        Escrow {
            terms: self.terms.clone(),
            blinding: self.escrow_blinding,
            source_mint,
        }
        .output(self.taker_viewing_pk)
    }

    pub fn source_output(&self, source_mint: Address) -> OutputUtxo {
        Recipient {
            address: self.maker_recipient,
            amount: self.terms.source_amount,
            blinding: self.source_output_blinding,
            mint: source_mint,
        }
        .output()
    }

    pub fn sdk_private_tx_hash(&self, source_mint: Address) -> Result<[u8; 32]> {
        let escrow_hash = self.escrow_output(source_mint)?.hash().map_err(err)?;
        let source_output_hash = self.source_output(source_mint).hash().map_err(err)?;
        sdk_private_tx_hash(
            &[escrow_hash],
            &[source_output_hash],
            &self.external_data_hash,
        )
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
    pub inputs: CancelSharedInputs,
    pub signed: SignedTransaction,
    pub source_mint: Address,
    pub payer: Pubkey,
    pub tree: Pubkey,
}

/// The escrow (input 0) is owned by the escrow-authority PDA appended readonly
/// after `tree`; the swap program signs for it via `invoke_signed`. The signer
/// index selects the account whose pubkey the SPP proof's input_owner_pk_hash
/// must match; it is not itself a proof public input, so overriding it post-proof
/// is safe.
const ESCROW_AUTHORITY_SIGNER_INDEX: u8 = 2;

impl Cancel {
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
        let maker_signer = Pubkey::new_from_array(
            inputs
                .maker_recipient
                .signing_pubkey
                .as_ed25519()
                .map_err(err)?,
        );
        let mut transact = prove_transact(signed, spend_proofs, prover)?;
        if let Some(escrow_input) = transact.inputs.get_mut(0) {
            escrow_input.eddsa_signer_index = ESCROW_AUTHORITY_SIGNER_INDEX;
        }
        check_private_tx_hash("transact", transact.private_tx_hash, expected)?;
        let cancel_result = inputs
            .cancel_proof_inputs(source_mint)?
            .prove()
            .map_err(err)?;
        check_private_tx_hash("cancel proof", cancel_result.private_tx_hash, expected)?;
        let spp_accounts = vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(tree, false),
            AccountMeta::new_readonly(escrow_authority_pda(), false),
            spp_program_meta(),
        ];
        Ok(cancel(
            payer,
            maker_signer,
            spp_accounts,
            cancel_result.proof.into(),
            inputs.terms.expiry,
            transact,
        ))
    }
}
