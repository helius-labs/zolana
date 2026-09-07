use anyhow::Result;
use compression_example_program::state::{
    field_u64, output_blinding, private_tx_blinding, tx_secret,
};
use num_bigint::BigUint;
use solana_address::Address;
use zolana_client::{
    prover::field::be, NonInclusionProof, PublicInputs, PublicTransfers, TransferInput,
    TransferInputs, TransferOutput, STATE_TREE_HEIGHT,
};
use zolana_hasher::primitives::{right_align, solana_owner_identity};
use zolana_interface::{
    tree_slot::{tree_id_field, TreeSlot},
    ADDRESS_DOMAIN, INPUT_TREES,
};
use zolana_keypair::{hash::owner_hash, PublicKey};
use zolana_transaction::{instructions::transact::PrivateTxHash, ProofInputUtxo, Utxo};

use crate::{
    account_pda, err,
    shared::{external_data, zero_nullifier_key, DEFAULT_TREE_ID},
    state::{AccountState, AccountUtxo},
};

/// The address UTXO whose non-inclusion proof reserves this PDA's compressed
/// address, hashed under the tree the reservation is proven against. Returns
/// the address slot and its nullifier, which is the compressed address.
pub fn address_input(pda: &Address, tree_id: u16) -> Result<(ProofInputUtxo, [u8; 32])> {
    let key = zero_nullifier_key();
    let nullifier_pk = key.pubkey()?;
    let owner = PublicKey::from_pda(pda);
    let address_seed = solana_owner_identity(pda.as_array())?;
    let input = ProofInputUtxo {
        domain: right_align(&ADDRESS_DOMAIN.to_be_bytes()),
        tree_id: tree_id_field(tree_id),
        owner_hash: owner_hash(&owner, &nullifier_pk)?,
        blinding: address_seed,
        ..ProofInputUtxo::default()
    };
    let address = key.nullifier(&input.hash()?, &address_seed)?;
    Ok((input, address))
}

pub struct CreateProofInputParams {
    pub authority: Address,
    pub new_value: u64,
    pub non_inclusion: NonInclusionProof,
    pub utxo_root: [u8; 32],
    pub utxo_root_index: u16,
}

pub struct CreateCompressedAccount {
    pub transfer_inputs: TransferInputs,
    pub nullifier_tree_root_index: u16,
    pub utxo_tree_root_index: u16,
    pub output: Utxo,
    pub output_hash: [u8; 32],
    pub input_nullifier: [u8; 32],
}

impl CreateProofInputParams {
    pub fn to_proof_inputs(&self) -> Result<CreateCompressedAccount> {
        let pda = account_pda(&self.authority);
        // TODO(tree-id): resolve the tree id from the tree account.
        let tree_id = DEFAULT_TREE_ID;
        let (address_utxo, address_nullifier) = address_input(&pda, tree_id)?;
        let zero = [0u8; 32];
        let owner_pk_hash = solana_owner_identity(pda.as_array())?;
        let input = TransferInput {
            utxo: address_utxo,
            is_dummy: BigUint::ZERO,
            state_path_elements: vec![BigUint::ZERO; STATE_TREE_HEIGHT],
            state_path_index: BigUint::ZERO,
            nullifier_low_value: be(&self.non_inclusion.low_element),
            nullifier_next_value: be(&self.non_inclusion.high_element),
            nullifier_low_path_elements: self.non_inclusion.path.iter().map(be).collect(),
            nullifier_low_path_index: BigUint::from(self.non_inclusion.low_element_index),
            tree_slot: BigUint::ZERO,
            nullifier: be(&address_nullifier),
            owner_pk_hash: be(&owner_pk_hash),
            nullifier_secret: BigUint::ZERO,
        };

        // The address nullifier is the transaction's only, and therefore first,
        // nullifier, and the created version (0) is the deterministic
        // transaction secret: the program recomputes both derived blindings
        // from them, so the account output must sit in ACCOUNT_OUTPUT_SLOT.
        let version = 0;
        let tx_secret = tx_secret(version);
        let private_tx_blinding = private_tx_blinding(&address_nullifier, version).map_err(err)?;
        let account_utxo = AccountUtxo {
            pda,
            state: AccountState {
                address: address_nullifier,
                authority: self.authority.to_bytes(),
                value: self.new_value,
                version,
                blinding: output_blinding(&address_nullifier, version).map_err(err)?,
            },
        };
        let output = account_utxo.output_utxo()?;
        let payload = account_utxo.output_data()?;
        let output_hash = output.hash(tree_id)?;
        let proof_output = ProofInputUtxo::try_from((&output, tree_id))?;
        let transfer_output = TransferOutput {
            utxo: proof_output,
            is_dummy: BigUint::ZERO,
            hash: be(&output_hash),
            owner_pk_hash: be(&owner_pk_hash),
            nullifier_pk: be(&zero_nullifier_key().pubkey()?),
        };
        let external = external_data(output_hash, &pda, payload);
        let external_hash = external.hash()?;
        // The address slot enters the chain by its nullifier, the compressed
        // address itself, so the owner signature and the program both bind the
        // account that is created.
        let private_tx = PrivateTxHash {
            input_hashes: &[zero],
            output_hashes: &[output_hash],
            address_nullifiers: Some(&[address_nullifier]),
            external_data_hash: &external_hash,
            blinding: &private_tx_blinding,
        }
        .hash()?;
        let payer_hash = solana_owner_identity(self.authority.as_array())?;
        let signer_hashes = [payer_hash, owner_pk_hash];
        let output_owner_hashes = [owner_pk_hash];
        let public_transfers = PublicTransfers::default();
        let allow_dummy_inputs = field_u64(1);
        // Only slot 0 is populated: this example spends from one tree.
        let mut tree_slots = [TreeSlot::ZERO; INPUT_TREES];
        if let Some(slot) = tree_slots.first_mut() {
            *slot = TreeSlot::new(tree_id, self.utxo_root, self.non_inclusion.root);
        }
        let public_hash = PublicInputs {
            nullifiers: &[address_nullifier],
            output_hashes: &[output_hash],
            tree_slots: &tree_slots,
            output_tree_id: tree_id,
            private_tx: &private_tx,
            external_data_hash: &external_hash,
            public_transfers: &public_transfers,
            ring_program_id: &zero,
            allow_dummy_inputs: &allow_dummy_inputs,
            signer_pk_hashes: &signer_hashes,
            output_owner_pk_hashes: Some(&output_owner_hashes),
        }
        .hash()?;
        let transfer_inputs = TransferInputs {
            inputs: vec![input],
            outputs: vec![transfer_output],
            tree_slots: zolana_client::TreeSlotFields::encode_all(&tree_slots),
            output_tree_id: BigUint::from(tree_id),
            tx_secret: be(&tx_secret),
            external_data_hash: be(&external_hash),
            private_tx_hash: be(&private_tx),
            public_assets: core::array::from_fn(|_| BigUint::ZERO),
            public_amounts: core::array::from_fn(|_| BigUint::ZERO),
            ring_program_id: BigUint::ZERO,
            signer_pk_hashes: signer_hashes.iter().map(be).collect(),
            allow_dummy_inputs: BigUint::from(1u8),
            published_output_owner_pk_hashes: output_owner_hashes.iter().map(be).collect(),
            public_input_hash: be(&public_hash),
        };
        Ok(CreateCompressedAccount {
            transfer_inputs,
            nullifier_tree_root_index: self.non_inclusion.root_index,
            utxo_tree_root_index: self.utxo_root_index,
            output: account_utxo.utxo()?,
            output_hash,
            input_nullifier: address_nullifier,
        })
    }
}
