use anyhow::Result;
use zolana_keypair::NullifierKey;
use zolana_transaction::{Utxo, WalletUtxo};

/// Build an indexed note fixture with its committed hashes and physical location.
pub fn wallet(
    utxo: Utxo,
    key: &NullifierKey,
    tree_id: u16,
    leaf_index: u64,
    data_hash: Option<[u8; 32]>,
    ring_data_hash: Option<[u8; 32]>,
) -> Result<WalletUtxo> {
    let nullifier_pubkey = key.pubkey()?;
    let utxo_hash = utxo.hash(
        &nullifier_pubkey,
        &data_hash.unwrap_or_default(),
        &ring_data_hash.unwrap_or_default(),
        tree_id,
    )?;
    let nullifier = key.nullifier(&utxo_hash, &utxo.blinding)?;
    Ok(WalletUtxo {
        utxo,
        nullifier_pubkey,
        utxo_hash,
        nullifier,
        data_hash,
        ring_data_hash,
        tree_id,
        leaf_index,
        slot: 0,
        tx_signature: Default::default(),
        slot_index: 0,
    })
}

use zolana_transaction::{instructions::transact::SppProofInputs, SppProofOutputUtxo};

pub fn finalized_transaction(
    input_utxos: Vec<zolana_transaction::utxo::SppProofInputUtxo>,
    mut output_utxos: Vec<SppProofOutputUtxo>,
    sender: &zolana_keypair::ShieldedKeypair,
    payer: solana_address::Address,
    output_tree_id: u16,
    blinding_seed: [u8; 32],
    salt: [u8; 16],
) -> SppProofInputs {
    use zolana_interface::instruction::{OwnerTag, TransactOutput};
    use zolana_transaction::serialization::{
        confidential::{Confidential, ConfidentialEncode, ConfidentialOutputPlaintext},
        UtxoSerialization,
    };
    let first_nullifier = input_utxos.first().unwrap().nullifier;
    let seed =
        zolana_transaction::utxo::derive_output_blinding_seed(&first_nullifier, &blinding_seed)
            .unwrap();
    for (index, output) in output_utxos.iter_mut().enumerate() {
        output.blinding = zolana_transaction::utxo::derive_transact_output_blinding(
            &first_nullifier,
            &seed,
            index as u32,
        )
        .unwrap();
    }
    let tx = sender
        .get_transaction_viewing_key(&first_nullifier)
        .unwrap();
    let mut outputs = Vec::new();
    let mut tags = Vec::new();
    for (slot_index, output) in output_utxos.iter().enumerate() {
        let address = output.owner_address.unwrap();
        let tag = address.signing_pubkey.confidential_view_tag().unwrap();
        let message = Confidential::encode_plaintext(
            &ConfidentialOutputPlaintext {
                asset_id: output.asset.asset_id,
                amount: output.amount,
                blinding: output.blinding,
                ring_program_id: output.ring_program_id,
                data: output.data.clone(),
            },
            tag,
            &ConfidentialEncode {
                tx: tx.clone(),
                recipient_pubkey: address.viewing_pubkey,
                salt,
                slot_index: slot_index as u32,
            },
        )
        .unwrap();
        outputs.push(TransactOutput {
            utxo_hash: output.hash(output_tree_id).unwrap(),
            owner_tag: if tag == payer.to_bytes() {
                OwnerTag::Account(0)
            } else {
                OwnerTag::Inline(tag)
            },
            data: Some(message.data),
        });
        tags.push(tag);
    }
    SppProofInputs {
        input_utxos,
        output_utxos,
        blinding_seed,
        output_tree_id,
        external_data: zolana_transaction::ExternalData::new(
            *tx.pubkey().as_bytes(),
            salt,
            outputs,
            tags,
            vec![],
        ),
        payer,
    }
}

use borsh::BorshDeserialize;
use zolana_event::{MessageData, OutputDataEncoding};
use zolana_interface::instruction::{OwnerTag, TransactOutput};
use zolana_keypair::{
    constants::SALT_LEN, random_blinding, random_salt, ShieldedAddress, ViewingKey, ViewingKeyTrait,
};
use zolana_transaction::{
    serialization::{
        confidential::{Confidential, ConfidentialEncode, ConfidentialOutputPlaintext},
        UtxoSerialization,
    },
    utxo::{derive_output_blinding_seed, derive_transact_output_blinding, SppProofInputUtxo},
    EncryptedScheme, TransactionError,
};

pub struct EncryptedTransactionData {
    pub salt: [u8; SALT_LEN],
    pub output_utxos: Vec<SppProofOutputUtxo>,
    pub outputs: Vec<TransactOutput>,
    pub resolved_owner_tags: Vec<[u8; 32]>,
}

fn confidential_ciphertext(
    output: &SppProofOutputUtxo,
    address: ShieldedAddress,
    asset_id: u64,
    tx: &ViewingKey,
    salt: [u8; SALT_LEN],
    slot_index: u32,
) -> Result<MessageData, TransactionError> {
    let mut message = Confidential::encode_plaintext(
        &ConfidentialOutputPlaintext {
            asset_id,
            amount: output.amount,
            blinding: output.blinding,
            ring_program_id: output.ring_program_id,
            data: output.data.clone(),
        },
        address.signing_pubkey.confidential_view_tag()?,
        &ConfidentialEncode {
            tx: tx.clone(),
            recipient_pubkey: address.viewing_pubkey,
            salt,
            slot_index,
        },
    )?;
    if output.ring_program_id.is_some() {
        let OutputDataEncoding::Encrypted(mut blob) =
            OutputDataEncoding::try_from_slice(&message.data)
                .map_err(|error| TransactionError::Deserialize(error.to_string()))?
        else {
            return Err(TransactionError::BadDiscriminator(
                EncryptedScheme::Confidential.as_byte(),
            ));
        };
        *blob.first_mut().ok_or(TransactionError::MissingOutput)? =
            EncryptedScheme::RingConfidential.as_byte();
        message.data = borsh::to_vec(&OutputDataEncoding::Encrypted(blob))
            .map_err(|error| TransactionError::Deserialize(error.to_string()))?;
    }
    Ok(message)
}

/// Encrypts every output to its own owner and publishes its commitment under
/// `output_tree_id`, the raw id of the tree the transaction appends to.
pub fn encrypt_transaction_data(
    outputs: &[SppProofOutputUtxo],
    transaction_viewing_key: &ViewingKey,
    output_tree_id: u16,
) -> Result<EncryptedTransactionData, TransactionError> {
    let salt = random_salt();
    let mut output_utxos = Vec::with_capacity(outputs.len());
    let mut transact_outputs = Vec::with_capacity(outputs.len());
    let mut resolved_owner_tags = Vec::with_capacity(outputs.len());
    for (slot_index, output) in outputs.iter().enumerate() {
        let address = output
            .owner_address
            .ok_or(TransactionError::MissingOutput)?;
        let asset_id = output.asset.asset_id;
        let ciphertext = confidential_ciphertext(
            output,
            address,
            asset_id,
            transaction_viewing_key,
            salt,
            slot_index as u32,
        )?;
        transact_outputs.push(TransactOutput {
            utxo_hash: output.hash(output_tree_id)?,
            owner_tag: OwnerTag::Inline(ciphertext.view_tag),
            data: Some(ciphertext.data),
        });
        resolved_owner_tags.push(ciphertext.view_tag);
        output_utxos.push(output.clone());
    }
    Ok(EncryptedTransactionData {
        salt,
        output_utxos,
        outputs: transact_outputs,
        resolved_owner_tags,
    })
}

pub fn assign_output_blindings(
    outputs: &mut [SppProofOutputUtxo],
    first_nullifier: &[u8; 32],
    seed: &[u8; 32],
) -> Result<(), TransactionError> {
    for (index, output) in outputs.iter_mut().enumerate() {
        let index = u32::try_from(index).map_err(|_| TransactionError::TooManyOutputs)?;
        output.blinding = derive_transact_output_blinding(first_nullifier, seed, index)?;
    }
    Ok(())
}

/// Draws the blinding seed, derives the output blinding seed from it, and
/// assigns every final output blinding. Call this before hashing or encrypting
/// the outputs; the returned root seed goes into
/// [`SppProofInputs::blinding_seed`](SppProofInputs) and is disclosed to nobody.
pub fn prepare_output_blindings(
    input_utxos: &[SppProofInputUtxo],
    outputs: &mut [SppProofOutputUtxo],
) -> Result<[u8; 32], TransactionError> {
    let blinding_seed = random_blinding();
    let first_nullifier = input_utxos
        .first()
        .ok_or(TransactionError::NoInputs)?
        .nullifier;
    let seed = derive_output_blinding_seed(&first_nullifier, &blinding_seed)?;
    assign_output_blindings(outputs, &first_nullifier, &seed)?;
    Ok(blinding_seed)
}

pub fn get_transaction_viewing_key<K: ViewingKeyTrait>(
    keypair: &K,
    input_utxos: &[SppProofInputUtxo],
) -> Result<ViewingKey, TransactionError> {
    let first_nullifier = input_utxos
        .first()
        .ok_or(TransactionError::NoInputs)?
        .nullifier;
    Ok(keypair.get_transaction_viewing_key(&first_nullifier)?)
}

/// Complete each fixture input with the key that owns its published nullifier.
pub struct ProofKeys<'a>(pub &'a [&'a NullifierKey]);
impl zolana_client::ProofAuthority for ProofKeys<'_> {
    fn complete_inputs(
        &self,
        inputs: &mut [zolana_client::TransferInput],
    ) -> std::result::Result<(), zolana_client::ClientError> {
        for (index, input) in inputs.iter_mut().enumerate() {
            if input.nullifier_secret.is_some() {
                continue;
            }
            let hash = input.utxo.hash()?;
            let key = self
                .0
                .iter()
                .find(|key| {
                    key.nullifier(&hash, &input.utxo.blinding)
                        .is_ok_and(|nullifier| {
                            num_bigint::BigUint::from_bytes_be(&nullifier) == input.nullifier
                        })
                })
                .ok_or(zolana_client::ClientError::InputNullifierMismatch { index })?;
            key.complete_inputs(std::slice::from_mut(input))?;
        }
        Ok(())
    }
}

/// Non-inclusion witnesses for benchmark padding in a fresh fixture tree.
pub fn dummy_proofs(transaction: &SppProofInputs) -> Vec<zolana_client::NonInclusionProof> {
    let tree = crate::transact::nullifier_tree().expect("fixture nullifier tree");
    transaction
        .input_utxos
        .iter()
        .filter(|input| input.is_dummy())
        .map(|input| {
            let proof = tree
                .get_non_inclusion_proof(&num_bigint::BigUint::from_bytes_be(&input.nullifier))
                .expect("dummy non-inclusion");
            zolana_client::NonInclusionProof {
                leaf: input.nullifier,
                merkle_context: zolana_client::MerkleContext {
                    tree_type: 1,
                    tree: zolana_interface::pda::tree(input.tree_id),
                },
                path: proof.merkle_proof.to_vec(),
                low_element: proof.leaf_lower_range_value,
                low_element_index: proof.leaf_index as u64,
                high_element: proof.leaf_higher_range_value,
                high_element_index: 0,
                root: tree.root(),
                root_seq: 0,
                root_index: 0,
            }
        })
        .collect()
}

/// Resolve real fixture metadata before the transaction is finalized.
pub fn indexed<I: zolana_client::Rpc>(
    utxo: Utxo,
    key: &NullifierKey,
    indexer: &I,
    tree_id: u16,
) -> Result<WalletUtxo> {
    let hash = utxo.hash(&key.pubkey()?, &[0; 32], &[0; 32], tree_id)?;
    let proof = crate::test_validator_asserts::wait_for_merkle_proof(
        indexer,
        zolana_interface::pda::tree(tree_id),
        hash,
    );
    wallet(utxo, key, tree_id, proof.leaf_index, None, None)
}
