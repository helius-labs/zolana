//! Blocking RPC adapter for the Zolana indexer API.

use solana_address::Address;
use solana_signature::Signature;
use zolana_api::types::{
    Base64String, Hash as ApiHash, SerializablePubkey, ZolanaOutputSlot as ApiOutputSlot,
};
use zolana_api::BlockingZolanaApi;
use zolana_keypair::{constants::P256_PUBKEY_LEN, P256Pubkey};

use crate::{
    error::ClientError,
    rpc::{
        Context, EncryptedUtxoMatch, GetEncryptedUtxosByTagsResponse, GetMerkleProofsResponse,
        GetNonInclusionProofsResponse, GetShieldedTransactionsByTagsResponse, MerkleContext,
        MerkleProof, NonInclusionProof, OutputSlot, Rpc, ShieldedTransaction,
    },
};

#[derive(Clone, Debug)]
pub struct ZolanaIndexer {
    api: BlockingZolanaApi,
}

impl ZolanaIndexer {
    pub fn new(url: impl AsRef<str>) -> Self {
        Self {
            api: BlockingZolanaApi::new(url),
        }
    }

    pub fn with_api(api: BlockingZolanaApi) -> Self {
        Self { api }
    }

    pub fn with_http_trace(mut self) -> Self {
        self.api = self.api.with_http_trace();
        self
    }

    pub fn api(&self) -> &BlockingZolanaApi {
        &self.api
    }
}

impl Rpc for ZolanaIndexer {
    fn get_encrypted_utxos_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
    ) -> Result<GetEncryptedUtxosByTagsResponse, ClientError> {
        let response = self
            .api
            .get_encrypted_utxos_by_tags(
                tags.into_iter().map(encode_hash).collect(),
                encode_cursor(cursor),
                limit.map(u64::from),
            )
            .map_err(indexer_error)?;

        Ok(GetEncryptedUtxosByTagsResponse {
            context: convert_context(response.context),
            matches: response
                .matches
                .into_iter()
                .enumerate()
                .map(|(index, item)| convert_encrypted_utxo_match(index, item))
                .collect::<Result<Vec<_>, _>>()?,
            next_cursor: decode_optional_cursor(response.next_cursor)?,
        })
    }

    fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        let response = self
            .api
            .get_shielded_transactions_by_tags(
                tags.into_iter().map(encode_hash).collect(),
                encode_cursor(cursor),
                limit.map(u64::from),
            )
            .map_err(indexer_error)?;

        Ok(GetShieldedTransactionsByTagsResponse {
            context: convert_context(response.context),
            transactions: response
                .transactions
                .into_iter()
                .enumerate()
                .map(|(index, item)| convert_shielded_transaction(index, item))
                .collect::<Result<Vec<_>, _>>()?,
            next_cursor: decode_optional_cursor(response.next_cursor)?,
        })
    }

    fn get_merkle_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
    ) -> Result<GetMerkleProofsResponse, ClientError> {
        let response = self
            .api
            .get_merkle_proofs(
                encode_pubkey(tree_account),
                leaves.into_iter().map(encode_hash).collect(),
            )
            .map_err(indexer_error)?;

        Ok(GetMerkleProofsResponse {
            context: convert_context(response.context),
            proofs: response
                .proofs
                .into_iter()
                .enumerate()
                .map(|(index, proof)| convert_merkle_proof(index, proof))
                .collect::<Result<Vec<_>, _>>()?,
        })
    }

    fn get_non_inclusion_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
    ) -> Result<GetNonInclusionProofsResponse, ClientError> {
        let response = self
            .api
            .get_non_inclusion_proofs(
                encode_pubkey(tree_account),
                leaves.into_iter().map(encode_hash).collect(),
            )
            .map_err(indexer_error)?;

        Ok(GetNonInclusionProofsResponse {
            context: convert_context(response.context),
            proofs: response
                .proofs
                .into_iter()
                .enumerate()
                .map(|(index, proof)| convert_non_inclusion_proof(index, proof))
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

fn indexer_error(error: zolana_api::ApiError) -> ClientError {
    ClientError::Rpc(format!("indexer API: {error}"))
}

fn convert_context(context: zolana_api::Context) -> Context {
    Context { slot: context.slot }
}

fn convert_encrypted_utxo_match(
    index: usize,
    item: zolana_api::EncryptedUtxoMatch,
) -> Result<EncryptedUtxoMatch, ClientError> {
    Ok(EncryptedUtxoMatch {
        slot: item.slot,
        tx_signature: decode_signature(
            &item.tx_signature,
            &format!("matches[{index}].tx_signature"),
        )?,
        view_tag: decode_hash(&item.view_tag, &format!("matches[{index}].view_tag"))?,
        tx_viewing_pk: decode_optional_p256(
            item.tx_viewing_pk,
            &format!("matches[{index}].tx_viewing_pk"),
        )?,
        salt: decode_optional_salt(item.salt, &format!("matches[{index}].salt"))?,
        ciphertext: decode_base64(&item.ciphertext, &format!("matches[{index}].ciphertext"))?,
    })
}

fn convert_shielded_transaction(
    index: usize,
    item: zolana_api::ShieldedTransaction,
) -> Result<ShieldedTransaction, ClientError> {
    Ok(ShieldedTransaction {
        slot: item.slot,
        tx_signature: decode_signature(
            &item.tx_signature,
            &format!("transactions[{index}].tx_signature"),
        )?,
        tx_viewing_pk: decode_optional_p256(
            item.tx_viewing_pk,
            &format!("transactions[{index}].tx_viewing_pk"),
        )?,
        salt: decode_optional_salt(item.salt, &format!("transactions[{index}].salt"))?,
        output_slots: item
            .output_slots
            .into_iter()
            .enumerate()
            .map(|(slot_index, slot)| {
                convert_output_slot(
                    slot,
                    &format!("transactions[{index}].output_slots[{slot_index}]"),
                )
            })
            .collect::<Result<Vec<_>, _>>()?,
        nullifiers: item
            .nullifiers
            .iter()
            .enumerate()
            .map(|(nullifier_index, nullifier)| {
                decode_hash(
                    nullifier,
                    &format!("transactions[{index}].nullifiers[{nullifier_index}]"),
                )
            })
            .collect::<Result<Vec<_>, _>>()?,
        proofless: item.proofless,
    })
}

fn convert_output_slot(slot: ApiOutputSlot, field: &str) -> Result<OutputSlot, ClientError> {
    Ok(OutputSlot {
        view_tag: decode_hash(&slot.view_tag, &format!("{field}.view_tag"))?,
        utxo_hash: decode_hash(&slot.hash, &format!("{field}.hash"))?,
        payload: decode_base64(&slot.payload, &format!("{field}.payload"))?,
    })
}

fn convert_merkle_proof(
    index: usize,
    proof: zolana_api::MerkleProof,
) -> Result<MerkleProof, ClientError> {
    Ok(MerkleProof {
        leaf: decode_hash(&proof.leaf, &format!("proofs[{index}].leaf"))?,
        merkle_context: convert_merkle_context(
            proof.merkle_context,
            &format!("proofs[{index}].merkle_context"),
        )?,
        path: proof
            .path
            .iter()
            .enumerate()
            .map(|(path_index, hash)| {
                decode_hash(hash, &format!("proofs[{index}].path[{path_index}]"))
            })
            .collect::<Result<Vec<_>, _>>()?,
        leaf_index: proof.leaf_index,
        root: decode_hash(&proof.root, &format!("proofs[{index}].root"))?,
        root_seq: proof.root_seq,
        root_index: proof.root_index,
    })
}

fn convert_non_inclusion_proof(
    index: usize,
    proof: zolana_api::NonInclusionProof,
) -> Result<NonInclusionProof, ClientError> {
    Ok(NonInclusionProof {
        leaf: decode_hash(&proof.leaf, &format!("proofs[{index}].leaf"))?,
        merkle_context: convert_merkle_context(
            proof.merkle_context,
            &format!("proofs[{index}].merkle_context"),
        )?,
        path: proof
            .path
            .iter()
            .enumerate()
            .map(|(path_index, hash)| {
                decode_hash(hash, &format!("proofs[{index}].path[{path_index}]"))
            })
            .collect::<Result<Vec<_>, _>>()?,
        low_element: decode_hash(&proof.low_element, &format!("proofs[{index}].low_element"))?,
        low_element_index: proof.low_element_index,
        high_element: decode_hash(
            &proof.high_element,
            &format!("proofs[{index}].high_element"),
        )?,
        high_element_index: proof.high_element_index,
        root: decode_hash(&proof.root, &format!("proofs[{index}].root"))?,
        root_seq: proof.root_seq,
        root_index: proof.root_index,
    })
}

fn convert_merkle_context(
    context: zolana_api::MerkleContext,
    field: &str,
) -> Result<MerkleContext, ClientError> {
    Ok(MerkleContext {
        tree_type: context.tree_type,
        tree: decode_pubkey(&context.tree, &format!("{field}.tree"))?,
    })
}

fn encode_hash(hash: [u8; 32]) -> ApiHash {
    ApiHash(bs58::encode(hash).into_string())
}

fn encode_pubkey(address: Address) -> SerializablePubkey {
    SerializablePubkey(bs58::encode(address.to_bytes()).into_string())
}

fn encode_cursor(cursor: Option<Vec<u8>>) -> Option<Base64String> {
    cursor.map(|cursor| Base64String(base64::encode(cursor)))
}

fn decode_optional_cursor(cursor: Option<Base64String>) -> Result<Option<Vec<u8>>, ClientError> {
    cursor
        .map(|cursor| decode_base64(&cursor, "next_cursor"))
        .transpose()
}

fn decode_signature(
    signature: &zolana_api::SerializableSignature,
    field: &str,
) -> Result<Signature, ClientError> {
    signature
        .0
        .parse::<Signature>()
        .map_err(|error| decode_error(field, error))
}

fn decode_pubkey(
    pubkey: &zolana_api::SerializablePubkey,
    field: &str,
) -> Result<Address, ClientError> {
    Ok(Address::new_from_array(decode_base58_32(&pubkey.0, field)?))
}

fn decode_hash(hash: &ApiHash, field: &str) -> Result<[u8; 32], ClientError> {
    decode_base58_32(&hash.0, field)
}

fn decode_base58_32(value: &str, field: &str) -> Result<[u8; 32], ClientError> {
    let bytes = bs58::decode(value)
        .into_vec()
        .map_err(|error| decode_error(field, error))?;
    fixed_bytes(bytes, 32, field)
}

fn decode_base64(value: &Base64String, field: &str) -> Result<Vec<u8>, ClientError> {
    base64::decode(&value.0).map_err(|error| decode_error(field, error))
}

fn decode_optional_p256(
    value: Option<Base64String>,
    field: &str,
) -> Result<Option<P256Pubkey>, ClientError> {
    value
        .map(|value| {
            let bytes = fixed_bytes(decode_base64(&value, field)?, P256_PUBKEY_LEN, field)?;
            P256Pubkey::from_bytes(bytes).map_err(|error| decode_error(field, error))
        })
        .transpose()
}

fn decode_optional_salt(
    value: Option<Base64String>,
    field: &str,
) -> Result<Option<[u8; 16]>, ClientError> {
    value
        .map(|value| fixed_bytes(decode_base64(&value, field)?, 16, field))
        .transpose()
}

fn fixed_bytes<const N: usize>(
    bytes: Vec<u8>,
    expected_len: usize,
    field: &str,
) -> Result<[u8; N], ClientError> {
    let actual_len = bytes.len();
    bytes.try_into().map_err(|_| {
        ClientError::Rpc(format!(
            "invalid indexer field {field}: expected {expected_len} bytes, got {actual_len}"
        ))
    })
}

fn decode_error(field: &str, error: impl std::fmt::Display) -> ClientError {
    ClientError::Rpc(format!("invalid indexer field {field}: {error}"))
}

#[cfg(test)]
mod tests {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::SecretKey;

    use super::*;

    #[test]
    fn round_trips_hashes_and_cursors() {
        let hash = [7u8; 32];
        let encoded = encode_hash(hash);
        assert_eq!(decode_hash(&encoded, "hash").unwrap(), hash);

        let cursor = Some(vec![1, 2, 3, 4]);
        let encoded = encode_cursor(cursor.clone());
        assert_eq!(decode_optional_cursor(encoded).unwrap(), cursor);
    }

    #[test]
    fn decodes_compressed_p256_pubkey() {
        let secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let public = secret.public_key();
        let point = public.to_encoded_point(true);
        let key = decode_optional_p256(
            Some(Base64String(base64::encode(point.as_bytes()))),
            "tx_viewing_pk",
        )
        .unwrap()
        .unwrap();

        assert_eq!(key.as_bytes(), point.as_bytes());
    }

    #[test]
    fn rejects_bad_hash_length() {
        let err = decode_hash(&ApiHash(bs58::encode([1u8; 31]).into_string()), "root")
            .expect_err("short hash must fail");
        assert!(err.to_string().contains("expected 32 bytes"));
    }
}
