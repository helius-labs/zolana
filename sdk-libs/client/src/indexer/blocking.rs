use std::{
    thread::sleep,
    time::{Duration, Instant},
};

use solana_address::Address;
use solana_signature::Signature;
use zolana_api::{BlockingZolanaApi, SerializableSignature};
use zolana_interface::instruction::instruction_data::transact::TransactIxData;
use zolana_transaction::instructions::transact::SppProofInputs;

use crate::{
    authority::ProofAuthority,
    error::ClientError,
    prover::{witness::WitnessReader, Prover, ProverClient},
    rpc::{
        Context, GetEncryptedUtxosByTagsResponse, GetMerkleProofsResponse,
        GetNonInclusionProofsResponse, GetRingKeyRegistryEntryResponse,
        GetRingKeyRegistryRegisterProofResponse, GetRingSpendRecordResponse,
        GetShieldedTransactionsByNullifiersResponse, GetShieldedTransactionsBySignatureResponse,
        GetShieldedTransactionsByTagsResponse, IndexerRpcConfig, RingHistoryOptions,
        RingMemberProofRequest, RingSpendRecordRequest, Rpc,
    },
};

use super::{
    conversion::{
        convert_context, convert_encrypted_utxo_match, convert_merkle_proof,
        convert_non_inclusion_proof, convert_shielded_transaction,
        convert_shielded_transactions_by_signature_response,
        convert_shielded_transactions_response, encode_cursor, encode_hash, encode_pubkey,
        ring_history_request,
    },
    error::indexer_error,
};

const MERKLE_PROOF_POLL_TIMEOUT: Duration = Duration::from_secs(60);
/// First wait after an incomplete answer.
///
/// A transfer spends a note the indexer has only just written, so the first
/// attempt often lands a few milliseconds early and this sleep is on the
/// critical path of every transfer. A flat 500ms charged the tail's wait to
/// every caller; starting short and backing off keeps the 60s ceiling for an
/// indexer that is genuinely behind.
const MERKLE_PROOF_POLL_START: Duration = Duration::from_millis(25);
const MERKLE_PROOF_POLL_MAX: Duration = Duration::from_millis(500);

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

    /// Fetch the witnesses the inputs name and prove locally.
    ///
    /// The witnesses come from [`WitnessReader`], the one place that knows how
    /// to split real inputs from padding and which tree each is proven against;
    /// a second copy of that split here would be a second thing to keep in step
    /// with the circuit.
    pub fn prove_transact(
        &self,
        proof_inputs: SppProofInputs,
        authority: &dyn ProofAuthority,
    ) -> Result<TransactIxData, ClientError> {
        let commitments = proof_inputs.input_utxo_hashes()?;
        let witnesses = WitnessReader::input_witnesses(
            self,
            &commitments,
            &proof_inputs.dummy_nullifiers(),
            None,
        )?;
        ProverClient::local().prove_transact(
            proof_inputs,
            &witnesses.spend_proofs,
            &witnesses.dummy_nullifier_proofs,
            authority,
        )
    }
}

impl Rpc for ZolanaIndexer {
    fn should_retry(&self, error: &ClientError) -> bool {
        matches!(error, ClientError::IndexerUnavailable(_))
    }

    fn get_encrypted_utxos_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetEncryptedUtxosByTagsResponse, ClientError> {
        wait_for_indexer(
            config,
            |response: &GetEncryptedUtxosByTagsResponse| response.context,
            || {
                let response = self
                    .api
                    .get_encrypted_utxos_by_tags(
                        tags.iter().copied().map(encode_hash).collect(),
                        encode_cursor(cursor.clone()),
                        limit.map(u64::from),
                    )
                    .map_err(indexer_error)?;

                Ok(GetEncryptedUtxosByTagsResponse {
                    context: convert_context(response.context),
                    output_tree_id: response.output_tree_id,
                    matches: response
                        .matches
                        .into_iter()
                        .enumerate()
                        .map(|(index, item)| convert_encrypted_utxo_match(index, item))
                        .collect::<Result<Vec<_>, _>>()?,
                    next_cursor: response.next_cursor.map(Into::into),
                    scanned_through: response.scanned_through.map(Into::into),
                })
            },
        )
    }

    fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        wait_for_indexer(
            config,
            |response: &GetShieldedTransactionsByTagsResponse| response.context,
            || {
                let response = self
                    .api
                    .get_shielded_transactions_by_tags(
                        tags.iter().copied().map(encode_hash).collect(),
                        encode_cursor(cursor.clone()),
                        limit.map(u64::from),
                    )
                    .map_err(indexer_error)?;

                convert_shielded_transactions_response(response)
            },
        )
    }

    fn get_shielded_transactions_by_ring(
        &self,
        options: RingHistoryOptions,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        wait_for_indexer(
            config,
            |response: &GetShieldedTransactionsByTagsResponse| response.context,
            || {
                let response = self
                    .api
                    .get_shielded_transactions(ring_history_request(options.clone())?)
                    .map_err(indexer_error)?;
                convert_shielded_transactions_response(response)
            },
        )
    }

    fn get_shielded_transactions_by_signature(
        &self,
        signature: Signature,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsBySignatureResponse, ClientError> {
        wait_for_indexer(
            config,
            |response: &GetShieldedTransactionsBySignatureResponse| response.context,
            || {
                let response = self
                    .api
                    .get_shielded_transactions_by_signature(SerializableSignature(signature))
                    .map_err(indexer_error)?;

                convert_shielded_transactions_by_signature_response(response)
            },
        )
    }

    fn get_shielded_transactions_by_nullifiers(
        &self,
        nullifiers: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByNullifiersResponse, ClientError> {
        wait_for_indexer(
            config,
            |response: &GetShieldedTransactionsByNullifiersResponse| response.context,
            || {
                let response = self
                    .api
                    .get_shielded_transactions_by_nullifiers(
                        nullifiers.iter().copied().map(encode_hash).collect(),
                        encode_cursor(cursor.clone()),
                        limit.map(u64::from),
                    )
                    .map_err(indexer_error)?;

                Ok(GetShieldedTransactionsByNullifiersResponse {
                    context: convert_context(response.context),
                    output_tree_id: response.output_tree_id,
                    transactions: response
                        .transactions
                        .into_iter()
                        .enumerate()
                        .map(|(index, item)| {
                            convert_shielded_transaction(&format!("transactions[{index}]"), item)
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                    next_cursor: response.next_cursor.map(Into::into),
                    scanned_through: response.scanned_through.map(Into::into),
                })
            },
        )
    }

    fn get_merkle_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetMerkleProofsResponse, ClientError> {
        let single = || {
            let response = {
                let _t = crate::prover::timing::Phase::start("merkle_http", 0);
                self.api.get_merkle_proofs(
                    encode_pubkey(tree_account),
                    leaves.iter().copied().map(encode_hash).collect(),
                )
            };
            response
                .map_err(indexer_error)
                .map(|response| GetMerkleProofsResponse {
                    context: convert_context(response.context),
                    proofs: response
                        .proofs
                        .into_iter()
                        .map(convert_merkle_proof)
                        .collect(),
                })
        };

        // A caller that named a slot wants that guarantee, so honour it directly and
        // skip the completeness-polling path below.
        if let Some(config) = config.filter(|config| config.require_slot.is_some()) {
            return wait_for_indexer(
                Some(config),
                |response: &GetMerkleProofsResponse| response.context,
                single,
            );
        }

        let expected = leaves.len();
        let started = Instant::now();
        let mut last_error = None;
        let mut wait = MERKLE_PROOF_POLL_START;
        loop {
            match single() {
                Ok(response) if response.proofs.len() >= expected => return Ok(response),
                Ok(_) => {}
                Err(error) => last_error = Some(error),
            }
            if started.elapsed() >= MERKLE_PROOF_POLL_TIMEOUT {
                return Err(last_error.unwrap_or_else(|| {
                    ClientError::Rpc(format!(
                        "merkle proofs for {expected} leaves not indexed within {MERKLE_PROOF_POLL_TIMEOUT:?}"
                    ))
                }));
            }
            sleep(wait);
            wait = (wait * 2).min(MERKLE_PROOF_POLL_MAX);
        }
    }

    fn get_non_inclusion_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetNonInclusionProofsResponse, ClientError> {
        wait_for_indexer(
            config,
            |response: &GetNonInclusionProofsResponse| response.context,
            || {
                let response = self
                    .api
                    .get_non_inclusion_proofs(
                        encode_pubkey(tree_account),
                        leaves.iter().copied().map(encode_hash).collect(),
                    )
                    .map_err(indexer_error)?;

                Ok(GetNonInclusionProofsResponse {
                    context: convert_context(response.context),
                    proofs: response
                        .proofs
                        .into_iter()
                        .map(convert_non_inclusion_proof)
                        .collect(),
                })
            },
        )
    }

    fn get_ring_spend_record(
        &self,
        request: RingSpendRecordRequest,
    ) -> Result<GetRingSpendRecordResponse, ClientError> {
        self.api
            .get_ring_spend_record(request)
            .map_err(indexer_error)
    }

    fn get_ring_key_registry_entry(
        &self,
        request: RingMemberProofRequest,
    ) -> Result<GetRingKeyRegistryEntryResponse, ClientError> {
        self.api
            .get_ring_key_registry_entry(request)
            .map_err(indexer_error)
    }

    fn get_ring_key_registry_register_proof(
        &self,
        request: RingMemberProofRequest,
    ) -> Result<GetRingKeyRegistryRegisterProofResponse, ClientError> {
        self.api
            .get_ring_key_registry_register_proof(request)
            .map_err(indexer_error)
    }
}

fn wait_for_indexer<T>(
    config: Option<IndexerRpcConfig>,
    context: impl Fn(&T) -> Context,
    mut request: impl FnMut() -> Result<T, ClientError>,
) -> Result<T, ClientError> {
    let Some((config, required)) = config.and_then(|c| c.require_slot.map(|slot| (c, slot))) else {
        return request();
    };
    let mut indexed = 0;
    for delay in std::iter::once(Duration::ZERO).chain(config.poll.backoff()) {
        if !delay.is_zero() {
            sleep(delay);
        }
        let response = request()?;
        indexed = context(&response).slot;
        if indexed >= required {
            return Ok(response);
        }
    }
    Err(ClientError::IndexerNotCaughtUp {
        required,
        indexed,
        attempts: config.poll.num_retries.saturating_add(1),
    })
}
