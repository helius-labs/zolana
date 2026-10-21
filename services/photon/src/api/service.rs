use std::sync::Arc;
#[cfg(feature = "custom-rings")]
use zolana_indexer_api::{
    method::{
        GetRingApplyProofInputs, GetRingMemberOpenings, GetRingMemberRecord, GetRingMemberRecords,
        GetRingMemberRegistryRoot, GetRingRecordQueue,
    },
    GetRingApplyProofInputsRequest, GetRingApplyProofInputsResponse, GetRingMemberOpeningsRequest,
    GetRingMemberOpeningsResponse, GetRingMemberRecordRequest, GetRingMemberRecordResponse,
    GetRingMemberRecordsRequest, GetRingMemberRecordsResponse, GetRingMemberRegistryRootRequest,
    GetRingMemberRegistryRootResponse, GetRingRecordQueueRequest, GetRingRecordQueueResponse,
};

use crate::api::root_index_cache::RootIndexCache;
#[cfg(feature = "custom-rings")]
use crate::custom_rings::member_registry;
use crate::rpc::RpcClient;
use sea_orm::{ConnectionTrait, DatabaseConnection, Statement};
use utoipa::openapi::{RefOr, Schema};
use utoipa::PartialSchema;
use zolana_indexer_api::{
    method::{
        GetEncryptedUtxosByTags, GetMerkleProofs, GetNonInclusionProofs, GetNullifierQueueElements,
        GetShieldedTransactionsByNullifiers, GetShieldedTransactionsBySignature,
        GetShieldedTransactionsByTags, GetUserRecords,
    },
    GetEncryptedUtxosByTagsResponse, GetMerkleProofsRequest, GetMerkleProofsResponse,
    GetNonInclusionProofsRequest, GetNonInclusionProofsResponse, GetNullifierQueueElementsRequest,
    GetNullifierQueueElementsResponse, GetRingsByNullifiersRequest, GetRingsByTagsRequest,
    GetShieldedTransactionsByNullifiersResponse, GetShieldedTransactionsBySignatureRequest,
    GetShieldedTransactionsBySignatureResponse, GetShieldedTransactionsByTagsResponse,
    GetUserRecordsRequest, GetUserRecordsResponse, RpcMethod,
};

use super::{
    error::PhotonApiError,
    method::{
        get_indexer_health::get_indexer_health,
        get_indexer_slot::get_indexer_slot,
        rings::{
            get_encrypted_utxos_by_tags, get_merkle_proofs, get_non_inclusion_proofs,
            get_nullifier_queue_elements, get_shielded_transactions_by_nullifiers,
            get_shielded_transactions_by_signature, get_shielded_transactions_by_tags,
            get_user_records,
        },
    },
};
pub struct PhotonApi {
    #[cfg(feature = "custom-rings")]
    custom_rings: bool,
    db_conn: Arc<DatabaseConnection>,
    rpc_client: Arc<RpcClient>,
    root_index_cache: Arc<RootIndexCache>,
}

pub struct OpenApiSpec {
    pub name: &'static str,
    pub request: RefOr<Schema>,
    pub response: RefOr<Schema>,
}

fn method_api_spec<M>() -> OpenApiSpec
where
    M: RpcMethod,
    M::Request: PartialSchema,
    M::Response: PartialSchema,
{
    OpenApiSpec {
        name: M::NAME,
        request: M::Request::schema(),
        response: M::Response::schema(),
    }
}

impl PhotonApi {
    pub fn new(db_conn: Arc<DatabaseConnection>, rpc_client: Arc<RpcClient>) -> Self {
        Self {
            #[cfg(feature = "custom-rings")]
            custom_rings: true,
            db_conn,
            rpc_client,
            root_index_cache: Arc::new(RootIndexCache::new()),
        }
    }

    /// Serve the shielded pool methods only.
    #[cfg(feature = "custom-rings")]
    #[must_use]
    pub fn without_custom_rings(mut self) -> Self {
        self.custom_rings = false;
        self
    }

    #[cfg(feature = "custom-rings")]
    pub(crate) fn custom_rings_enabled(&self) -> bool {
        self.custom_rings
    }

    /// Start the task that keeps the root-index ring current.
    ///
    /// Without it the ring is only refreshed when a request asks for a newly
    /// indexed root, and that account fetch is then the largest single cost of
    /// the request. Callers that only serve reads of other methods can skip it;
    /// the on-miss path still answers correctly, just slowly.
    pub fn spawn_root_index_refresher(&self) -> tokio::task::JoinHandle<()> {
        let cache = Arc::clone(&self.root_index_cache);
        let db = Arc::clone(&self.db_conn);
        let rpc_client = Arc::clone(&self.rpc_client);
        tokio::spawn(async move { cache.refresh_loop(db.as_ref(), rpc_client.as_ref()).await })
    }

    pub async fn liveness(&self) -> Result<(), PhotonApiError> {
        Ok(())
    }

    pub async fn readiness(&self) -> Result<(), PhotonApiError> {
        self.db_conn
            .execute(Statement::from_string(
                self.db_conn.as_ref().get_database_backend(),
                "SELECT 1".to_string(),
            ))
            .await
            .map(|_| ())
            .map_err(Into::into)
    }

    pub async fn get_indexer_health(&self) -> Result<String, PhotonApiError> {
        get_indexer_health(self.db_conn.as_ref(), &self.rpc_client).await
    }

    pub async fn get_indexer_slot(&self) -> Result<u64, PhotonApiError> {
        get_indexer_slot(self.db_conn.as_ref()).await
    }

    pub async fn get_encrypted_utxos_by_tags(
        &self,
        request: GetRingsByTagsRequest,
    ) -> Result<GetEncryptedUtxosByTagsResponse, PhotonApiError> {
        get_encrypted_utxos_by_tags(self.db_conn.as_ref(), request).await
    }

    pub async fn get_shielded_transactions_by_tags(
        &self,
        request: GetRingsByTagsRequest,
    ) -> Result<GetShieldedTransactionsByTagsResponse, PhotonApiError> {
        get_shielded_transactions_by_tags(self.db_conn.as_ref(), request).await
    }

    pub async fn get_shielded_transactions_by_signature(
        &self,
        request: GetShieldedTransactionsBySignatureRequest,
    ) -> Result<GetShieldedTransactionsBySignatureResponse, PhotonApiError> {
        get_shielded_transactions_by_signature(self.db_conn.as_ref(), request).await
    }

    pub async fn get_shielded_transactions_by_nullifiers(
        &self,
        request: GetRingsByNullifiersRequest,
    ) -> Result<GetShieldedTransactionsByNullifiersResponse, PhotonApiError> {
        get_shielded_transactions_by_nullifiers(self.db_conn.as_ref(), request).await
    }

    pub async fn get_merkle_proofs(
        &self,
        request: GetMerkleProofsRequest,
    ) -> Result<GetMerkleProofsResponse, PhotonApiError> {
        get_merkle_proofs(
            self.db_conn.as_ref(),
            &self.rpc_client,
            &self.root_index_cache,
            request,
        )
        .await
    }

    pub async fn get_non_inclusion_proofs(
        &self,
        request: GetNonInclusionProofsRequest,
    ) -> Result<GetNonInclusionProofsResponse, PhotonApiError> {
        get_non_inclusion_proofs(self.db_conn.as_ref(), request).await
    }

    pub async fn get_nullifier_queue_elements(
        &self,
        request: GetNullifierQueueElementsRequest,
    ) -> Result<GetNullifierQueueElementsResponse, PhotonApiError> {
        get_nullifier_queue_elements(self.db_conn.as_ref(), request).await
    }

    pub async fn get_user_records(
        &self,
        request: GetUserRecordsRequest,
    ) -> Result<GetUserRecordsResponse, PhotonApiError> {
        get_user_records(self.db_conn.as_ref(), &self.rpc_client, request).await
    }

    #[cfg(feature = "custom-rings")]
    pub async fn get_ring_member_record(
        &self,
        request: GetRingMemberRecordRequest,
    ) -> Result<GetRingMemberRecordResponse, PhotonApiError> {
        member_registry::member_record(&self.db_conn, &self.rpc_client, request).await
    }

    #[cfg(feature = "custom-rings")]
    pub async fn get_ring_member_records(
        &self,
        request: GetRingMemberRecordsRequest,
    ) -> Result<GetRingMemberRecordsResponse, PhotonApiError> {
        member_registry::member_records(&self.db_conn, &self.rpc_client, request).await
    }

    #[cfg(feature = "custom-rings")]
    pub async fn get_ring_member_openings(
        &self,
        request: GetRingMemberOpeningsRequest,
    ) -> Result<GetRingMemberOpeningsResponse, PhotonApiError> {
        member_registry::member_openings(&self.db_conn, &self.rpc_client, request).await
    }

    #[cfg(feature = "custom-rings")]
    pub async fn get_ring_member_registry_root(
        &self,
        request: GetRingMemberRegistryRootRequest,
    ) -> Result<GetRingMemberRegistryRootResponse, PhotonApiError> {
        member_registry::registry_root(&self.db_conn, &self.rpc_client, request).await
    }

    #[cfg(feature = "custom-rings")]
    pub async fn get_ring_record_queue(
        &self,
        request: GetRingRecordQueueRequest,
    ) -> Result<GetRingRecordQueueResponse, PhotonApiError> {
        member_registry::record_queue(&self.db_conn, &self.rpc_client, request).await
    }

    #[cfg(feature = "custom-rings")]
    pub async fn get_ring_apply_proof_inputs(
        &self,
        request: GetRingApplyProofInputsRequest,
    ) -> Result<GetRingApplyProofInputsResponse, PhotonApiError> {
        member_registry::apply_proof_inputs(&self.db_conn, &self.rpc_client, request).await
    }

    pub fn rings_method_api_specs() -> Vec<OpenApiSpec> {
        vec![
            method_api_spec::<GetEncryptedUtxosByTags>(),
            method_api_spec::<GetShieldedTransactionsBySignature>(),
            method_api_spec::<GetShieldedTransactionsByTags>(),
            method_api_spec::<GetShieldedTransactionsByNullifiers>(),
            method_api_spec::<GetMerkleProofs>(),
            method_api_spec::<GetNonInclusionProofs>(),
            method_api_spec::<GetNullifierQueueElements>(),
            method_api_spec::<GetUserRecords>(),
            #[cfg(feature = "custom-rings")]
            method_api_spec::<GetRingMemberRecord>(),
            #[cfg(feature = "custom-rings")]
            method_api_spec::<GetRingMemberRecords>(),
            #[cfg(feature = "custom-rings")]
            method_api_spec::<GetRingMemberOpenings>(),
            #[cfg(feature = "custom-rings")]
            method_api_spec::<GetRingMemberRegistryRoot>(),
            #[cfg(feature = "custom-rings")]
            method_api_spec::<GetRingRecordQueue>(),
            #[cfg(feature = "custom-rings")]
            method_api_spec::<GetRingApplyProofInputs>(),
        ]
    }
}
