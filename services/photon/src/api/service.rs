use std::sync::Arc;

use sea_orm::{ConnectionTrait, DatabaseConnection, Statement};
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use utoipa::openapi::{RefOr, Schema};
use utoipa::PartialSchema;
use zolana_indexer_api::{
    method::{
        GetEncryptedUtxosByTags, GetMerkleProofs, GetNonInclusionProofs, GetNullifierQueueElements,
        GetShieldedTransactionsByTags,
    },
    GetEncryptedUtxosByTagsResponse, GetMerkleProofsRequest, GetMerkleProofsResponse,
    GetNonInclusionProofsRequest, GetNonInclusionProofsResponse, GetNullifierQueueElementsRequest,
    GetNullifierQueueElementsResponse, GetRingsByTagsRequest,
    GetShieldedTransactionsByTagsResponse, RpcMethod,
};

use super::{
    error::PhotonApiError,
    method::{
        get_indexer_health::get_indexer_health,
        get_indexer_slot::get_indexer_slot,
        rings::{
            get_encrypted_utxos_by_tags, get_merkle_proofs, get_non_inclusion_proofs,
            get_nullifier_queue_elements, get_shielded_transactions_by_tags,
        },
    },
};
pub struct PhotonApi {
    db_conn: Arc<DatabaseConnection>,
    rpc_client: Arc<RpcClient>,
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
            db_conn,
            rpc_client,
        }
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

    pub async fn get_merkle_proofs(
        &self,
        request: GetMerkleProofsRequest,
    ) -> Result<GetMerkleProofsResponse, PhotonApiError> {
        get_merkle_proofs(self.db_conn.as_ref(), request).await
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

    pub fn rings_method_api_specs() -> Vec<OpenApiSpec> {
        vec![
            method_api_spec::<GetEncryptedUtxosByTags>(),
            method_api_spec::<GetShieldedTransactionsByTags>(),
            method_api_spec::<GetMerkleProofs>(),
            method_api_spec::<GetNonInclusionProofs>(),
            method_api_spec::<GetNullifierQueueElements>(),
        ]
    }
}
