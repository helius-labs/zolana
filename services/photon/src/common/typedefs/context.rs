use crate::api::error::PhotonApiError;
use crate::common::typedefs::unsigned_integer::UnsignedInteger;
use crate::dao::generated::blocks;
use crate::migration::Expr;
use sea_orm::{DatabaseConnection, EntityTrait, FromQueryResult, QuerySelect};
use serde::{Deserialize, Serialize};
use utoipa::openapi::{
    schema::{ObjectBuilder, Schema, Type},
    RefOr,
};
use utoipa::{PartialSchema, ToSchema};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, FromQueryResult, Default)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Context {
    pub slot: u64,
}

impl PartialSchema for Context {
    fn schema() -> RefOr<Schema> {
        let schema = Schema::Object(
            ObjectBuilder::new()
                .schema_type(Type::Object)
                .property("slot", UnsignedInteger::schema())
                .required("slot")
                .build(),
        );
        RefOr::T(schema)
    }
}

impl ToSchema for Context {}

#[derive(FromQueryResult)]
pub struct ContextModel {
    // Postgres and SQLite do not support u64 as return type. We validate after reading i64.
    pub slot: i64,
}

impl Context {
    pub async fn extract(db: &DatabaseConnection) -> Result<Self, PhotonApiError> {
        let context = blocks::Entity::find()
            .select_only()
            .column_as(Expr::col(blocks::Column::Slot).max(), "slot")
            .into_model::<ContextModel>()
            .one(db)
            .await?
            .ok_or(PhotonApiError::RecordNotFound(
                "No data has been indexed".to_string(),
            ))?;
        Ok(Context {
            slot: u64::try_from(context.slot).map_err(|_| {
                PhotonApiError::UnexpectedError(format!(
                    "Invalid negative slot in database: {}",
                    context.slot
                ))
            })?,
        })
    }
}
