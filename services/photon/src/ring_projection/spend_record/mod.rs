pub(super) mod parser;

use anyhow::{anyhow, Result};
use custom_ring_interface::instruction::tag;
use sea_orm::{
    ConnectionTrait, DatabaseConnection, DatabaseTransaction, QueryResult, TransactionTrait,
};
use serde::{Deserialize, Serialize};
use solana_pubkey::Pubkey;
use solana_signature::{Signature, SIGNATURE_BYTES};
use zolana_indexer_api::{
    GetRingSpendRecordResponse, RingSpendRecord, RingSpendRecordRequest, SerializableSignature,
};
use zolana_ring_key_registry::FIELD_MAX;

use super::{
    api::{canonical_context, internal},
    fault,
    storage::{self, statement, ProjectionCursor},
    BlockEnv, Invocation, ProjectError,
};
use crate::{
    api::{
        error::{PhotonApiError, RingProjectionError},
        method::rings::shielded_transaction_at,
        set_transaction_isolation_if_needed,
    },
    rpc::RpcClient,
};
use parser::Rail;

pub(super) const TAGS: [u8; 2] = [tag::REGISTER_SPEND, tag::TRANSACT];

const RINGS_TABLE: &str = "ring_spend_record_rings";
const RECORDS_TABLE: &str = "ring_spend_records";
const RECORD_COLUMNS: &str = "member,nullifier,signature,event_index,output_index,slot";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RecordRow {
    pub member: [u8; 32],
    /// Revealed by the transfer that spends the record.
    pub nullifier: [u8; 32],
    pub signature: SerializableSignature,
    pub event_index: u16,
    pub output_index: u16,
    pub slot: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) enum SpendUndo {
    Opened {
        program: [u8; 32],
    },
    Quarantined {
        program: [u8; 32],
    },
    Recorded {
        program: [u8; 32],
        member: [u8; 32],
        before: Option<RecordRow>,
    },
}

/// A quarantined ring serves no records until a rollback clears the fault.
pub(crate) struct SpendRing {
    pub fault: Option<String>,
}

pub(super) enum Update {
    Register(RecordRow),
    Transfer {
        spent: RecordRow,
        successor: RecordRow,
    },
}

impl Update {
    pub(super) async fn apply(
        self,
        store: &SpendStore<'_, DatabaseTransaction>,
    ) -> Result<Option<SpendUndo>, ProjectError> {
        let (successor, before) = match self {
            Self::Register(successor) => match store.record(&successor.member).await? {
                // A replayed registration is already applied.
                Some(existing) if existing == successor => return Ok(None),
                Some(_) => return Err(fault("member registered twice")),
                None => (successor, None),
            },
            Self::Transfer { spent, successor } => {
                if spent.member != successor.member {
                    return Err(fault("transfer successor belongs to another member"));
                }
                (successor, Some(spent))
            }
        };
        store.save(&successor).await?;
        Ok(Some(SpendUndo::Recorded {
            program: store.program,
            member: successor.member,
            before,
        }))
    }
}

pub(super) async fn restore(tx: &DatabaseTransaction, undos: &[SpendUndo]) -> Result<()> {
    for undo in undos.iter().rev() {
        match undo {
            SpendUndo::Opened { program } => SpendStore::new(tx, *program).close().await?,
            SpendUndo::Quarantined { program } => {
                SpendStore::new(tx, *program).set_fault(None).await?
            }
            SpendUndo::Recorded {
                program,
                member,
                before,
            } => {
                let store = SpendStore::new(tx, *program);
                match before {
                    Some(row) => store.save(row).await?,
                    None => store.delete(member).await?,
                }
            }
        }
    }
    Ok(())
}

pub(crate) async fn lookup(
    db: &DatabaseConnection,
    rpc: &RpcClient,
    request: RingSpendRecordRequest,
) -> Result<GetRingSpendRecordResponse, PhotonApiError> {
    if request.member.0 == [0; 32] || request.member.0 >= FIELD_MAX {
        return Err(PhotonApiError::ValidationError(
            "invalid spend record member".into(),
        ));
    }
    let tx = db.begin().await?;
    set_transaction_isolation_if_needed(&tx).await?;
    let cursor = storage::cursor(&tx)
        .await
        .map_err(internal)?
        .filter(ProjectionCursor::is_ready)
        .ok_or_else(|| out_of_sync("projector is catching up or recovering"))?;
    let program = request.ring_program_id.0.to_bytes();
    if storage::pending_ring(&tx, &program)
        .await
        .map_err(internal)?
        .is_some()
    {
        return Err(out_of_sync("ring history is being replayed"));
    }
    let store = SpendStore::new(&tx, program);
    let row = match store.ring().await.map_err(internal)? {
        None => None,
        Some(SpendRing {
            fault: Some(reason),
        }) => return Err(out_of_sync(format!("ring quarantined, {reason}"))),
        Some(SpendRing { fault: None }) => {
            store.record(&request.member.0).await.map_err(internal)?
        }
    };
    let record = match row {
        Some(row) => {
            let transaction = shielded_transaction_at(
                &tx,
                <[u8; SIGNATURE_BYTES]>::from(row.signature.0),
                row.event_index,
            )
            .await?
            .ok_or_else(|| out_of_sync("record transaction is not indexed yet"))?;
            Some(RingSpendRecord {
                transaction,
                output_index: row.output_index,
            })
        }
        None => None,
    };
    tx.commit().await?;
    let context = canonical_context(rpc, cursor.tip.as_ref())
        .await
        .map_err(out_of_sync)?;
    Ok(GetRingSpendRecordResponse { context, record })
}

pub(super) struct SpendStore<'c, C> {
    conn: &'c C,
    program: [u8; 32],
}

impl<'c, C: ConnectionTrait> SpendStore<'c, C> {
    pub fn new(conn: &'c C, program: [u8; 32]) -> Self {
        Self { conn, program }
    }

    pub async fn ring(&self) -> Result<Option<SpendRing>> {
        self.conn
            .query_one(statement(
                self.conn,
                &format!("SELECT fault FROM {RINGS_TABLE} WHERE program=$1"),
                vec![self.program.to_vec().into()],
            ))
            .await?
            .map(|row| {
                Ok(SpendRing {
                    fault: row.try_get("", "fault")?,
                })
            })
            .transpose()
    }

    pub async fn open(&self) -> Result<SpendUndo> {
        self.conn
            .execute(statement(
                self.conn,
                &format!("INSERT INTO {RINGS_TABLE}(program,fault) VALUES($1,NULL)"),
                vec![self.program.to_vec().into()],
            ))
            .await?;
        Ok(SpendUndo::Opened {
            program: self.program,
        })
    }

    pub async fn quarantine(&self, reason: String) -> Result<SpendUndo> {
        log::warn!(
            "spend records of ring {} quarantined ({reason})",
            solana_pubkey::Pubkey::new_from_array(self.program)
        );
        self.set_fault(Some(reason)).await?;
        Ok(SpendUndo::Quarantined {
            program: self.program,
        })
    }

    async fn set_fault(&self, fault: Option<String>) -> Result<()> {
        self.conn
            .execute(statement(
                self.conn,
                &format!("UPDATE {RINGS_TABLE} SET fault=$2 WHERE program=$1"),
                vec![self.program.to_vec().into(), fault.into()],
            ))
            .await?;
        Ok(())
    }

    async fn close(&self) -> Result<()> {
        for table in [RECORDS_TABLE, RINGS_TABLE] {
            self.conn
                .execute(statement(
                    self.conn,
                    &format!("DELETE FROM {table} WHERE program=$1"),
                    vec![self.program.to_vec().into()],
                ))
                .await?;
        }
        Ok(())
    }

    pub async fn record(&self, member: &[u8; 32]) -> Result<Option<RecordRow>> {
        self.conn
            .query_one(statement(
                self.conn,
                &format!(
                    "SELECT {RECORD_COLUMNS} FROM {RECORDS_TABLE} WHERE program=$1 AND member=$2"
                ),
                vec![self.program.to_vec().into(), member.to_vec().into()],
            ))
            .await?
            .as_ref()
            .map(record_row)
            .transpose()
    }

    /// The member record among `nullifiers`, at most one per transfer.
    pub async fn spent_by(
        &self,
        nullifiers: &[[u8; 32]],
    ) -> Result<Option<RecordRow>, ProjectError> {
        if nullifiers.is_empty() {
            return Ok(None);
        }
        let placeholders = (2..nullifiers.len() + 2)
            .map(|index| format!("${index}"))
            .collect::<Vec<_>>()
            .join(",");
        let mut values = vec![self.program.to_vec().into()];
        values.extend(nullifiers.iter().map(|nullifier| nullifier.to_vec().into()));
        let spent = self
            .conn
            .query_all(statement(
                self.conn,
                &format!(
                    "SELECT {RECORD_COLUMNS} FROM {RECORDS_TABLE} \
                     WHERE program=$1 AND nullifier IN ({placeholders})"
                ),
                values,
            ))
            .await?
            .iter()
            .map(record_row)
            .collect::<Result<Vec<_>>>()?;
        match <[RecordRow; 1]>::try_from(spent) {
            Ok([spent]) => Ok(Some(spent)),
            Err(spent) if spent.is_empty() => Ok(None),
            Err(_) => Err(fault("transfer spent several spend records")),
        }
    }

    pub async fn save(&self, row: &RecordRow) -> Result<()> {
        self.conn
            .execute(statement(
                self.conn,
                &format!(
                    "INSERT INTO {RECORDS_TABLE}(program,{RECORD_COLUMNS}) \
                     VALUES($1,$2,$3,$4,$5,$6,$7) \
                     ON CONFLICT(program,member) DO UPDATE SET nullifier=excluded.nullifier,\
                     signature=excluded.signature,event_index=excluded.event_index,\
                     output_index=excluded.output_index,slot=excluded.slot"
                ),
                vec![
                    self.program.to_vec().into(),
                    row.member.to_vec().into(),
                    row.nullifier.to_vec().into(),
                    <[u8; SIGNATURE_BYTES]>::from(row.signature.0)
                        .to_vec()
                        .into(),
                    i32::from(row.event_index).into(),
                    i32::from(row.output_index).into(),
                    i64::try_from(row.slot)?.into(),
                ],
            ))
            .await?;
        Ok(())
    }

    async fn delete(&self, member: &[u8; 32]) -> Result<()> {
        self.conn
            .execute(statement(
                self.conn,
                &format!("DELETE FROM {RECORDS_TABLE} WHERE program=$1 AND member=$2"),
                vec![self.program.to_vec().into(), member.to_vec().into()],
            ))
            .await?;
        Ok(())
    }
}

impl SpendStore<'_, DatabaseTransaction> {
    /// A transfer is a record update only when it spends a record held here.
    pub(super) async fn advance(
        &self,
        invocation: &Invocation<'_>,
        env: &mut BlockEnv<'_>,
    ) -> Result<Option<SpendUndo>, ProjectError> {
        let Some(rail) = parser::decode(invocation.instruction).map_err(invalid)? else {
            return Ok(None);
        };
        let event = parser::event(invocation).map_err(invalid)?;
        let spent = match rail {
            Rail::Register { .. } => None,
            Rail::Transfer => {
                let nullifiers = event
                    .nullifiers
                    .iter()
                    .map(|input| input.nullifier)
                    .collect::<Vec<_>>();
                let Some(spent) = self.spent_by(&nullifiers).await? else {
                    return Ok(None);
                };
                Some(spent)
            }
        };
        let policy = env.policy(&invocation.instruction.program_id).await?;
        let output_tree_id = env
            .tree_id(&Pubkey::new_from_array(event.output_tree))
            .await?;
        let successor = parser::Reconstruction {
            invocation,
            rail,
            event: &event,
            policy: &policy,
            output_tree_id,
        }
        .reconstruct()
        .map_err(invalid)?;
        let successor = RecordRow {
            member: successor.member,
            nullifier: successor.nullifier,
            signature: event.signature.into(),
            event_index: u16::try_from(event.event_index).map_err(|error| invalid(error.into()))?,
            output_index: successor.output_index,
            slot: event.slot,
        };
        match spent {
            Some(spent) => Update::Transfer { spent, successor },
            None => Update::Register(successor),
        }
        .apply(self)
        .await
    }
}

fn record_row(row: &QueryResult) -> Result<RecordRow> {
    let bytes = |column: &str| -> Result<Vec<u8>> { Ok(row.try_get("", column)?) };
    let hash = |column: &str| -> Result<[u8; 32]> {
        bytes(column)?
            .try_into()
            .map_err(|_| anyhow!("stored {column} is not 32 bytes"))
    };
    let signature: [u8; SIGNATURE_BYTES] = bytes("signature")?
        .try_into()
        .map_err(|_| anyhow!("stored signature has the wrong length"))?;
    Ok(RecordRow {
        member: hash("member")?,
        nullifier: hash("nullifier")?,
        signature: Signature::from(signature).into(),
        event_index: u16::try_from(row.try_get::<i32>("", "event_index")?)?,
        output_index: u16::try_from(row.try_get::<i32>("", "output_index")?)?,
        slot: u64::try_from(row.try_get::<i64>("", "slot")?)?,
    })
}

fn invalid(error: anyhow::Error) -> ProjectError {
    fault(format!("{error:#}"))
}

fn out_of_sync(reason: impl std::fmt::Display) -> PhotonApiError {
    RingProjectionError::SpendRecordOutOfSync(reason.to_string()).into()
}

#[cfg(test)]
mod tests;
