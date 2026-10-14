pub(super) mod parser;

use anyhow::{anyhow, Result};
use sea_orm::{ConnectionTrait, DatabaseConnection, DatabaseTransaction, QueryResult, Value};
use serde::{Deserialize, Serialize};
use solana_pubkey::Pubkey;
use solana_signature::{Signature, SIGNATURE_BYTES};
use zolana_indexer_api::{
    GetRingSpendRecordResponse, RingSpendRecord, RingSpendRecordRequest, SerializableSignature,
};
use zolana_ring_key_registry::FIELD_MAX;

use super::{
    api::{canonical_context, internal, ready, validation},
    fault,
    storage::{int, Store},
    BlockEnv, Invocation, ProjectError,
};
use crate::{
    api::{
        error::{PhotonApiError, RingProjectionError},
        method::rings::shielded_transaction_at,
    },
    rpc::RpcClient,
};
use parser::Rail;

const RECORD_COLUMNS: &str = "member,nullifier,signature,event_index,output_index,slot";
const DELETE_RECORD: &str = "DELETE FROM ring_spend_records WHERE program=$1 AND member=$2";

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
        store: &Store<'_, DatabaseTransaction>,
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
        store.save_record(&successor).await?;
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
            SpendUndo::Opened { program } => {
                let tables = ["ring_spend_records", "ring_spend_record_rings"];
                Store::new(tx, *program).delete_rows(&tables).await?
            }
            SpendUndo::Quarantined { program } => {
                Store::new(tx, *program).set_records_fault(None).await?
            }
            SpendUndo::Recorded {
                program,
                member,
                before,
            } => {
                let store = Store::new(tx, *program);
                match before {
                    Some(row) => store.save_record(row).await?,
                    None => {
                        store
                            .exec(DELETE_RECORD, vec![member.to_vec().into()])
                            .await?
                    }
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
        return Err(validation("invalid spend record member"));
    }
    let program = request.ring_program_id.0.to_bytes();
    let (tx, cursor) = ready(db, &program, RingProjectionError::SpendRecordOutOfSync).await?;
    let store = Store::new(&tx, program);
    let row = match store.records_fault().await.map_err(internal)? {
        None => None,
        Some(Some(reason)) => return Err(out_of_sync(format!("ring quarantined, {reason}"))),
        Some(None) => store.record(&request.member.0).await.map_err(internal)?,
    };
    let record = match row {
        Some(row) => Some(RingSpendRecord {
            transaction: shielded_transaction_at(&tx, row.signature.0.into(), row.event_index)
                .await?
                .ok_or_else(|| out_of_sync("record transaction is not indexed yet"))?,
            output_index: row.output_index,
        }),
        None => None,
    };
    tx.commit().await?;
    let context = canonical_context(rpc, cursor.tip.as_ref())
        .await
        .map_err(out_of_sync)?;
    Ok(GetRingSpendRecordResponse { context, record })
}

impl<C: ConnectionTrait> Store<'_, C> {
    /// `None` until the ring's first registration, then the fault that quarantines its records.
    pub async fn records_fault(&self) -> Result<Option<Option<String>>> {
        let sql = "SELECT fault FROM ring_spend_record_rings WHERE program=$1";
        let row = self.conn.query_one(self.statement(sql, vec![])).await?;
        Ok(row.map(|row| row.try_get("", "fault")).transpose()?)
    }

    pub async fn open_records(&self) -> Result<SpendUndo> {
        let sql = "INSERT INTO ring_spend_record_rings(program,fault) VALUES($1,NULL)";
        self.exec(sql, vec![]).await?;
        Ok(SpendUndo::Opened {
            program: self.program,
        })
    }

    pub async fn quarantine_records(&self, reason: String) -> Result<SpendUndo> {
        let program = Pubkey::new_from_array(self.program);
        log::warn!("spend records of ring {program} quarantined ({reason})");
        self.set_records_fault(Some(reason)).await?;
        Ok(SpendUndo::Quarantined {
            program: self.program,
        })
    }

    async fn set_records_fault(&self, fault: Option<String>) -> Result<()> {
        let sql = "UPDATE ring_spend_record_rings SET fault=$2 WHERE program=$1";
        self.exec(sql, vec![fault.into()]).await
    }

    pub async fn record(&self, member: &[u8; 32]) -> Result<Option<RecordRow>> {
        Ok(self
            .records("member=$2", vec![member.to_vec().into()])
            .await?
            .pop())
    }

    async fn records(&self, filter: &str, values: Vec<Value>) -> Result<Vec<RecordRow>> {
        let columns = RECORD_COLUMNS;
        let sql = format!("SELECT {columns} FROM ring_spend_records WHERE program=$1 AND {filter}");
        let rows = self.conn.query_all(self.statement(&sql, values)).await?;
        rows.iter().map(record_row).collect()
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
        let values = nullifiers.iter().map(|nullifier| nullifier.to_vec().into());
        let filter = format!("nullifier IN ({placeholders})");
        let spent = self.records(&filter, values.collect()).await?;
        match <[RecordRow; 1]>::try_from(spent) {
            Ok([spent]) => Ok(Some(spent)),
            Err(spent) if spent.is_empty() => Ok(None),
            Err(_) => Err(fault("transfer spent several spend records")),
        }
    }

    pub async fn save_record(&self, row: &RecordRow) -> Result<()> {
        let sql = format!(
            "INSERT INTO ring_spend_records(program,{RECORD_COLUMNS}) VALUES($1,$2,$3,$4,$5,$6,$7) \
             ON CONFLICT(program,member) DO UPDATE SET nullifier=excluded.nullifier,\
             signature=excluded.signature,event_index=excluded.event_index,\
             output_index=excluded.output_index,slot=excluded.slot"
        );
        let values = vec![
            row.member.to_vec().into(),
            row.nullifier.to_vec().into(),
            <[u8; SIGNATURE_BYTES]>::from(row.signature.0)
                .to_vec()
                .into(),
            i32::from(row.event_index).into(),
            i32::from(row.output_index).into(),
            int(row.slot)?,
        ];
        self.exec(&sql, values).await
    }
}

impl Store<'_, DatabaseTransaction> {
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
                let nullifiers: Vec<_> = event
                    .nullifiers
                    .iter()
                    .map(|input| input.nullifier)
                    .collect();
                match self.spent_by(&nullifiers).await? {
                    None => return Ok(None),
                    spent => spent,
                }
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
