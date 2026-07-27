//! First-byte instruction dispatch tags for the shielded-pool program.

pub const TRANSACT: u8 = 0;
pub const DEPOSIT: u8 = 1;
pub const ZONE_TRANSACT: u8 = 2;
pub const ZONE_AUTHORITY_TRANSACT: u8 = 3;
pub const CREATE_SPL_INTERFACE: u8 = 4;
pub const CREATE_TREE: u8 = 5;
pub const CREATE_PROTOCOL_CONFIG: u8 = 6;
pub const UPDATE_PROTOCOL_CONFIG: u8 = 7;
pub const PAUSE_TREE: u8 = 8;
pub const CREATE_ZONE_CONFIG: u8 = 9;
pub const UPDATE_ZONE_CONFIG_OWNER: u8 = 10;
pub const UPDATE_ZONE_CONFIG: u8 = 11;
pub const MERGE_TRANSACT: u8 = 12;
pub const ZONE_MERGE_TRANSACT: u8 = 13;
/// No-op self-CPI target used to log events as inner-instruction data. The
/// program performs no validation on this tag, so ANY program can CPI the
/// shielded pool with `EMIT_EVENT` and forged payload bytes. Consumers MUST
/// only trust an `EMIT_EVENT` inner instruction whose direct parent
/// (reconstructed via `stack_height`) is a shielded-pool instruction with a
/// state-transitioning tag (never `EMIT_EVENT` itself) -- see photon's
/// `rings_event_parser::is_event_source` for the reference filter.
pub const EMIT_EVENT: u8 = 14;
pub const ZONE_DEPOSIT: u8 = 15;
pub const CREATE_ASSET_COUNTER: u8 = 16;

pub const BATCH_UPDATE_NULLIFIER_TREE: u8 = 51;
pub const BATCH_UPDATE_NULLIFIER_TREE_MANY: u8 = 52;

/// Implemented instruction tags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum InstructionTag {
    Transact = TRANSACT,
    ZoneTransact = ZONE_TRANSACT,
    ZoneAuthorityTransact = ZONE_AUTHORITY_TRANSACT,
    CreateTree = CREATE_TREE,
    BatchUpdateNullifierTree = BATCH_UPDATE_NULLIFIER_TREE,
    BatchUpdateNullifierTreeMany = BATCH_UPDATE_NULLIFIER_TREE_MANY,
    Deposit = DEPOSIT,
    CreateSplInterface = CREATE_SPL_INTERFACE,
    CreateProtocolConfig = CREATE_PROTOCOL_CONFIG,
    UpdateProtocolConfig = UPDATE_PROTOCOL_CONFIG,
    PauseTree = PAUSE_TREE,
    CreateZoneConfig = CREATE_ZONE_CONFIG,
    UpdateZoneConfigOwner = UPDATE_ZONE_CONFIG_OWNER,
    UpdateZoneConfig = UPDATE_ZONE_CONFIG,
    MergeTransact = MERGE_TRANSACT,
    ZoneMergeTransact = ZONE_MERGE_TRANSACT,
    EmitEvent = EMIT_EVENT,
    ZoneDeposit = ZONE_DEPOSIT,
    CreateAssetCounter = CREATE_ASSET_COUNTER,
}

impl TryFrom<u8> for InstructionTag {
    type Error = ();

    fn try_from(tag: u8) -> Result<Self, Self::Error> {
        match tag {
            TRANSACT => Ok(Self::Transact),
            ZONE_TRANSACT => Ok(Self::ZoneTransact),
            ZONE_AUTHORITY_TRANSACT => Ok(Self::ZoneAuthorityTransact),
            CREATE_TREE => Ok(Self::CreateTree),
            BATCH_UPDATE_NULLIFIER_TREE => Ok(Self::BatchUpdateNullifierTree),
            BATCH_UPDATE_NULLIFIER_TREE_MANY => Ok(Self::BatchUpdateNullifierTreeMany),
            DEPOSIT => Ok(Self::Deposit),
            CREATE_SPL_INTERFACE => Ok(Self::CreateSplInterface),
            CREATE_PROTOCOL_CONFIG => Ok(Self::CreateProtocolConfig),
            UPDATE_PROTOCOL_CONFIG => Ok(Self::UpdateProtocolConfig),
            PAUSE_TREE => Ok(Self::PauseTree),
            CREATE_ZONE_CONFIG => Ok(Self::CreateZoneConfig),
            UPDATE_ZONE_CONFIG_OWNER => Ok(Self::UpdateZoneConfigOwner),
            UPDATE_ZONE_CONFIG => Ok(Self::UpdateZoneConfig),
            MERGE_TRANSACT => Ok(Self::MergeTransact),
            ZONE_MERGE_TRANSACT => Ok(Self::ZoneMergeTransact),
            EMIT_EVENT => Ok(Self::EmitEvent),
            ZONE_DEPOSIT => Ok(Self::ZoneDeposit),
            CREATE_ASSET_COUNTER => Ok(Self::CreateAssetCounter),
            _ => Err(()),
        }
    }
}
