//! First-byte instruction dispatch tags for the shielded-pool program.

// Administrative and maintenance instructions.
pub const CREATE_PROTOCOL_CONFIG: u8 = 0;
pub const UPDATE_PROTOCOL_CONFIG: u8 = 1;
pub const CREATE_TREE: u8 = 2;
pub const PAUSE_TREE: u8 = 3;
pub const BATCH_UPDATE_NULLIFIER_TREE: u8 = 4;
pub const CREATE_ASSET_COUNTER: u8 = 5;
pub const CREATE_SPL_INTERFACE: u8 = 6;
pub const CREATE_RING_CONFIG: u8 = 7;
pub const UPDATE_RING_CONFIG: u8 = 8;
pub const UPDATE_RING_CONFIG_OWNER: u8 = 9;

/// No-op self-CPI target used to log events as inner-instruction data. The
/// program performs no validation on this tag, so ANY program can CPI the
/// shielded pool with `EMIT_EVENT` and forged payload bytes. Consumers MUST
/// only trust an `EMIT_EVENT` inner instruction whose direct parent
/// (reconstructed via `stack_height`) is a shielded-pool instruction with a
/// state-transitioning tag (never `EMIT_EVENT` itself) -- see photon's
/// `rings_event_parser::is_event_source` for the reference filter.
pub const EMIT_EVENT: u8 = 10;

// Default-ring instructions.
pub const DEPOSIT: u8 = 11;
pub const TRANSACT: u8 = 12;
pub const MERGE_TRANSACT: u8 = 13;

// Policy-ring instructions.
pub const RING_DEPOSIT: u8 = 14;
pub const RING_TRANSACT: u8 = 15;
pub const RING_MERGE_TRANSACT: u8 = 16;
pub const RING_AUTHORITY_TRANSACT: u8 = 17;

// Forester maintenance, gated by `protocol_config.forester_authority` like
// `BATCH_UPDATE_NULLIFIER_TREE`.
pub const CLOSE_NULLIFIER_PDAS: u8 = 18;

// Administration, continued.
pub const SET_TREE_FEES: u8 = 19;

/// Implemented instruction tags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum InstructionTag {
    CreateProtocolConfig = CREATE_PROTOCOL_CONFIG,
    UpdateProtocolConfig = UPDATE_PROTOCOL_CONFIG,
    CreateTree = CREATE_TREE,
    PauseTree = PAUSE_TREE,
    BatchUpdateNullifierTree = BATCH_UPDATE_NULLIFIER_TREE,
    CreateAssetCounter = CREATE_ASSET_COUNTER,
    CreateSplInterface = CREATE_SPL_INTERFACE,
    CreateRingConfig = CREATE_RING_CONFIG,
    UpdateRingConfig = UPDATE_RING_CONFIG,
    UpdateRingConfigOwner = UPDATE_RING_CONFIG_OWNER,
    EmitEvent = EMIT_EVENT,
    Deposit = DEPOSIT,
    Transact = TRANSACT,
    MergeTransact = MERGE_TRANSACT,
    RingDeposit = RING_DEPOSIT,
    RingTransact = RING_TRANSACT,
    RingMergeTransact = RING_MERGE_TRANSACT,
    RingAuthorityTransact = RING_AUTHORITY_TRANSACT,
    CloseNullifierPdas = CLOSE_NULLIFIER_PDAS,
    SetTreeFees = SET_TREE_FEES,
}

impl TryFrom<u8> for InstructionTag {
    type Error = ();

    fn try_from(tag: u8) -> Result<Self, Self::Error> {
        match tag {
            CREATE_PROTOCOL_CONFIG => Ok(Self::CreateProtocolConfig),
            UPDATE_PROTOCOL_CONFIG => Ok(Self::UpdateProtocolConfig),
            CREATE_TREE => Ok(Self::CreateTree),
            PAUSE_TREE => Ok(Self::PauseTree),
            BATCH_UPDATE_NULLIFIER_TREE => Ok(Self::BatchUpdateNullifierTree),
            CREATE_ASSET_COUNTER => Ok(Self::CreateAssetCounter),
            CREATE_SPL_INTERFACE => Ok(Self::CreateSplInterface),
            CREATE_RING_CONFIG => Ok(Self::CreateRingConfig),
            UPDATE_RING_CONFIG => Ok(Self::UpdateRingConfig),
            UPDATE_RING_CONFIG_OWNER => Ok(Self::UpdateRingConfigOwner),
            EMIT_EVENT => Ok(Self::EmitEvent),
            DEPOSIT => Ok(Self::Deposit),
            TRANSACT => Ok(Self::Transact),
            MERGE_TRANSACT => Ok(Self::MergeTransact),
            RING_DEPOSIT => Ok(Self::RingDeposit),
            RING_TRANSACT => Ok(Self::RingTransact),
            RING_MERGE_TRANSACT => Ok(Self::RingMergeTransact),
            RING_AUTHORITY_TRANSACT => Ok(Self::RingAuthorityTransact),
            CLOSE_NULLIFIER_PDAS => Ok(Self::CloseNullifierPdas),
            SET_TREE_FEES => Ok(Self::SetTreeFees),
            _ => Err(()),
        }
    }
}
