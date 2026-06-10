//! First-byte instruction dispatch tags for the shielded-pool program.
//!
//! Tag values are the on-chain wire format and MUST stay stable. They follow
//! the SPP spec's instruction table.

// === Implemented instructions (have a handler in the program dispatch) ===
pub const TRANSACT: u8 = 0;
pub const PROOFLESS_SHIELD: u8 = 1;
pub const CREATE_SPL_INTERFACE: u8 = 6;
pub const CREATE_POOL_TREE: u8 = 7;
pub const CREATE_PROTOCOL_CONFIG: u8 = 9;
pub const UPDATE_PROTOCOL_CONFIG: u8 = 10;
pub const PAUSE_TREE: u8 = 11;
pub const CREATE_POCKET_CONFIG: u8 = 12;
pub const UPDATE_POCKET_CONFIG_OWNER: u8 = 13;
pub const UPDATE_POCKET_CONFIG: u8 = 14;

/// Spec-reserved instruction tags that have **no handler** in the program.
///
/// These values are reserved by the SPP spec but are not dispatchable: the
/// program rejects them with `InvalidInstructionData` exactly like any unknown
/// byte, and there are no instruction-data types for them. They live in this
/// separate `reserved` namespace — rather than alongside the crate-level `tag::`
/// constants — so the top-level tag surface is exactly the shipped,
/// dispatchable instruction set. These only reserve their wire numbers so a
/// future implementation keeps the numbering stable.
pub mod reserved {
    pub const POCKET_TRANSACT: u8 = 2;
    pub const POCKET_AUTHORITY_TRANSACT: u8 = 3;
    pub const MERGE_TRANSACT: u8 = 15;
    pub const ENABLE_MERGE_AUTHORITY: u8 = 16;
    pub const DISABLE_MERGE_AUTHORITY: u8 = 17;
    pub const CREATE_MERGE_AUTHORITY_TREE: u8 = 18;
    pub const MERGE_POCKET: u8 = 19;
}

// === Forester tree maintenance ===
// Outside the SPP spec dispatch table; intentionally above the reserved
// proof/pocket tag range so they never collide with spec tags.
pub const BATCH_UPDATE_ADDRESS_TREE: u8 = 51;

/// Typed view of an *implemented* instruction tag.
///
/// Reserved-but-unimplemented spec tags (POCKET_TRANSACT, MERGE_*) are
/// deliberately not variants: they have no handler, so `try_from` returns `Err`
/// for them exactly like any unknown byte. This keeps the public surface to
/// what the program can actually dispatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum InstructionTag {
    CreatePoolTree = CREATE_POOL_TREE,
    BatchUpdateAddressTree = BATCH_UPDATE_ADDRESS_TREE,
    Transact = TRANSACT,
    ProoflessShield = PROOFLESS_SHIELD,
    CreateSplInterface = CREATE_SPL_INTERFACE,
    CreateProtocolConfig = CREATE_PROTOCOL_CONFIG,
    UpdateProtocolConfig = UPDATE_PROTOCOL_CONFIG,
    PauseTree = PAUSE_TREE,
    CreatePocketConfig = CREATE_POCKET_CONFIG,
    UpdatePocketConfigOwner = UPDATE_POCKET_CONFIG_OWNER,
    UpdatePocketConfig = UPDATE_POCKET_CONFIG,
}

impl TryFrom<u8> for InstructionTag {
    type Error = ();

    fn try_from(tag: u8) -> Result<Self, Self::Error> {
        match tag {
            CREATE_POOL_TREE => Ok(Self::CreatePoolTree),
            BATCH_UPDATE_ADDRESS_TREE => Ok(Self::BatchUpdateAddressTree),
            TRANSACT => Ok(Self::Transact),
            PROOFLESS_SHIELD => Ok(Self::ProoflessShield),
            CREATE_SPL_INTERFACE => Ok(Self::CreateSplInterface),
            CREATE_PROTOCOL_CONFIG => Ok(Self::CreateProtocolConfig),
            UPDATE_PROTOCOL_CONFIG => Ok(Self::UpdateProtocolConfig),
            PAUSE_TREE => Ok(Self::PauseTree),
            CREATE_POCKET_CONFIG => Ok(Self::CreatePocketConfig),
            UPDATE_POCKET_CONFIG_OWNER => Ok(Self::UpdatePocketConfigOwner),
            UPDATE_POCKET_CONFIG => Ok(Self::UpdatePocketConfig),
            _ => Err(()),
        }
    }
}
