/// First-byte instruction dispatch tags for the shielded-pool program.
pub const TRANSACT: u8 = 0;
pub const PROOFLESS_SHIELD: u8 = 1;
pub const POCKET_TRANSACT: u8 = 2;
pub const POCKET_AUTHORITY_TRANSACT: u8 = 3;
pub const CREATE_SPL_INTERFACE: u8 = 6;
pub const CREATE_POOL_TREE: u8 = 7;
pub const CREATE_PROTOCOL_CONFIG: u8 = 9;
pub const UPDATE_PROTOCOL_CONFIG: u8 = 10;
pub const PAUSE_TREE: u8 = 11;
pub const CREATE_POCKET_CONFIG: u8 = 12;
pub const UPDATE_POCKET_CONFIG_OWNER: u8 = 13;
pub const UPDATE_POCKET_CONFIG: u8 = 14;
pub const MERGE_TRANSACT: u8 = 15;
pub const ENABLE_MERGE_AUTHORITY: u8 = 16;
pub const DISABLE_MERGE_AUTHORITY: u8 = 17;
pub const CREATE_MERGE_AUTHORITY_TREE: u8 = 18;
pub const MERGE_POCKET: u8 = 19;

// Legacy/internal tree maintenance instructions. They are outside the SPP spec
// dispatch table and intentionally avoid the reserved proof/pocket tags.
pub const INSERT_ADDRESSES: u8 = 50;
pub const BATCH_UPDATE_ADDRESS_TREE: u8 = 51;
pub const APPEND_STATE_LEAVES: u8 = 52;
pub const BATCH_UPDATE_NULLIFIER_TREE: u8 = 53;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum InstructionTag {
    CreatePoolTree = CREATE_POOL_TREE,
    InsertAddresses = INSERT_ADDRESSES,
    BatchUpdateAddressTree = BATCH_UPDATE_ADDRESS_TREE,
    BatchUpdateNullifierTree = BATCH_UPDATE_NULLIFIER_TREE,
    AppendStateLeaves = APPEND_STATE_LEAVES,
    Transact = TRANSACT,
    ProoflessShield = PROOFLESS_SHIELD,
    PocketTransact = POCKET_TRANSACT,
    PocketAuthorityTransact = POCKET_AUTHORITY_TRANSACT,
    CreateSplInterface = CREATE_SPL_INTERFACE,
    CreateProtocolConfig = CREATE_PROTOCOL_CONFIG,
    UpdateProtocolConfig = UPDATE_PROTOCOL_CONFIG,
    PauseTree = PAUSE_TREE,
    CreatePocketConfig = CREATE_POCKET_CONFIG,
    UpdatePocketConfigOwner = UPDATE_POCKET_CONFIG_OWNER,
    UpdatePocketConfig = UPDATE_POCKET_CONFIG,
    MergeTransact = MERGE_TRANSACT,
    EnableMergeAuthority = ENABLE_MERGE_AUTHORITY,
    DisableMergeAuthority = DISABLE_MERGE_AUTHORITY,
    CreateMergeAuthorityTree = CREATE_MERGE_AUTHORITY_TREE,
    MergePocket = MERGE_POCKET,
}

impl TryFrom<u8> for InstructionTag {
    type Error = ();

    fn try_from(tag: u8) -> Result<Self, Self::Error> {
        match tag {
            CREATE_POOL_TREE => Ok(Self::CreatePoolTree),
            INSERT_ADDRESSES => Ok(Self::InsertAddresses),
            BATCH_UPDATE_ADDRESS_TREE => Ok(Self::BatchUpdateAddressTree),
            BATCH_UPDATE_NULLIFIER_TREE => Ok(Self::BatchUpdateNullifierTree),
            APPEND_STATE_LEAVES => Ok(Self::AppendStateLeaves),
            TRANSACT => Ok(Self::Transact),
            PROOFLESS_SHIELD => Ok(Self::ProoflessShield),
            POCKET_TRANSACT => Ok(Self::PocketTransact),
            POCKET_AUTHORITY_TRANSACT => Ok(Self::PocketAuthorityTransact),
            CREATE_SPL_INTERFACE => Ok(Self::CreateSplInterface),
            CREATE_PROTOCOL_CONFIG => Ok(Self::CreateProtocolConfig),
            UPDATE_PROTOCOL_CONFIG => Ok(Self::UpdateProtocolConfig),
            PAUSE_TREE => Ok(Self::PauseTree),
            CREATE_POCKET_CONFIG => Ok(Self::CreatePocketConfig),
            UPDATE_POCKET_CONFIG_OWNER => Ok(Self::UpdatePocketConfigOwner),
            UPDATE_POCKET_CONFIG => Ok(Self::UpdatePocketConfig),
            MERGE_TRANSACT => Ok(Self::MergeTransact),
            ENABLE_MERGE_AUTHORITY => Ok(Self::EnableMergeAuthority),
            DISABLE_MERGE_AUTHORITY => Ok(Self::DisableMergeAuthority),
            CREATE_MERGE_AUTHORITY_TREE => Ok(Self::CreateMergeAuthorityTree),
            MERGE_POCKET => Ok(Self::MergePocket),
            _ => Err(()),
        }
    }
}
