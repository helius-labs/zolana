//! First-byte instruction dispatch tags for the Squads zone program.

pub const TRANSACT: u8 = 0;
pub const DEPOSIT: u8 = 1;
pub const MERGE_TRANSACT: u8 = 2;
pub const CREATE_ZONE_CONFIG: u8 = 3;
pub const UPDATE_ZONE_CONFIG: u8 = 4;
pub const CREATE_VIEWING_KEY_ACCOUNT: u8 = 5;
pub const UPDATE_VIEWING_KEY_ACCOUNT: u8 = 6;
pub const FILL_KEY_UPDATE: u8 = 7;
pub const CLOSE_VIEWING_KEY_ACCOUNT: u8 = 8;
pub const TOGGLE_VIEWING_KEY_ACCOUNT: u8 = 9;
pub const FULL_WITHDRAWAL: u8 = 10;
pub const CREATE_PROPOSAL: u8 = 11;
pub const CANCEL_PROPOSAL: u8 = 12;
pub const EXECUTE_PROPOSAL: u8 = 13;
pub const EXECUTE_KEY_UPDATE: u8 = 14;
pub const CANCEL_KEY_UPDATE: u8 = 15;
pub const INIT_SPP_ZONE_CONFIG: u8 = 16;

/// Implemented instruction tags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum InstructionTag {
    Transact = TRANSACT,
    Deposit = DEPOSIT,
    MergeTransact = MERGE_TRANSACT,
    CreateZoneConfig = CREATE_ZONE_CONFIG,
    UpdateZoneConfig = UPDATE_ZONE_CONFIG,
    CreateViewingKeyAccount = CREATE_VIEWING_KEY_ACCOUNT,
    UpdateViewingKeyAccount = UPDATE_VIEWING_KEY_ACCOUNT,
    FillKeyUpdate = FILL_KEY_UPDATE,
    CloseViewingKeyAccount = CLOSE_VIEWING_KEY_ACCOUNT,
    ToggleViewingKeyAccount = TOGGLE_VIEWING_KEY_ACCOUNT,
    FullWithdrawal = FULL_WITHDRAWAL,
    CreateProposal = CREATE_PROPOSAL,
    CancelProposal = CANCEL_PROPOSAL,
    ExecuteProposal = EXECUTE_PROPOSAL,
    ExecuteKeyUpdate = EXECUTE_KEY_UPDATE,
    CancelKeyUpdate = CANCEL_KEY_UPDATE,
    InitSppZoneConfig = INIT_SPP_ZONE_CONFIG,
}

impl TryFrom<u8> for InstructionTag {
    type Error = ();

    fn try_from(tag: u8) -> Result<Self, Self::Error> {
        match tag {
            TRANSACT => Ok(Self::Transact),
            DEPOSIT => Ok(Self::Deposit),
            MERGE_TRANSACT => Ok(Self::MergeTransact),
            CREATE_ZONE_CONFIG => Ok(Self::CreateZoneConfig),
            UPDATE_ZONE_CONFIG => Ok(Self::UpdateZoneConfig),
            CREATE_VIEWING_KEY_ACCOUNT => Ok(Self::CreateViewingKeyAccount),
            UPDATE_VIEWING_KEY_ACCOUNT => Ok(Self::UpdateViewingKeyAccount),
            FILL_KEY_UPDATE => Ok(Self::FillKeyUpdate),
            CLOSE_VIEWING_KEY_ACCOUNT => Ok(Self::CloseViewingKeyAccount),
            TOGGLE_VIEWING_KEY_ACCOUNT => Ok(Self::ToggleViewingKeyAccount),
            FULL_WITHDRAWAL => Ok(Self::FullWithdrawal),
            CREATE_PROPOSAL => Ok(Self::CreateProposal),
            CANCEL_PROPOSAL => Ok(Self::CancelProposal),
            EXECUTE_PROPOSAL => Ok(Self::ExecuteProposal),
            EXECUTE_KEY_UPDATE => Ok(Self::ExecuteKeyUpdate),
            CANCEL_KEY_UPDATE => Ok(Self::CancelKeyUpdate),
            INIT_SPP_ZONE_CONFIG => Ok(Self::InitSppZoneConfig),
            _ => Err(()),
        }
    }
}
