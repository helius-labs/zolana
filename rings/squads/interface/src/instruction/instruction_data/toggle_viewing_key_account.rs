//! `toggle_viewing_key_account` (tag 9) instruction data (spec: squads
//! `toggle_viewing_key_account`).

use wincode::{SchemaRead, SchemaWrite};

/// `toggle_viewing_key_account` instruction data (spec: squads
/// `toggle_viewing_key_account`). Sets the viewing key account's `state` to
/// block or unblock transfers and key updates. `state` values are the
/// `VIEWING_KEY_STATE_*` constants in `crate::constants`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct ToggleViewingKeyAccountIxData {
    /// New account state: active or transfers blocked.
    pub state: u8,
}

impl ToggleViewingKeyAccountIxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(bytes)?)
    }
}
