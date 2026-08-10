//! Events the Squads zone records with the `EMIT_EVENT` self-CPI.
//!
//! A key rotation and an account close both destroy viewing key material in
//! place while the ciphertexts it decrypts stay on chain forever. A recovery or
//! auditor key holder that was offline across the write has no other source for
//! the destroyed keys, so the full prior account state must reach the
//! inner-instruction log before the write.
//!
//! Instruction layout is `[EMIT_EVENT, kind, wincode(payload)]`. The payload
//! uses wincode because it embeds a [`ViewingKeyAccount`], whose on-chain
//! encoding is wincode.

use wincode::{config::DefaultConfig, SchemaRead, SchemaWrite};

use crate::{instruction::tag, state::viewing_key_account::ViewingKeyAccount, types::Address};

/// First payload byte after `EMIT_EVENT`. It names the emitting instruction so
/// an indexer dispatches the body without trial-parsing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SquadsEventKind {
    /// Body is a [`KeyRotationEvent`].
    KeyRotation = 1,
    /// Body is a [`ViewingKeyAccountClosedEvent`].
    ViewingKeyAccountClosed = 2,
}

impl SquadsEventKind {
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::KeyRotation),
            2 => Some(Self::ViewingKeyAccountClosed),
            _ => None,
        }
    }
}

/// The viewing key account as it stood before `execute_key_update` overwrote
/// it. `old_state_hash` is the rotation commitment the proof was bound to, and
/// `new_key_nonce` is the nonce the rotation wrote, so a consumer orders the
/// rotations of one account without replaying every transaction.
#[derive(SchemaWrite, SchemaRead, Clone, Debug, PartialEq, Eq)]
pub struct KeyRotationEvent {
    /// Address of the rotated account. `old_state.owner` is a hash for a smart
    /// account owner, so it cannot stand in for the account address.
    pub account: Address,
    pub old_state_hash: [u8; 32],
    pub new_key_nonce: u64,
    pub old_state: ViewingKeyAccount,
}

/// The viewing key account as it stood before `close_viewing_key_account`
/// zeroed it.
#[derive(SchemaWrite, SchemaRead, Clone, Debug, PartialEq, Eq)]
pub struct ViewingKeyAccountClosedEvent {
    pub account: Address,
    pub state: ViewingKeyAccount,
}

/// Encode an `EMIT_EVENT` instruction body: `[EMIT_EVENT, kind,
/// wincode(payload)]`.
pub fn encode_event_instruction<T>(
    kind: SquadsEventKind,
    payload: &T,
) -> Result<Vec<u8>, wincode::Error>
where
    T: SchemaWrite<DefaultConfig, Src = T>,
{
    let mut data = Vec::with_capacity(2 + wincode::serialized_size(payload)? as usize);
    data.push(tag::EMIT_EVENT);
    data.push(kind as u8);
    wincode::serialize_into(&mut data, payload)?;
    Ok(data)
}

/// Split an `EMIT_EVENT` instruction body into its kind and its undecoded
/// payload. Returns `None` when the first byte is not [`tag::EMIT_EVENT`] or
/// the kind byte names no known event.
pub fn split_event_instruction(data: &[u8]) -> Option<(SquadsEventKind, &[u8])> {
    let [tag::EMIT_EVENT, kind, payload @ ..] = data else {
        return None;
    };
    Some((SquadsEventKind::from_byte(*kind)?, payload))
}

impl KeyRotationEvent {
    pub fn deserialize(bytes: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(bytes)?)
    }
}

impl ViewingKeyAccountClosedEvent {
    pub fn deserialize(bytes: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(bytes)?)
    }
}
