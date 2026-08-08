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

/// Batch of `transact` legs settled against one recursive proof.
pub const AGGREGATE_TRANSACT: u8 = 18;

/// Run of consecutive nullifier-tree appends settled against one folded proof.
pub const BATCH_UPDATE_NULLIFIER_TREE_FOLDED: u8 = 19;

/// Tree of `merge` legs settled against one recursive proof.
pub const MERGE_CHAIN_TRANSACT: u8 = 20;

/// Permissionless one-time creation of a per-verifying-key registry
/// account. Only handled by a `vk-registry` program build. It is deliberately
/// not an [`InstructionTag`] variant so the default build's dispatch stays
/// untouched and a default program still rejects it as unknown.
pub const INIT_VK_REGISTRY: u8 = 21;

/// The next unused instruction tag.
///
/// Every byte below this one dispatches. A tag that is handled outside
/// [`InstructionTag`], as a feature-gated arm ahead of the enum match, still
/// consumes a byte. The arm runs first, so reusing a dispatched byte shadows
/// that instruction silently instead of failing to build. `NEXT_FREE_TAG` is
/// what such a tag takes.
pub const NEXT_FREE_TAG: u8 = 22;

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
    AggregateTransact = AGGREGATE_TRANSACT,
    BatchUpdateNullifierTreeFolded = BATCH_UPDATE_NULLIFIER_TREE_FOLDED,
    MergeChainTransact = MERGE_CHAIN_TRANSACT,
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
            AGGREGATE_TRANSACT => Ok(Self::AggregateTransact),
            BATCH_UPDATE_NULLIFIER_TREE_FOLDED => Ok(Self::BatchUpdateNullifierTreeFolded),
            MERGE_CHAIN_TRANSACT => Ok(Self::MergeChainTransact),
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `NEXT_FREE_TAG` is the first byte no instruction claims, and the tags
    /// below it are contiguous. A branch that adds a tag without moving this
    /// constant fails here rather than at the dispatch it would shadow.
    #[test]
    fn next_free_tag_is_the_first_unclaimed_byte() {
        for byte in (0..NEXT_FREE_TAG).filter(|byte| *byte != INIT_VK_REGISTRY) {
            assert!(
                InstructionTag::try_from(byte).is_ok(),
                "tag {byte} is below NEXT_FREE_TAG but dispatches to nothing"
            );
        }
        assert!(
            InstructionTag::try_from(NEXT_FREE_TAG).is_err(),
            "NEXT_FREE_TAG {NEXT_FREE_TAG} is already claimed"
        );
    }

    /// `INIT_VK_REGISTRY` dispatches ahead of the enum under a feature gate, so
    /// it claims its byte without being a variant. A variant added for it would
    /// make a default build accept the instruction it must reject.
    #[test]
    fn init_vk_registry_claims_its_byte_outside_the_enum() {
        const { assert!(INIT_VK_REGISTRY < NEXT_FREE_TAG) };
        assert!(InstructionTag::try_from(INIT_VK_REGISTRY).is_err());
    }
}
