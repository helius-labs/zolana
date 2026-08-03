//! The role table for the five protocol authority smart accounts.
//!
//! The localnet test harnesses create the five Squads `Settings` accounts in
//! one batch at consecutive seeds above the fixture `smart_account_index` (0)
//! and name them through this table.
//!
//! `xtask init-protocol` deploys the same five roles in the same order, but it
//! does not use this table: it creates each account against the *live* index
//! (`seed = smart_account_index + 1` per call), so the offsets below are
//! implied by its call order rather than shared with it. The two agree today;
//! deduplicating them means driving xtask's creation sequence from `Role::ALL`,
//! which is deliberately left out of this change because `init_protocol.rs`
//! has no tests and a wrong role order would misassign authorities on a live
//! deployment.
//!
//! Seed offsets:
//!
//! | role     | seed offset |
//! |----------|-------------|
//! | protocol | +1          |
//! | tree     | +2          |
//! | ring     | +3          |
//! | merge    | +4          |
//! | forester | +5          |
//!
//! This is the order `init-protocol` creates them, and therefore the order on
//! any persistent deployment it initialized; the localnet harnesses were
//! migrated from their historical protocol/forester/merge/tree/ring order to
//! match. xtask's `--resume` recovery path derives the batch as
//! `smart_account_index - 5` plus the same offsets.

use solana_pubkey::Pubkey;

use zolana_smart_account_client::{settings_pda, smart_account_pda};

/// One of the five protocol authority smart accounts, in creation order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Protocol,
    Tree,
    Ring,
    Merge,
    Forester,
}

impl Role {
    /// All roles in creation order; their seed offsets are `1..=5`.
    pub const ALL: [Role; 5] = [
        Role::Protocol,
        Role::Tree,
        Role::Ring,
        Role::Merge,
        Role::Forester,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Role::Protocol => "protocol",
            Role::Tree => "tree",
            Role::Ring => "ring",
            Role::Merge => "merge",
            Role::Forester => "forester",
        }
    }

    /// The role's seed offset within the batch (1-based; see the module table).
    pub fn seed_offset(self) -> u128 {
        match self {
            Role::Protocol => 1,
            Role::Tree => 2,
            Role::Ring => 3,
            Role::Merge => 4,
            Role::Forester => 5,
        }
    }

    /// The role's settings seed above `base_index` (the smart-account index
    /// before the batch was created; 0 for the localnet fixture).
    pub fn seed(self, base_index: u128) -> u128 {
        base_index + self.seed_offset()
    }

    /// The role's `Settings` PDA above `base_index`.
    pub fn settings_pda(self, base_index: u128) -> (Pubkey, u8) {
        settings_pda(self.seed(base_index))
    }

    /// The role's vault PDA (account index 0) above `base_index`: the address
    /// stored on-chain as the role's protocol authority.
    pub fn vault_pda(self, base_index: u128) -> (Pubkey, u8) {
        let (settings, _) = self.settings_pda(base_index);
        smart_account_pda(&settings, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_offsets_are_consecutive_in_creation_order() {
        let offsets: Vec<u128> = Role::ALL.iter().map(|role| role.seed_offset()).collect();
        assert_eq!(offsets, [1, 2, 3, 4, 5]);
        let labels: Vec<&str> = Role::ALL.iter().map(|role| role.label()).collect();
        assert_eq!(labels, ["protocol", "tree", "ring", "merge", "forester"]);
    }

    #[test]
    fn seeds_are_relative_to_the_base_index() {
        assert_eq!(Role::Protocol.seed(0), 1);
        assert_eq!(Role::Forester.seed(0), 5);
        assert_eq!(Role::Protocol.seed(40), 41);
        assert_eq!(Role::Forester.seed(40), 45);
        assert_eq!(Role::Protocol.settings_pda(0), settings_pda(1));
        assert_eq!(Role::Forester.settings_pda(40), settings_pda(45));
    }
}
