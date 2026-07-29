//! The role table for the five protocol authority smart accounts.
//!
//! `xtask init-protocol` creates the five Squads `Settings` accounts in one
//! batch at consecutive seeds above the smart-account program's current
//! `smart_account_index`; the localnet harnesses create the same batch above
//! the fixture index 0. Both sides name accounts through this table, so a
//! role's seed offset is defined exactly once:
//!
//! | role     | seed offset |
//! |----------|-------------|
//! | protocol | +1          |
//! | tree     | +2          |
//! | zone     | +3          |
//! | merge    | +4          |
//! | forester | +5          |
//!
//! This is the order `init-protocol` creates them (and therefore the order on
//! any persistent deployment it initialized); the localnet harnesses were
//! migrated from their historical protocol/forester/merge/tree/zone order to
//! match. The `--resume` recovery path derives the batch as
//! `smart_account_index - 5` plus these offsets, so the table also pins what
//! resume expects to find.

use solana_pubkey::Pubkey;

use crate::{settings_pda, smart_account_pda};

/// One of the five protocol authority smart accounts, in creation order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Protocol,
    Tree,
    Zone,
    Merge,
    Forester,
}

impl Role {
    /// All roles in creation order; their seed offsets are `1..=5`.
    pub const ALL: [Role; 5] = [
        Role::Protocol,
        Role::Tree,
        Role::Zone,
        Role::Merge,
        Role::Forester,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Role::Protocol => "protocol",
            Role::Tree => "tree",
            Role::Zone => "zone",
            Role::Merge => "merge",
            Role::Forester => "forester",
        }
    }

    /// The role's seed offset within the batch (1-based; see the module table).
    pub fn seed_offset(self) -> u128 {
        match self {
            Role::Protocol => 1,
            Role::Tree => 2,
            Role::Zone => 3,
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
        assert_eq!(labels, ["protocol", "tree", "zone", "merge", "forester"]);
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
