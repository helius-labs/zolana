//! Every ring circuit and its proving key, no verifying keys.
use crate::{
    disclosure::{AnonymousAuditKey, DisclosureLayout},
    member_registry::APPLY_BATCH,
    transact::RingRail,
};

pub use crate::ring_keys::RING_KEYS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RingCircuit {
    PackedAudit {
        outputs: u8,
    },
    DeliveredAudit {
        outputs: u8,
    },
    AnonymousAudit {
        class: u8,
        outputs: u8,
    },
    /// Opens every spent UTXO, the key of a transfer spending a default-ring note.
    AnonymousEntryAudit {
        class: u8,
        outputs: u8,
    },
    /// A statement bit reads the sender.
    MemberPolicy {
        outputs: u8,
    },
    DelegatePolicy {
        inputs: u8,
        outputs: u8,
    },
    ApplyRecords {
        writes: u8,
    },
    RegisterKey,
    Deposit,
    AnonymousMerge {
        width: u8,
    },
}

impl RingCircuit {
    pub const fn audit(layout: DisclosureLayout, n_out: u8) -> Self {
        match layout {
            DisclosureLayout::Packed(_) => Self::PackedAudit { outputs: n_out },
            DisclosureLayout::Delivered(_) => Self::DeliveredAudit { outputs: n_out },
            DisclosureLayout::Anonymous(layout) => {
                let class = layout.key.class() as u8;
                match layout.key {
                    AnonymousAuditKey::Commitment { .. } => Self::AnonymousAudit {
                        class,
                        outputs: n_out,
                    },
                    AnonymousAuditKey::Entry => Self::AnonymousEntryAudit {
                        class,
                        outputs: n_out,
                    },
                }
            }
        }
    }

    pub const fn policy(rail: RingRail, n_in: u8, n_out: u8) -> Self {
        match rail {
            RingRail::Confidential | RingRail::Anonymous => Self::MemberPolicy { outputs: n_out },
            RingRail::Delegate => Self::DelegatePolicy {
                inputs: n_in,
                outputs: n_out,
            },
        }
    }

    pub const fn apply_records(pending: u64) -> Self {
        Self::ApplyRecords {
            writes: if pending == 1 { 1 } else { APPLY_BATCH as u8 },
        }
    }
}

/// `name` is the prover's circuit name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingKey {
    pub circuit: RingCircuit,
    pub name: &'static str,
}

impl RingKey {
    pub fn file_name(self) -> String {
        format!("{}.key", self.name.replace('-', "_"))
    }

    /// The release lock section, `custom-ring-audit-packed-2` reads `audit_packed_2_key`.
    pub fn section(self) -> String {
        let stem = self.name.strip_prefix(NAME_PREFIX).unwrap_or(self.name);
        key_suffixed(&stem.replace('-', "_"), "_")
    }

    pub fn asset(self, tag: &str) -> String {
        format!("{}-{tag}.key", key_suffixed(self.name, "-"))
    }
}

const NAME_PREFIX: &str = "custom-ring-";

/// One `key` suffix, a name that already ends in key takes none.
fn key_suffixed(name: &str, separator: &str) -> String {
    match name.ends_with("key") {
        true => name.to_owned(),
        false => format!("{name}{separator}key"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_names_carry_one_key_suffix() {
        let packed = RingKey {
            circuit: RingCircuit::PackedAudit { outputs: 2 },
            name: "custom-ring-audit-packed-2",
        };
        let register = RingKey {
            circuit: RingCircuit::RegisterKey,
            name: "custom-ring-register-key",
        };
        assert_eq!(packed.file_name(), "custom_ring_audit_packed_2.key");
        assert_eq!(packed.section(), "audit_packed_2_key");
        assert_eq!(packed.asset("v5"), "custom-ring-audit-packed-2-key-v5.key");
        assert_eq!(register.section(), "register_key");
        assert_eq!(register.asset("v5"), "custom-ring-register-key-v5.key");
    }
}
