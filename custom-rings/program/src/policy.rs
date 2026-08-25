use zolana_ring_policy::{Policy, RecordKind, Rule, Subject};

/// The table hash is pinned at `create_policy`, a drifted build fails every
/// mutation closed.
pub const POLICY: Policy = Policy::builder()
    .rule_if(
        cfg!(feature = "allowlist"),
        Rule::require(Subject::OutputOwner, RecordKind::Allow),
    )
    .rule_if(
        cfg!(feature = "allowlist"),
        Rule::require(Subject::Sender, RecordKind::Allow),
    )
    .rule_if(
        cfg!(feature = "blocklist"),
        Rule::forbid(Subject::OutputOwner, RecordKind::Block),
    )
    .rule_if(
        cfg!(feature = "freeze"),
        Rule::forbid(Subject::Sender, RecordKind::Frozen),
    )
    .build();
