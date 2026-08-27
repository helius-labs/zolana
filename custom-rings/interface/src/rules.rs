use zolana_ring_policy::{ListId, Rule, RuleTable, Subject};

/// The table hash is pinned at `create_policy`, a drifted build fails every
/// mutation closed.
pub const RULES: RuleTable = RuleTable::builder()
    .rule_if(
        cfg!(feature = "allowlist"),
        Rule::require(Subject::OutputOwner, ListId::Allow),
    )
    .rule_if(
        cfg!(feature = "allowlist"),
        Rule::require(Subject::Sender, ListId::Allow),
    )
    .rule_if(
        cfg!(feature = "blocklist"),
        Rule::forbid(Subject::OutputOwner, ListId::Block),
    )
    .rule_if(
        cfg!(feature = "freeze"),
        Rule::forbid(Subject::Sender, ListId::Frozen),
    )
    .build();
