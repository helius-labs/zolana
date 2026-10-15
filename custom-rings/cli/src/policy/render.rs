//! The `[policy]` table as `new` writes it, a comment per source and per rule.

use toml_edit::{value, Array, ArrayOfTables, InlineTable, Item, Table, Value};

use crate::{
    config::Target,
    policy::grammar::{describe, Alternative, PolicyError, PolicySpec, RuleSpec, SourceSpec},
};

/// Every row is compiled for its comment, a refused row stops the rendering.
pub fn render(spec: &PolicySpec) -> Result<Table, PolicyError> {
    let mut policy = Table::new();
    policy.decor_mut().set_prefix(if spec.rules.is_empty() {
        "\n# No rule is pinned yet, `zolana-ring policy set` adds rules on a live ring.\n"
    } else {
        "\n# Every rule below must hold, `zolana-ring policy set` replaces them on a live ring.\n"
    });
    let tree = spec.address_tree().to_string();
    let comment = "entry and spend record addresses are claimed in the named tree";
    commented(&mut policy, "address_tree", tree, comment);
    let mut sources = Table::new();
    sources.set_implicit(true);
    for target in Target::ALL {
        let mut cluster = Table::new();
        for (list, curator) in spec.sources.get(target) {
            let comment = format!("the {list} list reads the entries of the named curator ring");
            commented(&mut cluster, list.as_str(), curator.to_string(), &comment);
        }
        if !cluster.is_empty() {
            sources.insert(target.as_str(), Item::Table(cluster));
        }
    }
    if !sources.is_empty() {
        policy.insert("sources", Item::Table(sources));
    }
    if let Some(velocity) = &spec.velocity {
        let mut table = Table::new();
        table.decor_mut().set_prefix(
            "\n# A sender's outflow per mint, capped alone or over a window of slots.\n",
        );
        let too_large =
            |row, field| move |amount| PolicyError::VelocityTooLarge { row, field, amount };
        if velocity.window_slots != 0 {
            let slots = toml_int(velocity.window_slots, too_large(0, "window_slots"))?;
            table.insert("window_slots", value(slots));
        }
        let rows = velocity.rows.iter().enumerate().map(|(index, row)| {
            let cap = toml_int(row.cap, too_large(index, "cap"))?;
            let cosign = toml_int(row.cosign_above, too_large(index, "cosign_above"))?;
            let asset = row.asset.to_string();
            Ok(inline([
                ("asset", asset.into()),
                ("cap", cap.into()),
                ("cosign_above", cosign.into()),
            ]))
        });
        let rows: Array = rows.collect::<Result<_, PolicyError>>()?;
        table.insert("rows", value(rows));
        policy.insert("velocity", Item::Table(table));
    }
    let mut rules = ArrayOfTables::new();
    let (mut assets, mut limits) = (Vec::new(), Vec::new());
    for (index, rule) in spec.rules.iter().enumerate() {
        let row = rule.rule(index, &mut assets, &mut limits)?;
        let mut table = rule_table(rule, index)?;
        let comment = format!("\n# {}\n", describe(&row));
        table.decor_mut().set_prefix(comment);
        rules.push(table);
    }
    if !rules.is_empty() {
        policy.insert("rules", Item::ArrayOfTables(rules));
    }
    Ok(policy)
}

fn rule_table(spec: &RuleSpec, rule: usize) -> Result<Table, PolicyError> {
    let threshold = |amount| {
        toml_int(amount, |amount| PolicyError::ThresholdTooLarge {
            rule,
            amount,
        })
    };
    let mut table = Table::new();
    table.insert("subject", value(spec.subject.as_str()));
    let (key, source) = match &spec.source {
        SourceSpec::Require(list) => ("require", value(list.as_str())),
        SourceSpec::Forbid(list) => ("forbid", value(list.as_str())),
        SourceSpec::Any(alternatives) => {
            let any = alternatives.iter().map(|alternative| {
                let key = match alternative {
                    Alternative::Require(_) => "require",
                    Alternative::Forbid(_) => "forbid",
                };
                inline([(key, alternative.list().as_str().into())])
            });
            ("any", value(any.collect::<Array>()))
        }
        SourceSpec::Assets(mints) => (
            "assets",
            value(mints.iter().map(ToString::to_string).collect::<Array>()),
        ),
    };
    table.insert(key, source);
    if let Some(amount) = spec.above {
        table.insert("above", value(threshold(amount)?));
    }
    if let Some(limits) = &spec.limits {
        let limits = limits.iter().map(|limit| {
            let above = threshold(limit.above)?;
            Ok(inline([
                ("asset", limit.asset.to_string().into()),
                ("above", above.into()),
            ]))
        });
        let limits: Array = limits.collect::<Result<_, PolicyError>>()?;
        table.insert("limits", value(limits));
    }
    Ok(table)
}

fn inline<const N: usize>(pairs: [(&str, Value); N]) -> InlineTable {
    pairs.into_iter().collect()
}

fn toml_int(value: u64, too_large: impl FnOnce(u64) -> PolicyError) -> Result<i64, PolicyError> {
    i64::try_from(value).map_err(|_| too_large(value))
}

fn commented(table: &mut Table, key: &str, text: String, comment: &str) {
    table.insert(key, value(text));
    if let Some(mut key) = table.key_mut(key) {
        key.leaf_decor_mut().set_prefix(format!("# {comment}\n"));
    }
}

#[cfg(test)]
mod tests {
    use zolana_ring_policy::{ListId, ListSet, Rule, Subject};

    use super::*;
    use crate::config::Target;

    const CURATOR: &str = "9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh";
    const MINT: &str = "So11111111111111111111111111111111111111112";

    fn document(spec: &PolicySpec) -> String {
        let mut document = toml_edit::DocumentMut::new();
        document.insert("policy", Item::Table(render(spec).expect("renders")));
        document.to_string()
    }

    #[test]
    fn the_rendered_table_carries_a_comment_per_rule_and_per_source_and_reads_back() {
        let spec: PolicySpec = toml::from_str(&format!(
            r#"
address_tree = "{CURATOR}"

[sources.devnet]
block = "{CURATOR}"

[[rules]]
subject = "output-owner"
any = [{{ forbid = "block" }}, {{ require = "approval" }}]

[[rules]]
subject = "asset"
assets = ["{MINT}"]

[[rules]]
subject = "output-owner"
require = "allow"
above = 1000000
"#
        ))
        .expect("parses");
        let text = document(&spec);
        for expected in [
            "# entry and spend record addresses are claimed in the named tree\naddress_tree = ",
            "[policy.sources.devnet]\n# the block list reads the entries of the named curator ring\nblock = ",
            "# each output owner must be on the approval list or must not be on the block list\n[[policy.rules]]\nsubject = \"output-owner\"\nany = [{ forbid = \"block\" }, { require = \"approval\" }]\n",
            "# each asset must be one of the listed assets\n[[policy.rules]]\nsubject = \"asset\"\nassets = [",
            "when the amount is above 1000000\n[[policy.rules]]\nsubject = \"output-owner\"\nrequire = \"allow\"\nabove = 1000000\n",
        ] {
            assert!(text.contains(expected), "{expected:?} in\n{text}");
        }
        #[derive(serde::Deserialize)]
        struct Document {
            policy: PolicySpec,
        }
        let read: Document = toml::from_str(&text).expect("reads back");
        assert_eq!(read.policy, spec);
        let compiled = read.policy.compile(Target::Devnet).expect("compiles");
        assert_eq!(
            compiled.rules,
            spec.compile(Target::Devnet).expect("compiles").rules
        );
        assert_eq!(
            compiled.rules.rules()[0],
            Rule::any_of(
                Subject::OutputOwner,
                ListSet::single(ListId::Approval),
                ListSet::single(ListId::Block)
            )
        );
    }

    #[test]
    fn an_empty_table_says_no_rule_is_pinned() {
        let text = document(&PolicySpec::default());
        assert!(
            text.contains(
                "# No rule is pinned yet, `zolana-ring policy set` adds rules on a live ring.\n[policy]\n# entry and spend record addresses are claimed in the named tree\naddress_tree = "
            ),
            "{text}"
        );
        assert!(!text.contains("Every rule below"));
    }

    #[test]
    fn a_threshold_past_the_toml_integer_range_is_refused() {
        let spec = PolicySpec {
            rules: vec![RuleSpec {
                subject: crate::policy::SubjectName::OutputOwner,
                source: SourceSpec::Require("allow".parse().expect("list")),
                above: Some(u64::MAX),
                limits: None,
            }],
            ..Default::default()
        };
        assert_eq!(
            render(&spec).err(),
            Some(PolicyError::ThresholdTooLarge {
                rule: 0,
                amount: u64::MAX
            })
        );
    }
}
