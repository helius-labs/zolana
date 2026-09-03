//! The `[policy]` table as `new` writes it, a comment per source and per rule.

use toml_edit::{value, Array, ArrayOfTables, InlineTable, Item, Table};

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
    if let Some(tree) = spec.entries_tree {
        policy.insert("entries_tree", value(tree.0.to_string()));
        comment(
            &mut policy,
            "entries_tree",
            "every entry the rules read lives in the named tree",
        );
    }
    let mut sources = Table::new();
    sources.set_implicit(true);
    for target in Target::ALL {
        let map = spec.sources.get(target);
        if map.is_empty() {
            continue;
        }
        let mut cluster = Table::new();
        for (list, curator) in map {
            cluster.insert(list.as_str(), value(curator.0.to_string()));
            comment(
                &mut cluster,
                list.as_str(),
                &format!("the {list} list reads the entries of the named curator ring"),
            );
        }
        sources.insert(target.as_str(), Item::Table(cluster));
    }
    if !sources.is_empty() {
        policy.insert("sources", Item::Table(sources));
    }
    let mut rules = ArrayOfTables::new();
    let mut assets = Vec::new();
    for (index, rule) in spec.rules.iter().enumerate() {
        let row = rule.rule(index, &mut assets)?;
        let mut table = rule_table(rule, index)?;
        table
            .decor_mut()
            .set_prefix(format!("\n# {}\n", describe(&row)));
        rules.push(table);
    }
    if !rules.is_empty() {
        policy.insert("rules", Item::ArrayOfTables(rules));
    }
    Ok(policy)
}

fn rule_table(rule: &RuleSpec, index: usize) -> Result<Table, PolicyError> {
    let mut table = Table::new();
    table.insert("subject", value(rule.subject.as_str()));
    match &rule.source {
        SourceSpec::Require(list) => {
            table.insert("require", value(list.as_str()));
        }
        SourceSpec::Forbid(list) => {
            table.insert("forbid", value(list.as_str()));
        }
        SourceSpec::Any(alternatives) => {
            let any: Array = alternatives
                .iter()
                .map(|alternative| {
                    let (key, list) = match alternative {
                        Alternative::Require(list) => ("require", list),
                        Alternative::Forbid(list) => ("forbid", list),
                    };
                    let mut inline = InlineTable::new();
                    inline.insert(key, list.as_str().into());
                    inline
                })
                .collect();
            table.insert("any", value(any));
        }
        SourceSpec::Assets(mints) => {
            let assets: Array = mints.iter().map(|mint| mint.0.to_string()).collect();
            table.insert("assets", value(assets));
        }
    }
    if let Some(amount) = rule.above {
        let amount = i64::try_from(amount).map_err(|_| PolicyError::ThresholdTooLarge {
            rule: index,
            amount,
        })?;
        table.insert("above", value(amount));
    }
    Ok(table)
}

fn comment(table: &mut Table, key: &str, text: &str) {
    if let Some(mut key) = table.key_mut(key) {
        key.leaf_decor_mut().set_prefix(format!("# {text}\n"));
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
entries_tree = "{CURATOR}"

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
            "# every entry the rules read lives in the named tree\nentries_tree = ",
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
                "# No rule is pinned yet, `zolana-ring policy set` adds rules on a live ring.\n[policy]\n"
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
