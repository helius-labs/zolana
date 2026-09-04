//! The worked examples under `custom-rings/examples`, each a `ring.toml` the cli loads.

use std::path::{Path, PathBuf};

use zolana_ring_policy::{Guard, RuleSource};

use crate::{
    config::{RingConfig, Target},
    file,
    new::read_policy,
    policy::{SourceSpec, SubjectName},
};

const EXAMPLES: [&str; 7] = [
    "audit-only",
    "empty-policy",
    "own-blocklist",
    "curated-blocklist-approval-exception",
    "allowlist",
    "asset-allowlist-owner-threshold",
    "token-blocklist",
];

fn path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../examples")
        .join(name)
        .join("ring.toml")
}

#[derive(Default)]
struct Forms {
    require: bool,
    forbid: bool,
    any: bool,
    asset_list: bool,
    assets: bool,
    above: bool,
    per_cluster_source: bool,
    entries_tree: bool,
    empty_table: bool,
    audit_only: bool,
}

#[test]
fn every_example_loads_and_compiles_on_both_clusters() {
    let mut forms = Forms::default();
    for name in EXAMPLES {
        let path = path(name);
        let config: RingConfig =
            file::parse_toml(&path).unwrap_or_else(|error| panic!("{name} parses, {error}"));
        assert_eq!(config.name, name);
        let Some(policy) = config.policy.as_ref() else {
            assert!(read_policy(&path).is_err(), "{name} holds no policy table");
            forms.audit_only = true;
            continue;
        };
        // The path `new --policy-from` takes.
        let from_file = read_policy(&path)
            .unwrap_or_else(|error| panic!("{name} loads as a policy file, {error}"));
        assert_eq!(&from_file, policy, "{name}");
        for target in Target::ALL {
            let compiled = policy
                .compile(target)
                .unwrap_or_else(|error| panic!("{name} compiles on {target:?}, {error}"));
            assert_eq!(compiled.rules.rules().len(), policy.rules.len());
            for rule in compiled.rules.rules() {
                forms.above |= matches!(rule.guard, Guard::AboveAmount(_));
                forms.above |= matches!(rule.guard, Guard::AboveAmountByAsset);
                forms.assets |= matches!(rule.source, RuleSource::InlineAssets);
            }
            forms.assets |= !compiled.rules.inline_assets().is_empty();
        }
        forms.empty_table |= policy.rules.is_empty();
        forms.entries_tree |= policy.entries_tree.is_some();
        forms.per_cluster_source |= Target::ALL
            .into_iter()
            .all(|target| !policy.sources.get(target).is_empty());
        for rule in &policy.rules {
            match &rule.source {
                SourceSpec::Require(_) => forms.require = true,
                SourceSpec::Forbid(_) => forms.forbid = true,
                SourceSpec::Any(_) => forms.any = true,
                SourceSpec::Assets(_) => {
                    assert_eq!(rule.subject, SubjectName::Asset);
                    continue;
                }
            }
            forms.asset_list |= rule.subject == SubjectName::Asset;
        }
        // The file re-renders to the same policy, comments aside.
        let rendered = config
            .render()
            .unwrap_or_else(|error| panic!("{name} renders, {error}"));
        let again: RingConfig = toml::from_str(&rendered).expect("the rendering parses");
        assert_eq!(again, config, "{name}");
    }
    assert!(forms.require, "an example requires a list");
    assert!(forms.forbid, "an example forbids a list");
    assert!(forms.any, "an example names alternatives");
    assert!(forms.asset_list, "an example reads an asset list");
    assert!(forms.assets, "an example lists assets inline");
    assert!(forms.above, "an example guards by amount");
    assert!(
        forms.per_cluster_source,
        "an example names a curator per cluster"
    );
    assert!(forms.entries_tree, "an example names its tree");
    assert!(forms.empty_table, "an example pins an empty table");
    assert!(forms.audit_only, "an example carries no policy table");
}
