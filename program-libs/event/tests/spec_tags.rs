//! Pins the instruction tags documented in `docs/spec.md` to the constants in
//! `src/tag.rs`. Integrators read the spec to hand-encode CPIs, so a stale tag
//! there is a broken integration.

use std::{collections::BTreeMap, path::Path};

use spr_event::tag::InstructionTag;

fn spec() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/spec.md");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The spec's snake_case name for each implemented instruction.
fn spec_name(tag: InstructionTag) -> &'static str {
    match tag {
        InstructionTag::CreateProtocolConfig => "create_protocol_config",
        InstructionTag::UpdateProtocolConfig => "update_protocol_config",
        InstructionTag::CreateTree => "create_tree",
        InstructionTag::PauseTree => "pause_tree",
        InstructionTag::SetTreeFees => "set_tree_fees",
        InstructionTag::ClaimTreeLamports => "claim_tree_lamports",
        InstructionTag::CreateAssetCounter => "create_asset_counter",
        InstructionTag::CreateSplInterface => "create_spl_interface",
        InstructionTag::CreateRingConfig => "create_ring_config",
        InstructionTag::UpdateRingConfig => "update_ring_config",
        InstructionTag::UpdateRingConfigOwner => "update_ring_config_owner",
        InstructionTag::SetRingActivation => "set_ring_activation",
        InstructionTag::BatchUpdateNullifierTree => "batch_update_nullifier_tree",
        InstructionTag::CloseNullifierPdas => "close_nullifier_pdas",
        InstructionTag::EmitEvent => "emit_event",
        InstructionTag::Deposit => "deposit",
        InstructionTag::Transact => "transact",
        InstructionTag::MergeTransact => "merge_transact",
        InstructionTag::RingDeposit => "ring_deposit",
        InstructionTag::RingTransact => "ring_transact",
        InstructionTag::RingMergeTransact => "merge_ring",
        InstructionTag::RingAuthorityTransact => "ring_authority_transact",
        InstructionTag::CreateCache => "create_cache",
        InstructionTag::CloseCache => "close_cache",
    }
}

fn implemented() -> BTreeMap<&'static str, u8> {
    (0..=u8::MAX)
        .filter_map(|byte| {
            InstructionTag::try_from(byte)
                .ok()
                .map(|tag| (spec_name(tag), byte))
        })
        .collect()
}

/// `| name | Tag N; ...` rows of the shielded-pool table under `## Instructions`.
fn table_tags(spec: &str) -> BTreeMap<&str, u8> {
    let section = spec
        .split_once("\n## Instructions\n")
        .map(|(_, rest)| rest)
        .expect("spec has an `## Instructions` section");
    let table = section
        .split_once("\n### ")
        .map_or(section, |(table, _)| table);
    table
        .lines()
        .filter_map(|line| {
            let rest = line.strip_prefix("| ")?;
            let (name, rest) = rest.split_once(" | Tag ")?;
            let (tag, _) = rest.split_once(';')?;
            Some((name, tag.parse().expect("numeric tag")))
        })
        .collect()
}

/// `### \`name\`` headings followed by a `**Discriminator:** N` line.
fn discriminators(spec: &str) -> BTreeMap<&str, u8> {
    let mut found = BTreeMap::new();
    let mut heading: Option<&str> = None;
    for line in spec.lines() {
        if let Some(name) = line
            .strip_prefix("### `")
            .and_then(|rest| rest.strip_suffix('`'))
        {
            heading = Some(name);
        } else if let Some(value) = line.strip_prefix("**Discriminator:** ") {
            let name = heading.expect("discriminator under an instruction heading");
            found.insert(name, value.trim().parse().expect("numeric tag"));
        } else if line.starts_with("## ") {
            heading = None;
        }
    }
    found
}

#[test]
fn spec_instruction_table_matches_tags() {
    let spec = spec();
    assert_eq!(table_tags(&spec), implemented());
}

#[test]
fn spec_discriminators_match_tags() {
    let implemented = implemented();
    let spec = spec();
    let documented = discriminators(&spec);
    assert!(
        !documented.is_empty(),
        "no `**Discriminator:**` lines found"
    );
    for (name, tag) in documented {
        assert_eq!(
            implemented.get(name),
            Some(&tag),
            "`### {name}` discriminator"
        );
    }
}
