//! Row encoding over generated inputs.

use proptest::prelude::*;
use zolana_ring_policy::{Guard, ListSet, Rule, RuleSource, RuleTable, Subject};

fn subject() -> impl Strategy<Value = Subject> {
    prop_oneof![
        Just(Subject::OutputOwner),
        Just(Subject::Sender),
        Just(Subject::ExitDestination),
        Just(Subject::Asset),
    ]
}

fn guard() -> impl Strategy<Value = Guard> {
    prop_oneof![
        Just(Guard::Always),
        any::<u64>().prop_map(Guard::AboveAmount),
        Just(Guard::AboveAmount(u64::MAX)),
        Just(Guard::AboveAmountByAsset),
    ]
}

fn source() -> impl Strategy<Value = RuleSource> {
    prop_oneof![
        Just(RuleSource::InlineAssets),
        (any::<u8>(), any::<u8>()).prop_map(|(present, absent)| RuleSource::Lists {
            present: ListSet::from_bits(present),
            absent: ListSet::from_bits(absent),
        }),
    ]
}

fn rule() -> impl Strategy<Value = Rule> {
    (subject(), source(), guard()).prop_map(|(subject, source, guard)| Rule {
        subject,
        source,
        guard,
    })
}

/// Rows with zero reserved bytes and tags near the admitted ranges.
fn row_bytes() -> impl Strategy<Value = [u8; 32]> {
    let threshold = prop_oneof![Just(0u64), 1u64..];
    (
        any::<u8>(),
        threshold,
        0u8..=3,
        any::<u8>(),
        0u8..=3,
        0u8..=5,
    )
        .prop_map(|(alternative, threshold, guard_tag, mask, mode, subject)| {
            let mut row = [0u8; 32];
            row[19] = alternative;
            row[20..28].copy_from_slice(&threshold.to_be_bytes());
            row[28] = guard_tag;
            row[29] = mask;
            row[30] = mode;
            row[31] = subject;
            row
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    #[test]
    fn an_admitted_rule_round_trips_through_its_row(rule in rule()) {
        let decoded = Rule::decode(&rule.encoded());
        let admitted = RuleTable::builder()
            .rule(rule)
            .inline_assets(&[[7u8; 32]])
            .inline_limits(&[1])
            .try_build()
            .is_ok()
            || RuleTable::builder().rule(rule).try_build().is_ok()
            || RuleTable::builder()
                .rule(rule)
                .inline_assets(&[[7u8; 32]])
                .try_build()
                .is_ok();
        match decoded {
            Ok(decoded) => prop_assert_eq!(decoded, rule),
            Err(_) => prop_assert!(!admitted),
        }
    }

    #[test]
    fn a_decoded_row_re_encodes_to_the_same_bytes(bytes in row_bytes()) {
        if let Ok(rule) = Rule::decode(&bytes) {
            prop_assert_eq!(rule.encoded(), bytes);
        }
    }
}
