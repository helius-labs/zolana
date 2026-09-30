use ark_bn254::Fr;
use ark_ff::One;
use solana_address::Address;
use zolana_hasher::primitives::{P256_OWNER_TAG, SOLANA_OWNER_TAG};
use zolana_program::{
    circuit::VariableRole,
    testing::{FreeVariable, PrivateVariableReport},
};
use zolana_transaction::Mint;

use super::{
    fixtures::{
        hashed_dummy_preimages_commitment, Carried, Instantiated, UtxoHash, CARRIED_RULE,
        CLAIM_WIRE, HASH_RULE,
    },
    vectors::{blinding, dummy, preimages, Preimage, TREE_ID},
};
use crate::{
    harness::{
        digest::r1cs_digest,
        fixture::{
            assignment, breaks_rule, check_constraints, check_private_variables, check_tampered,
            exported, first_unsatisfied, per_vector, size, with_wires, Size,
        },
    },
    protocol::{
        asset::vectors::field_of,
        owner::{
            keys,
            native::TAG_RULE,
            wires::{allocated, before_check, check, labels, wire},
        },
    },
};

pub const HASH_SIZE: Size = Size {
    constraints: 2167,
    variables: 2178,
};
pub const HASH_ROW: usize = 2166;
pub const HASH_DIGEST: &str = "73266cfb46af8d8f6df5b458e37fe47823104d74d55f5719365733b9a2cf1dbe";

fn fixture(preimage: &Preimage) -> UtxoHash {
    UtxoHash {
        hash: preimage.hash(),
        utxo: preimage.wallet(),
    }
}

fn dummy_fixture() -> UtxoHash {
    let wallet = dummy(blinding(5), TREE_ID);
    let hash = field_of(&wallet.utxo_hash);
    UtxoHash { hash, utxo: wallet }
}

#[test]
fn the_utxo_fixtures_have_pinned_sizes_digest_and_no_public_input() {
    let r1cs = exported::<UtxoHash>();
    assert_eq!(
        (
            size::<UtxoHash>(),
            size::<Carried>(),
            size::<Instantiated>(),
            r1cs_digest::<UtxoHash>(),
            (r1cs.header.public_inputs, r1cs.header.public_outputs),
        ),
        (
            HASH_SIZE,
            Size {
                constraints: 585,
                variables: 595,
            },
            Size {
                constraints: 581,
                variables: 592,
            },
            HASH_DIGEST.to_string(),
            (0, 0),
        )
    );
}

#[test]
fn every_preimage_and_a_dummy_satisfy_every_row_with_the_commitment_on_the_claim_wire() {
    let mut fixtures: Vec<(&str, UtxoHash)> = preimages()
        .iter()
        .map(|preimage| (preimage.name, fixture(preimage)))
        .collect();
    fixtures.push(("dummy", dummy_fixture()));
    assert_eq!(
        fixtures
            .iter()
            .map(|(name, fixture)| {
                let honest = assignment(fixture);
                (
                    *name,
                    check_constraints(fixture),
                    first_unsatisfied::<UtxoHash>(&honest),
                    honest[CLAIM_WIRE] == Fr::from(fixture.hash),
                )
            })
            .collect::<Vec<_>>(),
        fixtures
            .iter()
            .map(|(name, _)| (*name, Ok(HASH_SIZE.constraints), None, true))
            .collect::<Vec<_>>()
    );
}

#[test]
fn a_claimed_commitment_of_another_preimage_breaks_exactly_the_hash_row() {
    let preimages = preimages();
    let refused: Vec<_> = preimages
        .iter()
        .enumerate()
        .map(|(index, preimage)| {
            let other = preimages[(index + 1) % preimages.len()].hash();
            let fixture = fixture(preimage);
            (
                first_unsatisfied::<UtxoHash>(&with_wires(
                    assignment(&fixture),
                    &[(CLAIM_WIRE, Fr::from(other))],
                )),
                check_tampered(&fixture, CLAIM_WIRE, other),
            )
        })
        .collect();
    assert_eq!(
        refused,
        vec![(Some(HASH_ROW), Err(breaks_rule(HASH_ROW, HASH_RULE))); preimages.len()]
    );
}

fn changed_preimages(base: &Preimage) -> Vec<(&'static str, Preimage)> {
    vec![
        (
            "amount",
            Preimage {
                amount: base.amount + 1,
                ..base.clone()
            },
        ),
        (
            "blinding",
            Preimage {
                blinding: blinding(10),
                ..base.clone()
            },
        ),
        (
            "data hash",
            Preimage {
                data_hash: Some(blinding(11)),
                ..base.clone()
            },
        ),
        (
            "ring data hash",
            Preimage {
                ring_data_hash: Some(blinding(12)),
                ..base.clone()
            },
        ),
        (
            "ring program id",
            Preimage {
                ring_program_id: Some(Address::new_from_array([13u8; 32])),
                ..base.clone()
            },
        ),
        (
            "tree id",
            Preimage {
                tree_id: base.tree_id + 1,
                ..base.clone()
            },
        ),
        (
            "owner",
            Preimage {
                key: keys::p256(99),
                ..base.clone()
            },
        ),
        (
            "asset",
            Preimage {
                mint: Mint::new(Address::new_from_array([77u8; 32]), 77),
                ..base.clone()
            },
        ),
    ]
}

#[test]
fn every_changed_preimage_field_with_the_original_commitment_breaks_exactly_the_hash_row() {
    let base = &preimages()[3];
    let changed = changed_preimages(base);
    assert_eq!(
        changed
            .iter()
            .map(|(name, preimage)| {
                let witness = with_wires(
                    assignment(&fixture(preimage)),
                    &[(CLAIM_WIRE, Fr::from(base.hash()))],
                );
                (
                    *name,
                    preimage.hash() == base.hash(),
                    first_unsatisfied::<UtxoHash>(&witness),
                )
            })
            .collect::<Vec<_>>(),
        changed
            .iter()
            .map(|(name, _)| (*name, false, Some(HASH_ROW)))
            .collect::<Vec<_>>()
    );
}

#[test]
fn every_preimage_wire_changed_alone_leaves_a_row_unsatisfied() {
    let base = fixture(&preimages()[3]);
    let honest = assignment(&base);
    let bytes = allocated(&base, "a byte proof input");
    let named = [
        "utxo domain",
        "an owner tag",
        "a 32-byte proof input",
        "utxo amount",
        "utxo blinding",
        "utxo data hash",
        "utxo ring data hash",
        "utxo ring program id",
        "utxo tree id",
    ]
    .map(|text| (text, wire(&base, text)));
    let wires: Vec<(&str, usize)> = named
        .into_iter()
        .chain([
            ("owner key byte 0", bytes[0]),
            ("owner key byte 31", bytes[31]),
            ("asset byte 0", bytes[32]),
            ("asset byte 31", bytes[63]),
        ])
        .collect();
    assert_eq!(
        (
            bytes.len(),
            wires
                .iter()
                .map(|(name, wire)| {
                    let shifted = honest[*wire] + Fr::one();
                    (
                        *name,
                        first_unsatisfied::<UtxoHash>(&with_wires(
                            honest.clone(),
                            &[(*wire, shifted)],
                        )),
                    )
                })
                .collect::<Vec<_>>(),
        ),
        (
            64,
            vec![
                ("utxo domain", Some(0)),
                ("an owner tag", Some(290)),
                ("a 32-byte proof input", Some(826)),
                ("utxo amount", Some(1794)),
                ("utxo blinding", Some(1548)),
                ("utxo data hash", Some(1797)),
                ("utxo ring data hash", Some(1305)),
                ("utxo ring program id", Some(1308)),
                ("utxo tree id", Some(1788)),
                ("owner key byte 0", Some(10)),
                ("owner key byte 31", Some(289)),
                ("asset byte 0", Some(300)),
                ("asset byte 31", Some(579)),
            ]
        )
    );
}

#[test]
fn only_the_carried_nullifier_and_latest_tree_id_are_unconstrained() {
    let base = fixture(&preimages()[0]);
    let carried = |text: &'static str| {
        let label = labels(&base)
            .into_iter()
            .find(|label| label.text == text)
            .expect("carried label");
        FreeVariable {
            variable: label.private_variables.start,
            role: VariableRole::Carried,
            allocation: Some(label),
        }
    };
    assert_eq!(
        check_private_variables(&base),
        PrivateVariableReport {
            constraints: HASH_SIZE.constraints,
            private_variables: HASH_SIZE.variables - 1,
            free: vec![],
            tolerated: vec![carried("utxo nullifier"), carried("utxo latest tree id")],
        }
    );
}

#[test]
fn a_claimed_nullifier_or_latest_tree_id_other_than_the_carried_one_breaks_the_carried_rule() {
    let preimage = &preimages()[4];
    let fixture = Carried {
        nullifier: field_of(&preimage.native_nullifier()),
        latest_tree_id: 4u64.into(),
        has_latest_tree_id: true,
        utxo: preimage.wallet(),
    };
    let rows = check(&fixture, CARRIED_RULE).rows;
    assert_eq!(
        (
            check_constraints(&fixture),
            check_tampered(&fixture, 1, field_of(&preimages()[0].native_nullifier())),
            check_tampered(&fixture, 2, 5u64.into()),
            check_tampered(&fixture, 3, 0u64.into()),
        ),
        (
            Ok(585),
            Err(breaks_rule(rows.start, CARRIED_RULE)),
            Err(breaks_rule(rows.start + 1, CARRIED_RULE)),
            Err(breaks_rule(rows.start + 2, CARRIED_RULE)),
        )
    );
}

fn tag_product(tag: u64) -> Fr {
    (Fr::from(tag) - Fr::from(u64::from(SOLANA_OWNER_TAG)))
        * (Fr::from(tag) - Fr::from(u64::from(P256_OWNER_TAG)))
}

#[test]
fn the_tag_check_is_skipped_exactly_for_a_dummy_input() {
    let real = Instantiated {
        utxo: preimages()[0].wallet(),
    };
    let skipped = Instantiated {
        utxo: dummy(blinding(5), TREE_ID),
    };
    let tag_wire = wire(&real, "an owner tag");
    let product = before_check(&real, TAG_RULE);
    let tag_row = check(&real, TAG_RULE).rows.start;
    let tags: Vec<u64> = (0..=255).collect();
    let tampered = |fixture: &Instantiated| -> Vec<Option<usize>> {
        let honest = assignment(fixture);
        tags.iter()
            .map(|tag| {
                first_unsatisfied::<Instantiated>(&with_wires(
                    honest.clone(),
                    &[(tag_wire, Fr::from(*tag)), (product, tag_product(*tag))],
                ))
            })
            .collect()
    };
    assert_eq!(
        (
            (tag_wire, product),
            (
                wire(&skipped, "an owner tag"),
                before_check(&skipped, TAG_RULE)
            ),
            assignment(&skipped)[tag_wire],
            tampered(&real),
            tampered(&skipped),
        ),
        (
            (4, 293),
            (4, 293),
            Fr::from(0u64),
            tags.iter()
                .map(|tag| {
                    (![u64::from(SOLANA_OWNER_TAG), u64::from(P256_OWNER_TAG)].contains(tag))
                        .then_some(tag_row)
                })
                .collect::<Vec<_>>(),
            vec![None; tags.len()],
        )
    );
}

#[test]
fn every_preimage_instantiates_to_the_dummy_placeholders_shape() {
    let preimages = preimages();
    assert_eq!(
        per_vector(&preimages, |preimage| check_constraints(&Instantiated {
            utxo: preimage.wallet()
        })),
        per_vector(&preimages, |_| Ok(581))
    );
}

#[test]
fn dummy_commitments_bind_the_tree_and_blinding_and_reject_hashed_dummy_preimages() {
    let rows = exported::<UtxoHash>();
    for tree in [0, TREE_ID, u16::MAX] {
        for salt in [0u8, 5, 99] {
            let wallet = dummy(blinding(salt), tree);
            let fixture = UtxoHash {
                hash: field_of(&wallet.utxo_hash),
                utxo: wallet.clone(),
            };
            assert_eq!(check_constraints(&fixture), Ok(HASH_SIZE.constraints));
            let honest = assignment(&fixture);
            assert_eq!(rows.first_unsatisfied(&honest), None);
            for wrong in [
                hashed_dummy_preimages_commitment(&wallet),
                field_of(&dummy(blinding(salt), tree ^ 1).utxo_hash),
                field_of(&dummy(blinding(salt ^ 1), tree).utxo_hash),
            ] {
                assert_ne!(wrong, fixture.hash);
                assert_eq!(
                    check_tampered(&fixture, CLAIM_WIRE, wrong),
                    Err(breaks_rule(HASH_ROW, HASH_RULE))
                );
            }
        }
    }
}

#[test]
fn a_dummy_hash_has_no_free_wire_beyond_carried_fields_and_equality_inverse_hints() {
    let report = check_private_variables(&dummy_fixture());
    let tolerated: Vec<_> = report
        .tolerated
        .iter()
        .map(|wire| (wire.role, wire.allocation.as_ref().map(|label| label.text)))
        .collect();
    assert!(
        report.free.is_empty(),
        "unexpected free wires: {:?}",
        report.free
    );
    assert_eq!(
        (report.constraints, report.private_variables),
        (HASH_SIZE.constraints, HASH_SIZE.variables - 1)
    );
    assert_eq!(
        tolerated,
        vec![
            (
                VariableRole::Multiplier,
                Some("the inverse hint of an equality test")
            ),
            (VariableRole::Carried, Some("utxo nullifier")),
            (VariableRole::Carried, Some("utxo latest tree id")),
            (
                VariableRole::Multiplier,
                Some("the inverse hint of an equality test")
            ),
        ]
    );
}
