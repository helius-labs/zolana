use super::{
    fixtures::{HashBytes, RULE},
    vectors::native_hash,
};
use crate::{
    bytes::support::{byte_rows, golden, low_bits, unsatisfied_rows, BYTE_RULE},
    harness::{
        digest::r1cs_digest,
        fixture::{
            assignment, breaks_rule, check_constraints, check_private_variables, check_tampered,
            exported, size, with_wires,
        },
    },
};
use ark_bn254::Fr;
use ark_ff::One;
use zk_program_sdk::{circuit::Field, Bytes};

#[test]
fn empty_and_single_chunk_hashes_have_exact_byte_and_packing_rows() {
    let one = Fr::one();
    assert_eq!(
        exported::<HashBytes<0>>(),
        golden(2, vec![(vec![(-one, 1)], vec![(one, 0)], vec![])])
    );
    assert_eq!(
        exported::<HashBytes<1>>(),
        golden(
            11,
            [
                byte_rows(1),
                vec![(vec![(one, 1), (-one, 10)], vec![(one, 0)], vec![])]
            ]
            .concat()
        )
    );
    assert_eq!(
        exported::<HashBytes<2>>(),
        golden(
            20,
            [
                byte_rows(1),
                byte_rows(10),
                vec![(
                    vec![(Fr::from(256u64), 1), (one, 10), (-one, 19)],
                    vec![(one, 0)],
                    vec![],
                )],
            ]
            .concat(),
        )
    );
}

fn honest<const N: usize>() {
    let bytes: [u8; N] = std::array::from_fn(|i| (i as u8).wrapping_mul(17));
    let fixture = HashBytes {
        bytes: Bytes(bytes),
        hash: native_hash(&bytes),
    };
    let r1cs = exported::<HashBytes<N>>();
    assert_eq!(check_constraints(&fixture), Ok(r1cs.header.constraints));
    assert_eq!(
        r1cs.header.constraints,
        9 * N + 240 * N.div_ceil(31).saturating_sub(1) + 1
    );
    assert_eq!(r1cs.header.variables, r1cs.header.constraints + 1);
    assert_eq!(r1cs.first_unsatisfied(&assignment(&fixture)), None);
    let wrong = Field::from(Fr::from(fixture.hash) + Fr::one());
    assert_eq!(
        check_tampered(&fixture, 9 * N + 1, wrong),
        Err(breaks_rule(r1cs.header.constraints - 1, RULE))
    );
    assert!(r1cs
        .first_unsatisfied(&with_wires(
            assignment(&fixture),
            &[(9 * N + 1, wrong.into())]
        ))
        .is_some());
    for (index, byte) in bytes.into_iter().enumerate() {
        assert!(
            check_tampered(&fixture, 9 * index + 1, Field::from(byte.wrapping_add(1))).is_err()
        );
    }
    let report = check_private_variables(&fixture);
    assert!(report.free.is_empty());
    assert!(report.tolerated.is_empty());
}

#[test]
fn every_chunk_boundary_has_identical_setup_and_proving_rows_and_rejects_tampering() {
    honest::<0>();
    honest::<1>();
    honest::<31>();
    honest::<32>();
    honest::<62>();
    honest::<63>();
}

#[test]
fn hash_counts_and_large_exports_are_pinned() {
    let observed = [
        (size::<HashBytes<31>>(), r1cs_digest::<HashBytes<31>>()),
        (size::<HashBytes<32>>(), r1cs_digest::<HashBytes<32>>()),
        (size::<HashBytes<63>>(), r1cs_digest::<HashBytes<63>>()),
    ];
    let expected = [
        (
            280,
            281,
            "1ad84b3e00398c7816e49652acc45be470c3aaccbc25fbc156eaa45bca1f03e3",
        ),
        (
            529,
            530,
            "c6665057d6a3f10f74514f97a8cf95cc177008968da22f71ccf236573e0c7788",
        ),
        (
            1048,
            1049,
            "3da986a64c3a9dd4b8d32d3d92738dc42126361c83b22dd2dcc651a5830b085b",
        ),
    ]
    .map(|(constraints, variables, digest)| {
        (
            crate::harness::fixture::Size {
                constraints,
                variables,
            },
            digest.to_owned(),
        )
    });
    assert_eq!(observed, expected);
}

#[test]
fn byte_range_checks_reject_coordinated_aliases_that_preserve_the_hash() {
    let r1cs = exported::<HashBytes<2>>();
    for (last_byte, packed) in [(2u8, 258u64), (0u8, 256u64)] {
        let fixture = HashBytes {
            bytes: Bytes([1, last_byte]),
            hash: Field::from(packed),
        };
        assert_eq!(check_constraints(&fixture), Ok(19));
        let honest = assignment(&fixture);
        assert_eq!(r1cs.first_unsatisfied(&honest), None);

        // [1, b] and [0, 256+b] have the same packed value. Recompute the
        // first byte's bits, retaining the second byte's honest low eight bits.
        let wires: Vec<_> = [(1, Fr::from(0u64)), (10, Fr::from(packed))]
            .into_iter()
            .chain((2..10).zip(low_bits(0)))
            .collect();
        let forged = with_wires(honest, &wires);
        let first = *forged.get(1).expect("first byte");
        let second = *forged.get(10).expect("second byte");
        let claim = *forged.get(19).expect("hash claim");
        assert_eq!(first * Fr::from(256u64) + second, claim);
        assert_eq!(
            forged.get(11..19).expect("second byte bits"),
            low_bits(last_byte)
        );
        assert_eq!(unsatisfied_rows(&r1cs, &forged), vec![17]);
        assert_eq!(
            check_tampered(&fixture, 10, Field::from(packed)),
            Err(breaks_rule(17, BYTE_RULE)),
        );
    }
}
