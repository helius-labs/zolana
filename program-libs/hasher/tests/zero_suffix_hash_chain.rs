use zolana_hasher::{
    hash_chain::create_right_hash_chain_4_from_slice,
    zero_suffix_hash_chain::{
        create_padded_right_hash_chain_4, create_zero_suffix_right_hash_chain_4,
        PADDED_CHAIN_MAX_WIDTH, ZERO_SUFFIX_CHAINS, ZERO_SUFFIX_CHAIN_MAX_WIDTH,
        ZERO_SUFFIX_GROUPS,
    },
    HasherError,
};

/// Regenerates `ZERO_SUFFIX_CHAINS` in `src/zero_suffix_hash_chain.rs`. Only
/// needed if `ZERO_SUFFIX_CHAIN_MAX_WIDTH` grows; run with
/// `--ignored --nocapture` and paste.
#[test]
#[ignore = "prints the zero-suffix table for src/zero_suffix_hash_chain.rs"]
fn print_zero_suffix_chains() {
    let zero = [0u8; 32];
    for groups in 0..=ZERO_SUFFIX_GROUPS {
        let suffix = vec![zero; 1 + 3 * groups];
        let value = create_right_hash_chain_4_from_slice(&suffix).unwrap();
        let bytes: Vec<String> = value.iter().map(|byte| format!("0x{byte:02x}")).collect();
        println!("    [{}],", bytes.join(", "));
    }
}

/// The table is the fold over zeros, recomputed here from the primitive rather
/// than from the table itself, so a transcription slip cannot pass.
#[test]
fn the_zero_suffix_table_is_the_fold_over_zeros() {
    let zero = [0u8; 32];
    for (groups, entry) in ZERO_SUFFIX_CHAINS.iter().enumerate() {
        let suffix = vec![zero; 1 + 3 * groups];
        assert_eq!(
            *entry,
            create_right_hash_chain_4_from_slice(&suffix).unwrap(),
            "Z({groups})"
        );
    }
    assert_eq!(
        ZERO_SUFFIX_CHAINS.len(),
        (ZERO_SUFFIX_CHAIN_MAX_WIDTH - 1).div_ceil(3) + 1,
        "the table must reach the widest chain's group count"
    );
}

fn value(index: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    if let Some(low) = out.last_mut() {
        *low = u8::try_from(index + 1).expect("fits a byte");
    }
    out
}

#[test]
fn the_padded_fold_is_the_full_fold_for_every_width_and_sent_count() {
    for width in 0..=PADDED_CHAIN_MAX_WIDTH {
        for sent_count in 0..=width {
            let sent: Vec<[u8; 32]> = (0..sent_count).map(value).collect();
            let mut full = sent.clone();
            full.resize(width, [0u8; 32]);
            let expected = create_right_hash_chain_4_from_slice(&full).unwrap();
            assert_eq!(
                create_padded_right_hash_chain_4(&sent, width).unwrap(),
                expected,
                "width {width}, sent {sent_count}"
            );
            assert_eq!(
                create_zero_suffix_right_hash_chain_4(&full).unwrap(),
                expected,
                "width {width}, sent {sent_count}"
            );
        }
    }
}

#[test]
fn the_padded_fold_rejects_a_width_past_the_table() {
    assert_eq!(
        create_padded_right_hash_chain_4(&[], PADDED_CHAIN_MAX_WIDTH + 1),
        Err(HasherError::InvalidInputLength(
            PADDED_CHAIN_MAX_WIDTH,
            PADDED_CHAIN_MAX_WIDTH + 1
        ))
    );
}

#[test]
fn the_zero_suffix_fold_is_the_full_fold_up_to_the_widest_chain() {
    let widths = (PADDED_CHAIN_MAX_WIDTH + 1..=ZERO_SUFFIX_CHAIN_MAX_WIDTH).step_by(7);
    for width in widths.chain([ZERO_SUFFIX_CHAIN_MAX_WIDTH]) {
        for sent_count in [0, 1, 2, 3, 4, width / 2, width - 1, width] {
            let mut full: Vec<[u8; 32]> = (0..sent_count).map(value).collect();
            full.resize(width, [0u8; 32]);
            assert_eq!(
                create_zero_suffix_right_hash_chain_4(&full).unwrap(),
                create_right_hash_chain_4_from_slice(&full).unwrap(),
                "width {width}, sent {sent_count}"
            );
        }
    }
}

#[test]
fn the_padded_fold_rejects_more_sent_values_than_its_width() {
    let sent: Vec<[u8; 32]> = (0..3).map(value).collect();
    assert_eq!(
        create_padded_right_hash_chain_4(&sent, 2),
        Err(HasherError::InvalidInputLength(2, 3))
    );
}
