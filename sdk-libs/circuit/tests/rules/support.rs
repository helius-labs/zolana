use core::fmt::Debug;

use spr_circuit::protocol::{PublicInputs, TxContext, Utxo, UtxoMeta};
use spr_circuit::{CircuitError, CircuitErrorKind, Field, SigningPubkey, UtxoOwner, poseidon};

pub const SOLANA_TAG: u8 = 0x53;
pub const SOL: [u8; 32] = [0; 32];
pub const USDC: [u8; 32] = [5; 32];

/// The 1-based line and column of the first `call` at or after the first line
/// containing `anchor` in `src/<path>`.
fn site(path: &str, anchor: &str, call: &str) -> (u32, u32) {
    let source = std::fs::read_to_string(format!("{}/src/{path}", env!("CARGO_MANIFEST_DIR")))
        .unwrap_or_else(|error| panic!("read src/{path}: {error}"));
    let start = source
        .lines()
        .position(|line| line.contains(anchor))
        .unwrap_or_else(|| panic!("`{anchor}` is not in src/{path}"));
    let (line, column) = source
        .lines()
        .enumerate()
        .skip(start)
        .find_map(|(line, text)| text.find(call).map(|column| (line, column)))
        .unwrap_or_else(|| panic!("`{call}` does not follow `{anchor}` in src/{path}"));
    (
        u32::try_from(line + 1).unwrap(),
        u32::try_from(column + 1).unwrap(),
    )
}

/// Asserts that `result` failed at exactly the requirement `call`, the first
/// one after `anchor` in `src/<path>`.
#[track_caller]
pub fn assert_requirement<T: Debug>(
    result: Result<T, CircuitError>,
    path: &str,
    anchor: &str,
    call: &str,
) {
    let error = result.expect_err("the circuit must reject these values");
    let expected = site(path, anchor, call);
    match error.kind() {
        CircuitErrorKind::RequirementFailed { file, line, column } => {
            assert!(
                file.ends_with(&format!("src/{path}")),
                "expected `{call}` in src/{path}, failed in {file}:{line}"
            );
            assert_eq!(
                (*line, *column),
                expected,
                "expected `{call}` after `{anchor}` in src/{path}"
            );
        }
        other => panic!("expected `{call}` in src/{path} to fail, got {other:?}"),
    }
}

pub fn owner(seed: u8) -> UtxoOwner {
    UtxoOwner::new(
        SigningPubkey::new(SOLANA_TAG, [seed; 32]),
        Field::from(u64::from(seed) + 1),
    )
}

/// An owner whose nullifier key is the program-owner constant, as address
/// reservations require.
pub fn program_owner(seed: u8) -> UtxoOwner {
    UtxoOwner::new(
        SigningPubkey::new(SOLANA_TAG, [seed; 32]),
        poseidon(&[Field::zero()]).unwrap(),
    )
}

pub fn utxo(owner: UtxoOwner, asset: [u8; 32], amount: u64) -> Utxo {
    Utxo {
        owner,
        asset,
        amount,
        blinding: Field::from(23u64),
        tree_id: 3,
        meta: UtxoMeta {
            nullifier: Field::from(amount) + Field::from(1000u64),
            ..UtxoMeta::default()
        },
        ..Utxo::default()
    }
}

pub fn context() -> TxContext {
    TxContext {
        blinding_seed: Field::from(11u64),
        output_tree_id: 17,
        uses_output_tree_id: true,
    }
}

pub struct Public;

impl PublicInputs for Public {
    fn hash(&self, transaction_hash: &Field) -> Result<Field, CircuitError> {
        poseidon(&[*transaction_hash])
    }
}
