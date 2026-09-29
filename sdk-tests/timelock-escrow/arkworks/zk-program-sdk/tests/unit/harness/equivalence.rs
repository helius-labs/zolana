//! Relation equivalence with a circom reference whose variable layout differs
//! from the SDK's (intermediate signals, a different allocation order), where
//! rows and witnesses cannot be compared index by index as they are for
//! addition. Both circuits must accept exactly the same (inputs, claimed
//! outputs) cases, and both are checked twice:
//!
//! - the SDK natively, and by its exported R1CS against an SDK witness;
//! - circom by its witness calculation with the aborting handler, and by its
//!   own R1CS against the witness calculated with failed asserts ignored, so
//!   a row that does not enforce an `assert` still shows.
//!
//! The circom reference takes the claimed outputs as input signals and
//! asserts them (`claimed === computed`), as `add.circom` does.

#![cfg(feature = "external-tools")]

use std::time::Duration;

use ark_bn254::Fr;
use zk_program_sdk::ZkCircuit;

use super::{
    circom::{Asserts, Compiled},
    fixture::{assignment, exported, native, picus_export, with_wires, Size, Visited},
    iden3::read_wtns,
    picus::{circom_verdict, picus_wire, promote_all, verdict_within, Verdict},
    WorkDir,
};

/// The witness the SDK's exported R1CS is checked against. The SDK cannot
/// assign a fixture its native run refuses, so a rejected claim is either an
/// honest fixture's assignment with the claimed wires overwritten or a whole
/// witness built by hand.
pub enum SdkWitness<F> {
    /// The case's own fixture's assignment; a fixture the SDK cannot assign
    /// counts as rejected.
    Assignment,
    /// `honest`'s assignment with each `(wire, value)` overwritten.
    Tampered { honest: F, wires: Vec<(usize, Fr)> },
    /// A witness in the layout of the SDK export, wire 0 the constant one.
    Explicit(Vec<Fr>),
}

pub struct Case<F> {
    pub name: &'static str,
    /// Whether the relation holds for these inputs and claimed outputs.
    pub holds: bool,
    /// The fixture holding the inputs and the claimed outputs.
    pub fixture: F,
    pub sdk_witness: SdkWitness<F>,
    /// circom's input signals in decimal; an array is its flattened elements.
    pub circom: Vec<(&'static str, Vec<String>)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Accepts {
    pub sdk_native: bool,
    pub sdk_r1cs: bool,
    pub circom_witness: bool,
    pub circom_r1cs: bool,
}

impl Accepts {
    pub fn all(holds: bool) -> Self {
        Self {
            sdk_native: holds,
            sdk_r1cs: holds,
            circom_witness: holds,
            circom_r1cs: holds,
        }
    }
}

pub fn accepts<F: ZkCircuit>(circom: &Compiled, cases: &[Case<F>]) -> Visited<Accepts> {
    let (sdk_r1cs, circom_r1cs) = (exported::<F>(), circom.read_r1cs());
    cases
        .iter()
        .map(|case| {
            let sdk_witness = match &case.sdk_witness {
                SdkWitness::Assignment => case
                    .fixture
                    .export_assignment()
                    .ok()
                    .map(|wtns| read_wtns(&wtns)),
                SdkWitness::Tampered { honest, wires } => {
                    Some(with_wires(assignment(honest), wires))
                }
                SdkWitness::Explicit(witness) => Some(witness.clone()),
            };
            let accepts = Accepts {
                sdk_native: native(&case.fixture).is_ok(),
                sdk_r1cs: sdk_witness
                    .is_some_and(|witness| sdk_r1cs.first_unsatisfied(&witness).is_none()),
                circom_witness: circom.calculate(&case.circom, Asserts::Abort).is_ok(),
                circom_r1cs: circom
                    .calculate(&case.circom, Asserts::Ignore)
                    .is_ok_and(|witness| circom_r1cs.first_unsatisfied(&witness).is_none()),
            };
            (case.name, accepts)
        })
        .collect()
}

/// Asserts that for every case, all four checks accept exactly when the case
/// holds.
pub fn assert_relation_equivalent<F: ZkCircuit>(circom: &Compiled, cases: &[Case<F>]) {
    assert_eq!(
        accepts(circom, cases),
        cases
            .iter()
            .map(|case| (case.name, Accepts::all(case.holds)))
            .collect::<Visited<Accepts>>()
    );
}

/// The sizes of the SDK export and of circom's R1CS, to pin both.
pub fn sizes<F: ZkCircuit>(circom: &Compiled) -> (Size, Size) {
    (Size::of(&exported::<F>()), Size::of(&circom.read_r1cs()))
}

/// Picus on the SDK's `export_picus_r1cs` with `sdk_outputs` promoted to
/// outputs next to its gadget witnesses, and on circom's R1CS with
/// `circom_outputs` promoted (or, when empty, with its own `signal output`s
/// as the targets). `sdk_outputs` are numbered as in the `export_r1cs` file
/// and the assignment, `circom_outputs` as in circom's `.r1cs`
/// ([`Compiled::wire`]).
pub fn picus_verdicts<F: ZkCircuit>(
    work: &WorkDir,
    name: &str,
    sdk_outputs: &[usize],
    circom: &Compiled,
    circom_outputs: &[usize],
    limit: Duration,
) -> (Verdict, Verdict) {
    let picus = picus_export::<F>();
    let sdk_wires: Vec<usize> = sdk_outputs
        .iter()
        .map(|variable| picus_wire(&picus, *variable))
        .collect();
    let sdk = verdict_within(
        work,
        &format!("{name}-sdk"),
        &promote_all(&picus, &sdk_wires),
        limit,
    );
    let circom = if circom_outputs.is_empty() {
        circom_verdict(work, &format!("{name}-circom"), circom, limit)
    } else {
        let bytes = std::fs::read(&circom.r1cs).expect("circom r1cs");
        verdict_within(
            work,
            &format!("{name}-circom"),
            &promote_all(&bytes, circom_outputs),
            limit,
        )
    };
    (sdk, circom)
}
