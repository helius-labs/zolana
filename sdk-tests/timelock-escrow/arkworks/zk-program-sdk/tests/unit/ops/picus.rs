#![cfg(feature = "external-tools")]

use zk_program_sdk::ZkCircuit;

use crate::harness::{
    fixture::picus_export,
    iden3::read_r1cs,
    picus::{picus_wire, promote_all, verdict, Verdict},
    WorkDir,
};

/// Picus on `F`'s `export_picus_r1cs` with `variables`, numbered as in the
/// `export_r1cs` file, promoted to outputs next to its gadget witnesses.
pub fn verdict_of<F: ZkCircuit>(work: &WorkDir, name: &str, variables: &[usize]) -> Verdict {
    let picus = picus_export::<F>();
    let wires: Vec<usize> = variables
        .iter()
        .map(|variable| picus_wire(&picus, *variable))
        .collect();
    verdict(work, name, &promote_all(&picus, &wires))
}

/// The Picus export's label map and output count: which variable each wire
/// holds, and how many gadget witnesses lead as outputs.
pub fn wire_order<F: ZkCircuit>() -> (Vec<u64>, usize) {
    let picus = read_r1cs(&picus_export::<F>());
    (picus.wire_labels, picus.header.public_outputs)
}
