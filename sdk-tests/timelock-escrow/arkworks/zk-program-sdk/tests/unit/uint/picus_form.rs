//! Picus with cvc5 proves circomlib's `Num2Bits(64)` deterministic in
//! seconds but times out on the SDK's 64-bit range check, whose rows differ
//! from circom's only in how they are written: arkworks writes a boolean as
//! `(1 - b) * b = 0` where circom writes `b * (b - 1) = 0`, and a linear row
//! as `A * 1 = C` where circom writes `0 * 0 = C - A`. Rewriting both into
//! circom's form keeps every row's solutions, and Picus then finishes.

use ark_bn254::Fr;
use ark_ff::One;

use super::rows::lc;
use crate::harness::iden3::{read_r1cs, write_r1cs, R1cs};

pub fn circom_form(r1cs: &[u8]) -> Vec<u8> {
    let R1cs {
        header,
        a,
        b,
        c,
        wire_labels,
    } = read_r1cs(r1cs);
    let one = Fr::one();
    let mut rows = (vec![], vec![], vec![]);
    for ((a, b), c) in a.into_iter().zip(b).zip(c) {
        let (a, b, c) = match (a.as_slice(), b.as_slice()) {
            ([(k, 0), (minus, bit)], [(unit, same)])
                if *k == one && *minus == -one && *unit == one && bit == same && c.is_empty() =>
            {
                (vec![(one, *bit)], vec![(-one, 0), (one, *bit)], c)
            }
            (_, [(unit, 0)]) if *unit == one => {
                let negated = a.iter().map(|(coefficient, wire)| (-*coefficient, *wire));
                let difference: Vec<_> = c.iter().copied().chain(negated).collect();
                (vec![], vec![], lc(&difference))
            }
            _ => (a, b, c),
        };
        rows.0.push(a);
        rows.1.push(b);
        rows.2.push(c);
    }
    write_r1cs(&R1cs {
        header,
        a: rows.0,
        b: rows.1,
        c: rows.2,
        wire_labels,
    })
}

#[cfg(feature = "external-tools")]
mod verdicts {
    use std::time::Duration;

    use zk_program_sdk::ZkCircuit;

    use super::circom_form;
    use crate::harness::{
        circom::Compiled,
        fixture::picus_export,
        picus::{picus_wire, promote_all, verdict_within, Verdict},
        WorkDir,
    };

    pub fn verdict_in_circom_form(
        work: &WorkDir,
        name: &str,
        r1cs: &[u8],
        limit: Duration,
    ) -> Verdict {
        verdict_within(
            work,
            &format!("{name}-circom-form"),
            &circom_form(r1cs),
            limit,
        )
    }

    /// Picus on `F`'s `export_picus_r1cs` in circom form with `outputs`
    /// (numbered as in the assignment) promoted next to its gadget witnesses,
    /// and on circom's R1CS with the signals `circom_outputs` promoted.
    pub fn claim_verdicts<F: ZkCircuit>(
        work: &WorkDir,
        name: &str,
        outputs: &[usize],
        circom: &Compiled,
        circom_outputs: &[&str],
        limit: Duration,
    ) -> (Verdict, Verdict) {
        let picus = picus_export::<F>();
        let wires: Vec<usize> = outputs
            .iter()
            .map(|variable| picus_wire(&picus, *variable))
            .collect();
        let circom_wires: Vec<usize> = circom_outputs
            .iter()
            .map(|signal| circom.wire(signal))
            .collect();
        let circom_r1cs = std::fs::read(&circom.r1cs).expect("circom r1cs");
        (
            verdict_in_circom_form(
                work,
                &format!("{name}-sdk"),
                &promote_all(&picus, &wires),
                limit,
            ),
            verdict_within(
                work,
                &format!("{name}-circom"),
                &promote_all(&circom_r1cs, &circom_wires),
                limit,
            ),
        )
    }
}

#[cfg(feature = "external-tools")]
pub use verdicts::{claim_verdicts, verdict_in_circom_form};
