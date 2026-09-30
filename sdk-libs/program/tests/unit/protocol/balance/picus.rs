#![cfg(feature = "external-tools")]

use std::time::Duration;

use zolana_transaction::Mint;

use super::{
    fixtures::{arithmetic, balance, Arithmetic, Balance, TOKEN, TRANSFER},
    vectors::TRANSFERS,
};
use crate::{
    harness::{
        fixture::picus_export,
        picus::{picus_wire, promote_all, verdict_within, Verdict},
        WorkDir,
    },
    protocol::transaction::labels::allocated,
};

const LIMIT: Duration = Duration::from_secs(30);

type Transfer = Balance<TOKEN, TOKEN, TRANSFER, true>;

fn balances_promoted(r1cs: &[u8], balances: Vec<usize>) -> Vec<u8> {
    let wires: Vec<usize> = balances
        .into_iter()
        .map(|wire| picus_wire(r1cs, wire))
        .collect();
    promote_all(r1cs, &wires)
}

#[test]
fn picus_finds_no_counterexample_for_the_balance_arithmetic_within_its_limit() {
    let work = WorkDir::new("picus-balance-arithmetic");
    let r1cs = picus_export::<Arithmetic>();
    let balances = allocated(&arithmetic(&TRANSFERS[0]), "a field proof input");
    let verdicts = [
        verdict_within(&work, "arithmetic", &r1cs, LIMIT),
        verdict_within(
            &work,
            "arithmetic-balances",
            &balances_promoted(&r1cs, balances),
            LIMIT,
        ),
    ];
    assert_eq!(
        verdicts.map(|verdict| verdict != Verdict::Unsafe),
        [true; 2]
    );
}

#[test]
fn picus_finds_no_counterexample_for_a_whole_transfer_within_its_limit() {
    let work = WorkDir::new("picus-balance-transfer");
    let r1cs = picus_export::<Transfer>();
    let fixture = balance::<TOKEN, TOKEN, TRANSFER, true>(Mint::SOL, &TRANSFERS[0]);
    let balances = allocated(&fixture, "a field proof input");
    let verdict = verdict_within(
        &work,
        "transfer-balances",
        &balances_promoted(&r1cs, balances),
        LIMIT,
    );
    assert_ne!(verdict, Verdict::Unsafe);
}
