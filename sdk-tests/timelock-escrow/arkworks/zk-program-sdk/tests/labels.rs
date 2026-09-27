use zk_program_sdk::{
    circuit,
    circuit::{
        Balance, CheckedTransaction, Circuit, CircuitLabel, ConfidentialTransaction,
        FailedConstraint, Field, LabelKind, PublicInputs, TokenUtxo,
    },
    conversion::{Allocator, Placeholder, ProofInput},
    testing::{check_tampered, constraint_labels, Tamper},
    CircuitError, Groth16Prover, ProverError, ProverErrorKind, TxContext, ZkProgram,
};
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{Mint, WalletUtxo};

mod shared;
use shared::{keypair, spendable};

#[derive(Clone, ProofInput)]
struct Payment {
    private: PaymentPrivateInputs,
    public: RecipientPublicInputs,
}

#[derive(Clone, ProofInput)]
struct PaymentPrivateInputs {
    tx_context: TxContext,
    token_utxos_asset_a: [WalletUtxo; 2],
    amount: u64,
}

#[derive(Clone, ProofInput, PublicInputs)]
struct RecipientPublicInputs {
    recipient: ShieldedAddress,
}

#[circuit]
impl Circuit for Payment {
    fn circuit(&self) -> Result<CheckedTransaction, CircuitError> {
        let private = &self.private;
        let mut tokens = TokenUtxo::new_mut(&private.token_utxos_asset_a)?;
        let mut payment = TokenUtxo::new_init(&self.public.recipient, &tokens.asset());
        tokens.transfer(&mut payment, &private.amount)?;
        ConfidentialTransaction::new(&private.tx_context, &self.public)
            .with_token_utxos(tokens)
            .with_token_utxos(payment)
            .check()
    }
}

#[derive(Clone)]
struct OverspendingPayment(Payment);

impl ProofInput for OverspendingPayment {
    type Circuit = PaymentCircuit;

    fn instantiate(&self, allocator: &Allocator) -> Result<PaymentCircuit, CircuitError> {
        let mut payment = self.0.clone();
        if let Allocator::R1cs(_) = allocator {
            payment.private.amount = 600;
        }
        payment.instantiate(allocator)
    }
}

impl Placeholder for OverspendingPayment {
    fn placeholder() -> Result<Self, CircuitError> {
        Ok(Self(Payment::placeholder()?))
    }
}

fn payment(amount: u64) -> Payment {
    let sender = keypair(5);
    Payment {
        private: PaymentPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [
                spendable(&sender, Mint::SOL, 300, 0),
                spendable(&sender, Mint::SOL, 200, 1),
            ],
            amount,
        },
        public: RecipientPublicInputs {
            recipient: keypair(6).shielded_address().unwrap(),
        },
    }
}

fn unsatisfied(result: Result<(), ProverError>) -> FailedConstraint {
    match result.map_err(ProverError::into_kind) {
        Err(ProverErrorKind::ProofInputsBreakRule(row)) => *row,
        other => panic!("expected an unsatisfied row, got {other:?}"),
    }
}

fn label_of(row: &FailedConstraint) -> (LabelKind, &'static str, bool) {
    let label = row.label.as_ref().expect("a labelled row");
    (label.kind, label.text, label.rows.contains(&row.row))
}

#[test]
fn a_tampered_public_hash_fails_the_public_hash_row() {
    let row = unsatisfied(check_tampered(
        &payment(400),
        Tamper::PublicHash(Field::from(1u64)),
    ));

    assert_eq!(
        (
            label_of(&row),
            row.label
                .as_ref()
                .is_some_and(|label| label.file.ends_with("src/prover/synthesis.rs")),
        ),
        (
            (
                LabelKind::Check,
                "the circuit's public hash is not the proof's public input",
                true
            ),
            true,
        )
    );
}

#[test]
fn a_tampered_range_check_reports_the_rule_at_the_circuits_line() {
    let payment = payment(400);
    let labels = constraint_labels(&payment).unwrap();
    let debit = labels
        .iter()
        .find(|label| label.text == "the transfer exceeds the balance")
        .expect("the debit label")
        .clone();
    let row = unsatisfied(check_tampered(
        &payment,
        Tamper::PrivateVariable {
            index: debit.private_variables.start,
            value: Field::from(2u64),
        },
    ));

    assert_eq!(
        (
            label_of(&row),
            row.label
                .as_ref()
                .is_some_and(|label| label.file.ends_with("tests/labels.rs")),
            debit.rows.contains(&row.row),
        ),
        (
            (LabelKind::Check, "the transfer exceeds the balance", true),
            true,
            true,
        )
    );
}

#[test]
fn a_tampered_hash_variable_reports_its_scope() {
    let payment = payment(400);
    let labels = constraint_labels(&payment).unwrap();
    let checked = |index: usize| {
        labels
            .iter()
            .any(|label| label.kind == LabelKind::Check && label.private_variables.contains(&index))
    };
    let index = labels
        .iter()
        .filter(|label| label.text == "a poseidon hash")
        .flat_map(|label| label.private_variables.clone())
        .find(|index| !checked(*index))
        .expect("a hash variable outside every check");
    let row = unsatisfied(check_tampered(
        &payment,
        Tamper::PrivateVariable {
            index,
            value: Field::from(7u64),
        },
    ));

    assert_eq!(label_of(&row), (LabelKind::Scope, "a poseidon hash", true));
}

#[test]
fn a_row_only_the_constraints_refuse_is_labelled_by_the_prover_and_the_check() {
    let overspending = OverspendingPayment(payment(400));
    let prover = Groth16Prover::<OverspendingPayment>::new_with_test_setup().unwrap();
    let proved = match prover.prove(&overspending).map_err(ProverError::into_kind) {
        Err(ProverErrorKind::ProofInputsBreakRule(row)) => *row,
        other => panic!("expected an unsatisfied row, got {:?}", other.map(|_| ())),
    };
    let checked = unsatisfied(overspending.check_constraints().map(|_| ()));

    assert_eq!(
        (label_of(&proved), proved == checked),
        (
            (LabelKind::Check, "the transfer exceeds the balance", true),
            true
        )
    );
}

#[test]
fn a_private_variable_outside_the_circuit_is_named() {
    assert_eq!(
        check_tampered(
            &payment(400),
            Tamper::PrivateVariable {
                index: usize::MAX,
                value: Field::from(0u64),
            },
        )
        .err()
        .map(|error| error.to_string()),
        Some(format!(
            "the circuit has no private variable {}",
            usize::MAX
        ))
    );
}

#[test]
fn an_unsatisfied_row_names_its_rule_and_location() {
    let label = |kind| CircuitLabel {
        kind,
        text: "the amount is too large",
        file: "src/circuit.rs",
        line: 7,
        column: 5,
        rows: 4..6,
        private_variables: 0..0,
    };
    let row = |label| FailedConstraint { row: 5, label };

    assert_eq!(
        (
            ProverErrorKind::ProofInputsBreakRule(Box::new(row(Some(label(LabelKind::Check)))))
                .to_string(),
            row(Some(label(LabelKind::Scope))).to_string(),
            row(None).to_string(),
        ),
        (
            "the proof inputs break a rule at row 5: the amount is too large (src/circuit.rs:7)"
                .to_string(),
            "row 5, inside the amount is too large (src/circuit.rs:7)".to_string(),
            "row 5".to_string(),
        )
    );
}
