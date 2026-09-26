use zk_program_sdk::{
    circuit,
    circuit::{
        value, Balance, CheckedTransaction, Circuit, ConfidentialTransaction, Field, LabelKind,
        PublicInputs, TokenUtxo, Uint,
    },
    conversion::{Allocator, Placeholder, ProofInput},
    Groth16Prover, RelationError, TxContext, ZkProgram,
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
    fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
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

#[derive(Clone, ProofInput)]
struct Peeking {
    private: PaymentPrivateInputs,
    public: RecipientPublicInputs,
}

#[circuit]
impl Circuit for Peeking {
    fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
        let private = &self.private;
        if value(&private.amount.var())? == Field::from(0u64) {
            return Err(RelationError::Violated("the payment moves nothing"));
        }
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
struct Reshaped {
    payment: Payment,
    extra_input: bool,
}

impl ProofInput for Reshaped {
    type Circuit = PaymentCircuit;

    fn instantiate(&self, allocator: &Allocator) -> Result<PaymentCircuit, RelationError> {
        if self.extra_input {
            let _extra = Field::from(0u64).instantiate(allocator)?;
        }
        self.payment.instantiate(allocator)
    }
}

impl Placeholder for Reshaped {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            payment: Payment::placeholder()?,
            extra_input: false,
        })
    }
}

#[derive(Clone)]
struct ConstantAmount(Payment);

impl ProofInput for ConstantAmount {
    type Circuit = PaymentCircuit;

    fn instantiate(&self, allocator: &Allocator) -> Result<PaymentCircuit, RelationError> {
        let mut circuit = self.0.instantiate(allocator)?;
        circuit.private.amount = Uint::constant(self.0.private.amount)?;
        Ok(circuit)
    }
}

impl Placeholder for ConstantAmount {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self(Payment::placeholder()?))
    }
}

fn private_inputs(amount: u64) -> PaymentPrivateInputs {
    let sender = keypair(5);
    PaymentPrivateInputs {
        tx_context: TxContext::new(),
        token_utxos_asset_a: [
            spendable(&sender, Mint::SOL, 300, 0),
            spendable(&sender, Mint::SOL, 200, 1),
        ],
        amount,
    }
}

fn recipient() -> RecipientPublicInputs {
    RecipientPublicInputs {
        recipient: keypair(6).shielded_address().unwrap(),
    }
}

fn payment(amount: u64) -> Payment {
    Payment {
        private: private_inputs(amount),
        public: recipient(),
    }
}

#[test]
fn an_honest_payment_reports_the_provers_constraint_count() {
    let prover = Groth16Prover::<Payment>::new_with_test_setup().unwrap();

    assert_eq!(
        payment(400).check_constraints().ok(),
        Some(prover.constraint_count())
    );
}

#[test]
fn an_extra_private_variable_is_a_shape_difference_named_where_it_parts() {
    let reshaped = Reshaped {
        payment: payment(400),
        extra_input: true,
    };
    let error = reshaped.check_constraints().unwrap_err();
    let message = error.to_string();

    match error {
        RelationError::ShapeDiffers {
            setup,
            proof,
            first_apart,
        } => assert_eq!(
            (
                proof.constraints == setup.constraints,
                proof.private_variables - setup.private_variables,
                first_apart.map(|label| label.text),
                message.contains("; they part at a field proof input ("),
            ),
            (true, 1, Some("a field proof input"), true,)
        ),
        other => panic!("expected a shape difference, got {other}"),
    }
}

#[test]
fn an_input_dependent_constant_is_a_constraint_difference() {
    match ConstantAmount(payment(400)).check_constraints() {
        Err(RelationError::ConstraintsDiffer(row)) => assert_eq!(
            row.label.map(|label| (label.kind, label.text)),
            Some((LabelKind::Check, "the transfer exceeds the balance"))
        ),
        other => panic!("expected a constraint difference, got {other:?}"),
    }
}

#[test]
fn a_value_read_of_a_variable_names_its_line() {
    let peeking = Peeking {
        private: private_inputs(400),
        public: recipient(),
    };
    let read_at = |result: Result<(), RelationError>| match result {
        Err(RelationError::ValueOfVariable(location)) => {
            location.file().ends_with("tests/check_constraints.rs")
        }
        other => panic!("expected a value read of a variable, got {other:?}"),
    };

    assert_eq!(
        (
            read_at(peeking.check_constraints().map(|_| ())),
            read_at(Groth16Prover::<Peeking>::new_with_test_setup().map(|_| ())),
            peeking.check_constraints().err().map(|error| error
                .to_string()
                .starts_with("the circuit reads the value of a variable at ")),
        ),
        (true, true, Some(true))
    );
}
