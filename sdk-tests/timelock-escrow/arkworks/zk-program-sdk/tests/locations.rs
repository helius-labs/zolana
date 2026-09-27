use ark_relations::r1cs::{SynthesisError, SynthesisMode};
use zk_program_sdk::{
    circuit,
    circuit::{
        constant, select_index, value, Assert, Asset, Balance, Bool, CheckedTransaction, Circuit,
        ConfidentialTransaction, ConstraintSystem, Field, PublicInputs, TokenUtxo, Uint,
    },
    conversion::{Allocator, Placeholder, ProofInput},
    testing::constraint_labels,
    CircuitError, CircuitErrorKind, Groth16Prover, TxContext,
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
struct SetupReader(Payment);

impl ProofInput for SetupReader {
    type Circuit = PaymentCircuit;

    fn instantiate(&self, allocator: &Allocator) -> Result<PaymentCircuit, CircuitError> {
        if let Allocator::R1cs(cs) = allocator {
            if cs.is_in_setup_mode() {
                Err::<(), _>(SynthesisError::AssignmentMissing)?;
            }
        }
        self.0.instantiate(allocator)
    }
}
const SETUP_READ_LINE: u32 = line!() - 6;

impl Placeholder for SetupReader {
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

fn here(error: &CircuitError, line: u32) -> (bool, u32) {
    let location = error.location();
    (location.file().ends_with("tests/locations.rs"), line)
}

fn at_line<T: std::fmt::Debug>(result: Result<T, CircuitError>, line: u32) -> (bool, u32, u32) {
    let error = result.expect_err("the gadget fails");
    let (in_this_file, line) = here(&error, line);
    (in_this_file, error.location().line(), line)
}

#[test]
fn a_native_overdraft_points_at_the_same_line_as_its_constraint_label() {
    let label = constraint_labels(&payment(400))
        .unwrap()
        .into_iter()
        .find(|label| label.text == "the transfer exceeds the balance")
        .expect("the debit label");
    let error = payment(600)
        .instantiate(&Allocator::native())
        .and_then(|circuit| circuit.circuit())
        .expect_err("the overdraft fails natively");

    let location = error.location();
    assert_eq!(
        (
            error.broken_rule(),
            label.file.ends_with("tests/locations.rs"),
            (location.file(), location.line(), location.column()),
        ),
        (
            Some("the transfer exceeds the balance"),
            true,
            (label.file, label.line, label.column),
        )
    );
}

#[test]
fn assert_equal_points_at_its_caller() {
    let line = line!() + 1;
    let result = constant(1u64).assert_equal(&constant(2u64), "the values match");
    assert_eq!(at_line(result, line), (true, line, line));
}

#[test]
fn an_assert_through_a_trait_impl_points_at_its_caller() {
    let line = line!() + 1;
    let result = Bool::constant(true).assert_equal(&Bool::constant(false), "the flags match");
    assert_eq!(at_line(result, line), (true, line, line));

    let sol = Asset::sol();
    let line = line!() + 1;
    let result = sol.assert_not_equal(&sol, "the assets differ");
    assert_eq!(at_line(result, line), (true, line, line));
}

#[test]
fn uint_asserts_point_at_their_caller() {
    let line = line!() + 1;
    let result = Uint::<8>::try_from(&constant(300u64));
    assert_eq!(at_line(result, line), (true, line, line));

    let one = Uint::<16>::constant(1).unwrap();
    let line = line!() + 1;
    let result = one.assert_less_than(&one, "one is below one");
    assert_eq!(at_line(result, line), (true, line, line));
}

#[test]
fn an_out_of_range_index_points_at_its_caller() {
    let items = [constant(1u64), constant(2u64)];
    let line = line!() + 1;
    let result = select_index(&items, &constant(5u64));
    let error = result.as_ref().expect_err("the index is outside");
    assert_eq!(
        (
            matches!(error.kind(), CircuitErrorKind::IndexOutOfBounds { len: 2 }),
            here(error, line),
            error.location().line(),
        ),
        (true, (true, line), line)
    );
}

#[test]
fn reading_a_variable_points_at_its_caller() {
    let cs = ConstraintSystem::new_ref();
    cs.set_mode(SynthesisMode::Prove {
        construct_matrices: false,
    });
    let allocated = Field::from(3u64).instantiate(&Allocator::R1cs(cs)).unwrap();
    let line = line!() + 1;
    let result = value(&allocated);
    assert_eq!(at_line(result, line), (true, line, line));
}

#[test]
fn reading_a_value_while_the_shape_is_built_points_at_its_caller() {
    let error = Groth16Prover::<SetupReader>::new_with_test_setup()
        .err()
        .expect("the setup reads a value");
    let location = error.location();
    assert_eq!(
        (
            error.name(),
            location.file().ends_with("tests/locations.rs"),
            location.line(),
        ),
        ("ProverError.ReadsValueDuringSetup", true, SETUP_READ_LINE)
    );
}
