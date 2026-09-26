use zk_program_sdk::{
    circuit,
    circuit::{
        Balance, CheckedTransaction, Circuit, ConfidentialTransaction, PublicInputs, TokenUtxo,
        VariableRole,
    },
    conversion::ProofInput,
    testing::{check_private_variables, FreeVariable},
    RelationError, TxContext,
};
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{Mint, WalletUtxo};

mod shared;
use shared::{keypair, spendable, TREE_ID};

#[derive(Clone, ProofInput)]
struct Payment<const N: usize> {
    private: PaymentPrivateInputs<N>,
    public: RecipientPublicInputs,
}

#[derive(Clone, ProofInput)]
struct PaymentPrivateInputs<const N: usize> {
    tx_context: TxContext,
    token_utxos_asset_a: [WalletUtxo; N],
    amount: u64,
}

#[derive(Clone, ProofInput, PublicInputs)]
struct RecipientPublicInputs {
    recipient: ShieldedAddress,
}

#[circuit]
impl<const N: usize> Circuit for Payment<N> {
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
struct Memo {
    private: MemoPrivateInputs,
    public: RecipientPublicInputs,
}

#[derive(Clone, ProofInput)]
struct MemoPrivateInputs {
    tx_context: TxContext,
    token_utxos_asset_a: [WalletUtxo; 1],
    memo: [u8; 32],
}

#[circuit]
impl Circuit for Memo {
    fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
        let private = &self.private;
        let tokens = TokenUtxo::new_mut(&private.token_utxos_asset_a)?;
        ConfidentialTransaction::new(&private.tx_context, &self.public)
            .with_token_utxos(tokens)
            .check()
    }
}

fn payment<const N: usize>(token_utxos_asset_a: [WalletUtxo; N], amount: u64) -> Payment<N> {
    Payment {
        private: PaymentPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a,
            amount,
        },
        public: RecipientPublicInputs {
            recipient: keypair(6).shielded_address().unwrap(),
        },
    }
}

fn described(variables: &[FreeVariable]) -> Vec<(VariableRole, &'static str)> {
    let mut described: Vec<_> = variables
        .iter()
        .map(|free| {
            (
                free.role,
                free.allocation.as_ref().map_or("", |label| label.text),
            )
        })
        .collect();
    described.sort_by_key(|(_, text)| *text);
    described
}

#[test]
fn an_honest_payment_leaves_only_the_second_inputs_carried_fields_free() {
    let sender = keypair(5);
    let report = check_private_variables(&payment(
        [
            spendable(&sender, Mint::SOL, 300, 0),
            spendable(&sender, Mint::SOL, 200, 1),
        ],
        400,
    ))
    .unwrap();

    assert_eq!(
        (report.free, described(&report.tolerated)),
        (
            Vec::new(),
            vec![
                (VariableRole::Carried, "utxo latest tree id"),
                (VariableRole::Carried, "utxo nullifier"),
            ]
        )
    );
}

#[test]
fn a_dummy_input_leaves_only_equality_hints_and_carried_fields_free() {
    let sender = keypair(5);
    let report = check_private_variables(&payment(
        [
            spendable(&sender, Mint::SOL, 300, 0),
            WalletUtxo::dummy(TREE_ID).unwrap(),
        ],
        200,
    ))
    .unwrap();
    let roles: Vec<VariableRole> = report.tolerated.iter().map(|free| free.role).collect();

    assert_eq!(
        (
            report.free,
            roles.contains(&VariableRole::Multiplier),
            roles.contains(&VariableRole::Carried),
        ),
        (Vec::new(), true, true)
    );
}

#[test]
fn an_input_the_circuit_ignores_is_a_free_variable_named_by_its_allocation() {
    let memo = Memo {
        private: MemoPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [spendable(&keypair(5), Mint::SOL, 300, 0)],
            memo: [7u8; 32],
        },
        public: RecipientPublicInputs {
            recipient: keypair(6).shielded_address().unwrap(),
        },
    };
    let report = check_private_variables(&memo).unwrap();

    assert_eq!(
        described(&report.free),
        vec![(VariableRole::Constrained, "a 32-byte proof input")]
    );
}

#[test]
fn a_sixteen_input_payment_is_checked_without_free_variables() {
    let sender = keypair(5);
    let inputs: [WalletUtxo; 16] = core::array::from_fn(|index| {
        spendable(&sender, Mint::SOL, 10, u64::try_from(index).unwrap())
    });
    let report = check_private_variables(&payment(inputs, 150)).unwrap();

    assert_eq!(
        (report.free, report.constraints > 30_000),
        (Vec::new(), true)
    );
}
