use zolana_interface::{DUMMY_DOMAIN, UTXO_DOMAIN};
use zolana_keypair::ShieldedAddress;
use zolana_program::{
    circuit::{
        self, value, CheckedTransaction, Circuit, ConfidentialTransaction, Field, PublicInputs,
        TokenUtxos, Uint, UtxoTrait,
    },
    conversion::{Allocator, Dummy, ProofInput},
    CircuitError, CircuitErrorKind, ProgramTransaction, TxContext, ZkProgram,
};
use zolana_transaction::{Mint, WalletUtxo};

use crate::shared::{keypair, token_input_in};

const TOKEN_INPUTS: usize = 3;
const INPUT_TREE_ID: u16 = 7;

#[derive(Clone, ProofInput)]
pub struct BoundedPayment {
    private: BoundedPaymentPrivateInputs,
    public: PaymentPublicInputs,
}

#[derive(Clone, ProofInput)]
struct BoundedPaymentPrivateInputs {
    tx_context: TxContext,
    #[max_len(TOKEN_INPUTS)]
    token_utxos_asset_a: Vec<WalletUtxo>,
    amount: u64,
}

#[derive(Clone, ProofInput)]
pub struct PaddedPayment {
    private: PaddedPaymentPrivateInputs,
    public: PaymentPublicInputs,
}

#[derive(Clone, ProofInput)]
struct PaddedPaymentPrivateInputs {
    tx_context: TxContext,
    token_utxos_asset_a: [WalletUtxo; TOKEN_INPUTS],
    amount: u64,
}

#[derive(Clone, PublicInputs)]
struct PaymentPublicInputs {
    recipient: ShieldedAddress,
}

#[derive(Clone, ProofInput)]
struct Optional {
    #[min_len(0)]
    #[max_len(TOKEN_INPUTS)]
    token_utxos_asset_a: Vec<WalletUtxo>,
}

#[derive(Clone, ProofInput)]
struct AtLeastTwo {
    #[min_len(2)]
    #[max_len(TOKEN_INPUTS)]
    token_utxos_asset_a: Vec<WalletUtxo>,
}

fn pay(
    tx_context: &circuit::TxContext,
    token_utxos: &[circuit::Utxo; TOKEN_INPUTS],
    amount: &Uint<64>,
    public: &PaymentPublicInputsCircuit,
) -> Result<CheckedTransaction, CircuitError> {
    let mut tokens = TokenUtxos::new_mut(token_utxos)?;
    let mut recipient = TokenUtxos::new_init(&public.recipient, &tokens.asset());
    tokens.transfer(&mut recipient, amount)?;
    ConfidentialTransaction::new(tx_context, public)
        .with_token_utxos(recipient)
        .with_token_utxos(tokens)
        .check()
}

#[deny(clippy::disallowed_types)]
impl Circuit for <BoundedPayment as ProofInput>::Circuit {
    fn circuit(&self) -> Result<CheckedTransaction, CircuitError> {
        let private = &self.private;
        pay(
            &private.tx_context,
            &private.token_utxos_asset_a,
            &private.amount,
            &self.public,
        )
    }
}

#[deny(clippy::disallowed_types)]
impl Circuit for <PaddedPayment as ProofInput>::Circuit {
    fn circuit(&self) -> Result<CheckedTransaction, CircuitError> {
        let private = &self.private;
        pay(
            &private.tx_context,
            &private.token_utxos_asset_a,
            &private.amount,
            &self.public,
        )
    }
}

fn token_utxos(amounts: &[u64]) -> Vec<WalletUtxo> {
    let owner = keypair(5);
    amounts
        .iter()
        .zip(0u64..)
        .map(|(amount, leaf_index)| {
            token_input_in(&owner, Mint::SOL, *amount, INPUT_TREE_ID, leaf_index)
        })
        .collect()
}

fn instantiation_error<P: ProofInput>(inputs: &P) -> CircuitErrorKind {
    match inputs.instantiate(&Allocator::native()) {
        Ok(_) => panic!("the inputs instantiate"),
        Err(error) => error.into_kind(),
    }
}

#[test]
fn fewer_token_utxos_instantiate_like_a_hand_padded_array() {
    let sender = keypair(5);
    let address = sender.shielded_address().expect("sender address");
    let payer = address.solana_address().expect("payer");
    let public = PaymentPublicInputs {
        recipient: keypair(6).shielded_address().expect("recipient address"),
    };
    let tx_context = TxContext::new().with_blinding_seed([3u8; 32]);
    let utxos = token_utxos(&[300, 200]);
    let mut padded_utxos = utxos.clone();
    let first = utxos.first().expect("a token utxo");
    padded_utxos.push(<WalletUtxo as Dummy>::dummy(Some(first)).expect("dummy utxo"));

    let bounded = BoundedPayment {
        private: BoundedPaymentPrivateInputs {
            tx_context,
            token_utxos_asset_a: utxos,
            amount: 250,
        },
        public: public.clone(),
    };
    let padded = PaddedPayment {
        private: PaddedPaymentPrivateInputs {
            tx_context,
            token_utxos_asset_a: padded_utxos.try_into().expect("three token utxos"),
            amount: 250,
        },
        public,
    };

    let summary = |constraints: usize, transaction: ProgramTransaction| {
        (
            constraints,
            transaction.public_hash,
            transaction
                .proof_inputs
                .to_bytes()
                .expect("proof input bytes"),
        )
    };
    assert_eq!(
        summary(
            bounded.check_constraints().expect("bounded constraints"),
            bounded
                .create_program_transaction(&address, payer)
                .expect("bounded transaction"),
        ),
        summary(
            padded.check_constraints().expect("padded constraints"),
            padded
                .create_program_transaction(&address, payer)
                .expect("padded transaction"),
        )
    );
}

#[test]
fn padding_dummies_are_in_the_first_utxos_tree() {
    let inputs = BoundedPaymentPrivateInputs {
        tx_context: TxContext::new(),
        token_utxos_asset_a: token_utxos(&[300]),
        amount: 100,
    };
    let circuit = inputs
        .instantiate(&Allocator::native())
        .expect("native instantiation");
    let tree_id = Field::from(u64::from(INPUT_TREE_ID));
    let dummy = Field::from(u64::from(DUMMY_DOMAIN));
    assert_eq!(
        slots(&circuit.token_utxos_asset_a),
        [
            (Field::from(u64::from(UTXO_DOMAIN)), tree_id),
            (dummy, tree_id),
            (dummy, tree_id),
        ]
    );
}

#[test]
fn an_empty_optional_field_is_all_dummies() {
    let circuit = Optional {
        token_utxos_asset_a: Vec::new(),
    }
    .instantiate(&Allocator::native())
    .expect("native instantiation");
    let dummy = (Field::from(u64::from(DUMMY_DOMAIN)), Field::from(0u64));
    assert_eq!(slots(&circuit.token_utxos_asset_a), [dummy; TOKEN_INPUTS]);
}

fn slots(utxos: &[circuit::Utxo; TOKEN_INPUTS]) -> [(Field, Field); TOKEN_INPUTS] {
    utxos.each_ref().map(|utxo| {
        (
            value(&utxo.domain).expect("domain"),
            value(&utxo.tree_id).expect("tree id"),
        )
    })
}

#[test]
fn more_token_utxos_than_the_maximum_are_refused() {
    let inputs = BoundedPaymentPrivateInputs {
        tx_context: TxContext::new(),
        token_utxos_asset_a: token_utxos(&[1, 2, 3, 4]),
        amount: 1,
    };
    assert!(matches!(
        instantiation_error(&inputs),
        CircuitErrorKind::TooManyItems {
            field: "token_utxos_asset_a",
            max: TOKEN_INPUTS,
            given: 4,
        }
    ));
}

#[test]
fn fewer_token_utxos_than_the_minimum_are_refused() {
    let empty = BoundedPaymentPrivateInputs {
        tx_context: TxContext::new(),
        token_utxos_asset_a: Vec::new(),
        amount: 1,
    };
    assert!(matches!(
        instantiation_error(&empty),
        CircuitErrorKind::TooFewItems {
            field: "token_utxos_asset_a",
            min: 1,
            given: 0,
        }
    ));
    let one = AtLeastTwo {
        token_utxos_asset_a: token_utxos(&[1]),
    };
    assert!(matches!(
        instantiation_error(&one),
        CircuitErrorKind::TooFewItems {
            field: "token_utxos_asset_a",
            min: 2,
            given: 1,
        }
    ));
}
