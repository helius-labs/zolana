use solana_address::Address;
use spr_keypair::ShieldedAddress;
use spr_program::{
    circuit::{
        CheckedTransaction, Circuit, ConfidentialTransaction, NewAddress, SolanaAddress, TokenUtxos,
    },
    conversion::ProofInput,
    CircuitError, ProgramOwner, TxContext, ZkProgramCircuit,
};
use spr_transaction::WalletUtxo;

use crate::{
    harness::fixture::check_constraints,
    protocol::transaction::{
        fixtures::NoFields,
        vectors::tx_context,
        wallets::{address, keypair, PAYER, SENDER},
    },
};

#[derive(Clone, Debug, ProofInput)]
struct Reservation<const DUMMY_PADDING: bool> {
    tx_context: TxContext,
    owner: ShieldedAddress,
    seed: [u8; 32],
    inputs: [WalletUtxo; 2],
    public: NoFields,
}

impl<const DUMMY_PADDING: bool> Circuit for ReservationCircuit<DUMMY_PADDING> {
    type Output = CheckedTransaction;

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        let address = NewAddress::new(&self.owner, &self.seed)?;
        let tokens = TokenUtxos::new_mut(&self.inputs)?
            .with_optional(
                &self.owner,
                &SolanaAddress::constant(&spr_transaction::SOL_MINT),
            )
            .close();
        let transaction = ConfidentialTransaction::new(&self.tx_context, &self.public)
            .with(address)
            .with(tokens);
        let transaction = if DUMMY_PADDING {
            transaction.with_dummy_padding()
        } else {
            transaction
        };
        transaction.check()
    }
}

fn fixture<const DUMMY_PADDING: bool>() -> Reservation<DUMMY_PADDING> {
    let viewer = keypair(SENDER);
    let program = ProgramOwner::new(Address::new_from_array([11; 32]));
    let mut seed = [0; 32];
    seed[31] = 42;
    Reservation {
        tx_context: tx_context(Some(0)),
        owner: program
            .address(viewer.viewing_pubkey())
            .expect("program owner"),
        seed,
        inputs: std::array::from_fn(|_| WalletUtxo::dummy(0).expect("dummy")),
        public: NoFields,
    }
}

fn slots<const DUMMY_PADDING: bool>() -> (usize, usize, Vec<bool>) {
    let transaction = fixture::<DUMMY_PADDING>()
        .create_finalized_transaction(&address(SENDER), PAYER)
        .expect("address-only transaction");
    (
        transaction.input_utxos().len(),
        transaction
            .input_utxos()
            .iter()
            .filter(|input| input.is_address())
            .count(),
        transaction
            .output_utxos()
            .iter()
            .map(|output| output.is_compact())
            .collect(),
    )
}

#[test]
fn address_reservations_are_not_duplicated_as_dummy_input_slots() {
    assert_eq!(
        (slots::<false>(), slots::<true>()),
        ((1, 1, vec![true, true]), (3, 1, vec![false, false])),
        "compact padding omits optional dummies; explicit dummy padding keeps only their slots"
    );
}

#[test]
fn independent_reservations_and_optional_inputs_satisfy_r1cs() {
    assert_eq!(
        (
            check_constraints(&fixture::<false>()).map(|_| ()),
            check_constraints(&fixture::<true>()).map(|_| ()),
        ),
        (Ok(()), Ok(())),
        "address reservations and all-dummy groups share the same proof statement in either padding mode"
    );
}
