use spr_keypair::ShieldedAddress;
use spr_program::{
    circuit::{CheckedTransaction, Circuit, ConfidentialTransaction, TokenUtxos, Uint, UtxoTrait},
    conversion::ProofInput,
    CircuitError, TxContext, ZkProgramCircuit,
};
use spr_transaction::{Mint, WalletUtxo};

use crate::{
    harness::fixture::{check_constraints, native},
    protocol::transaction::{
        fixtures::NoFields,
        vectors::tx_context,
        wallets::{address, dummy, token_input, ACCOUNT, PAYER, SENDER, STRANGER, USDC},
    },
};

#[derive(Clone, Debug, ProofInput)]
struct Optional<const N: usize, const ALLOW: bool, const LATE: bool> {
    tx_context: TxContext,
    inputs: [WalletUtxo; N],
    anchor: [WalletUtxo; 1],
    owner: ShieldedAddress,
    mint: Mint,
    account: solana_address::Address,
    public: NoFields,
}

impl<const N: usize, const ALLOW: bool, const LATE: bool> Circuit
    for OptionalCircuit<N, ALLOW, LATE>
{
    type Output = CheckedTransaction;

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        let mut tokens = TokenUtxos::new_mut(&self.inputs)?;
        if LATE {
            tokens.deposit(&Uint::constant(1)?, &self.account)?;
        }
        if ALLOW {
            tokens = tokens.with_optional(&self.owner, &self.mint);
        }
        let anchor = TokenUtxos::new_mut(&self.anchor)?.close();
        ConfidentialTransaction::new(&self.tx_context, &self.public)
            .with_dummy_padding()
            .with(tokens.with_zero_output())
            .with(anchor)
            .check()
    }
}

fn fixture<const N: usize, const ALLOW: bool, const LATE: bool>(
    inputs: [WalletUtxo; N],
) -> Optional<N, ALLOW, LATE> {
    Optional {
        tx_context: tx_context(Some(0)),
        inputs,
        anchor: [token_input(SENDER, Mint::SOL, 0, 9)],
        owner: address(SENDER),
        mint: Mint::SOL,
        account: ACCOUNT,
        public: NoFields,
    }
}

type OutputSummary = (Option<ShieldedAddress>, Mint, u64);

fn outcome<const N: usize>(inputs: [WalletUtxo; N]) -> (Vec<bool>, Vec<OutputSummary>) {
    let transaction = fixture::<N, true, false>(inputs)
        .create_finalized_transaction(&address(SENDER), PAYER)
        .expect("optional transaction");
    (
        transaction
            .input_utxos()
            .iter()
            .map(|input| input.is_dummy())
            .collect(),
        transaction
            .output_utxos()
            .iter()
            .map(|output| (output.owner_address, output.asset, output.amount))
            .collect(),
    )
}

#[test]
fn arbitrary_dummy_positions_share_one_balance_and_one_output() {
    let sol = |amount, index| token_input(SENDER, Mint::SOL, amount, index);
    let outputs = |amount| {
        vec![
            (Some(address(SENDER)), Mint::SOL, amount),
            (None, Mint::default(), 0),
        ]
    };
    assert_eq!(
        [
            outcome([dummy(), sol(10, 0), dummy()]),
            outcome([sol(10, 0), dummy(), sol(20, 1)]),
            outcome([dummy(), dummy(), dummy()]),
            outcome([]),
        ],
        [
            (vec![false, false, true, true], outputs(10)),
            (vec![false, false, false, true], outputs(30)),
            (vec![false, true, true, true], outputs(0)),
            (vec![false], outputs(0)),
        ],
        "all real inputs precede padding and each optional group has one output"
    );
}

#[test]
fn dummy_placements_have_one_constraint_shape() {
    let sol = |amount, index| token_input(SENDER, Mint::SOL, amount, index);
    let arrays = [
        [sol(10, 0), sol(20, 1), sol(30, 2)],
        [dummy(), sol(10, 0), dummy()],
        [sol(10, 0), dummy(), sol(20, 1)],
        [dummy(), dummy(), dummy()],
    ];
    let counts = arrays.map(|inputs| check_constraints(&fixture::<3, true, false>(inputs)));
    assert_eq!(
        counts.map(|count| count.map(|_| ())),
        [Ok(()); 4],
        "real and all-dummy assignments use the same exported circuit"
    );
}

#[test]
fn zero_real_inputs_require_the_optional_builder_at_registration() {
    let refused = |result: Result<(), crate::harness::fixture::Refusal>| {
        result.map_err(|error: crate::harness::fixture::Refusal| (error.0, error.1))
    };
    let error = Err((
        "CircuitError.RuleBroken",
        Some("a token utxo spends at least one real input"),
    ));
    assert_eq!(
        [
            refused(native(&fixture::<1, false, false>([dummy()]))),
            refused(native(&fixture::<0, false, false>([]))),
        ],
        [error; 2],
        "ordinary new_mut groups must contain a real input even when their balance is zero"
    );
}

#[test]
fn real_inputs_match_the_optional_owner_and_asset() {
    let input = token_input(SENDER, Mint::SOL, 10, 0);
    let mut wrong_owner = fixture::<1, true, false>([input.clone()]);
    wrong_owner.owner = address(STRANGER);
    let mut wrong_asset = fixture::<1, true, false>([input]);
    wrong_asset.mint = USDC;
    let refusal = |result: Result<(), crate::harness::fixture::Refusal>| {
        result.map_err(|error: crate::harness::fixture::Refusal| (error.0, error.1))
    };
    assert_eq!(
        [refusal(native(&wrong_owner)), refusal(native(&wrong_asset))],
        [
            Err((
                "CircuitError.RuleBroken",
                Some("a deposit belongs to its program owner")
            )),
            Err((
                "CircuitError.RuleBroken",
                Some("a deposit has its expected asset")
            )),
        ],
        "optional registration must not bypass owner or asset checks on real inputs"
    );
}

#[test]
fn optional_identity_is_configured_before_balance_operations() {
    assert_eq!(
        native(&fixture::<1, true, true>([dummy()])).map_err(|error| (error.0, error.1)),
        Err((
            "CircuitError.RuleBroken",
            Some("optional token inputs are configured before balance operations")
        )),
        "an optional builder cannot change the owner or asset of an earlier transfer"
    );
}
