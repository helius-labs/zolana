use solana_address::Address;
use spr_keypair::{ShieldedAddress as NativeShieldedAddress, ShieldedKeypair, SigningKey};
use spr_program::circuit::{
    CheckedTransaction, ConfidentialTransaction, PublicInputs, TokenUtxos, Utxo, UtxoTrait,
};
use spr_program::{
    input, poseidon, ArrayVec, Asset, CircuitError, ClientError, ClientInputs, Field, InputRecords,
    ProgramOwner, ShieldedAddress, TransactionOptions, TxContext,
};
use spr_transaction::instructions::transact::FinalizedTransaction;
use spr_transaction::{Mint, SppProofOutputUtxo, WalletUtxo};

#[input]
#[derive(ClientInputs)]
pub struct Numbers {
    pub context: TxContext,
    pub amounts: ArrayVec<u64, 3>,
    pub commitment: Field,
}

fn client(amounts: Vec<u64>) -> NumbersClient {
    NumbersClient {
        context: TransactionOptions {
            blinding_seed: Some([0; 32]),
            output_tree_id: Some(7),
        },
        amounts,
        commitment: Field::from(42u64),
    }
}

#[test]
fn generated_conversion_keeps_context_padding_and_native_fields() {
    let numbers = Numbers::from_client(client(vec![7, 2]), &mut InputRecords::new()).unwrap();
    assert_eq!(
        (
            numbers.context.output_tree_id,
            numbers.context.uses_output_tree_id,
            &*numbers.amounts,
            numbers.commitment,
        ),
        (7, true, &[7u64, 2, 0][..], Field::from(42u64)),
    );
}

#[test]
fn generated_conversion_refuses_excess_capacity() {
    assert!(matches!(
        Numbers::from_client(client(vec![1; 4]), &mut InputRecords::new()),
        Err(ClientError::TooManyInputs {
            capacity: 3,
            found: 4
        })
    ));
}

#[input]
#[derive(ClientInputs)]
pub struct Destination {
    pub commitment: Field,
    pub amount: u64,
}

#[input]
#[derive(ClientInputs)]
pub struct Terms {
    pub destination: Destination,
    pub blinding: Field,
}

#[input]
#[derive(ClientInputs)]
pub struct Create {
    pub tx_context: TxContext,
    pub terms: Terms,
}

#[test]
fn nested_structs_convert_recursively_and_native_structs_convert_back() {
    let destination = Destination {
        commitment: Field::from(42u64),
        amount: 9,
    };
    let client = CreateClient {
        tx_context: TransactionOptions {
            blinding_seed: Some([0; 32]),
            output_tree_id: Some(7),
        },
        terms: TermsClient {
            destination: destination.into(),
            blinding: Field::from(13u64),
        },
    };
    let converted = Create::from_client(client, &mut InputRecords::new()).unwrap();
    assert_eq!(
        (
            converted.tx_context.output_tree_id,
            converted.terms.destination.amount,
            converted.terms.destination.commitment,
            converted.terms.blinding
        ),
        (7, 9, Field::from(42u64), Field::from(13u64)),
    );
}

#[input]
#[derive(ClientInputs)]
pub struct Payout {
    pub tx_context: TxContext,
    pub deposit: Utxo,
    pub owner: ShieldedAddress,
    pub asset: Asset,
}

impl PublicInputs for Payout {
    fn hash(&self, transaction_hash: &Field) -> Result<Field, CircuitError> {
        poseidon(&[self.owner.hash()?, *transaction_hash])
    }
}

/// Refunds a SOL deposit and creates an empty token output of `payout.asset`,
/// which no spent input carries: only the `Asset` field names its mint.
fn refund_with_empty_output(payout: &Payout) -> Result<CheckedTransaction, CircuitError> {
    let mut deposit = TokenUtxos::new_mut(core::slice::from_ref(&payout.deposit))?.close();
    let mut refund = TokenUtxos::new_init(&payout.owner, &deposit.asset());
    deposit.transfer_all(&mut refund)?;
    let empty = TokenUtxos::new_init(&payout.owner, &payout.asset).with_zero_output();
    ConfidentialTransaction::new(&payout.tx_context, payout)
        .with(deposit)
        .with(refund)
        .with(empty)
        .check()
}

struct Fixture {
    viewer: ShieldedKeypair,
    owner: NativeShieldedAddress,
    deposit: WalletUtxo,
    mint: Mint,
}

impl Fixture {
    fn new() -> Self {
        let viewer =
            ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[5; 32])).unwrap();
        let program = ProgramOwner::new(Address::new_from_array([9; 32]));
        let owner = program.address(viewer.viewing_pubkey()).unwrap();
        let deposit = program
            .input(
                &SppProofOutputUtxo::new(Mint::SOL, 30, owner).unwrap(),
                3,
                4,
            )
            .unwrap();
        Self {
            viewer,
            owner,
            deposit,
            mint: Mint::new(Address::new_from_array([3; 32]), 12),
        }
    }

    fn client(&self) -> PayoutClient {
        PayoutClient {
            tx_context: TransactionOptions {
                blinding_seed: Some([1; 32]),
                output_tree_id: Some(7),
            },
            deposit: self.deposit.clone(),
            owner: self.owner,
            asset: self.mint,
        }
    }

    fn finalize(
        &self,
        records: &InputRecords,
        checked: &CheckedTransaction,
    ) -> Result<FinalizedTransaction, ClientError> {
        let sender = self.viewer.shielded_address().unwrap();
        records.finalize(checked, &sender, sender.solana_address().unwrap())
    }
}

#[test]
fn an_asset_input_records_its_mint_for_the_outputs_that_use_it() {
    let fixture = Fixture::new();
    let mut records = InputRecords::new();
    let payout = Payout::from_client(fixture.client(), &mut records).unwrap();
    assert_eq!(payout.asset, fixture.mint.asset.to_bytes());

    let checked = spr_program::checked(|| refund_with_empty_output(&payout)).unwrap();
    let finalized = fixture.finalize(&records, &checked).unwrap();
    assert_eq!(
        finalized
            .output_utxos()
            .iter()
            .map(|output| (output.asset, output.amount))
            .collect::<Vec<_>>(),
        vec![(Mint::SOL, 30), (fixture.mint, 0)]
    );
}

fn is_conflicting_asset_id(result: Result<impl Sized, ClientError>) -> bool {
    matches!(result, Err(ClientError::InvalidInput(message)) if message == "the asset is recorded with a different asset id")
}

#[test]
fn an_asset_recorded_with_another_asset_id_is_refused() {
    let fixture = Fixture::new();
    // The spent deposit records SOL; the client names SOL with another ID.
    let client = PayoutClient {
        asset: Mint::new(Mint::SOL.asset, 99),
        ..fixture.client()
    };
    assert!(is_conflicting_asset_id(Payout::from_client(
        client,
        &mut InputRecords::new()
    )));

    let mut records = InputRecords::new();
    records.asset(fixture.mint).unwrap();
    records.asset(fixture.mint).unwrap();
    let other_id = Mint::new(fixture.mint.asset, fixture.mint.asset_id + 1);
    assert!(is_conflicting_asset_id(records.asset(other_id)));
}

#[test]
fn an_output_asset_without_a_recorded_mint_is_refused() {
    let fixture = Fixture::new();
    let payout = Payout::from_client(fixture.client(), &mut InputRecords::new()).unwrap();
    let checked = spr_program::checked(|| refund_with_empty_output(&payout)).unwrap();
    // The same spent input and owner, but no record of the mint.
    let mut records = InputRecords::new();
    records.utxo(&fixture.deposit).unwrap();
    records.address(&fixture.owner).unwrap();
    let Err(error) = fixture.finalize(&records, &checked) else {
        panic!("an unrecorded asset must not resolve");
    };
    assert!(
        matches!(&error, ClientError::InvalidInput(message) if message == "the asset has no registry record"),
        "{error}"
    );
}
