//! `InputRecords::finalize`: native SPP transactions built from a checked
//! program transaction, including address reservations, dummy padding and
//! output owner resolution.

use solana_address::Address;
use spr_keypair::{
    ShieldedAddress as NativeShieldedAddress, ShieldedKeypair, SigningKey, ViewingKey,
};
use spr_program::circuit::{
    CheckedTransaction, ConfidentialTransaction, DataUtxo, NewAddress, PublicInputs, TokenUtxos,
    Utxo, UtxoTrait,
};
use spr_program::{
    poseidon, to_bytes, CircuitError, ClientError, Field, InputRecords, ProgramOwner,
    ShieldedAddress, TxContext, ADDRESS_TREE_ID,
};
use spr_transaction::instructions::transact::FinalizedTransaction;
use spr_transaction::{Mint, SppProofOutputUtxo, WalletUtxo};

const STATE_TREE: u16 = 3;

fn keypair(seed: u8) -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32])).unwrap()
}

struct StatePublic {
    owner: ShieldedAddress,
    state_hash: Field,
}

impl PublicInputs for StatePublic {
    fn hash(&self, transaction_hash: &Field) -> Result<Field, CircuitError> {
        poseidon(&[self.owner.hash()?, self.state_hash, *transaction_hash])
    }
}

struct Fixture {
    viewer: ShieldedKeypair,
    program: ProgramOwner,
    owner: NativeShieldedAddress,
}

impl Fixture {
    fn new() -> Self {
        let viewer = keypair(7);
        let program = ProgramOwner::new(Address::new_from_array([9; 32]));
        let owner = program.address(viewer.viewing_pubkey()).unwrap();
        Self {
            viewer,
            program,
            owner,
        }
    }

    fn sender(&self) -> NativeShieldedAddress {
        self.viewer.shielded_address().unwrap()
    }

    fn finalize(
        &self,
        records: &InputRecords,
        checked: &CheckedTransaction,
    ) -> Result<FinalizedTransaction, ClientError> {
        let sender = self.sender();
        records.finalize(checked, &sender, sender.solana_address().unwrap())
    }

    fn public(&self, records: &mut InputRecords) -> StatePublic {
        StatePublic {
            owner: records.address(&self.owner).unwrap(),
            state_hash: Field::from(42u64),
        }
    }

    fn context(output_tree: u16) -> TxContext {
        InputRecords::context(&[1; 32], Some(output_tree)).unwrap()
    }

    /// Reserves the state's address and creates it under a raw state hash,
    /// with optional deposit inputs that may all be dummies.
    fn create(
        public: &StatePublic,
        deposits: &[Utxo],
        dummy_padding: bool,
    ) -> Result<CheckedTransaction, CircuitError> {
        let state = DataUtxo::new_init_with_hash(&public.owner, &public.state_hash);
        let deposit = TokenUtxos::new_mut(deposits)?.with_optional(&public.owner, &state.asset());
        let context = Self::context(0);
        let transaction = ConfidentialTransaction::new(&context, public);
        let transaction = if dummy_padding {
            transaction.with_dummy_padding()
        } else {
            transaction
        };
        transaction
            .with(NewAddress::new(&public.owner, &public.state_hash)?)
            .with(state)
            .with(deposit)
            .check()
    }

    /// Closes the state and refunds two optional deposits into their own
    /// outputs, keeping every input slot.
    fn close(
        public: &StatePublic,
        state: &Utxo,
        deposits: [&Utxo; 2],
    ) -> Result<CheckedTransaction, CircuitError> {
        let state = DataUtxo::new_mut_with_hash(state, &public.state_hash)?.close();
        let context = Self::context(7);
        let mut transaction = ConfidentialTransaction::new(&context, public).with_dummy_padding();
        let mut refunds = Vec::new();
        for deposit in deposits {
            let mut deposit = TokenUtxos::new_mut(core::slice::from_ref(deposit))?
                .with_optional(&public.owner, &state.asset())
                .close();
            let mut refund = TokenUtxos::new_init(&public.owner, &state.asset()).with_zero_output();
            deposit.transfer_all(&mut refund)?;
            transaction = transaction.with(deposit);
            refunds.push(refund);
        }
        transaction = transaction.with(state);
        refunds
            .into_iter()
            .fold(transaction, |transaction, refund| transaction.with(refund))
            .check()
    }

    /// The created state, spent from `STATE_TREE`.
    fn state_input(&self) -> WalletUtxo {
        let mut records = InputRecords::new();
        let public = self.public(&mut records);
        let created = self
            .finalize(
                &records,
                &Self::create(&public, &[Utxo::dummy()], false).unwrap(),
            )
            .unwrap();
        self.program
            .input(created.output_utxos().first().unwrap(), STATE_TREE, 0)
            .unwrap()
    }
}

fn input_slots(finalized: &FinalizedTransaction) -> Vec<(bool, bool, u16)> {
    finalized
        .input_utxos()
        .iter()
        .map(|input| (input.is_address(), input.is_dummy(), input.tree_id))
        .collect()
}

#[test]
fn a_raw_state_commitment_reserves_its_address_and_keeps_its_hash() {
    let fixture = Fixture::new();
    let mut records = InputRecords::new();
    let public = fixture.public(&mut records);
    let finalized = fixture
        .finalize(
            &records,
            &Fixture::create(&public, &[Utxo::dummy()], false).unwrap(),
        )
        .unwrap();
    let output = finalized.output_utxos().first().unwrap();
    assert_eq!(
        (
            input_slots(&finalized)
                .first()
                .map(|(address, ..)| *address),
            finalized
                .output_utxos()
                .iter()
                .map(|output| output.compact)
                .collect::<Vec<_>>(),
            (
                output.asset,
                output.amount,
                output.data_hash,
                output.data.utxo_data()
            ),
        ),
        (
            Some(true),
            vec![false, true],
            (Mint::SOL, 0, Some(to_bytes(&public.state_hash)), None),
        )
    );
}

/// An address-only transaction has no spent input to take a padding tree from,
/// so its dummy slots sit in the address tree.
#[test]
fn dummy_padding_of_an_address_only_transaction_sits_in_the_address_tree() {
    let fixture = Fixture::new();
    let mut records = InputRecords::new();
    let public = fixture.public(&mut records);
    let dummy = records
        .utxo(&WalletUtxo::dummy(STATE_TREE).unwrap())
        .unwrap();
    let checked = Fixture::create(&public, &[dummy, dummy], true).unwrap();
    let finalized = fixture.finalize(&records, &checked).unwrap();
    assert_eq!(
        input_slots(&finalized),
        vec![
            (true, false, ADDRESS_TREE_ID),
            (false, true, ADDRESS_TREE_ID),
            (false, true, ADDRESS_TREE_ID)
        ]
    );
}

#[test]
fn dummy_padding_sits_in_the_tree_of_the_first_spent_input() {
    let fixture = Fixture::new();
    let state = fixture.state_input();
    for funded_first in [false, true] {
        let mut records = InputRecords::new();
        let public = fixture.public(&mut records);
        let deposit = fixture
            .program
            .input(
                &SppProofOutputUtxo::new(Mint::SOL, 77, fixture.owner).unwrap(),
                STATE_TREE,
                1,
            )
            .unwrap();
        let deposit = records.utxo(&deposit).unwrap();
        let dummy = records.utxo(&WalletUtxo::dummy(0).unwrap()).unwrap();
        let deposits = if funded_first {
            [&deposit, &dummy]
        } else {
            [&dummy, &deposit]
        };
        let state = records.utxo(&state).unwrap();
        let finalized = fixture
            .finalize(
                &records,
                &Fixture::close(&public, &state, deposits).unwrap(),
            )
            .unwrap();
        assert_eq!(
            (
                input_slots(&finalized),
                finalized.output_tree_id(),
                finalized
                    .output_utxos()
                    .iter()
                    .map(|output| (output.amount, output.compact))
                    .collect::<Vec<_>>(),
            ),
            (
                vec![
                    (false, false, STATE_TREE),
                    (false, false, STATE_TREE),
                    (false, true, STATE_TREE)
                ],
                7,
                if funded_first {
                    vec![(77, false), (0, false)]
                } else {
                    vec![(0, false), (77, false)]
                },
            )
        );
    }
}

/// Pays `first` 10 of a program-owned deposit of 30 and `second` the rest.
fn pay(
    records: &mut InputRecords,
    destinations: [&NativeShieldedAddress; 2],
) -> Result<FinalizedTransaction, ClientError> {
    let fixture = Fixture::new();
    let deposit = fixture
        .program
        .input(
            &SppProofOutputUtxo::new(Mint::SOL, 30, fixture.owner).unwrap(),
            STATE_TREE,
            4,
        )
        .unwrap();
    let deposit = records.utxo(&deposit)?;
    let [first, second] = destinations.map(|address| records.address(address));
    let (first, second) = (first?, second?);
    let public = fixture.public(records);
    let checked = spr_program::checked(|| {
        let mut deposit = TokenUtxos::new_mut(&[deposit])?.close();
        let mut first = TokenUtxos::new_init(&first, &deposit.asset());
        let mut second = TokenUtxos::new_init(&second, &deposit.asset());
        deposit.transfer(&mut first, &10)?;
        deposit.transfer_all(&mut second)?;
        ConfidentialTransaction::new(&Fixture::context(7), &public)
            .with(deposit)
            .with(first)
            .with(second)
            .check()
    })?;
    fixture.finalize(records, &checked)
}

fn destination(signer: u8, viewer: u8) -> NativeShieldedAddress {
    NativeShieldedAddress {
        viewing_pubkey: ViewingKey::from_bytes(&[viewer; 32]).pubkey(),
        ..keypair(signer).shielded_address().unwrap()
    }
}

#[test]
fn outputs_resolve_each_owner_to_its_recorded_address() {
    let (first, second) = (destination(11, 11), destination(13, 13));
    let finalized = pay(&mut InputRecords::new(), [&first, &second]).unwrap();
    assert_eq!(
        finalized
            .output_utxos()
            .iter()
            .map(|output| (output.owner_address, output.amount))
            .collect::<Vec<_>>(),
        vec![(Some(first), 10), (Some(second), 20)]
    );
}

#[test]
fn an_owner_recorded_with_two_viewing_keys_is_refused_as_ambiguous() {
    let Err(error) = pay(
        &mut InputRecords::new(),
        [&destination(11, 11), &destination(11, 13)],
    ) else {
        panic!("an ambiguous owner must not resolve");
    };
    assert!(
        matches!(&error, ClientError::InvalidInput(message) if message == "the output owner has ambiguous viewing addresses"),
        "{error}"
    );
}
