use borsh::BorshSerialize;
use solana_address::Address;
use solana_signature::Signature;
use zk_program_sdk::{
    circuit::{
        constant, nonzero_hash_chain, poseidon, Asset, Balance, CircuitVar,
        ConfidentialTransaction, ConstraintSystem, DataHash, DataUtxo, Field, Owner, PublicInputs,
        TokenUtxo, Utxo,
    },
    conversion::{field_bytes, to_bytes, Allocator, FromCircuit, ProofInput},
    RelationError, TxContext,
};
use zolana_client::ProofInputUtxo;
use zolana_hasher::{Hasher, Poseidon};
use zolana_keypair::{ShieldedAddress, ShieldedKeypair, SigningKey};
use zolana_program::{
    derive_output_blinding_seed, derive_private_tx_blinding, derive_transact_output_blinding,
};
use zolana_transaction::{Data, Mint, WalletUtxo};

const TREE_ID: u16 = 2;
const BLINDING_SEED: u64 = 23;
const MINT: Mint = Mint::new(Address::new_from_array([4u8; 32]), 4);

fn bytes(value: u64) -> [u8; 32] {
    field_bytes(&Field::from(value))
}

fn keypair(seed: u8) -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32])).unwrap()
}

fn address(seed: u8) -> ShieldedAddress {
    keypair(seed).shielded_address().unwrap()
}

fn owner(seed: u8) -> Owner {
    address(seed).instantiate(&Allocator::native()).unwrap()
}

fn wallet_input(
    owner_seed: u8,
    amount: u64,
    blinding: u64,
    data_hash: Option<[u8; 32]>,
) -> WalletUtxo {
    let owner = keypair(owner_seed);
    let address = owner.shielded_address().unwrap();
    let utxo = zolana_transaction::utxo::Utxo {
        owner: owner.signing_pubkey(),
        asset: MINT,
        amount,
        blinding: bytes(blinding),
        ring_program_id: None,
        data: Data::default(),
    };
    let utxo_hash = utxo
        .hash(
            &address.nullifier_pubkey,
            &data_hash.unwrap_or_default(),
            &[0u8; 32],
            TREE_ID,
        )
        .unwrap();
    WalletUtxo {
        nullifier: owner.nullifier(&utxo_hash, &utxo.blinding).unwrap(),
        utxo,
        nullifier_pubkey: address.nullifier_pubkey,
        utxo_hash,
        data_hash,
        ring_data_hash: None,
        tree_id: TREE_ID,
        leaf_index: 0,
        latest_tree_id: None,
        slot: 0,
        tx_signature: Signature::default(),
        slot_index: 0,
    }
}

fn tx_context() -> TxContext {
    TxContext {
        blinding_seed: bytes(BLINDING_SEED),
        output_tree_id: Some(TREE_ID),
    }
}

fn first_nullifier() -> [u8; 32] {
    inputs()
        .first()
        .map(|input| input.nullifier)
        .expect("first input")
}

fn context() -> zk_program_sdk::circuit::TxContext {
    tx_context().instantiate(&Allocator::native()).unwrap()
}

#[derive(BorshSerialize)]
pub struct Counter {
    value: u64,
}

impl ProofInput for Counter {
    type Circuit = circuit::Counter;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::Counter, RelationError> {
        Ok(circuit::Counter {
            value: self.value.instantiate(allocator)?,
        })
    }
}

impl FromCircuit for Counter {
    fn from_circuit(circuit: &circuit::Counter) -> Result<Self, RelationError> {
        Ok(Self {
            value: u64::from_circuit(&circuit.value)?,
        })
    }
}

mod circuit {
    use zk_program_sdk::{
        circuit::{poseidon, zero, CircuitVar, DataHash, UtxoData},
        RelationError,
    };

    #[derive(Clone, Debug)]
    pub struct Counter {
        pub value: CircuitVar,
    }

    impl Default for Counter {
        fn default() -> Self {
            Self { value: zero() }
        }
    }

    impl DataHash for Counter {
        fn hash(&self) -> Result<CircuitVar, RelationError> {
            poseidon(&[self.value.hash()?])
        }
    }

    impl UtxoData for Counter {
        type Client = super::Counter;
    }
}

fn counter(value: u64) -> circuit::Counter {
    circuit::Counter {
        value: constant(value),
    }
}

struct PrivateTxHash;

impl PublicInputs for PrivateTxHash {
    fn hash(&self, private_tx_hash: &CircuitVar) -> Result<CircuitVar, RelationError> {
        Ok(private_tx_hash.clone())
    }
}

struct Tagged {
    tag: CircuitVar,
}

impl PublicInputs for Tagged {
    fn hash(&self, private_tx_hash: &CircuitVar) -> Result<CircuitVar, RelationError> {
        poseidon(&[self.tag.clone(), private_tx_hash.clone()])
    }
}

fn expected_output(
    owner: [u8; 32],
    asset: &Address,
    amount: u64,
    data_hash: [u8; 32],
    slot: u32,
) -> [u8; 32] {
    let first = first_nullifier();
    let seed = derive_output_blinding_seed(&first, &bytes(BLINDING_SEED)).unwrap();
    ProofInputUtxo::new(
        owner,
        asset,
        amount,
        &derive_transact_output_blinding(&first, &seed, slot).unwrap(),
        TREE_ID,
    )
    .unwrap()
    .with_data_hash(data_hash)
    .hash()
    .unwrap()
}

fn chain(values: &[[u8; 32]]) -> [u8; 32] {
    values
        .iter()
        .filter(|value| **value != [0u8; 32])
        .fold([0u8; 32], |chain, value| {
            Poseidon::hashv(&[chain.as_slice(), value.as_slice()]).unwrap()
        })
}

fn expected_private_tx_hash(inputs: &[[u8; 32]], outputs: &[[u8; 32]]) -> [u8; 32] {
    let blinding = derive_private_tx_blinding(&first_nullifier(), &bytes(BLINDING_SEED)).unwrap();
    Poseidon::hashv(&[
        chain(inputs).as_slice(),
        chain(outputs).as_slice(),
        [0u8; 32].as_slice(),
        blinding.as_slice(),
    ])
    .unwrap()
}

fn transaction<P: PublicInputs>(
    context: &zk_program_sdk::circuit::TxContext,
    public: &P,
    inputs: [Utxo; 3],
) -> Result<CircuitVar, RelationError> {
    let [first, second, data] = inputs;
    let mut token = TokenUtxo::new_mut(&[first, second])?;
    let mut transfer = TokenUtxo::new_init(&owner(30), &token.asset());
    token.transfer(&mut transfer, &constant(350u64))?;
    let mut mutated = DataUtxo::new_mut(&data, &counter(9))?;
    mutated.value = constant(10u64);
    ConfidentialTransaction::new(context, public)
        .with_token_utxos(token)
        .with_token_utxos(transfer)
        .with_data_utxo(mutated)
        .check()
        .map(|checked| checked.public_hash().clone())
}

fn inputs() -> [WalletUtxo; 3] {
    let counter_hash = to_bytes(&counter(9).hash().unwrap()).unwrap();
    [
        wallet_input(11, 300, 1, None),
        wallet_input(11, 200, 2, None),
        wallet_input(12, 7, 17, Some(counter_hash)),
    ]
}

fn native_inputs() -> [Utxo; 3] {
    inputs().map(|input| input.instantiate(&Allocator::native()).unwrap())
}

#[test]
fn nonzero_hash_chain_skips_zeros_for_every_length() {
    for length in 0..=7u64 {
        let values: Vec<CircuitVar> = (1..=length)
            .map(|value| constant(if value % 3 == 0 { 0 } else { value }))
            .collect();
        let value_bytes: Vec<[u8; 32]> = values.iter().map(|v| to_bytes(v).unwrap()).collect();

        assert_eq!(
            to_bytes(&nonzero_hash_chain(&values).unwrap()).unwrap(),
            chain(&value_bytes),
            "length {length}"
        );
    }
}

#[test]
fn the_private_tx_hash_follows_the_order_utxos_are_added() {
    let next_hash = to_bytes(&counter(10).hash().unwrap()).unwrap();
    let owner_hash = |seed| address(seed).owner_hash().unwrap();
    let expected = expected_private_tx_hash(
        &inputs().map(|input| input.utxo_hash),
        &[
            expected_output(owner_hash(11), &MINT.asset, 150, [0u8; 32], 0),
            expected_output(owner_hash(30), &MINT.asset, 350, [0u8; 32], 1),
            expected_output(owner_hash(12), &MINT.asset, 7, next_hash, 2),
        ],
    );
    let tag = constant(5u64);

    assert_eq!(
        (
            to_bytes(&transaction(&context(), &PrivateTxHash, native_inputs()).unwrap()).unwrap(),
            to_bytes(
                &transaction(&context(), &Tagged { tag: tag.clone() }, native_inputs()).unwrap()
            )
            .unwrap(),
        ),
        (
            expected,
            Poseidon::hashv(&[to_bytes(&tag).unwrap().as_slice(), expected.as_slice()]).unwrap(),
        )
    );
}

#[test]
fn two_transfers_into_one_destination_produce_one_output_holding_the_sum() {
    let pay_twice = |allocator: &Allocator| -> Result<([u8; 32], bool), RelationError> {
        let context = tx_context().instantiate(allocator)?;
        let [first, second, data] = inputs().map(|input| input.instantiate(allocator).unwrap());
        let mut token = TokenUtxo::new_mut(&[first, second])?;
        let mut payment = TokenUtxo::new_init(&owner(30), &token.asset());
        token.transfer(&mut payment, &allocator.private_input(&constant(100u64))?)?;
        token.transfer(&mut payment, &allocator.private_input(&constant(250u64))?)?;
        let mut mutated = DataUtxo::new_mut(&data, &counter(9))?;
        mutated.value = constant(10u64);
        let checked = ConfidentialTransaction::new(&context, &PrivateTxHash)
            .with_token_utxos(token)
            .with_token_utxos(payment)
            .with_data_utxo(mutated)
            .check()?;
        let satisfied = match allocator {
            Allocator::R1cs(cs) => cs.is_satisfied()?,
            Allocator::Native(_) => true,
        };
        Ok((to_bytes(checked.private_tx_hash())?, satisfied))
    };
    let owner_hash = |seed| address(seed).owner_hash().unwrap();
    let expected = expected_private_tx_hash(
        &inputs().map(|input| input.utxo_hash),
        &[
            expected_output(owner_hash(11), &MINT.asset, 150, [0u8; 32], 0),
            expected_output(owner_hash(30), &MINT.asset, 350, [0u8; 32], 1),
            expected_output(
                owner_hash(12),
                &MINT.asset,
                7,
                to_bytes(&counter(10).hash().unwrap()).unwrap(),
                2,
            ),
        ],
    );

    assert_eq!(
        (
            pay_twice(&Allocator::native()).unwrap(),
            pay_twice(&Allocator::R1cs(ConstraintSystem::new_ref())).unwrap(),
        ),
        ((expected, true), (expected, true))
    );
}

#[test]
fn a_transfer_that_leaves_a_utxo_out_of_the_transaction_is_refused() {
    let leave_out = |allocator: &Allocator, destination_added: bool| -> Result<bool, String> {
        let context = tx_context()
            .instantiate(allocator)
            .map_err(|e| e.to_string())?;
        let [first, second, data] = inputs().map(|input| input.instantiate(allocator).unwrap());
        let transaction = || -> Result<(), RelationError> {
            let mut token = TokenUtxo::new_mut(&[first, second])?;
            let mut vault = DataUtxo::new_mut(&data, &counter(9))?;
            let mut payment = TokenUtxo::new_init(&owner(30), &token.asset());
            token.transfer(&mut payment, &allocator.private_input(&constant(100u64))?)?;
            vault.transfer(&mut payment, &allocator.private_input(&constant(3u64))?)?;
            let transaction =
                ConfidentialTransaction::new(&context, &PrivateTxHash).with_token_utxos(token);
            let transaction = if destination_added {
                transaction.with_token_utxos(payment)
            } else {
                transaction.with_data_utxo(vault)
            };
            transaction.check().map(|_| ())
        };
        transaction().map_err(|e| e.to_string())?;
        match allocator {
            Allocator::R1cs(cs) => cs.is_satisfied().map_err(|e| e.to_string()),
            Allocator::Native(_) => Ok(true),
        }
    };
    let natively_and_in_r1cs = |destination_added: bool| {
        (
            leave_out(&Allocator::native(), destination_added),
            leave_out(
                &Allocator::R1cs(ConstraintSystem::new_ref()),
                destination_added,
            ),
        )
    };
    let refused = || {
        (
            Err("value leaves the transaction: a utxo was not added".to_string()),
            Ok(false),
        )
    };

    assert_eq!(
        (natively_and_in_r1cs(false), natively_and_in_r1cs(true)),
        (refused(), refused())
    );
}

#[test]
fn the_same_transaction_is_satisfied_in_r1cs() {
    let cs = ConstraintSystem::new_ref();
    let allocator = Allocator::R1cs(cs.clone());
    let context = tx_context().instantiate(&allocator).unwrap();
    let inputs = inputs().map(|input| input.instantiate(&allocator).unwrap());
    let in_circuit = transaction(&context, &PrivateTxHash, inputs).unwrap();

    assert_eq!(
        (to_bytes(&in_circuit).unwrap(), cs.is_satisfied().unwrap()),
        (
            to_bytes(&transaction(&self::context(), &PrivateTxHash, native_inputs()).unwrap())
                .unwrap(),
            true
        )
    );
}

#[test]
fn a_burned_utxo_pays_out_everything() {
    let context = context();
    let [first, _, data] = native_inputs();
    let burn = |paid: u64| {
        let mut burned = DataUtxo::new_burn(&data, &counter(9)).unwrap();
        let mut payout = TokenUtxo::new_init(&owner(40), &burned.asset());
        burned.transfer(&mut payout, &constant(paid)).unwrap();
        ConfidentialTransaction::new(&context, &PrivateTxHash)
            .with_data_utxo(burned)
            .with_token_utxos(payout)
            .check()
            .map(|_| ())
            .map_err(|e| e.to_string())
    };
    let mut token = TokenUtxo::new_burn(&[first]).unwrap();
    let mut transfer = TokenUtxo::new_init(&owner(30), &token.asset());
    token.transfer(&mut transfer, &constant(100u64)).unwrap();
    let token_leftover = ConfidentialTransaction::new(&context, &PrivateTxHash)
        .with_token_utxos(token)
        .with_token_utxos(transfer)
        .check()
        .map(|_| ())
        .map_err(|e| e.to_string());
    let no_input = ConfidentialTransaction::new(&context, &PrivateTxHash)
        .with_data_utxo(DataUtxo::<circuit::Counter>::new_init(
            &owner(3),
            &Asset::sol(),
        ))
        .check()
        .map(|_| ())
        .map_err(|e| e.to_string());
    let in_r1cs = {
        let cs = ConstraintSystem::new_ref();
        let allocator = Allocator::R1cs(cs.clone());
        let [first_input, _, _] = inputs();
        let mut token =
            TokenUtxo::new_burn(&[first_input.instantiate(&allocator).unwrap()]).unwrap();
        let mut transfer = TokenUtxo::new_init(&owner(30), &token.asset());
        token.transfer(&mut transfer, &constant(100u64)).unwrap();
        let _public_hash = ConfidentialTransaction::new(
            &tx_context().instantiate(&allocator).unwrap(),
            &PrivateTxHash,
        )
        .with_token_utxos(token)
        .with_token_utxos(transfer)
        .check()
        .unwrap();
        cs.is_satisfied().unwrap()
    };

    assert_eq!(
        (burn(7), burn(5), token_leftover, no_input, in_r1cs),
        (
            Ok(()),
            Err("a burned data utxo leaves a balance".to_string()),
            Err("a burned token utxo leaves a balance".to_string()),
            Err("a transaction spends at least one input".to_string()),
            false,
        )
    );
}
