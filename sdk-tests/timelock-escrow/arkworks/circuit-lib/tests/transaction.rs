use ark_relations::r1cs::ConstraintSystem;
use circuit_lib::{
    constant,
    convert::{field_bytes, to_bytes, tx_context, utxo},
    hash_chain4, poseidon, zero, Allocator, CircuitVar, ConfidentialTransaction, DataHash,
    DataUtxo, Field, ProofInput, PublicInputs, RelationError, TokenUtxo, TxContext, Utxo,
};
use zolana_client::ProofInputUtxo;
use zolana_hasher::{hash_chain::create_hash_chain_4_from_slice, Hasher, Poseidon};
use zolana_program::{
    derive_output_blinding_seed, derive_private_tx_blinding, derive_transact_output_blinding,
};

const TREE_ID: u16 = 2;
const FIRST_NULLIFIER: u64 = 22;
const BLINDING_SEED: u64 = 23;

fn bytes(value: u64) -> [u8; 32] {
    field_bytes(&Field::from(value))
}

fn plain_input(owner: u64, amount: u64, blinding: u64) -> ProofInputUtxo {
    ProofInputUtxo::new(
        bytes(owner),
        &[4u8; 32].into(),
        amount,
        &bytes(blinding),
        TREE_ID,
    )
    .unwrap()
}

fn context() -> TxContext {
    tx_context(&bytes(FIRST_NULLIFIER), &bytes(BLINDING_SEED), TREE_ID).unwrap()
}

#[derive(Clone, Debug)]
struct Counter {
    value: CircuitVar,
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

fn counter(value: u64) -> Counter {
    Counter {
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

fn expected_output(owner: u64, amount: u64, data_hash: [u8; 32], slot: u32) -> [u8; 32] {
    let first = bytes(FIRST_NULLIFIER);
    let seed = derive_output_blinding_seed(&first, &bytes(BLINDING_SEED)).unwrap();
    ProofInputUtxo::new(
        bytes(owner),
        &[4u8; 32].into(),
        amount,
        &derive_transact_output_blinding(&first, &seed, slot).unwrap(),
        TREE_ID,
    )
    .unwrap()
    .with_data_hash(data_hash)
    .hash()
    .unwrap()
}

fn expected_private_tx_hash(inputs: &[[u8; 32]], outputs: &[[u8; 32]]) -> [u8; 32] {
    let blinding =
        derive_private_tx_blinding(&bytes(FIRST_NULLIFIER), &bytes(BLINDING_SEED)).unwrap();
    Poseidon::hashv(&[
        create_hash_chain_4_from_slice(inputs).unwrap().as_slice(),
        create_hash_chain_4_from_slice(outputs).unwrap().as_slice(),
        create_hash_chain_4_from_slice(&vec![[0u8; 32]; inputs.len()])
            .unwrap()
            .as_slice(),
        blinding.as_slice(),
    ])
    .unwrap()
}

fn transaction<P: PublicInputs>(
    context: &TxContext,
    public: &P,
    inputs: [Utxo; 3],
) -> Result<CircuitVar, RelationError> {
    let [first, second, data] = inputs;
    let mut token = TokenUtxo::new_mut([first, second])?;
    let transfer = token.transfer(&constant(30u64), constant(350u64));
    let mut mutated = DataUtxo::new_mut(&data, counter(9))?;
    mutated.value = constant(10u64);
    ConfidentialTransaction::<P, 3, 4>::new(context, public)
        .with_token_utxos(token)
        .with_output_token_utxo(transfer)
        .with_data_utxo(mutated)
        .check()
}

fn inputs() -> [Utxo; 3] {
    let counter_hash = to_bytes(&counter(9).hash().unwrap()).unwrap();
    [
        utxo(&plain_input(11, 300, 1)).unwrap(),
        utxo(&plain_input(11, 200, 2)).unwrap(),
        utxo(&plain_input(12, 7, 17).with_data_hash(counter_hash)).unwrap(),
    ]
}

#[test]
fn hash_chain4_matches_zolana_for_every_length() {
    for length in 0..=7u64 {
        let values: Vec<CircuitVar> = (1..=length).map(constant).collect();
        let value_bytes: Vec<[u8; 32]> = values.iter().map(|v| to_bytes(v).unwrap()).collect();

        assert_eq!(
            to_bytes(&hash_chain4(&values).unwrap()).unwrap(),
            create_hash_chain_4_from_slice(&value_bytes).unwrap(),
            "length {length}"
        );
    }
}

#[test]
fn the_private_tx_hash_follows_the_order_utxos_are_added() {
    let counter_hash = to_bytes(&counter(9).hash().unwrap()).unwrap();
    let next_hash = to_bytes(&counter(10).hash().unwrap()).unwrap();
    let expected = expected_private_tx_hash(
        &[
            plain_input(11, 300, 1).hash().unwrap(),
            plain_input(11, 200, 2).hash().unwrap(),
            plain_input(12, 7, 17)
                .with_data_hash(counter_hash)
                .hash()
                .unwrap(),
        ],
        &[
            expected_output(11, 150, [0u8; 32], 0),
            expected_output(30, 350, [0u8; 32], 1),
            expected_output(12, 7, next_hash, 2),
            [0u8; 32],
        ],
    );
    let tag = constant(5u64);

    assert_eq!(
        (
            to_bytes(&transaction(&context(), &PrivateTxHash, inputs()).unwrap()).unwrap(),
            to_bytes(&transaction(&context(), &Tagged { tag: tag.clone() }, inputs()).unwrap())
                .unwrap(),
        ),
        (
            expected,
            Poseidon::hashv(&[to_bytes(&tag).unwrap().as_slice(), expected.as_slice()]).unwrap(),
        )
    );
}

#[test]
fn the_same_transaction_is_satisfied_in_r1cs() {
    let cs = ConstraintSystem::<Field>::new_ref();
    let allocator = Allocator::R1cs(cs.clone());
    let context = context().instantiate(&allocator).unwrap();
    let inputs = inputs().map(|input| input.instantiate(&allocator).unwrap());
    let in_circuit = transaction(&context, &PrivateTxHash, inputs).unwrap();

    assert_eq!(
        (to_bytes(&in_circuit).unwrap(), cs.is_satisfied().unwrap()),
        (
            to_bytes(&transaction(&self::context(), &PrivateTxHash, self::inputs()).unwrap())
                .unwrap(),
            true
        )
    );
}

#[test]
fn a_transaction_names_the_misuse() {
    let context = context();
    let [first, second, data] = inputs();
    let token = TokenUtxo::new_mut([first.clone(), second]).unwrap();
    let mut burned = DataUtxo::new_burn(&data, counter(9)).unwrap();
    let _payout = burned.transfer(&constant(40u64), constant(7u64)).unwrap();
    let too_many_outputs =
        ConfidentialTransaction::<PrivateTxHash, 3, 1>::new(&context, &PrivateTxHash)
            .with_token_utxos(token.clone())
            .with_data_utxo(DataUtxo::<Counter>::new_init(&constant(3u64)).unwrap())
            .check();
    let too_many_inputs =
        ConfidentialTransaction::<PrivateTxHash, 2, 2>::new(&context, &PrivateTxHash)
            .with_token_utxos(token)
            .with_data_utxo(burned)
            .check();

    assert_eq!(
        (
            too_many_outputs.map(|_| ()).map_err(|e| e.to_string()),
            too_many_inputs.map(|_| ()).map_err(|e| e.to_string()),
        ),
        (
            Err("output slot 1 is outside the transaction".to_string()),
            Err("input slot 2 is outside the transaction".to_string()),
        )
    );
}

#[test]
fn a_burned_utxo_pays_out_everything() {
    let context = context();
    let [first, _, data] = inputs();
    let burn = |paid: u64| {
        let mut burned = DataUtxo::new_burn(&data, counter(9)).unwrap();
        let payout = burned.transfer(&constant(40u64), constant(paid)).unwrap();
        ConfidentialTransaction::<PrivateTxHash, 1, 1>::new(&context, &PrivateTxHash)
            .with_data_utxo(burned)
            .with_output_token_utxo(payout)
            .check()
            .map(|_| ())
            .map_err(|e| e.to_string())
    };
    let mut token = TokenUtxo::new_burn([first.clone()]).unwrap();
    let transfer = token.transfer(&constant(30u64), constant(100u64));
    let token_leftover =
        ConfidentialTransaction::<PrivateTxHash, 1, 1>::new(&context, &PrivateTxHash)
            .with_token_utxos(token)
            .with_output_token_utxo(transfer)
            .check()
            .map(|_| ())
            .map_err(|e| e.to_string());
    let no_input = ConfidentialTransaction::<PrivateTxHash, 1, 1>::new(&context, &PrivateTxHash)
        .with_data_utxo(DataUtxo::<Counter>::new_init(&constant(3u64)).unwrap())
        .check()
        .map(|_| ())
        .map_err(|e| e.to_string());
    let in_r1cs = {
        let cs = ConstraintSystem::<Field>::new_ref();
        let allocator = Allocator::R1cs(cs.clone());
        let mut token = TokenUtxo::new_burn([first.instantiate(&allocator).unwrap()]).unwrap();
        let transfer = token.transfer(&constant(30u64), constant(100u64));
        let _public_hash = ConfidentialTransaction::<PrivateTxHash, 1, 1>::new(
            &context.instantiate(&allocator).unwrap(),
            &PrivateTxHash,
        )
        .with_token_utxos(token)
        .with_output_token_utxo(transfer)
        .check()
        .unwrap();
        cs.is_satisfied().unwrap()
    };

    assert_eq!(
        (burn(7), burn(5), token_leftover, no_input, in_r1cs),
        (
            Ok(()),
            Err("a burned data utxo leaves value unpaid".to_string()),
            Err("a burned token utxo leaves a balance".to_string()),
            Err("a transaction spends at least one input".to_string()),
            false,
        )
    );
}
