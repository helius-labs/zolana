use ark_relations::r1cs::SynthesisMode;
use zk_program_sdk::{
    circuit::{constant, value, Assert, Bool, ConstraintSystem, Field, Uint},
    conversion::{field_bytes, to_bytes, Allocator, FromCircuit, ProofInput},
    CircuitErrorKind,
};
use zolana_hasher::primitives::hash_bytes;
use zolana_transaction::{Mint, WalletUtxo};

mod shared;
use shared::{keypair, spendable};

fn r1cs(input: &impl ProofInput) -> (bool, usize) {
    let cs = ConstraintSystem::new_ref();
    input
        .instantiate(&Allocator::R1cs(cs.clone()))
        .map(|_| ())
        .unwrap();
    (cs.is_satisfied().unwrap(), cs.num_constraints())
}

fn native_error(input: &impl ProofInput) -> Option<String> {
    input
        .instantiate(&Allocator::native())
        .err()
        .map(|e| e.to_string())
}

#[test]
fn plain_integers_and_bools_are_range_checked_in_r1cs() {
    let over_64 = {
        let cs = ConstraintSystem::new_ref();
        let value = (Field::from(u64::MAX) + Field::from(1u64))
            .instantiate(&Allocator::R1cs(cs.clone()))
            .unwrap();
        let _value = Uint::<64>::try_from(&value).unwrap();
        cs.is_satisfied().unwrap()
    };

    assert_eq!(
        (
            r1cs(&u64::MAX),
            r1cs(&u32::MAX),
            r1cs(&u16::MAX),
            r1cs(&true),
            over_64,
            Uint::<64>::try_from(&constant(Field::from(u64::MAX) + Field::from(1u64)))
                .err()
                .map(|e| e.to_string()),
        ),
        (
            (true, 65),
            (true, 33),
            (true, 17),
            (true, 1),
            false,
            Some("a value does not fit in 64 bits".to_string()),
        )
    );
}

#[test]
fn bytes_must_be_canonical() {
    let canonical = field_bytes(&Field::from(7u64));

    assert_eq!(
        (native_error(&canonical), native_error(&[0xffu8; 32])),
        (
            None,
            Some("32-byte input is too large for a circuit value".to_string())
        )
    );
}

#[test]
fn the_native_run_records_what_a_circuit_var_cannot_hold() {
    let owner = keypair(5);
    let address = owner.shielded_address().unwrap();
    let input = spendable(&owner, Mint::SOL, 300, 0);
    let dummy = WalletUtxo::dummy(3).unwrap();
    let allocator = Allocator::native();
    let owner = address.instantiate(&allocator).unwrap();
    let asset = Mint::SOL.instantiate(&allocator).unwrap();
    let utxo_hash = input.instantiate(&allocator).unwrap().hash().unwrap();
    let dummy_domain = dummy.instantiate(&allocator).unwrap().domain;
    let records = allocator.into_records();
    let r1cs_records = {
        let allocator = Allocator::R1cs(ConstraintSystem::new_ref());
        let _owner = address.instantiate(&allocator).unwrap();
        allocator.into_records()
    };
    let sol_asset = hash_bytes(Mint::SOL.asset.as_array()).unwrap();

    assert_eq!(
        (
            to_bytes(&owner.hash().unwrap()).unwrap(),
            records.owner(&address.owner_hash().unwrap()).copied(),
            to_bytes(&asset.hash().unwrap()).unwrap(),
            records.mint(&sol_asset).copied(),
            to_bytes(&utxo_hash).unwrap(),
            records
                .utxo(&input.utxo_hash)
                .map(|recorded| recorded.utxo_hash),
            records.utxo(&dummy.utxo_hash).is_some(),
            to_bytes(&dummy_domain).unwrap(),
            r1cs_records.owner(&address.owner_hash().unwrap()).is_some(),
        ),
        (
            address.owner_hash().unwrap(),
            Some(address),
            sol_asset,
            Some(Mint::SOL),
            input.utxo_hash,
            Some(input.utxo_hash),
            false,
            field_bytes(&Field::from(u64::from(zolana_interface::DUMMY_DOMAIN))),
            false,
        )
    );
}

#[test]
fn a_field_input_is_allocated_unchecked() {
    assert_eq!(
        r1cs(&(Field::from(u64::MAX) * Field::from(u64::MAX))),
        (true, 0)
    );
}

#[test]
fn only_a_constant_has_a_value_in_setup_and_in_prove_mode() {
    let read = |mode: SynthesisMode| {
        let cs = ConstraintSystem::new_ref();
        cs.set_mode(mode);
        let allocated = Field::from(3u64).instantiate(&Allocator::R1cs(cs)).unwrap();
        match value(&allocated) {
            Err(error) if matches!(error.kind(), CircuitErrorKind::ReadsVariableValue) => {
                error.location().file().ends_with("tests/types.rs")
            }
            other => panic!("expected a value read of a variable, got {other:?}"),
        }
    };

    assert_eq!(
        (
            read(SynthesisMode::Setup),
            read(SynthesisMode::Prove {
                construct_matrices: true
            }),
            value(&constant(3u64)).ok(),
        ),
        (true, true, Some(Field::from(3u64)))
    );
}

fn from_circuit_error<T: FromCircuit>(circuit: &T::Circuit) -> Option<String> {
    T::from_circuit(circuit).err().map(|e| e.to_string())
}

#[test]
fn circuit_values_convert_back_with_the_same_ranges() {
    assert_eq!(
        (
            u64::from_circuit(&Uint::constant(u64::MAX).unwrap()).ok(),
            u32::from_circuit(&Uint::constant(u64::from(u32::MAX)).unwrap()).ok(),
            bool::from_circuit(&Bool::constant(true)).ok(),
            <[u8; 32]>::from_circuit(&constant(7u64)).ok(),
            <[u16; 2]>::from_circuit(&[Uint::constant(1).unwrap(), Uint::constant(2).unwrap()])
                .ok(),
            from_circuit_error::<bool>(&true.instantiate(&Allocator::native()).unwrap()),
            Uint::<64>::try_from(&constant(Field::from(u64::MAX) + Field::from(1u64)))
                .err()
                .map(|e| e.to_string()),
            Uint::<16>::constant(70_000).err().map(|e| e.to_string()),
        ),
        (
            Some(u64::MAX),
            Some(u32::MAX),
            Some(true),
            Some(field_bytes(&Field::from(7u64))),
            Some([1u16, 2]),
            None,
            Some("a value does not fit in 64 bits".to_string()),
            Some("a value does not fit in 16 bits".to_string()),
        )
    );
}

#[test]
fn a_bool_selects_and_combines_natively_and_in_r1cs() {
    let native = |bool: Bool| {
        (
            value(&bool.select(&constant(5u64), &constant(9u64))).unwrap(),
            value(&bool.not().into()).unwrap(),
            value(&bool.and(&Bool::constant(true)).into()).unwrap(),
            value(&bool.or(&Bool::constant(false)).into()).unwrap(),
        )
    };
    let selects_in_r1cs = |input: bool, expected: u64| {
        let cs = ConstraintSystem::new_ref();
        let allocator = Allocator::R1cs(cs.clone());
        let bool = input.instantiate(&allocator).unwrap();
        let if_true = Field::from(5u64).instantiate(&allocator).unwrap();
        let if_false = Field::from(9u64).instantiate(&allocator).unwrap();
        bool.select(&if_true, &if_false)
            .assert_equal(&constant(expected), "the selection")
            .unwrap();
        cs.is_satisfied().unwrap()
    };

    assert_eq!(
        (
            native(Bool::constant(true)),
            native(Bool::constant(false)),
            value(&constant(3u64).is_equal(&constant(3u64)).unwrap().into()).unwrap(),
            value(&constant(3u64).is_equal(&constant(4u64)).unwrap().into()).unwrap(),
            [
                selects_in_r1cs(true, 5),
                selects_in_r1cs(true, 9),
                selects_in_r1cs(false, 9),
                selects_in_r1cs(false, 5),
            ],
        ),
        (
            (
                Field::from(5u64),
                Field::from(0u64),
                Field::from(1u64),
                Field::from(1u64)
            ),
            (
                Field::from(9u64),
                Field::from(1u64),
                Field::from(0u64),
                Field::from(0u64)
            ),
            Field::from(1u64),
            Field::from(0u64),
            [true, false, true, false],
        )
    );
}
