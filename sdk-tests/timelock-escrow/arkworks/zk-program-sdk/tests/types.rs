use zk_program_sdk::{
    circuit::{constant, Assert, CircuitVar, ConstraintSystem, Field},
    conversion::{field_bytes, to_bytes, Allocator, FromCircuit, ProofInput},
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
        let value = Allocator::R1cs(cs.clone())
            .private_input(&constant(Field::from(u64::MAX) + Field::from(1u64)))
            .unwrap();
        value.check_bits(64).unwrap();
        cs.is_satisfied().unwrap()
    };

    assert_eq!(
        (
            r1cs(&u64::MAX),
            r1cs(&u32::MAX),
            r1cs(&u16::MAX),
            r1cs(&true),
            over_64,
            constant(Field::from(u64::MAX) + Field::from(1u64))
                .check_bits(64)
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
            Some("32-byte input is not a canonical field element".to_string())
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
    let owner_hash = address.instantiate(&allocator).unwrap();
    let asset_hash = Mint::SOL.instantiate(&allocator).unwrap();
    let utxo_hash = input.instantiate(&allocator).unwrap().hash().unwrap();
    let dummy_domain = dummy.instantiate(&allocator).unwrap().domain;
    let records = allocator.into_records();
    let r1cs_records = {
        let allocator = Allocator::R1cs(ConstraintSystem::new_ref());
        let _owner_hash = address.instantiate(&allocator).unwrap();
        allocator.into_records()
    };
    let sol_asset = hash_bytes(Mint::SOL.asset.as_array()).unwrap();

    assert_eq!(
        (
            to_bytes(&owner_hash).unwrap(),
            records.owner(&address.owner_hash().unwrap()).copied(),
            to_bytes(&asset_hash).unwrap(),
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
fn a_plain_circuit_var_input_is_allocated_unchecked() {
    let hash: CircuitVar = constant(Field::from(u64::MAX) * Field::from(u64::MAX));

    assert_eq!(r1cs(&hash), (true, 0));
}

fn from_circuit_error<T: FromCircuit>(circuit: &T::Circuit) -> Option<String> {
    T::from_circuit(circuit).err().map(|e| e.to_string())
}

#[test]
fn circuit_values_convert_back_with_the_same_ranges() {
    assert_eq!(
        (
            u64::from_circuit(&constant(u64::MAX)).ok(),
            u32::from_circuit(&constant(u64::from(u32::MAX))).ok(),
            bool::from_circuit(&constant(1u64)).ok(),
            <[u8; 32]>::from_circuit(&constant(7u64)).ok(),
            <[u16; 2]>::from_circuit(&[constant(1u64), constant(2u64)]).ok(),
            from_circuit_error::<u64>(&constant(Field::from(u64::MAX) + Field::from(1u64))),
            from_circuit_error::<u16>(&constant(70_000u64)),
            from_circuit_error::<bool>(&constant(2u64)),
            from_circuit_error::<[u16; 2]>(&[constant(1u64), constant(70_000u64)]),
        ),
        (
            Some(u64::MAX),
            Some(u32::MAX),
            Some(true),
            Some(field_bytes(&Field::from(7u64))),
            Some([1u16, 2]),
            Some("a value does not fit in 64 bits".to_string()),
            Some("a value does not fit in 16 bits".to_string()),
            Some("a value is neither 0 nor 1".to_string()),
            Some("a value does not fit in 16 bits".to_string()),
        )
    );
}
