use zolana_hasher::primitives::right_align;
use zolana_keypair::{ShieldedAddress, ShieldedKeypair, SigningKey};
use zolana_program::{
    circuit::{constant, poseidon, CircuitVar, PublicInputs},
    conversion::{to_bytes, Allocator, ProofInput},
    hasher::{Hasher, Poseidon},
    PublicFieldKind, PublicInputLayout,
};

#[derive(Clone, PublicInputs)]
struct PaymentPublicInputs {
    recipient: ShieldedAddress,
    amount: u64,
}

#[derive(Clone, PublicInputs)]
struct FanOutPublicInputs {
    recipients: [ShieldedAddress; 2],
}

#[derive(Clone, PublicInputs)]
struct NoPublicInputs;

fn address(seed: u8) -> ShieldedAddress {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32]))
        .expect("keypair")
        .shielded_address()
        .expect("address")
}

fn native<T: ProofInput>(value: &T) -> T::Circuit {
    value
        .instantiate(&Allocator::native())
        .expect("native instantiation")
}

fn bytes(var: &CircuitVar) -> [u8; 32] {
    to_bytes(var).expect("bytes")
}

fn transaction_hash() -> CircuitVar {
    constant(123u64)
}

#[test]
fn the_public_hash_covers_the_fields_in_order_then_the_transaction_hash() {
    let recipient = address(6);
    let circuit = native(&PaymentPublicInputs {
        recipient,
        amount: 9,
    });
    let expected = Poseidon::hashv(&[
        &recipient.address_hash().expect("address hash"),
        &right_align(&9u64.to_be_bytes()),
        &bytes(&transaction_hash()),
    ])
    .expect("poseidon");
    assert_eq!(
        bytes(&circuit.hash(&transaction_hash()).expect("public hash")),
        expected
    );
}

#[test]
fn an_array_field_hashes_as_one_nested_input() {
    let recipients = [address(6), address(7)];
    let circuit = native(&FanOutPublicInputs { recipients });
    let [first, second] =
        recipients.map(|recipient| recipient.address_hash().expect("address hash"));
    let nested = Poseidon::hashv(&[&first, &second]).expect("poseidon");
    let expected = Poseidon::hashv(&[&nested, &bytes(&transaction_hash())]).expect("poseidon");
    assert_eq!(
        bytes(&circuit.hash(&transaction_hash()).expect("public hash")),
        expected
    );
}

#[test]
fn a_unit_struct_hashes_the_transaction_hash_alone() {
    let circuit = native(&NoPublicInputs);
    assert_eq!(
        bytes(&circuit.hash(&transaction_hash()).expect("public hash")),
        bytes(&poseidon(&[transaction_hash()]).expect("poseidon"))
    );
}

#[test]
fn the_public_hash_is_pinned() {
    let circuit = native(&PaymentPublicInputs {
        recipient: address(6),
        amount: 9,
    });
    let hex: String = bytes(&circuit.hash(&transaction_hash()).expect("public hash"))
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        hex,
        "12bd09a62da9b6e24d4245abc5d29d5974bd39c91538f03c45be9b30ae200036"
    );
}

#[test]
fn the_layout_names_each_field_with_its_on_chain_kind() {
    assert_eq!(
        PaymentPublicInputs::layout(),
        vec![
            ("recipient", PublicFieldKind::Hash),
            ("amount", PublicFieldKind::Integer { bits: 64 }),
        ]
    );
}

#[test]
fn an_array_field_lays_out_as_an_array_of_its_item_kind() {
    assert_eq!(
        FanOutPublicInputs::layout(),
        vec![(
            "recipients",
            PublicFieldKind::Array {
                len: 2,
                item: Box::new(PublicFieldKind::Hash),
            },
        )]
    );
}

#[test]
fn a_unit_struct_has_no_layout() {
    assert_eq!(NoPublicInputs::layout(), Vec::new());
}
