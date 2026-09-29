use zk_program_sdk::{
    circuit::{constant, Bytes, CircuitVar},
    CircuitError,
};

fn raw_field_slice(bytes: &[CircuitVar]) -> Result<CircuitVar, CircuitError> {
    zk_program_sdk::circuit::hash_bytes(bytes)
}

fn fixed_domain(bytes: &Bytes<32>) -> Result<CircuitVar, CircuitError> {
    bytes.hash_bytes()
}

fn one_byte_domain() -> Result<CircuitVar, CircuitError> {
    let bytes = Bytes::<1>::constant(&[1]);
    fixed_domain(&bytes)
}

fn two_byte_domain() -> Result<CircuitVar, CircuitError> {
    let bytes = Bytes::<2>::constant(&[0, 1]);
    fixed_domain(&bytes)
}

fn wider_elements() -> Bytes<2> {
    let bytes: [u16; 2] = [256, 258];
    Bytes::constant(&bytes)
}

fn unchecked_fields() -> Bytes<2> {
    Bytes::from_checked([constant(256u64), constant(258u64)])
}

fn dynamic_bytes(bytes: &[u8]) -> Bytes<2> {
    Bytes::constant(bytes)
}

fn main() {
    let _ = raw_field_slice(&[constant(256u64), constant(258u64)]);
    let _ = (
        one_byte_domain(),
        two_byte_domain(),
        wider_elements(),
        unchecked_fields(),
        dynamic_bytes(&[1, 2]),
    );
}
