/// Protocol encoding only: RFC 7748 multiplication must separately reject
/// all-zero DH. Canonical low-order u-coordinates remain representable here.
pub fn is_canonical_x25519_public_key(bytes: &[u8; 32]) -> bool {
    const MODULUS: [u8; 32] = {
        let mut bytes = [0xff; 32];
        bytes[0] = 0xed;
        bytes[31] = 0x7f;
        bytes
    };
    bytes.iter().rev().cmp(MODULUS.iter().rev()).is_lt()
}
