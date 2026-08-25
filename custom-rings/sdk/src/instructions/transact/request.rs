use serde::Serialize;
use zeroize::Zeroizing;

use super::proof::AuditProofInputError;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AuditPrivateTxHash([u8; 32]);

impl TryFrom<[u8; 32]> for AuditPrivateTxHash {
    type Error = AuditProofInputError;

    fn try_from(value: [u8; 32]) -> Result<Self, Self::Error> {
        canonical_audit_hash(value).map(Self)
    }
}

impl AsRef<[u8; 32]> for AuditPrivateTxHash {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

pub(crate) struct SecretHex<'a>(pub &'a [u8]);

impl Serialize for SecretHex<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let encoded = Zeroizing::new(bytes_to_hex(self.0));
        serializer.serialize_str(&encoded)
    }
}

/// A field element as the fixed-width hex the prover requires.
pub(crate) fn field_hex(value: &[u8; 32]) -> String {
    bytes_to_hex(value)
}

pub(crate) fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::from("0x"), |mut out, byte| {
        out.push_str(&format!("{byte:02x}"));
        out
    })
}

const BN254_SCALAR_MODULUS: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

fn canonical_audit_hash(value: [u8; 32]) -> Result<[u8; 32], AuditProofInputError> {
    if value >= BN254_SCALAR_MODULUS {
        return Err(AuditProofInputError::GreaterThanB254FieldSize);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_noncanonical_audit_hashes() {
        assert!(matches!(
            AuditPrivateTxHash::try_from(BN254_SCALAR_MODULUS),
            Err(AuditProofInputError::GreaterThanB254FieldSize)
        ));
    }
}
