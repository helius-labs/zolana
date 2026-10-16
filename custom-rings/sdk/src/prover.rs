use custom_ring_interface::{
    base_verifying_key, compressed_policy_verifying_key, delegate_policy_verifying_key,
    deposit_verifying_key, policy_verifying_key, register_key_verifying_key, CustomRingProof,
    PlainGroth16Proof, PROVING_KEY_SHA256S,
};
use serde::{Serialize, Serializer};
use zeroize::Zeroizing;
use zolana_client::{
    prover::{verify_proof_statement, ExpectedProvingKey, ProveRequest},
    ClientError, Proof, ProofCompressed,
};

use crate::RingError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RingCircuit {
    Base,
    Policy,
    CompressedPolicy,
    DelegatePolicy,
    Deposit,
    RegisterKey,
}

impl RingCircuit {
    pub(crate) const fn circuit_type(self) -> &'static str {
        match self {
            Self::Base => "custom-ring-base",
            Self::Policy => "custom-ring-policy",
            Self::CompressedPolicy => "custom-ring-compressed-policy",
            Self::DelegatePolicy => "custom-ring-delegate-policy",
            Self::Deposit => "custom-ring-deposit",
            Self::RegisterKey => "custom-ring-register-key",
        }
    }

    /// The key file is the circuit type in snake case.
    pub(crate) fn proving_key(self) -> Result<ExpectedProvingKey, ClientError> {
        let name = format!("{}.key", self.circuit_type().replace('-', "_"));
        PROVING_KEY_SHA256S
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, sha256)| ExpectedProvingKey {
                name: name.clone(),
                sha256: *sha256,
            })
            .ok_or(ClientError::Prover(format!("no pinned key {name}")))
    }

    pub(crate) fn verify(
        self,
        proof: &Proof,
        public_input_hash: [u8; 32],
    ) -> Result<(), ClientError> {
        let key = match self {
            Self::Base => &base_verifying_key::VERIFYINGKEY,
            Self::Policy => &policy_verifying_key::VERIFYINGKEY,
            Self::CompressedPolicy => &compressed_policy_verifying_key::VERIFYINGKEY,
            Self::DelegatePolicy => &delegate_policy_verifying_key::VERIFYINGKEY,
            Self::Deposit => &deposit_verifying_key::VERIFYINGKEY,
            Self::RegisterKey => &register_key_verifying_key::VERIFYINGKEY,
        };
        verify_proof_statement(proof, public_input_hash, key)
    }
}

impl Serialize for RingCircuit {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.circuit_type())
    }
}

/// A prover body that names its own circuit.
pub(crate) trait RingBody: Serialize + Sync {
    fn circuit(&self) -> RingCircuit;
}

pub(crate) struct RingRequest<'a, T>(pub &'a T);

impl<T: RingBody> ProveRequest for RingRequest<'_, T> {
    fn body(&self) -> Result<Zeroizing<String>, ClientError> {
        serde_json::to_string(self.0)
            .map(Zeroizing::new)
            .map_err(|error| ClientError::Prover(error.to_string()))
    }

    fn proving_key(&self) -> Result<ExpectedProvingKey, ClientError> {
        self.0.circuit().proving_key()
    }
}

/// The instruction encoding of an audited circuit's proof, BSB22 commitment included.
pub fn to_instruction_proof(proof: Proof) -> Result<CustomRingProof, RingError> {
    let compressed = ProofCompressed::try_from(proof)?;
    let commitment = compressed.commitment.ok_or(RingError::MissingCommitment)?;
    Ok(CustomRingProof {
        groth16: PlainGroth16Proof {
            proof_a: compressed.a,
            proof_b: compressed.compressed_b()?,
            proof_c: compressed.c,
        },
        commitment: commitment.commitment,
        commitment_pok: commitment.commitment_pok,
    })
}

pub fn to_plain_proof(proof: Proof) -> Result<PlainGroth16Proof, RingError> {
    let compressed = ProofCompressed::try_from(proof)?;
    if compressed.commitment.is_some() {
        return Err(RingError::UnexpectedCommitment);
    }
    Ok(PlainGroth16Proof {
        proof_a: compressed.a,
        proof_b: compressed.compressed_b()?,
        proof_c: compressed.c,
    })
}

/// Field elements and byte strings as `0x` lowercase hex, integers right aligned to 32 bytes.
pub(crate) mod fe {
    use serde::{ser::Error, Serialize, Serializer};
    use zeroize::{Zeroize, Zeroizing};
    use zolana_hasher::primitives::right_align;
    use zolana_keypair::{ViewingKey, X25519Pubkey};

    const HEX: &[u8; 16] = b"0123456789abcdef";

    /// A stack buffer, so a secret never lands in a heap string of its own.
    pub(crate) fn bytes<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        let mut buffer = [0u8; 2 + 2 * 32];
        let len = 2 + 2 * bytes.len();
        let out = buffer
            .get_mut(..len)
            .ok_or_else(|| S::Error::custom("value too long"))?;
        out[..2].copy_from_slice(b"0x");
        for (pair, byte) in out[2..].as_chunks_mut::<2>().0.iter_mut().zip(bytes) {
            *pair = [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 15)]];
        }
        let result = serializer.serialize_str(core::str::from_utf8(out).map_err(S::Error::custom)?);
        buffer.zeroize();
        result
    }

    pub(crate) fn serialize<S: Serializer, T: AsRef<[u8]> + ?Sized>(
        value: &T,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        bytes(value.as_ref(), serializer)
    }

    pub(crate) fn zeroizing<S: Serializer, const N: usize>(
        value: &Zeroizing<[u8; N]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        bytes(value.as_slice(), serializer)
    }

    pub(crate) fn zeroizing_seq<S: Serializer, const N: usize>(
        values: &Zeroizing<[[u8; 32]; N]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        seq(values.as_slice(), serializer)
    }

    pub(crate) fn int<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        bytes(&right_align(&value.to_be_bytes()), serializer)
    }

    pub(crate) fn short<S: Serializer>(value: &u16, serializer: S) -> Result<S::Ok, S::Error> {
        bytes(&right_align(&value.to_be_bytes()), serializer)
    }

    pub(crate) fn zero<S: Serializer>(_: &(), serializer: S) -> Result<S::Ok, S::Error> {
        bytes(&[0; 32], serializer)
    }

    pub(crate) fn secret<S: Serializer>(
        key: &ViewingKey,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        bytes(key.secret_bytes().as_slice(), serializer)
    }

    /// The circuit witnesses the untagged 32-byte coordinate.
    pub(crate) fn coordinate<S: Serializer>(
        key: &X25519Pubkey,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        bytes(&key.u(), serializer)
    }

    pub(crate) fn seq<S: Serializer, T: AsRef<[u8]>>(
        values: &[T],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(values.iter().map(Hex))
    }

    pub(crate) fn ints<S: Serializer>(values: &[u64], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(
            values
                .iter()
                .map(|value| Hex(right_align(&value.to_be_bytes()))),
        )
    }

    pub(crate) struct Hex<T>(pub T);

    impl<T: AsRef<[u8]>> Serialize for Hex<&T> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            bytes(self.0.as_ref(), serializer)
        }
    }

    impl<const N: usize> Serialize for Hex<[u8; N]> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            bytes(self.0.as_ref(), serializer)
        }
    }
}
