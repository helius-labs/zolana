use custom_ring_interface::{
    base_anonymous_wide_verifying_key, base_confidential_compact_verifying_key,
    base_confidential_verifying_key, base_verifying_key, delegate_policy_2x3_verifying_key,
    delegate_policy_verifying_key, deposit_verifying_key, policy_2x3_anonymous_verifying_key,
    policy_2x3_verifying_key, policy_verifying_key, register_key_verifying_key,
    update_members_verifying_key, BaseCircuit, CustomRingProof, PlainGroth16Proof,
    PROVING_KEY_SHA256S,
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
    BaseConfidential,
    BaseCompactConfidential,
    BaseWideAnonymous,
    Base,
    Policy,
    DelegatePolicy,
    PolicyTwoByThree,
    AnonymousPolicyTwoByThree,
    DelegatePolicyTwoByThree,
    Shaped {
        inputs: u8,
        outputs: u8,
        anonymous: bool,
        delegate: bool,
        subtree: bool,
    },
    Deposit,
    RegisterKey,
    UpdateMembers,
}

impl From<BaseCircuit> for RingCircuit {
    fn from(circuit: BaseCircuit) -> Self {
        match circuit {
            BaseCircuit::Base => Self::Base,
            BaseCircuit::WideAnonymous => Self::BaseWideAnonymous,
            BaseCircuit::Confidential => Self::BaseConfidential,
            BaseCircuit::CompactConfidential => Self::BaseCompactConfidential,
        }
    }
}

impl RingCircuit {
    pub(crate) fn circuit_type(self) -> String {
        match self {
            Self::BaseConfidential => "custom-ring-base-confidential",
            Self::BaseCompactConfidential => "custom-ring-base-confidential-compact",
            Self::BaseWideAnonymous => "custom-ring-base-anonymous-wide",
            Self::Base => "custom-ring-base",
            Self::Policy => "custom-ring-policy",
            Self::DelegatePolicy => "custom-ring-delegate-policy",
            Self::PolicyTwoByThree => "custom-ring-policy-2x3",
            Self::AnonymousPolicyTwoByThree => "custom-ring-policy-2x3-anonymous",
            Self::DelegatePolicyTwoByThree => "custom-ring-delegate-policy-2x3",
            Self::Deposit => "custom-ring-deposit",
            Self::RegisterKey => "custom-ring-register-key",
            Self::UpdateMembers => "custom-ring-update-members",
            Self::Shaped {
                inputs,
                outputs,
                anonymous,
                delegate,
                subtree,
            } => {
                return format!(
                    "custom-ring-{}policy-{inputs}-{outputs}{}{}",
                    if delegate { "delegate-" } else { "" },
                    if anonymous { "-anonymous" } else { "" },
                    if subtree { "-subtree" } else { "" }
                );
            }
        }
        .to_owned()
    }

    /// The key file is the circuit type in snake case.
    pub(crate) fn proving_key(self) -> Result<ExpectedProvingKey, ClientError> {
        let name = format!("{}.key", self.circuit_type().replace('-', "_"));
        PROVING_KEY_SHA256S
            .iter()
            .chain(custom_ring_interface::shaped_verifying_keys::SHAPED_PROVING_KEY_SHA256S)
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
            Self::BaseConfidential => &base_confidential_verifying_key::VERIFYINGKEY,
            Self::BaseCompactConfidential => &base_confidential_compact_verifying_key::VERIFYINGKEY,
            Self::BaseWideAnonymous => &base_anonymous_wide_verifying_key::VERIFYINGKEY,
            Self::Base => &base_verifying_key::VERIFYINGKEY,
            Self::Policy => &policy_verifying_key::VERIFYINGKEY,
            Self::DelegatePolicy => &delegate_policy_verifying_key::VERIFYINGKEY,
            Self::PolicyTwoByThree => &policy_2x3_verifying_key::VERIFYINGKEY,
            Self::AnonymousPolicyTwoByThree => &policy_2x3_anonymous_verifying_key::VERIFYINGKEY,
            Self::DelegatePolicyTwoByThree => &delegate_policy_2x3_verifying_key::VERIFYINGKEY,
            Self::Deposit => &deposit_verifying_key::VERIFYINGKEY,
            Self::RegisterKey => &register_key_verifying_key::VERIFYINGKEY,
            Self::UpdateMembers => &update_members_verifying_key::VERIFYINGKEY,
            Self::Shaped { .. } => {
                return Err(ClientError::ProofVerification(
                    "shaped policy requires its public table".to_owned(),
                ))
            }
        };
        verify_proof_statement(proof, public_input_hash, key)
    }

    pub(crate) fn is_two_by_three(self) -> bool {
        matches!(
            self,
            Self::PolicyTwoByThree
                | Self::AnonymousPolicyTwoByThree
                | Self::DelegatePolicyTwoByThree
        )
    }

    pub(crate) fn proof_kind(self) -> custom_ring_interface::PolicyProofKind {
        use custom_ring_interface::PolicyProofKind;
        match self {
            Self::Shaped { subtree: true, .. } => PolicyProofKind::Subtree,
            Self::Shaped { .. } => PolicyProofKind::General,
            _ if self.is_two_by_three() => PolicyProofKind::TwoByThree,
            _ => PolicyProofKind::Base,
        }
    }

    pub(crate) fn verify_table(
        self,
        proof: &Proof,
        inputs: &custom_ring_interface::PolicyTableInputs,
    ) -> Result<(), ClientError> {
        let key = match self {
            Self::PolicyTwoByThree => &policy_2x3_verifying_key::VERIFYINGKEY,
            Self::AnonymousPolicyTwoByThree => &policy_2x3_anonymous_verifying_key::VERIFYINGKEY,
            Self::DelegatePolicyTwoByThree => &delegate_policy_2x3_verifying_key::VERIFYINGKEY,
            Self::Shaped {
                inputs,
                outputs,
                anonymous,
                delegate,
                subtree,
            } => custom_ring_interface::shaped_verifying_keys::policy_shape_key(
                usize::from(inputs),
                usize::from(outputs),
                anonymous,
                delegate,
                subtree,
            )
            .ok_or_else(|| {
                ClientError::ProofVerification("unsupported shaped policy key".to_owned())
            })?,
            _ => {
                return Err(ClientError::ProofVerification(
                    "not a public-table policy key".to_owned(),
                ))
            }
        };
        zolana_client::prover::verify_proof_inputs(proof, inputs, key)
    }
}

impl Serialize for RingCircuit {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.circuit_type())
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
    use custom_ring_interface::ANONYMOUS_OUTPUT_PLAINTEXT_LEN;
    use serde::{ser::Error, Serialize, Serializer};
    use zeroize::{Zeroize, Zeroizing};
    use zolana_hasher::primitives::right_align;
    use zolana_keypair::{ViewingKey, X25519Pubkey};

    const HEX: &[u8; 16] = b"0123456789abcdef";

    /// A stack buffer, so a secret never lands in a heap string of its own. The longest
    /// value is a published anonymous output ciphertext.
    pub(crate) fn bytes<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        let mut buffer = [0u8; 2 + 2 * ANONYMOUS_OUTPUT_PLAINTEXT_LEN];
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
