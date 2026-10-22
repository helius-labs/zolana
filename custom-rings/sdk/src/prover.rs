//! Ring proof requests by the key catalog, every proof checked against its verifying key.

use custom_ring_interface::{
    key_catalog::{RingCircuit, RingKey, RING_KEYS},
    verifying_key, CustomRingProof, PlainGroth16Proof, PROVING_KEY_SHA256S,
};
use serde::Serialize;
use zeroize::Zeroizing;
use zolana_client::{
    prover::{verify_proof_statement, ExpectedProvingKey, ProveRequest},
    AsyncIndexer, AsyncRpc, AsyncZolanaClient, ClientError, Proof, ProofCompressed,
};

use crate::RingError;

#[cfg(test)]
#[path = "tests/prover.rs"]
mod tests;

pub(crate) struct RingRequest<'a, T> {
    circuit: RingCircuit,
    key: ExpectedProvingKey,
    body: RequestBody<'a, T>,
}

#[derive(Serialize)]
pub(crate) struct RequestBody<'a, T> {
    #[serde(rename = "circuitType")]
    circuit_type: &'static str,
    #[serde(flatten)]
    inputs: &'a T,
}

impl<'a, T: Serialize> RequestBody<'a, T> {
    pub(crate) fn new(circuit: RingCircuit, inputs: &'a T) -> Result<Self, RingError> {
        Ok(Self {
            circuit_type: ring_key(circuit)?.name,
            inputs,
        })
    }
}

impl<'a, T: Serialize + Sync> RingRequest<'a, T> {
    /// Refuses a circuit the pinned key set does not name.
    pub(crate) fn new(circuit: RingCircuit, body: &'a T) -> Result<Self, RingError> {
        let file = ring_key(circuit)?.file_name();
        let sha256 = PROVING_KEY_SHA256S
            .iter()
            .find(|(name, _)| *name == file)
            .map(|(_, sha256)| *sha256)
            .ok_or(RingError::UnpinnedProvingKey(circuit))?;
        Ok(Self {
            circuit,
            key: ExpectedProvingKey { name: file, sha256 },
            body: RequestBody::new(circuit, body)?,
        })
    }

    /// Verifies the proof under the statement the program rebuilds.
    pub(crate) async fn prove<R: AsyncRpc, I: AsyncIndexer>(
        &self,
        client: &AsyncZolanaClient<R, I>,
        public_input_hash: [u8; 32],
    ) -> Result<Proof, RingError> {
        let key =
            verifying_key(self.circuit).ok_or(RingError::MissingVerifyingKey(self.circuit))?;
        let proof = client.prove_request(self).await?;
        verify_proof_statement(&proof, public_input_hash, key)?;
        Ok(proof)
    }
}

impl<T: Serialize + Sync> ProveRequest for RingRequest<'_, T> {
    /// Sized before it is written, a reallocation would leave the secrets in freed memory.
    fn body(&self) -> Result<Zeroizing<String>, ClientError> {
        let encoding = |error: serde_json::Error| ClientError::Prover(error.to_string());
        let mut length = ByteCount::default();
        serde_json::to_writer(&mut length, &self.body).map_err(encoding)?;
        let mut body = Zeroizing::new(Vec::with_capacity(length.0));
        serde_json::to_writer(&mut *body, &self.body).map_err(encoding)?;
        String::from_utf8(core::mem::take(&mut *body))
            .map(Zeroizing::new)
            .map_err(|error| {
                drop(Zeroizing::new(error.into_bytes()));
                ClientError::Prover("the request body is not UTF-8".to_string())
            })
    }

    fn proving_key(&self) -> Result<ExpectedProvingKey, ClientError> {
        Ok(self.key.clone())
    }
}

#[derive(Default)]
struct ByteCount(usize);

impl std::io::Write for ByteCount {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn ring_key(circuit: RingCircuit) -> Result<RingKey, RingError> {
    RING_KEYS
        .iter()
        .find(|key| key.circuit == circuit)
        .copied()
        .ok_or(RingError::UncataloguedCircuit(circuit))
}

/// Refuses a proof without its BSB22 commitment.
pub(crate) fn to_instruction_proof(proof: Proof) -> Result<CustomRingProof, RingError> {
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

/// Field elements and byte strings as `0x` lowercase hex, integers right aligned to 32 bytes.
pub(crate) mod fe {
    use serde::{ser::Error, Serialize, Serializer};
    use zeroize::{Zeroize, Zeroizing};

    const HEX: &[u8; 16] = b"0123456789abcdef";
    /// The longest byte string a ring request carries, a longer one fails the request.
    const MAX_BYTES: usize = custom_ring_interface::RING_DELIVERED_BODY_LEN;

    /// The hex lives in a zeroized stack buffer, never in an intermediate heap string.
    pub(crate) fn bytes<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        let mut buffer = [0u8; 2 + 2 * MAX_BYTES];
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

    pub(crate) fn seq<S: Serializer, T: AsRef<[u8]>>(
        values: &[T],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(values.iter().map(Hex))
    }

    pub(crate) struct Hex<T>(pub T);

    impl<T: AsRef<[u8]>> Serialize for Hex<&T> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            bytes(self.0.as_ref(), serializer)
        }
    }
}
