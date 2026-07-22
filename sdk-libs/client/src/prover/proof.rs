use groth16_solana::groth16::negate_g1_be;
use num_traits::Num;
use serde::{Deserialize, Serialize};
use solana_bn254::compression::prelude::{alt_bn128_g1_compress_be, alt_bn128_g2_compress_be};
use zolana_interface::instruction::instruction_data::transact::{P256Proof, TransactProof};

use crate::error::ClientError;

/// The single BSB22 Pedersen commitment a proof carries: the commitment point and
/// its proof-of-knowledge (uncompressed G1, big-endian, not negated). Present only
/// for the P256 `transfer` rail; the Solana-only `transfer-eddsa` rail is vanilla
/// Groth16 with no commitment.
#[derive(Debug, Clone, Copy)]
pub struct Commitments {
    pub commitment: [u8; 64],
    pub commitment_pok: [u8; 64],
}

/// Uncompressed Groth16 proof with `proof_a` already negated. `commitment` is
/// `Some` for the P256 rail (verify with `Groth16Verifier::new_with_commitment`)
/// and `None` for the eddsa rail (verify with `Groth16Verifier::new`).
#[derive(Debug, Clone, Copy)]
pub struct Proof {
    pub a: [u8; 64],
    pub b: [u8; 128],
    pub c: [u8; 64],
    pub commitment: Option<Commitments>,
}

/// [`Commitments`] with its G1 points compressed (32 bytes each).
#[derive(Debug, Clone, Copy)]
pub struct CompressedCommitments {
    pub commitment: [u8; 32],
    pub commitment_pok: [u8; 32],
}

/// Wire-format Groth16 proof: the points of [`Proof`] compressed (G1 -> 32 bytes,
/// G2 -> 64 bytes). Mirrors [`Proof`]: `commitment` is `Some` for the P256 rail.
#[derive(Debug, Clone, Copy)]
pub struct ProofCompressed {
    pub a: [u8; 32],
    pub b: [u8; 64],
    pub c: [u8; 32],
    pub commitment: Option<CompressedCommitments>,
}

/// Compress the G1/G2 points of an uncompressed proof into the wire format.
/// Fallible because point compression validates the input bytes.
impl TryFrom<Proof> for ProofCompressed {
    type Error = ClientError;

    fn try_from(proof: Proof) -> Result<Self, Self::Error> {
        let a = compress_g1(&proof.a, "proof_a")?;
        let b = alt_bn128_g2_compress_be(&proof.b)
            .map_err(|e| ClientError::ProofParse(format!("failed to compress proof_b: {e:?}")))?;
        let c = compress_g1(&proof.c, "proof_c")?;
        let commitment = proof
            .commitment
            .map(|com| -> Result<CompressedCommitments, ClientError> {
                Ok(CompressedCommitments {
                    commitment: compress_g1(&com.commitment, "commitment")?,
                    commitment_pok: compress_g1(&com.commitment_pok, "commitment_pok")?,
                })
            })
            .transpose()?;
        Ok(ProofCompressed {
            a,
            b,
            c,
            commitment,
        })
    }
}

impl ProofCompressed {
    /// Build the wire-format `transact` proof enum directly from the compressed
    /// components: the P256 rail keeps its BSB22 commitment, the eddsa rail omits
    /// it (no padding). The program decompresses these points at verification time.
    pub fn to_transact_proof(self) -> TransactProof {
        match self.to_p256_proof() {
            Ok(proof) => TransactProof::P256(proof),
            Err(_) => TransactProof::Eddsa {
                a: self.a,
                b: self.b,
                c: self.c,
            },
        }
    }

    /// The P256-rail five-tuple ([`P256Proof`]), shared by `transact`'s P256
    /// variant and `merge_transact` instruction data. Rejected if the proof
    /// carries no BSB22 commitment (eddsa rail).
    pub fn to_p256_proof(&self) -> Result<P256Proof, ClientError> {
        let commitment = self.commitment.ok_or_else(|| {
            ClientError::ProofParse(
                "P256-rail proof is missing its BSB22 commitment (wrong rail?)".to_string(),
            )
        })?;
        Ok(P256Proof {
            a: self.a,
            b: self.b,
            c: self.c,
            commitment: commitment.commitment,
            commitment_pok: commitment.commitment_pok,
        })
    }

    /// The `merge_transact` proof. The merge circuit is the P256 BSB22 rail, so
    /// this is exactly [`Self::to_p256_proof`]: mandatory commitment, and a proof
    /// without one is not a valid merge proof.
    pub fn to_merge_proof(&self) -> Result<P256Proof, ClientError> {
        self.to_p256_proof()
    }
}

fn compress_g1(point: &[u8; 64], name: &str) -> Result<[u8; 32], ClientError> {
    alt_bn128_g1_compress_be(point)
        .map_err(|e| ClientError::ProofParse(format!("failed to compress {name}: {e:?}")))
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GnarkProofJson {
    pub ar: Vec<String>,
    pub bs: Vec<Vec<String>>,
    pub krs: Vec<String>,
    #[serde(default)]
    pub proof_commitment: Vec<String>,
    #[serde(default)]
    pub proof_commitment_pok: Vec<String>,
}

/// Build a 64-byte big-endian G1 point (X || Y) from a 2-element hex string array.
fn g1_from_hex_pair(pair: &[String]) -> Option<[u8; 64]> {
    let [x, y] = pair else { return None };
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&hex_to_be_32(x));
    out[32..].copy_from_slice(&hex_to_be_32(y));
    Some(out)
}

fn hex_to_be_32(hex_str: &str) -> [u8; 32] {
    let trimmed = hex_str.trim_start_matches("0x");
    let big_int = num_bigint::BigInt::from_str_radix(trimmed, 16).unwrap_or_default();
    let bytes = big_int.to_bytes_be().1;
    let mut result = [0u8; 32];
    if bytes.len() <= 32 {
        result[32 - bytes.len()..].copy_from_slice(&bytes);
    } else {
        result.copy_from_slice(&bytes[bytes.len() - 32..]);
    }
    result
}

/// Parse a gnark proof JSON (`{ar, bs, krs, proof_commitment?, proof_commitment_pok?}`)
/// into an uncompressed [`Proof`] with `proof_a` negated. The commitment is `Some`
/// only when both commitment fields are present (P256 rail).
pub(crate) fn proof_from_gnark_json(json_str: &str) -> Option<Proof> {
    let json: GnarkProofJson = serde_json::from_str(json_str).ok()?;

    let a = negate_g1_be(&g1_from_hex_pair(&json.ar)?);
    let c = g1_from_hex_pair(&json.krs)?;

    // proof_b is a G2 point: bs[0] = (x.a0, x.a1), bs[1] = (y.a0, y.a1).
    let [bx, by] = json.bs.as_slice() else {
        return None;
    };
    let bx = g1_from_hex_pair(bx)?;
    let by = g1_from_hex_pair(by)?;
    let mut b = [0u8; 128];
    b[..64].copy_from_slice(&bx);
    b[64..].copy_from_slice(&by);

    let commitment = if json.proof_commitment.is_empty() && json.proof_commitment_pok.is_empty() {
        None
    } else {
        Some(Commitments {
            commitment: g1_from_hex_pair(&json.proof_commitment)?,
            commitment_pok: g1_from_hex_pair(&json.proof_commitment_pok)?,
        })
    };

    Some(Proof {
        a,
        b,
        c,
        commitment,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proof_with_commitment() -> ProofCompressed {
        ProofCompressed {
            a: [1u8; 32],
            b: [2u8; 64],
            c: [3u8; 32],
            commitment: Some(CompressedCommitments {
                commitment: [4u8; 32],
                commitment_pok: [5u8; 32],
            }),
        }
    }

    #[test]
    fn to_merge_proof_maps_points_and_commitment() {
        let proof = proof_with_commitment()
            .to_merge_proof()
            .expect("merge proof maps");

        assert_eq!(proof.a, [1u8; 32]);
        assert_eq!(proof.b, [2u8; 64]);
        assert_eq!(proof.c, [3u8; 32]);
        assert_eq!(proof.commitment, [4u8; 32]);
        assert_eq!(proof.commitment_pok, [5u8; 32]);
    }

    /// The transact P256 variant and the merge proof must be the same
    /// five-tuple: one packing definition serves both instruction formats.
    #[test]
    fn transact_p256_and_merge_proof_are_the_same_tuple() {
        let compressed = proof_with_commitment();
        let merge = compressed.to_merge_proof().expect("merge proof maps");
        assert_eq!(compressed.to_transact_proof(), TransactProof::P256(merge));
    }

    #[test]
    fn to_merge_proof_rejects_a_proof_without_a_commitment() {
        let vanilla = ProofCompressed {
            commitment: None,
            ..proof_with_commitment()
        };

        let error = vanilla
            .to_merge_proof()
            .expect_err("a vanilla proof is not a merge proof");

        assert!(matches!(error, ClientError::ProofParse(_)));
    }
}
