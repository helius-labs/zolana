use groth16_solana::groth16::negate_g1_be;
use num_traits::Num;
use serde::{Deserialize, Serialize};
use solana_bn254::compression::prelude::{alt_bn128_g1_compress_be, alt_bn128_g2_compress_be};
use zolana_interface::instruction::{
    instruction_data::{
        merge_transact::MergeProof,
        transact::{Bsb22Commitment, TransactProof},
    },
    NullifierTreeProof,
};

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

/// The Groth16 proof as the SPP instructions carry it: the G1 points of
/// [`Proof`] compressed to 32 bytes, `b` kept as the raw 128-byte G2 point so
/// the program skips the G2 decompression syscall. Mirrors [`Proof`]:
/// `commitment` is `Some` for the P256 rail.
#[derive(Debug, Clone, Copy)]
pub struct ProofCompressed {
    pub a: [u8; 32],
    pub b: [u8; 128],
    pub c: [u8; 32],
    pub commitment: Option<CompressedCommitments>,
}

/// Compress the G1 points of an uncompressed proof. Fallible because point
/// compression validates the input bytes.
impl TryFrom<Proof> for ProofCompressed {
    type Error = ClientError;

    fn try_from(proof: Proof) -> Result<Self, Self::Error> {
        let a = compress_g1(&proof.a, "proof_a")?;
        let b = proof.b;
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
    /// Build the transact proof.
    pub fn to_transact_proof(self) -> TransactProof {
        debug_assert!(self.commitment.is_none());
        TransactProof {
            a: self.a,
            b: self.b,
            c: self.c,
        }
    }

    /// Split a committed custom-ring proof into the unchanged transact proof
    /// triple and the BSB22 payload embedded in `CircuitId::RingP256`.
    pub fn into_ring_p256_transact_parts(
        self,
    ) -> Result<(TransactProof, Bsb22Commitment), ClientError> {
        let commitment = self.commitment.ok_or_else(|| {
            ClientError::ProofParse("P256 ring proof is missing its BSB22 commitment".to_string())
        })?;
        Ok((
            TransactProof {
                a: self.a,
                b: self.b,
                c: self.c,
            },
            Bsb22Commitment {
                commitment: commitment.commitment,
                commitment_pok: commitment.commitment_pok,
            },
        ))
    }

    /// The merge proof: a vanilla Groth16 triple ([`MergeProof`]). The merge
    /// circuit carries no P256 gadget, so it has no BSB22 commitment; one is
    /// rejected (wrong rail?).
    pub fn to_merge_proof(&self) -> Result<MergeProof, ClientError> {
        if self.commitment.is_some() {
            return Err(ClientError::ProofParse(
                "merge proof carries an unexpected BSB22 commitment (wrong rail?)".to_string(),
            ));
        }
        Ok(MergeProof {
            a: self.a,
            b: self.b,
            c: self.c,
        })
    }

    /// `b` in the 64-byte compressed G2 encoding, for the one format that
    /// still carries the proof fully compressed: the custom-ring policy proof.
    pub fn compressed_b(&self) -> Result<[u8; 64], ClientError> {
        alt_bn128_g2_compress_be(&self.b)
            .map_err(|e| ClientError::ProofParse(format!("failed to compress proof_b: {e:?}")))
    }

    /// The proof of a nullifier-tree batch update ([`NullifierTreeProof`]):
    /// compressed G1 points and a raw G2 point, as for transact and merge. The
    /// batch address-append circuit is vanilla Groth16, so a BSB22 commitment
    /// is rejected (wrong circuit?).
    pub fn to_nullifier_tree_proof(&self) -> Result<NullifierTreeProof, ClientError> {
        if self.commitment.is_some() {
            return Err(ClientError::ProofParse(
                "batch update proof carries an unexpected BSB22 commitment (wrong circuit?)"
                    .to_string(),
            ));
        }
        Ok(NullifierTreeProof {
            a: self.a,
            b: self.b,
            c: self.c,
        })
    }
}

fn compress_g1(point: &[u8; 64], name: &str) -> Result<[u8; 32], ClientError> {
    alt_bn128_g1_compress_be(point)
        .map_err(|e| ClientError::ProofParse(format!("failed to compress {name}: {e:?}")))
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
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

/// Parse a gnark proof JSON (`{ar, bs, krs, proofCommitment?, proofCommitmentPok?}`)
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
            b: [2u8; 128],
            c: [3u8; 32],
            commitment: Some(CompressedCommitments {
                commitment: [4u8; 32],
                commitment_pok: [5u8; 32],
            }),
        }
    }

    #[test]
    fn to_merge_proof_maps_points() {
        let vanilla = ProofCompressed {
            commitment: None,
            ..proof_with_commitment()
        };
        let proof = vanilla.to_merge_proof().expect("merge proof maps");

        assert_eq!(proof.a, [1u8; 32]);
        assert_eq!(proof.b, [2u8; 128]);
        assert_eq!(proof.c, [3u8; 32]);
    }

    /// The merge circuit has no P256 gadget: a BSB22-committed proof is not a
    /// merge proof.
    #[test]
    fn to_merge_proof_rejects_a_proof_with_a_commitment() {
        let error = proof_with_commitment()
            .to_merge_proof()
            .expect_err("a committed proof is not a merge proof");

        assert!(matches!(error, ClientError::ProofParse(_)));
    }

    #[test]
    fn p256_transact_parts_keep_the_existing_proof_and_extract_commitment() {
        let (proof, commitment) = proof_with_commitment()
            .into_ring_p256_transact_parts()
            .expect("committed P256 proof maps");

        assert_eq!(proof.a, [1u8; 32]);
        assert_eq!(proof.b, [2u8; 128]);
        assert_eq!(proof.c, [3u8; 32]);
        assert_eq!(commitment.commitment, [4u8; 32]);
        assert_eq!(commitment.commitment_pok, [5u8; 32]);
    }

    // Solana's canonical big-endian G2 compression test point.
    const G2: [u8; 128] = [
        40, 57, 233, 205, 180, 46, 35, 111, 215, 5, 23, 93, 12, 71, 118, 225, 7, 46, 247, 147, 47,
        130, 106, 189, 184, 80, 146, 103, 141, 52, 242, 25, 0, 203, 124, 176, 110, 34, 151, 212,
        66, 180, 238, 151, 236, 189, 133, 209, 17, 137, 205, 183, 168, 196, 92, 159, 75, 174, 81,
        168, 18, 86, 176, 56, 16, 26, 210, 20, 18, 81, 122, 142, 104, 62, 251, 169, 98, 141, 21,
        253, 50, 130, 182, 15, 33, 109, 228, 31, 79, 183, 88, 147, 174, 108, 4, 22, 14, 129, 168,
        6, 80, 246, 254, 100, 218, 131, 94, 49, 247, 211, 3, 245, 22, 200, 177, 91, 60, 144, 147,
        174, 90, 17, 19, 189, 62, 147, 152, 18,
    ];

    /// The batch update carries `b` raw, as transact and merge do, so the
    /// program pays no G2 decompression syscall.
    #[test]
    fn to_nullifier_tree_proof_keeps_b_raw() {
        let proof = ProofCompressed {
            b: G2,
            commitment: None,
            ..proof_with_commitment()
        };
        let batch_update = proof
            .to_nullifier_tree_proof()
            .expect("vanilla proof maps to a batch update proof");

        assert_eq!(batch_update.a, [1u8; 32]);
        assert_eq!(batch_update.b, G2);
        assert_eq!(batch_update.c, [3u8; 32]);
    }

    #[test]
    fn to_nullifier_tree_proof_rejects_a_proof_with_a_commitment() {
        let error = proof_with_commitment()
            .to_nullifier_tree_proof()
            .expect_err("a committed proof is not a batch update proof");

        assert!(matches!(error, ClientError::ProofParse(_)));
    }

    #[test]
    fn p256_transact_parts_reject_vanilla_proof() {
        let vanilla = ProofCompressed {
            commitment: None,
            ..proof_with_commitment()
        };
        let error = vanilla
            .into_ring_p256_transact_parts()
            .expect_err("vanilla proof is not a P256 ring proof");

        assert!(matches!(error, ClientError::ProofParse(_)));
    }
}
