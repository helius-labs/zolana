//! Bounded-memory layout reader for the original compressed gnark batch-key container.
//!
//! The point queries and infinity masks stay in the source file. Parsing reads
//! fixed points, the small verifying key, and query lengths, then seeks over the
//! large vectors. The caller authenticates the complete file against its pinned
//! digest before using these offsets to prove.
use std::io::{Read, Seek, SeekFrom};

use anyhow::{anyhow, bail, ensure, Result};
use ark_bn254::{Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ec::{short_weierstrass::SWCurveConfig, AffineRepr};
use ark_ff::{BigInt, Field, PrimeField, Zero};

const G1_BYTES: usize = 32;
const G2_BYTES: usize = 64;
const FLAGS: u8 = 0xc0;
const INFINITY: u8 = 0x40;
const SMALL: u8 = 0x80;
const LARGE: u8 = 0xc0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Query {
    pub offset: u64,
    pub count: u64,
    pub point_bytes: usize,
}

impl Query {
    pub fn byte_len(self) -> Result<u64> {
        self.count
            .checked_mul(self.point_bytes as u64)
            .ok_or_else(|| anyhow!("query byte length overflow"))
    }
}

#[derive(Debug)]
pub(crate) struct VerifyingKey {
    pub alpha: G1Affine,
    pub beta: G1Affine,
    pub beta2: G2Affine,
    pub gamma2: G2Affine,
    pub delta: G1Affine,
    pub delta2: G2Affine,
    pub ic: Vec<G1Affine>,
}

#[derive(Debug)]
pub(crate) struct KeyLayout {
    pub height: u32,
    pub batch_size: u32,
    pub domain_size: usize,
    pub root: Fr,
    pub coset: Fr,
    pub alpha: G1Affine,
    pub beta: G1Affine,
    pub delta: G1Affine,
    pub beta2: G2Affine,
    pub delta2: G2Affine,
    pub a: Query,
    pub b: Query,
    pub z: Query,
    pub k: Query,
    pub b2: Query,
    pub wire_count: u64,
    pub public_count: u64,
    /// One byte per original witness wire, 0 or 1, with no length prefix.
    pub infinity_a_offset: u64,
    pub infinity_b_offset: u64,
    pub cs_offset: u64,
    pub vk: VerifyingKey,
}

impl KeyLayout {
    pub fn read_from(reader: &mut (impl Read + Seek)) -> Result<Self> {
        let file_len = reader.seek(SeekFrom::End(0))?;
        reader.seek(SeekFrom::Start(0))?;
        let height = read_u32(reader)?;
        let batch_size = read_u32(reader)?;
        ensure!(
            height > 0 && height < 64 && batch_size > 0,
            "invalid batch-key shape"
        );
        let cardinality = read_u64(reader)?;
        ensure!(
            cardinality.is_power_of_two() && cardinality <= 1 << 28,
            "invalid BN254 FFT domain size"
        );
        let domain_size = usize::try_from(cardinality)?;
        let size_inverse = read_field::<Fr>(reader)?;
        let root = read_field::<Fr>(reader)?;
        let root_inverse = read_field::<Fr>(reader)?;
        let coset = read_field::<Fr>(reader)?;
        let coset_inverse = read_field::<Fr>(reader)?;
        ensure!(
            read_byte(reader)? <= 1,
            "invalid domain precomputation flag"
        );
        ensure!(
            size_inverse * Fr::from(cardinality) == Fr::from(1u64),
            "invalid domain size inverse"
        );
        ensure!(
            root * root_inverse == Fr::from(1u64) && root.pow([cardinality]) == Fr::from(1u64),
            "invalid FFT root or inverse"
        );
        ensure!(
            cardinality == 1 || root.pow([cardinality / 2]) != Fr::from(1u64),
            "FFT root has insufficient order"
        );
        ensure!(
            !coset.is_zero() && coset * coset_inverse == Fr::from(1u64),
            "invalid coset or inverse"
        );

        let alpha = read_g1(reader)?;
        let beta = read_g1(reader)?;
        let delta = read_g1(reader)?;
        let a = skip_query(reader, file_len, G1_BYTES)?;
        let b = skip_query(reader, file_len, G1_BYTES)?;
        let z = skip_query(reader, file_len, G1_BYTES)?;
        let k = skip_query(reader, file_len, G1_BYTES)?;
        let beta2 = read_g2(reader)?;
        let delta2 = read_g2(reader)?;
        let b2 = skip_query(reader, file_len, G2_BYTES)?;
        let wire_count = read_u64(reader)?;
        let infinity_a_count = read_u64(reader)?;
        let infinity_b_count = read_u64(reader)?;
        ensure!(wire_count > 0, "proving key has no witness wires");
        ensure!(
            a.count.checked_add(infinity_a_count) == Some(wire_count),
            "A query and infinity mask sizes disagree"
        );
        ensure!(
            b.count.checked_add(infinity_b_count) == Some(wire_count),
            "B query and infinity mask sizes disagree"
        );
        ensure!(
            b2.count == b.count,
            "G1 and G2 B queries have different sizes"
        );
        ensure!(
            z.count.checked_add(1) == Some(cardinality),
            "Z query does not match FFT domain"
        );
        let infinity_a_offset = reader.stream_position()?;
        skip(reader, file_len, wire_count)?;
        let infinity_b_offset = reader.stream_position()?;
        skip(reader, file_len, wire_count)?;
        ensure!(
            read_u32(reader)? == 0,
            "batch proving keys must not contain commitments"
        );

        let vk = read_verifying_key(reader)?;
        ensure!(
            alpha == vk.alpha
                && beta == vk.beta
                && delta == vk.delta
                && beta2 == vk.beta2
                && delta2 == vk.delta2,
            "proving-key fixed points do not match verifying key"
        );
        let public_count = u64::try_from(vk.ic.len())?;
        ensure!(
            k.count.checked_add(public_count) == Some(wire_count),
            "private and public query sizes disagree"
        );
        let cs_offset = reader.stream_position()?;
        ensure!(
            cs_offset < file_len,
            "key container has no constraint system"
        );
        Ok(Self {
            height,
            batch_size,
            domain_size,
            root,
            coset,
            alpha,
            beta,
            delta,
            beta2,
            delta2,
            a,
            b,
            z,
            k,
            b2,
            wire_count,
            public_count,
            infinity_a_offset,
            infinity_b_offset,
            cs_offset,
            vk,
        })
    }
}

/// Decode a gnark compressed G1 point (big-endian x, sign in its top bits).
pub(crate) fn decode_g1(encoded: &[u8]) -> Result<G1Affine> {
    ensure!(
        encoded.len() == G1_BYTES,
        "compressed G1 point must be 32 bytes"
    );
    let Some(flag) = point_flag(encoded)? else {
        return Ok(G1Affine::zero());
    };
    let mut coordinate = [0u8; 32];
    coordinate.copy_from_slice(encoded);
    coordinate[0] &= !FLAGS;
    let x = field::<Fq>(&coordinate)?;
    let mut y = (x.square() * x + <ark_bn254::g1::Config as SWCurveConfig>::COEFF_B)
        .sqrt()
        .ok_or_else(|| anyhow!("G1 x coordinate is not on the curve"))?;
    if (y > -y) != (flag == LARGE) {
        y = -y;
    }
    let point = G1Affine::new_unchecked(x, y);
    ensure!(
        point.is_on_curve() && point.is_in_correct_subgroup_assuming_on_curve(),
        "invalid G1 point"
    );
    Ok(point)
}

/// Decode a gnark compressed G2 point: x.c1 then x.c0, each big-endian.
pub(crate) fn decode_g2(encoded: &[u8]) -> Result<G2Affine> {
    ensure!(
        encoded.len() == G2_BYTES,
        "compressed G2 point must be 64 bytes"
    );
    let Some(flag) = point_flag(encoded)? else {
        return Ok(G2Affine::zero());
    };
    let mut high = [0u8; 32];
    high.copy_from_slice(&encoded[..32]);
    high[0] &= !FLAGS;
    let low: &[u8; 32] = encoded[32..].try_into()?;
    let x = Fq2::new(field::<Fq>(low)?, field::<Fq>(&high)?);
    let mut y = (x.square() * x + <ark_bn254::g2::Config as SWCurveConfig>::COEFF_B)
        .sqrt()
        .ok_or_else(|| anyhow!("G2 x coordinate is not on the curve"))?;
    // Both gnark and arkworks order Fq2 lexicographically by c1, then c0.
    if (y > -y) != (flag == LARGE) {
        y = -y;
    }
    let point = G2Affine::new_unchecked(x, y);
    ensure!(
        point.is_on_curve() && point.is_in_correct_subgroup_assuming_on_curve(),
        "G2 point is not in the prime-order subgroup"
    );
    Ok(point)
}

pub(crate) fn read_g1(reader: &mut impl Read) -> Result<G1Affine> {
    let mut encoded = [0u8; G1_BYTES];
    reader.read_exact(&mut encoded)?;
    decode_g1(&encoded)
}

pub(crate) fn read_g2(reader: &mut impl Read) -> Result<G2Affine> {
    let mut encoded = [0u8; G2_BYTES];
    reader.read_exact(&mut encoded)?;
    decode_g2(&encoded)
}

fn point_flag(encoded: &[u8]) -> Result<Option<u8>> {
    let first = encoded
        .first()
        .ok_or_else(|| anyhow!("empty point encoding"))?;
    match first & FLAGS {
        INFINITY => {
            ensure!(
                first & !FLAGS == 0 && encoded[1..].iter().all(|&byte| byte == 0),
                "nonzero coordinates in point at infinity"
            );
            Ok(None)
        }
        flag @ (SMALL | LARGE) => Ok(Some(flag)),
        _ => bail!("uncompressed or invalid point encoding"),
    }
}

fn field<F: PrimeField<BigInt = BigInt<4>>>(bytes: &[u8; 32]) -> Result<F> {
    let mut limbs = [0u64; 4];
    for (limb, encoded) in limbs.iter_mut().rev().zip(bytes.as_chunks::<8>().0) {
        *limb = u64::from_be_bytes(*encoded);
    }
    F::from_bigint(BigInt(limbs)).ok_or_else(|| anyhow!("non-canonical field element"))
}

fn read_field<F: PrimeField<BigInt = BigInt<4>>>(reader: &mut impl Read) -> Result<F> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    field(&bytes)
}

fn skip_query(reader: &mut (impl Read + Seek), file_len: u64, point_bytes: usize) -> Result<Query> {
    let count = u64::from(read_u32(reader)?);
    let offset = reader.stream_position()?;
    let query = Query {
        offset,
        count,
        point_bytes,
    };
    if count > 0 {
        ensure!(
            read_byte(reader)? & FLAGS != 0,
            "query points are not compressed"
        );
        reader.seek(SeekFrom::Start(offset))?;
    }
    skip(reader, file_len, query.byte_len()?)?;
    Ok(query)
}

fn skip(reader: &mut impl Seek, file_len: u64, length: u64) -> Result<()> {
    let end = reader
        .stream_position()?
        .checked_add(length)
        .ok_or_else(|| anyhow!("key section offset overflow"))?;
    ensure!(end <= file_len, "truncated key section");
    reader.seek(SeekFrom::Start(end))?;
    Ok(())
}

fn read_verifying_key(reader: &mut impl Read) -> Result<VerifyingKey> {
    let alpha = read_g1(reader)?;
    let beta = read_g1(reader)?;
    let beta2 = read_g2(reader)?;
    let gamma2 = read_g2(reader)?;
    let delta = read_g1(reader)?;
    let delta2 = read_g2(reader)?;
    let ic_count = read_u32(reader)?;
    ensure!(
        (1..=4096).contains(&ic_count),
        "invalid verifying-key public input count"
    );
    let ic = (0..ic_count)
        .map(|_| read_g1(reader))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        read_u32(reader)? == 0,
        "batch verifying key must not contain committed public wires"
    );
    ensure!(
        read_u32(reader)? == 0,
        "batch verifying key must not contain commitments"
    );
    Ok(VerifyingKey {
        alpha,
        beta,
        beta2,
        gamma2,
        delta,
        delta2,
        ic,
    })
}

fn read_byte(reader: &mut impl Read) -> Result<u8> {
    let mut bytes = [0u8; 1];
    reader.read_exact(&mut bytes)?;
    Ok(bytes[0])
}
fn read_u32(reader: &mut impl Read) -> Result<u32> {
    let mut bytes = [0u8; 4];
    reader.read_exact(&mut bytes)?;
    Ok(u32::from_be_bytes(bytes))
}
fn read_u64(reader: &mut impl Read) -> Result<u64> {
    let mut bytes = [0u8; 8];
    reader.read_exact(&mut bytes)?;
    Ok(u64::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::AffineRepr;
    use ark_ff::BigInteger;
    use std::{fs::File, io::BufReader, path::Path};

    #[test]
    fn gnark_g1_generator_sign_and_infinity() {
        let mut encoded = [0; 32];
        encoded[0] = SMALL;
        encoded[31] = 1;
        assert_eq!(decode_g1(&encoded).unwrap(), G1Affine::generator());
        encoded[0] = LARGE;
        assert_eq!(decode_g1(&encoded).unwrap(), -G1Affine::generator());
        encoded = [0; 32];
        encoded[0] = INFINITY;
        assert_eq!(decode_g1(&encoded).unwrap(), G1Affine::zero());
        encoded[31] = 1;
        assert!(decode_g1(&encoded).is_err());
    }

    #[test]
    fn malformed_points_are_rejected() {
        assert!(decode_g1(&[0; 32]).is_err());
        assert!(decode_g1(&[0xff; 32]).is_err());
        assert!(decode_g2(&[0; 64]).is_err());
        assert!(decode_g2(&[0xff; 64]).is_err());
    }

    #[test]
    fn query_offsets_cannot_run_past_the_file() {
        let mut encoded = Vec::from(2u32.to_be_bytes());
        encoded.extend_from_slice(&[SMALL; G1_BYTES]);
        let file_len = encoded.len() as u64;
        let mut reader = std::io::Cursor::new(encoded);
        assert!(skip_query(&mut reader, file_len, G1_BYTES)
            .unwrap_err()
            .to_string()
            .contains("truncated key section"));
    }

    #[test]
    #[ignore = "requires the pinned 40x10 key in FORESTER_TEST_KEYS_DIR"]
    fn pinned_40x10_layout_matches_checked_in_verifier() {
        let key_dir =
            std::env::var_os("FORESTER_TEST_KEYS_DIR").expect("set FORESTER_TEST_KEYS_DIR");
        let path = Path::new(&key_dir).join("batch_address-append_40_10.key");
        let key = KeyLayout::read_from(&mut BufReader::new(File::open(&path).unwrap())).unwrap();
        assert_eq!(
            (
                key.height,
                key.batch_size,
                key.domain_size,
                key.wire_count,
                key.public_count,
                key.cs_offset
            ),
            (40, 10, 1 << 19, 416534, 2, 79671577)
        );
        assert_eq!(
            (
                key.a.offset,
                key.a.count,
                key.b.offset,
                key.b.count,
                key.z.offset,
                key.z.count,
                key.k.offset,
                key.k.count,
                key.b2.offset,
                key.b2.count
            ),
            (277, 285617, 9140025, 412414, 22337277, 524287, 39114465, 416532, 52443621, 412414)
        );
        let root = std::env::var_os("FORESTER_REPO_ROOT")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."));
        let generated = std::fs::read_to_string(root.join("program-libs/tree/src/nullifier_tree/verify/verifying_keys/batch_address_append_40_10.rs")).unwrap();
        let bytes = |name: &str| {
            generated
                .split(&format!("{name}: ["))
                .nth(1)
                .unwrap()
                .split(']')
                .next()
                .unwrap()
                .split(',')
                .map(str::trim)
                .filter(|token| !token.is_empty())
                .map(|token| token.trim_end_matches("u8").parse::<u8>().unwrap())
                .collect::<Vec<_>>()
        };
        let g1 = |point: G1Affine| {
            [
                point.x.into_bigint().to_bytes_be(),
                point.y.into_bigint().to_bytes_be(),
            ]
            .concat()
        };
        let g2 = |point: G2Affine| {
            [
                point.x.c1.into_bigint().to_bytes_be(),
                point.x.c0.into_bigint().to_bytes_be(),
                point.y.c1.into_bigint().to_bytes_be(),
                point.y.c0.into_bigint().to_bytes_be(),
            ]
            .concat()
        };
        assert_eq!(g1(key.alpha), bytes("vk_alpha_g1"));
        assert_eq!(g2(key.beta2), bytes("vk_beta_g2"));
        assert_eq!(g2(key.delta2), bytes("vk_delta_g2"));
        let mut file = File::open(path).unwrap();
        file.seek(SeekFrom::Start(key.cs_offset)).unwrap();
        let mut header = [0; 8];
        file.read_exact(&mut header).unwrap();
        assert_eq!(u64::from_le_bytes(header), 56995303);
    }
}
