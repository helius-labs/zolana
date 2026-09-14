use ark_bn254::{Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ff::{BigInteger, PrimeField};

use crate::Error;

const MASK: u8 = 0b11 << 6;
const UNCOMPRESSED: u8 = 0b00 << 6;
const COMPRESSED_LARGEST: u8 = 0b11 << 6;
const COMPRESSED_INFINITY: u8 = 0b01 << 6;

pub struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    pub fn position(&self) -> usize {
        self.position
    }

    pub fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(Error::Truncated(self.position))?;
        let slice = self
            .bytes
            .get(self.position..end)
            .ok_or(Error::Truncated(self.position))?;
        self.position = end;
        Ok(slice)
    }

    pub fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    pub fn u32(&mut self) -> Result<u32, Error> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub fn u64(&mut self) -> Result<u64, Error> {
        let bytes = self.take(8)?;
        let mut output = [0u8; 8];
        output.copy_from_slice(bytes);
        Ok(u64::from_be_bytes(output))
    }

    pub fn len(&mut self) -> Result<usize, Error> {
        Ok(self.u32()? as usize)
    }

    pub fn fr(&mut self) -> Result<Fr, Error> {
        let at = self.position;
        let bytes = self.take(32)?;
        canonical::<Fr>(bytes).ok_or(Error::NonCanonicalScalar(at))
    }

    pub fn g1(&mut self) -> Result<G1Affine, Error> {
        let at = self.position;
        decode_g1(self.take(32)?, at)
    }

    pub fn g2(&mut self) -> Result<G2Affine, Error> {
        let at = self.position;
        decode_g2(self.take(64)?, at)
    }

    pub fn g1_vec(&mut self) -> Result<Vec<G1Affine>, Error> {
        let length = self.len()?;
        let at = self.position;
        decode_many(self.take(length * 32)?, 32, at, decode_g1)
    }

    pub fn g2_vec(&mut self) -> Result<Vec<G2Affine>, Error> {
        let length = self.len()?;
        let at = self.position;
        decode_many(self.take(length * 64)?, 64, at, decode_g2)
    }

    pub fn bools(&mut self, length: usize) -> Result<Vec<bool>, Error> {
        Ok(self.take(length)?.iter().map(|&value| value != 0).collect())
    }

    pub fn u64_vec_vec(&mut self) -> Result<Vec<Vec<u64>>, Error> {
        let outer = self.len()?;
        (0..outer)
            .map(|_| {
                let inner = self.len()?;
                (0..inner).map(|_| self.u64()).collect()
            })
            .collect()
    }
}

fn canonical<F: PrimeField>(bytes: &[u8]) -> Option<F> {
    let value = F::from_be_bytes_mod_order(bytes);
    (value.into_bigint().to_bytes_be() == bytes).then_some(value)
}

fn decode_many<T: Send>(
    bytes: &[u8],
    size: usize,
    at: usize,
    decode: fn(&[u8], usize) -> Result<T, Error>,
) -> Result<Vec<T>, Error> {
    let count = bytes.len() / size;
    #[cfg(feature = "parallel")]
    {
        use rayon::prelude::*;
        (0..count)
            .into_par_iter()
            .map(|index| decode(&bytes[index * size..(index + 1) * size], at + index * size))
            .collect()
    }
    #[cfg(not(feature = "parallel"))]
    {
        (0..count)
            .map(|index| decode(&bytes[index * size..(index + 1) * size], at + index * size))
            .collect()
    }
}

fn fq_masked(bytes: &[u8], at: usize) -> Result<(Fq, u8), Error> {
    let mut x = [0u8; 32];
    x.copy_from_slice(bytes);
    let flags = x[0] & MASK;
    x[0] &= !MASK;
    let field = canonical::<Fq>(&x).ok_or(Error::NonCanonicalCoordinate(at))?;
    Ok((field, flags))
}

fn infinity(bytes: &[u8], at: usize) -> Result<bool, Error> {
    if bytes[0] & MASK != COMPRESSED_INFINITY {
        return Ok(false);
    }
    if bytes[0] != COMPRESSED_INFINITY || bytes[1..].iter().any(|&value| value != 0) {
        return Err(Error::MalformedInfinity(at));
    }
    Ok(true)
}

fn decode_g1(bytes: &[u8], at: usize) -> Result<G1Affine, Error> {
    if infinity(bytes, at)? {
        return Ok(G1Affine::identity());
    }
    let (x, flags) = fq_masked(bytes, at)?;
    if flags == UNCOMPRESSED {
        return Err(Error::UncompressedPoint(at));
    }
    G1Affine::get_point_from_x_unchecked(x, flags == COMPRESSED_LARGEST)
        .ok_or(Error::PointNotOnCurve(at))
}

fn decode_g2(bytes: &[u8], at: usize) -> Result<G2Affine, Error> {
    if infinity(bytes, at)? {
        return Ok(G2Affine::identity());
    }
    let (c1, flags) = fq_masked(&bytes[..32], at)?;
    let (c0, _) = fq_masked(&bytes[32..], at + 32)?;
    if flags == UNCOMPRESSED {
        return Err(Error::UncompressedPoint(at));
    }
    G2Affine::get_point_from_x_unchecked(Fq2::new(c0, c1), flags == COMPRESSED_LARGEST)
        .ok_or(Error::PointNotOnCurve(at))
}
