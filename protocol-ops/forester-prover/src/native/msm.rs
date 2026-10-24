//! Bounded-memory MSMs over the original compressed gnark key queries.
use std::{
    fs::File,
    io::{BufReader, Read, Seek, SeekFrom},
    os::unix::fs::FileExt,
    path::Path,
};

use anyhow::{bail, Context, Result};
use ark_bn254::{Fr, G1Projective, G2Projective};
use ark_ec::VariableBaseMSM;
use ark_ff::BigInt;
use rayon::prelude::*;

use super::key::{decode_g1, decode_g2, Query};

// Decompression, scalars and bucket scratch remain bounded independently of key size.
const POINTS_PER_CHUNK: usize = 1 << 15;
const READ_BUFFER: usize = 2 << 20;

struct Positioned<'a> {
    file: &'a File,
    offset: u64,
}
impl Read for Positioned<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let read = self.file.read_at(bytes, self.offset)?;
        self.offset += read as u64;
        Ok(read)
    }
}

fn scalar(reader: &mut impl Read) -> Result<Fr> {
    let mut encoded = [0u8; 32];
    reader
        .read_exact(&mut encoded)
        .context("read solved scalar")?;
    let mut limbs = [0u64; 4];
    for (limb, bytes) in limbs.iter_mut().zip(encoded.as_chunks::<8>().0) {
        *limb = u64::from_le_bytes(*bytes);
    }
    Ok(Fr::new_unchecked(BigInt(limbs)))
}

/// Scalars are either consecutive (K/H) or selected by gnark's infinity bitmap (A/B).
#[derive(Clone, Copy)]
pub(super) struct Scalars {
    pub first: u64,
    pub count: u64,
    pub infinity_offset: Option<u64>,
}

struct ScalarStream<'a> {
    scalars: BufReader<File>,
    infinity: Option<BufReader<Positioned<'a>>>,
    remaining: u64,
}
impl<'a> ScalarStream<'a> {
    fn new(key: &'a File, path: &Path, layout: Scalars) -> Result<Self> {
        let mut source = File::open(path)?;
        let scalar_end = layout
            .first
            .checked_add(layout.count)
            .and_then(|n| n.checked_mul(32))
            .ok_or_else(|| anyhow::anyhow!("scalar range overflow"))?;
        if source.metadata()?.len() < scalar_end {
            bail!("scalar file is shorter than its query range");
        }
        source.seek(SeekFrom::Start(
            layout
                .first
                .checked_mul(32)
                .context("scalar offset overflow")?,
        ))?;
        let infinity = layout
            .infinity_offset
            .map(|offset| BufReader::with_capacity(READ_BUFFER, Positioned { file: key, offset }));
        Ok(Self {
            scalars: BufReader::with_capacity(READ_BUFFER, source),
            infinity,
            remaining: layout.count,
        })
    }
    fn next(&mut self) -> Result<Option<Fr>> {
        while self.remaining > 0 {
            self.remaining -= 1;
            let value = scalar(&mut self.scalars)?;
            if let Some(bitmap) = &mut self.infinity {
                let mut flag = [0u8; 1];
                bitmap.read_exact(&mut flag)?;
                match flag[0] {
                    0 => {}
                    1 => continue,
                    other => bail!("invalid infinity bitmap byte {other}"),
                }
            }
            return Ok(Some(value));
        }
        Ok(None)
    }
}

pub(super) fn g1(
    key: &File,
    query: Query,
    path: &Path,
    layout: Scalars,
    label: &str,
) -> Result<G1Projective> {
    let mut point_reader = BufReader::with_capacity(
        READ_BUFFER,
        Positioned {
            file: key,
            offset: query.offset,
        },
    );
    let mut scalar_reader = ScalarStream::new(key, path, layout)?;
    let mut sum = G1Projective::default();
    let mut processed = 0u64;
    let width = query.point_bytes;
    while processed < query.count {
        let count = usize::try_from((query.count - processed).min(POINTS_PER_CHUNK as u64))?;
        let mut encoded = vec![0u8; count.checked_mul(width).context("query buffer overflow")?];
        point_reader.read_exact(&mut encoded)?;
        let points = encoded
            .par_chunks_exact(width)
            .map(decode_g1)
            .collect::<Result<Vec<_>>>()?;
        let scalars = (0..count)
            .map(|_| {
                scalar_reader
                    .next()?
                    .context("query has more points than selected scalars")
            })
            .collect::<Result<Vec<_>>>()?;
        sum += G1Projective::msm_unchecked(&points, &scalars);
        processed += count as u64;
        if processed == query.count || processed.is_multiple_of(POINTS_PER_CHUNK as u64 * 128) {
            eprintln!("native MSM {label}: {processed}/{} points", query.count);
        }
    }
    if scalar_reader.next()?.is_some() {
        bail!("query has fewer points than selected scalars");
    }
    Ok(sum)
}

pub(super) fn g2(
    key: &File,
    query: Query,
    path: &Path,
    layout: Scalars,
    label: &str,
) -> Result<G2Projective> {
    let mut point_reader = BufReader::with_capacity(
        READ_BUFFER,
        Positioned {
            file: key,
            offset: query.offset,
        },
    );
    let mut scalar_reader = ScalarStream::new(key, path, layout)?;
    let mut sum = G2Projective::default();
    let mut processed = 0u64;
    let width = query.point_bytes;
    while processed < query.count {
        let count = usize::try_from((query.count - processed).min(POINTS_PER_CHUNK as u64))?;
        let mut encoded = vec![0u8; count.checked_mul(width).context("query buffer overflow")?];
        point_reader.read_exact(&mut encoded)?;
        let points = encoded
            .par_chunks_exact(width)
            .map(decode_g2)
            .collect::<Result<Vec<_>>>()?;
        let scalars = (0..count)
            .map(|_| {
                scalar_reader
                    .next()?
                    .context("query has more points than selected scalars")
            })
            .collect::<Result<Vec<_>>>()?;
        sum += G2Projective::msm_unchecked(&points, &scalars);
        processed += count as u64;
        if processed == query.count || processed.is_multiple_of(POINTS_PER_CHUNK as u64 * 128) {
            eprintln!("native MSM {label}: {processed}/{} points", query.count);
        }
    }
    if scalar_reader.next()?.is_some() {
        bail!("query has fewer points than selected scalars");
    }
    Ok(sum)
}
