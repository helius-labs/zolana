//! Bounded-memory execution of the BN254 gnark R1CS program stored in a key.
//!
//! Instruction columns are decoded to temporary files; serialized calldata is
//! streamed directly in original builder order with checked dependencies. Only
//! bounded page caches and one instruction are retained. Scalars use Montgomery limbs.
use anyhow::{anyhow, bail, ensure, Context, Result};
use ark_bn254::Fr;
use ark_ff::{BigInt, BigInteger, Field, One, PrimeField, Zero};
use std::{
    collections::{HashMap, VecDeque},
    fs::{self, File, OpenOptions},
    io::{BufWriter, Read, Write},
    os::unix::fs::FileExt,
    path::{Path, PathBuf},
};

const PAGE_BYTES: usize = 65_536;
const MAX_INSTRUCTION_WORDS: usize = 16 * 1024 * 1024;
const HINT_TAG: u64 = 5_309_735;
const R1C_TAG: u64 = 5_309_736;
const BATCH_INVERSE_TAG: u64 = 5_309_750;

pub struct Solution {
    pub wires_path: PathBuf,
    pub a_path: PathBuf,
    pub b_path: PathBuf,
    pub c_path: PathBuf,
    pub wire_count: usize,
    pub constraint_count: usize,
    /// Includes gnark's constant-one wire.
    pub public_count: usize,
}

/// Execute a pinned gnark key. `flat_inputs` includes the constant-one wire.
/// The caller supplies a fresh, private scratch directory for each invocation.
pub fn solve(
    key_file: &File,
    cs_offset: u64,
    flat_inputs: &[Fr],
    scratch_dir: &Path,
) -> Result<Solution> {
    fs::create_dir_all(scratch_dir)?;
    let file_len = key_file.metadata()?.len();
    let mut outer = DiskReader::new(key_file, cs_offset, file_len)?;
    let payload_len = outer.u64()?;
    let version = [outer.u64()?, outer.u64()?, outer.u64()?];
    ensure!(
        version[0] == 0 && version[1] == 16,
        "unsupported gnark R1CS version {version:?}"
    );
    let payload_start = outer.position;
    let payload_end = payload_start
        .checked_add(payload_len)
        .ok_or_else(|| anyhow!("R1CS length overflow"))?;
    ensure!(payload_end <= file_len, "truncated R1CS payload");
    let lengths = [outer.u64()?, outer.u64()?, outer.u64()?, outer.u64()?];
    let levels_start = outer.position;
    let instructions_start = checked_sum(levels_start, lengths[0])?;
    let calldata_start = checked_sum(instructions_start, lengths[1])?;
    let body_start = checked_sum(calldata_start, lengths[2])?;
    let coefficients_start = checked_sum(body_start, lengths[3])?;
    ensure!(
        coefficients_start <= payload_end,
        "R1CS sections exceed payload"
    );
    let metadata = Metadata::read(DiskReader::new(key_file, body_start, coefficients_start)?)?;
    let wire_count = metadata
        .public_count
        .checked_add(metadata.secret_count)
        .and_then(|n| n.checked_add(metadata.internal_count))
        .ok_or_else(|| anyhow!("wire count overflow"))?;
    ensure!(
        wire_count <= u32::MAX as usize,
        "wire count exceeds gnark indices"
    );
    ensure!(
        flat_inputs.len() == metadata.public_count + metadata.secret_count,
        "expected {} input wires, got {}",
        metadata.public_count + metadata.secret_count,
        flat_inputs.len()
    );
    ensure!(
        flat_inputs.first() == Some(&Fr::one()),
        "missing constant-one input"
    );
    let coefficients =
        read_coefficients(DiskReader::new(key_file, coefficients_start, payload_end)?)?;
    ensure!(
        coefficients.first() == Some(&Fr::zero()) && coefficients.get(1) == Some(&Fr::one()),
        "invalid gnark coefficient identities"
    );

    let mut temporary = Vec::new();
    let mut instruction_reader = DiskReader::new(key_file, instructions_start, calldata_start)?;
    let mut column_paths = Vec::new();
    let mut instruction_count = None;
    eprintln!("native solver: decoding instruction columns");
    for (column, width) in [32u32, 32, 32, 64].into_iter().enumerate() {
        let path = scratch_dir.join(format!("witness-instructions-{column}.bin"));
        let mut writer = BufWriter::with_capacity(1 << 20, create_scratch(&path)?);
        let count = decode_column(&mut instruction_reader, width, |value| {
            if width == 32 {
                writer.write_all(&(value as u32).to_le_bytes())?;
            } else {
                writer.write_all(&value.to_le_bytes())?;
            }
            Ok(())
        })?;
        writer.flush()?;
        if let Some(previous) = instruction_count {
            ensure!(count == previous, "instruction column length mismatch");
        }
        instruction_count = Some(count);
        temporary.push(path.clone());
        column_paths.push(path);
    }
    ensure!(
        instruction_reader.position == calldata_start,
        "trailing instruction bytes"
    );
    let instruction_count = instruction_count.unwrap_or(0);
    ensure!(
        instruction_count <= metadata.constraint_count as u64 + wire_count as u64,
        "excessive instruction count"
    );
    let mut columns = column_paths
        .iter()
        .map(|path| PagedFile::open_existing(path, 1024))
        .collect::<Result<Vec<_>>>()?;
    let mut calldata = CalldataStream::new(DiskReader::new(key_file, calldata_start, body_start)?)?;
    eprintln!(
        "native solver: streaming {} original calldata words",
        calldata.total_words
    );
    let wires_path = scratch_dir.join("witness-wires.bin");
    let a_path = scratch_dir.join("witness-a.bin");
    let b_path = scratch_dir.join("witness-b.bin");
    let c_path = scratch_dir.join("witness-c.bin");
    let flags_path = scratch_dir.join("witness-solved.bin");
    temporary.push(flags_path.clone());
    let mut wires = PagedFile::create(&wires_path, wire_count as u64 * 32, 16_384)?;
    let mut flags = PagedFile::create(&flags_path, wire_count as u64, 1024)?;
    let mut rows = [
        PagedFile::create(&a_path, metadata.constraint_count as u64 * 32, 2048)?,
        PagedFile::create(&b_path, metadata.constraint_count as u64 * 32, 2048)?,
        PagedFile::create(&c_path, metadata.constraint_count as u64 * 32, 2048)?,
    ];
    let mut solver = Solver {
        wires: &mut wires,
        flags: &mut flags,
        coefficients: &coefficients,
        hints: &metadata.hints,
    };
    for (index, value) in flat_inputs.iter().enumerate() {
        solver.assign(index as u32, *value)?;
    }
    eprintln!(
        "native solver: executing {instruction_count} instructions in original builder order"
    );
    let mut completed_rows = 0usize;
    // Standard gnark builders append supported instructions after their input
    // expressions, including BatchInvert before its checking constraints. IDs
    // preserve that construction order and give sequential calldata/row access.
    // The solver's readiness checks reject unsupported forward dependencies.
    for id in 0..instruction_count {
        let blueprint_id = columns
            .get_mut(0)
            .ok_or_else(|| anyhow!("missing blueprint column"))?
            .u32(id * 4)? as usize;
        let row = columns
            .get_mut(1)
            .ok_or_else(|| anyhow!("missing constraint column"))?
            .u32(id * 4)? as usize;
        let wire_offset = columns
            .get_mut(2)
            .ok_or_else(|| anyhow!("missing wire column"))?
            .u32(id * 4)?;
        let start = columns
            .get_mut(3)
            .ok_or_else(|| anyhow!("missing calldata column"))?
            .u64(id * 8)?;
        let words = calldata.instruction(start)?;
        let tag = *metadata
            .blueprints
            .get(blueprint_id)
            .ok_or_else(|| anyhow!("unknown blueprint index"))?;
        match tag {
            R1C_TAG => {
                ensure!(
                    row < metadata.constraint_count,
                    "constraint index out of bounds"
                );
                ensure!(
                    row == completed_rows,
                    "nonsequential R1CS constraint offset"
                );
                let evaluated = solver
                    .r1c(&words)
                    .with_context(|| format!("constraint {row}"))?;
                for (output, value) in rows.iter_mut().zip(evaluated) {
                    output.set_scalar(row as u64, value)?;
                }
                completed_rows += 1;
            }
            HINT_TAG => solver
                .hint(&words)
                .with_context(|| format!("hint instruction {id}"))?,
            BATCH_INVERSE_TAG => solver.batch_inverse(&words, wire_offset)?,
            other => bail!("unsupported gnark blueprint tag {other}"),
        }
        let visited = id + 1;
        if visited.is_multiple_of(1 << 20) {
            eprintln!("native solver execution: {visited}/{instruction_count} instructions, {completed_rows} rows");
        }
    }
    calldata.finish()?;

    ensure!(
        completed_rows == metadata.constraint_count,
        "constraint row count mismatch"
    );
    for index in 0..wire_count {
        ensure!(
            solver.solved(index as u32)?,
            "wire {index} was never assigned"
        );
    }
    wires.flush()?;
    for row in &mut rows {
        row.flush()?;
    }
    drop(columns);
    drop(calldata);
    drop(flags);
    for path in temporary {
        fs::remove_file(path)?;
    }
    Ok(Solution {
        wires_path,
        a_path,
        b_path,
        c_path,
        wire_count,
        constraint_count: metadata.constraint_count,
        public_count: metadata.public_count,
    })
}

fn checked_sum(offset: u64, length: u64) -> Result<u64> {
    offset
        .checked_add(length)
        .ok_or_else(|| anyhow!("section length overflow"))
}
fn create_scratch(path: &Path) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("create scratch {}", path.display()))
}

struct Solver<'a> {
    wires: &'a mut PagedFile,
    flags: &'a mut PagedFile,
    coefficients: &'a [Fr],
    hints: &'a HashMap<u32, String>,
}
impl Solver<'_> {
    fn solved(&mut self, wire: u32) -> Result<bool> {
        Ok(self.flags.byte(wire as u64)? != 0)
    }
    fn assign(&mut self, wire: u32, value: Fr) -> Result<()> {
        ensure!(!self.solved(wire)?, "wire {wire} assigned twice");
        self.wires.set_scalar(wire as u64, value)?;
        self.flags.set_byte(wire as u64, 1)
    }
    fn coefficient(&self, id: u32) -> Result<Fr> {
        self.coefficients
            .get(id as usize)
            .copied()
            .ok_or_else(|| anyhow!("coefficient {id} out of bounds"))
    }
    fn evaluate(&mut self, terms: &[(u32, u32)]) -> Result<Fr> {
        let mut total = Fr::zero();
        for &(coefficient, wire) in terms {
            let coefficient = self.coefficient(coefficient)?;
            if coefficient.is_zero() {
                continue;
            }
            if wire == u32::MAX {
                total += coefficient;
                continue;
            }
            ensure!(self.solved(wire)?, "unsolved wire {wire} in expression");
            total += coefficient * self.wires.scalar(wire as u64)?;
        }
        Ok(total)
    }
    fn r1c(&mut self, words: &[u32]) -> Result<[Fr; 3]> {
        let mut cursor = Words::new(words, 1);
        let lengths = [
            cursor.next()? as usize,
            cursor.next()? as usize,
            cursor.next()? as usize,
        ];
        let mut expressions = [Vec::new(), Vec::new(), Vec::new()];
        let mut unknown = None;
        let mut evaluated = [Fr::zero(); 3];
        for side in 0..3 {
            expressions[side] = cursor.terms(lengths[side])?;
            for &(coefficient, wire) in &expressions[side] {
                let factor = self.coefficient(coefficient)?;
                if factor.is_zero() {
                    continue;
                }
                if wire == u32::MAX {
                    evaluated[side] += factor;
                } else if self.solved(wire)? {
                    evaluated[side] += factor * self.wires.scalar(wire as u64)?;
                } else {
                    ensure!(unknown.is_none(), "more than one unsolved R1CS term");
                    unknown = Some((side, wire, factor));
                }
            }
        }
        cursor.finish()?;
        if let Some((side, wire, factor)) = unknown {
            let term = match side {
                0 => match evaluated[1].inverse() {
                    Some(inverse) => evaluated[2] * inverse - evaluated[0],
                    None => {
                        ensure!(
                            evaluated[2].is_zero(),
                            "zero RHS divisor with nonzero output"
                        );
                        Fr::zero()
                    }
                },
                1 => match evaluated[0].inverse() {
                    Some(inverse) => evaluated[2] * inverse - evaluated[1],
                    None => {
                        ensure!(
                            evaluated[2].is_zero(),
                            "zero LHS divisor with nonzero output"
                        );
                        Fr::zero()
                    }
                },
                2 => evaluated[0] * evaluated[1] - evaluated[2],
                _ => bail!("invalid R1CS side"),
            };
            let value = term
                * factor
                    .inverse()
                    .ok_or_else(|| anyhow!("zero unknown coefficient"))?;
            self.assign(wire, value)?;
            evaluated[side] += term;
        }
        ensure!(
            evaluated[0] * evaluated[1] == evaluated[2],
            "R1CS relation is unsatisfied"
        );
        Ok(evaluated)
    }
    fn hint(&mut self, words: &[u32]) -> Result<()> {
        let mut cursor = Words::new(words, 1);
        let id = cursor.next()?;
        let count = cursor.next()? as usize;
        ensure!(count <= 4096, "excessive hint inputs");
        let mut inputs = Vec::with_capacity(count);
        for _ in 0..count {
            let terms = cursor.expression()?;
            inputs.push(self.evaluate(&terms)?);
        }
        let start = cursor.next()?;
        let end = cursor.next()?;
        cursor.finish()?;
        ensure!(end >= start, "invalid hint output range");
        let name = self
            .hints
            .get(&id)
            .ok_or_else(|| anyhow!("unknown hint {id}"))?;
        if name == "github.com/consensys/gnark/std/math/bits.nBits" {
            ensure!(inputs.len() == 1, "nBits expects one input");
            let scalar = inputs
                .first()
                .ok_or_else(|| anyhow!("missing nBits input"))?
                .into_bigint();
            for (bit, wire) in (start..end).enumerate() {
                self.assign(wire, Fr::from(u64::from(scalar.get_bit(bit))))?;
            }
        } else if name == "github.com/consensys/gnark/constraint/solver.InvZeroHint" {
            ensure!(
                inputs.len() == 1 && end - start == 1,
                "InvZero expects one input/output"
            );
            self.assign(
                start,
                inputs
                    .first()
                    .ok_or_else(|| anyhow!("missing inverse input"))?
                    .inverse()
                    .unwrap_or_else(Fr::zero),
            )?;
        } else {
            bail!("unsupported gnark hint {name}");
        }
        Ok(())
    }
    fn batch_inverse(&mut self, words: &[u32], wire_offset: u32) -> Result<()> {
        let mut cursor = Words::new(words, 1);
        let count = cursor.next()?;
        for index in 0..count {
            let terms = cursor.expression()?;
            let value = self.evaluate(&terms)?;
            self.assign(
                wire_offset
                    .checked_add(index)
                    .ok_or_else(|| anyhow!("inverse wire overflow"))?,
                value.inverse().unwrap_or_else(Fr::zero),
            )?;
        }
        cursor.finish()
    }
}

struct CalldataStream<'a> {
    reader: DiskReader<'a>,
    total_words: u64,
    consumed_words: u64,
}
impl<'a> CalldataStream<'a> {
    fn new(mut reader: DiskReader<'a>) -> Result<Self> {
        let total_words = reader.u64()?;
        Ok(Self {
            reader,
            total_words,
            consumed_words: 0,
        })
    }
    fn word(&mut self) -> Result<u32> {
        u32::try_from(
            self.reader
                .varint()
                .context("read serialized calldata word")?,
        )
        .context("serialized calldata word exceeds u32")
    }
    fn instruction(&mut self, start: u64) -> Result<Vec<u32>> {
        ensure!(
            start == self.consumed_words,
            "noncontiguous serialized calldata offset"
        );
        ensure!(
            start < self.total_words,
            "instruction calldata offset out of bounds"
        );
        let length = self.word()?;
        ensure!(
            (1..=MAX_INSTRUCTION_WORDS).contains(&(length as usize)),
            "invalid instruction calldata length"
        );
        let next = checked_sum(start, u64::from(length))?;
        ensure!(
            next <= self.total_words,
            "instruction exceeds serialized calldata word count"
        );
        let mut words = Vec::with_capacity(length as usize);
        words.push(length);
        for _ in 1..length {
            words.push(self.word()?);
        }
        self.consumed_words = next;
        Ok(words)
    }
    fn finish(&self) -> Result<()> {
        ensure!(
            self.consumed_words == self.total_words,
            "unused serialized calldata words"
        );
        ensure!(
            self.reader.position == self.reader.end,
            "trailing serialized calldata bytes"
        );
        Ok(())
    }
}

struct Words<'a> {
    words: &'a [u32],
    position: usize,
}
impl<'a> Words<'a> {
    fn new(words: &'a [u32], position: usize) -> Self {
        Self { words, position }
    }
    fn next(&mut self) -> Result<u32> {
        let value = *self
            .words
            .get(self.position)
            .ok_or_else(|| anyhow!("truncated instruction"))?;
        self.position += 1;
        Ok(value)
    }
    fn terms(&mut self, count: usize) -> Result<Vec<(u32, u32)>> {
        ensure!(
            count <= self.words.len().saturating_sub(self.position) / 2,
            "truncated linear expression"
        );
        (0..count)
            .map(|_| Ok((self.next()?, self.next()?)))
            .collect()
    }
    fn expression(&mut self) -> Result<Vec<(u32, u32)>> {
        let count = self.next()? as usize;
        self.terms(count)
    }
    fn finish(&self) -> Result<()> {
        ensure!(
            self.position == self.words.len(),
            "trailing instruction words"
        );
        Ok(())
    }
}

struct Metadata {
    public_count: usize,
    secret_count: usize,
    internal_count: usize,
    constraint_count: usize,
    blueprints: Vec<u64>,
    hints: HashMap<u32, String>,
}
impl Metadata {
    fn read(reader: DiskReader<'_>) -> Result<Self> {
        let mut cbor = Cbor { reader };
        let count = cbor.container(5)?;
        let mut metadata = Self {
            public_count: 0,
            secret_count: 0,
            internal_count: 0,
            constraint_count: 0,
            blueprints: Vec::new(),
            hints: HashMap::new(),
        };
        let mut r1cs = false;
        for _ in 0..count {
            let key = cbor.text(128)?;
            match key.as_str() {
                "Type" => {
                    ensure!(cbor.unsigned()? == 1, "constraint system is not R1CS");
                    r1cs = true;
                }
                "Public" => metadata.public_count = cbor.count_array()?,
                "Secret" => metadata.secret_count = cbor.count_array()?,
                "NbInternalVariables" => {
                    metadata.internal_count = usize::try_from(cbor.unsigned()?)?
                }
                "NbConstraints" => metadata.constraint_count = usize::try_from(cbor.unsigned()?)?,
                "Blueprints" => {
                    let count = cbor.container(4)?;
                    ensure!(count <= 64, "excessive blueprint count");
                    for _ in 0..count {
                        let (major, tag) = cbor.head()?;
                        ensure!(
                            major == 6 && [HINT_TAG, R1C_TAG, BATCH_INVERSE_TAG].contains(&tag),
                            "unsupported blueprint {tag}"
                        );
                        metadata.blueprints.push(tag);
                        cbor.skip(0)?;
                    }
                }
                "MHintsDependencies" => {
                    let count = cbor.container(5)?;
                    ensure!(count <= 64, "excessive hint count");
                    for _ in 0..count {
                        let id = u32::try_from(cbor.unsigned()?)?;
                        let name = cbor.text(512)?;
                        ensure!(
                            name == "github.com/consensys/gnark/std/math/bits.nBits"
                                || name
                                    == "github.com/consensys/gnark/constraint/solver.InvZeroHint",
                            "unsupported hint {name}"
                        );
                        ensure!(
                            metadata.hints.insert(id, name).is_none(),
                            "duplicate hint id"
                        );
                    }
                }
                "ScalarField" => ensure!(
                    cbor.text(128)?
                        == "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
                    "wrong R1CS scalar field"
                ),
                "GnarkVersion" => {
                    ensure!(cbor.text(64)?.starts_with("0.16."), "wrong gnark version")
                }
                "CommitmentInfo" => {
                    let (major, tag) = cbor.head()?;
                    ensure!(
                        major == 6 && tag == 5_309_737 && cbor.container(4)? == 0,
                        "batch circuit must have no commitments"
                    );
                }
                _ => cbor.skip(0)?,
            }
        }
        ensure!(
            r1cs && metadata.public_count > 0 && metadata.constraint_count > 0,
            "incomplete R1CS metadata"
        );
        ensure!(
            cbor.reader.position == cbor.reader.end,
            "trailing metadata bytes"
        );
        Ok(metadata)
    }
}

struct Cbor<'a> {
    reader: DiskReader<'a>,
}
impl Cbor<'_> {
    fn head(&mut self) -> Result<(u8, u64)> {
        let byte = self.reader.byte()?;
        let short = byte & 31;
        let value = match short {
            0..=23 => u64::from(short),
            24 => u64::from(self.reader.byte()?),
            25 => {
                let mut bytes = [0; 2];
                self.reader.read_exact(&mut bytes)?;
                u64::from(u16::from_be_bytes(bytes))
            }
            26 => {
                let mut bytes = [0; 4];
                self.reader.read_exact(&mut bytes)?;
                u64::from(u32::from_be_bytes(bytes))
            }
            27 => {
                let mut bytes = [0; 8];
                self.reader.read_exact(&mut bytes)?;
                u64::from_be_bytes(bytes)
            }
            _ => bail!("indefinite CBOR encoding is unsupported"),
        };
        Ok((byte >> 5, value))
    }
    fn unsigned(&mut self) -> Result<u64> {
        let (major, value) = self.head()?;
        ensure!(major == 0, "expected CBOR unsigned integer");
        Ok(value)
    }
    fn container(&mut self, expected: u8) -> Result<u64> {
        let (major, count) = self.head()?;
        ensure!(major == expected, "unexpected CBOR container");
        Ok(count)
    }
    fn text(&mut self, limit: usize) -> Result<String> {
        let size = self.container(3)?;
        ensure!(size <= limit as u64, "CBOR text exceeds bound");
        let mut bytes = vec![0; size as usize];
        self.reader.read_exact(&mut bytes)?;
        Ok(String::from_utf8(bytes)?)
    }
    fn count_array(&mut self) -> Result<usize> {
        let count = self.container(4)?;
        for _ in 0..count {
            self.skip(0)?;
        }
        Ok(usize::try_from(count)?)
    }
    fn skip(&mut self, depth: usize) -> Result<()> {
        ensure!(depth <= 64, "CBOR nesting limit exceeded");
        let (major, count) = self.head()?;
        match major {
            0 | 1 | 7 => {}
            2 | 3 => self.reader.advance(count)?,
            4 => {
                for _ in 0..count {
                    self.skip(depth + 1)?;
                }
            }
            5 => {
                for _ in 0..count {
                    self.skip(depth + 1)?;
                    self.skip(depth + 1)?;
                }
            }
            6 => self.skip(depth + 1)?,
            _ => bail!("unsupported CBOR value"),
        }
        Ok(())
    }
}

fn read_coefficients(mut reader: DiskReader<'_>) -> Result<Vec<Fr>> {
    let count = reader.u64()?;
    ensure!(
        count <= 1_048_576 && count.checked_mul(32) == Some(reader.end - reader.position),
        "invalid coefficient table length"
    );
    (0..count)
        .map(|_| {
            let mut bytes = [0; 32];
            reader.read_exact(&mut bytes)?;
            scalar_from_bytes(&bytes)
        })
        .collect()
}
fn scalar_from_bytes(bytes: &[u8; 32]) -> Result<Fr> {
    let mut limbs = [0u64; 4];
    for (limb, chunk) in limbs.iter_mut().zip(bytes.as_chunks::<8>().0.iter()) {
        *limb = u64::from_le_bytes(*chunk);
    }
    let integer = BigInt(limbs);
    ensure!(integer < Fr::MODULUS, "noncanonical Montgomery scalar");
    Ok(Fr::new_unchecked(integer))
}
fn scalar_bytes(value: Fr) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (chunk, limb) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(value.0 .0) {
        chunk.copy_from_slice(&limb.to_le_bytes());
    }
    bytes
}

struct DiskReader<'a> {
    file: &'a File,
    position: u64,
    end: u64,
    buffer: Box<[u8]>,
    buffer_start: u64,
    buffer_len: usize,
}
impl<'a> DiskReader<'a> {
    fn new(file: &'a File, start: u64, end: u64) -> Result<Self> {
        ensure!(
            start <= end && end <= file.metadata()?.len(),
            "invalid file section"
        );
        Ok(Self {
            file,
            position: start,
            end,
            buffer: vec![0; PAGE_BYTES].into_boxed_slice(),
            buffer_start: start,
            buffer_len: 0,
        })
    }
    fn advance(&mut self, count: u64) -> Result<()> {
        let next = checked_sum(self.position, count)?;
        ensure!(next <= self.end, "truncated file section");
        self.position = next;
        Ok(())
    }
    fn byte(&mut self) -> Result<u8> {
        let mut byte = [0];
        self.read_exact(&mut byte)?;
        Ok(byte[0])
    }
    fn u64(&mut self) -> Result<u64> {
        let mut bytes = [0; 8];
        self.read_exact(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }
    fn word(&mut self, width: u32) -> Result<u64> {
        if width == 64 {
            self.u64()
        } else {
            let mut bytes = [0; 4];
            self.read_exact(&mut bytes)?;
            Ok(u64::from(u32::from_le_bytes(bytes)))
        }
    }
    fn varint(&mut self) -> Result<u64> {
        let mut value = 0u64;
        for shift in (0..=63).step_by(7) {
            let byte = self.byte()?;
            ensure!(shift < 63 || byte <= 1, "varint overflow");
            value |= u64::from(byte & 127) << shift;
            if byte & 128 == 0 {
                return Ok(value);
            }
        }
        bail!("unterminated varint")
    }
}
impl Read for DiskReader<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        if bytes.is_empty() || self.position == self.end {
            return Ok(0);
        }
        if self.position < self.buffer_start
            || self.position >= self.buffer_start + self.buffer_len as u64
        {
            let wanted = self.buffer.len().min((self.end - self.position) as usize);
            self.buffer_len = self
                .file
                .read_at(&mut self.buffer[..wanted], self.position)?;
            self.buffer_start = self.position;
            if self.buffer_len == 0 {
                return Ok(0);
            }
        }
        let offset = (self.position - self.buffer_start) as usize;
        let count = bytes.len().min(self.buffer_len - offset);
        bytes[..count].copy_from_slice(&self.buffer[offset..offset + count]);
        self.position += count as u64;
        Ok(count)
    }
}

/// Decode ronanh/intcomp's unsigned delta-bitpacking/varbyte stream by block.
fn decode_column(
    reader: &mut DiskReader<'_>,
    width: u32,
    mut emit: impl FnMut(u64) -> Result<()>,
) -> Result<u64> {
    let compressed_words = reader.u64()?;
    if compressed_words == 0 {
        return Ok(0);
    }
    let word_bytes = u64::from(width / 8);
    let end = checked_sum(
        reader.position,
        compressed_words
            .checked_mul(word_bytes)
            .ok_or_else(|| anyhow!("integer stream length overflow"))?,
    )?;
    ensure!(
        end <= reader.end && compressed_words >= 2,
        "truncated compressed integer stream"
    );
    let content_end = end - word_bytes;
    let mut total = 0u64;
    while reader.position < content_end {
        let start = reader.position;
        let first = reader.word(width)?;
        let (count, encoded_words) = if width == 32 {
            (first, reader.word(width)?)
        } else {
            (first & 0xffff_ffff, first >> 32)
        };
        let block_end = checked_sum(
            start,
            encoded_words
                .checked_mul(word_bytes)
                .ok_or_else(|| anyhow!("integer block overflow"))?,
        )?;
        ensure!(
            count > 0 && block_end <= content_end && block_end >= reader.position,
            "invalid compressed block header"
        );
        let threshold = if width == 32 { 128 } else { 256 };
        if count < threshold {
            let mut previous = 0u64;
            let mut delta = 0u64;
            let mut shift = 0u32;
            let mut emitted = 0;
            while reader.position < block_end {
                let word = reader.word(width)?;
                for offset in (0..width).step_by(8).rev() {
                    if emitted == count {
                        continue;
                    }
                    let byte = (word >> offset) as u8;
                    ensure!(
                        shift < width && (shift < 63 || byte & 127 <= 1),
                        "integer delta overflow"
                    );
                    delta |= u64::from(byte & 127) << shift;
                    if byte & 128 == 0 {
                        previous = mask_width(previous.wrapping_add(delta), width);
                        emit(previous)?;
                        emitted += 1;
                        delta = 0;
                        shift = 0;
                    } else {
                        shift += 7;
                    }
                }
            }
            ensure!(emitted == count, "truncated variable-byte integers");
        } else {
            ensure!(count % threshold == 0, "invalid packed integer count");
            let mut previous = reader.word(width)?;
            for _ in 0..count / threshold {
                let header = reader.word(width)?;
                for group in 0..4 {
                    let shift = 24 - group * 8;
                    let bits = ((header >> shift) & 127) as u32;
                    let zigzag = ((header >> (shift + 7)) & 1) != 0;
                    ensure!(bits <= width, "invalid packed integer width");
                    let mut packed = Vec::with_capacity(bits as usize);
                    for _ in 0..bits {
                        packed.push(reader.word(width)?);
                    }
                    for index in 0..width {
                        let encoded = if bits == 0 {
                            0
                        } else {
                            let bit_offset = index * bits;
                            let slot = (bit_offset / width) as usize;
                            let offset = bit_offset % width;
                            let low = *packed
                                .get(slot)
                                .ok_or_else(|| anyhow!("packed integer index"))?;
                            let mut value = low >> offset;
                            if offset + bits > width {
                                value |= *packed
                                    .get(slot + 1)
                                    .ok_or_else(|| anyhow!("truncated packed integer"))?
                                    << (width - offset);
                            }
                            if bits < 64 {
                                value &= (1u64 << bits) - 1;
                            }
                            value
                        };
                        if bits == width {
                            previous = encoded;
                        } else {
                            let delta = if zigzag {
                                (encoded >> 1) ^ 0u64.wrapping_sub(encoded & 1)
                            } else {
                                encoded
                            };
                            previous = mask_width(previous.wrapping_add(delta), width);
                        }
                        emit(previous)?;
                    }
                }
            }
            ensure!(
                reader.position == block_end,
                "packed integer block length mismatch"
            );
        }
        total = total
            .checked_add(count)
            .ok_or_else(|| anyhow!("integer count overflow"))?;
    }
    ensure!(
        reader.position == content_end,
        "integer block exceeds stream"
    );
    let trailer = reader.word(width)?;
    ensure!(
        trailer > 0 && reader.position == end,
        "invalid compressed stream trailer"
    );
    Ok(total)
}
fn mask_width(value: u64, width: u32) -> u64 {
    if width == 32 {
        value & 0xffff_ffff
    } else {
        value
    }
}

struct Page {
    bytes: Box<[u8]>,
    dirty: bool,
    referenced: bool,
}
struct PagedFile {
    file: File,
    len: u64,
    capacity: usize,
    pages: HashMap<u64, Page>,
    clock: VecDeque<u64>,
}
impl PagedFile {
    fn create(path: &Path, len: u64, capacity: usize) -> Result<Self> {
        ensure!(capacity > 0, "page cache capacity must be positive");
        let file = create_scratch(path)?;
        file.set_len(len)?;
        Ok(Self {
            file,
            len,
            capacity,
            pages: HashMap::new(),
            clock: VecDeque::new(),
        })
    }
    fn open_existing(path: &Path, capacity: usize) -> Result<Self> {
        ensure!(capacity > 0, "page cache capacity must be positive");
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        let len = file.metadata()?.len();
        Ok(Self {
            file,
            len,
            capacity,
            pages: HashMap::new(),
            clock: VecDeque::new(),
        })
    }
    fn page(&mut self, id: u64) -> Result<&mut Page> {
        if !self.pages.contains_key(&id) {
            let offset = id
                .checked_mul(PAGE_BYTES as u64)
                .ok_or_else(|| anyhow!("page offset overflow"))?;
            ensure!(offset < self.len, "page exceeds scratch length");
            let valid = (self.len - offset).min(PAGE_BYTES as u64) as usize;
            let mut bytes = self.buffer_for_miss()?;
            self.file.read_exact_at(&mut bytes[..valid], offset)?;
            self.pages.insert(
                id,
                Page {
                    bytes,
                    dirty: false,
                    referenced: true,
                },
            );
            self.clock.push_back(id);
        }
        let page = self
            .pages
            .get_mut(&id)
            .ok_or_else(|| anyhow!("missing loaded page"))?;
        page.referenced = true;
        Ok(page)
    }
    fn buffer_for_miss(&mut self) -> Result<Box<[u8]>> {
        if self.pages.len() < self.capacity {
            return Ok(vec![0; PAGE_BYTES].into_boxed_slice());
        }
        // Hits set one bit; misses advance the bounded clock instead of scanning
        // the full cache for an LRU minimum. An evicted page lends its allocation.
        loop {
            let candidate = self
                .clock
                .pop_front()
                .ok_or_else(|| anyhow!("empty page clock"))?;
            let page = self
                .pages
                .get_mut(&candidate)
                .ok_or_else(|| anyhow!("clock references missing page"))?;
            if page.referenced {
                page.referenced = false;
                self.clock.push_back(candidate);
                continue;
            }
            let evicted = self
                .pages
                .remove(&candidate)
                .ok_or_else(|| anyhow!("missing eviction page"))?;
            if evicted.dirty {
                self.write_page(candidate, &evicted.bytes)?;
            }
            return Ok(evicted.bytes);
        }
    }
    fn write_page(&self, id: u64, bytes: &[u8]) -> Result<()> {
        let offset = id * PAGE_BYTES as u64;
        let valid = (self.len - offset).min(PAGE_BYTES as u64) as usize;
        self.file.write_all_at(&bytes[..valid], offset)?;
        Ok(())
    }
    fn bytes<const N: usize>(&mut self, offset: u64) -> Result<[u8; N]> {
        ensure!(
            offset
                .checked_add(N as u64)
                .is_some_and(|end| end <= self.len),
            "scratch read out of bounds"
        );
        let mut bytes = [0; N];
        let mut copied = 0;
        while copied < N {
            let position = offset + copied as u64;
            let within = (position % PAGE_BYTES as u64) as usize;
            let count = (PAGE_BYTES - within).min(N - copied);
            let page = self.page(position / PAGE_BYTES as u64)?;
            bytes[copied..copied + count].copy_from_slice(
                page.bytes
                    .get(within..within + count)
                    .ok_or_else(|| anyhow!("page read bounds"))?,
            );
            copied += count;
        }
        Ok(bytes)
    }
    fn set_bytes(&mut self, offset: u64, bytes: &[u8]) -> Result<()> {
        ensure!(
            offset
                .checked_add(bytes.len() as u64)
                .is_some_and(|end| end <= self.len),
            "scratch write out of bounds"
        );
        let mut copied = 0;
        while copied < bytes.len() {
            let position = offset + copied as u64;
            let within = (position % PAGE_BYTES as u64) as usize;
            let count = (PAGE_BYTES - within).min(bytes.len() - copied);
            let page = self.page(position / PAGE_BYTES as u64)?;
            page.bytes
                .get_mut(within..within + count)
                .ok_or_else(|| anyhow!("page write bounds"))?
                .copy_from_slice(&bytes[copied..copied + count]);
            page.dirty = true;
            copied += count;
        }
        Ok(())
    }
    fn byte(&mut self, offset: u64) -> Result<u8> {
        Ok(self.bytes::<1>(offset)?[0])
    }
    fn set_byte(&mut self, offset: u64, value: u8) -> Result<()> {
        self.set_bytes(offset, &[value])
    }
    fn u32(&mut self, offset: u64) -> Result<u32> {
        Ok(u32::from_le_bytes(self.bytes(offset)?))
    }
    fn u64(&mut self, offset: u64) -> Result<u64> {
        Ok(u64::from_le_bytes(self.bytes(offset)?))
    }
    fn scalar(&mut self, index: u64) -> Result<Fr> {
        scalar_from_bytes(
            &self.bytes(
                index
                    .checked_mul(32)
                    .ok_or_else(|| anyhow!("scalar index overflow"))?,
            )?,
        )
    }
    fn set_scalar(&mut self, index: u64, value: Fr) -> Result<()> {
        self.set_bytes(
            index
                .checked_mul(32)
                .ok_or_else(|| anyhow!("scalar index overflow"))?,
            &scalar_bytes(value),
        )
    }
    fn flush(&mut self) -> Result<()> {
        for (&id, page) in &self.pages {
            if page.dirty {
                self.write_page(id, &page.bytes)?;
            }
        }
        for page in self.pages.values_mut() {
            page.dirty = false;
        }
        Ok(())
    }
}

/// Conservatively estimate additional disk space for one proof without solving.
/// The pinned source key already occupies disk and is not included. The caller
/// must additionally reserve filesystem overhead and operational headroom.
pub fn scratch_bytes(key_file: &File, cs_offset: u64, domain_size: u64) -> Result<u64> {
    ensure!(
        domain_size.is_power_of_two() && domain_size <= (1u64 << 28),
        "invalid BN254 FFT domain size"
    );
    let file_len = key_file.metadata()?.len();
    let mut outer = DiskReader::new(key_file, cs_offset, file_len)?;
    let payload_len = outer.u64()?;
    let version = [outer.u64()?, outer.u64()?, outer.u64()?];
    ensure!(
        version[0] == 0 && version[1] == 16,
        "unsupported gnark R1CS version {version:?}"
    );
    let payload_end = checked_sum(outer.position, payload_len)?;
    ensure!(payload_end <= file_len, "truncated R1CS payload");
    let lengths = [outer.u64()?, outer.u64()?, outer.u64()?, outer.u64()?];
    let instructions_start = checked_sum(outer.position, lengths[0])?;
    let calldata_start = checked_sum(instructions_start, lengths[1])?;
    let body_start = checked_sum(calldata_start, lengths[2])?;
    let coefficients_start = checked_sum(body_start, lengths[3])?;
    ensure!(
        coefficients_start <= payload_end,
        "R1CS sections exceed payload"
    );
    let metadata = Metadata::read(DiskReader::new(key_file, body_start, coefficients_start)?)?;
    let wires = u64::try_from(metadata.public_count)?
        .checked_add(u64::try_from(metadata.secret_count)?)
        .and_then(|count| count.checked_add(u64::try_from(metadata.internal_count).ok()?))
        .ok_or_else(|| anyhow!("wire count overflow"))?;
    ensure!(
        wires <= u64::from(u32::MAX),
        "wire count exceeds gnark indices"
    );
    let constraints = u64::try_from(metadata.constraint_count)?;
    ensure!(
        constraints <= domain_size,
        "constraints exceed proving-key domain"
    );
    let mut instructions = DiskReader::new(key_file, instructions_start, calldata_start)?;
    let instruction_count = integer_column_count(&mut instructions)?;
    ensure!(
        instruction_count >= constraints && instruction_count <= checked_sum(constraints, wires)?,
        "invalid instruction count"
    );
    let mut calldata = DiskReader::new(key_file, calldata_start, body_start)?;
    let calldata_words = calldata.u64()?;
    let encoded_bytes = body_start - calldata.position;
    ensure!(
        calldata_words <= encoded_bytes
            && calldata_words
                .checked_mul(5)
                .is_some_and(|max| encoded_bytes <= max),
        "invalid calldata word count"
    );
    // Four independent columns, stored as u32/u32/u32/u64; scalar rows are
    // unpadded until the solver's temporary files and wire file are removed.
    let bytes = |count: u64, width: u64| {
        count
            .checked_mul(width)
            .ok_or_else(|| anyhow!("scratch byte count overflow"))
    };
    let solver_peak = bytes(instruction_count, 20)?
        .checked_add(bytes(wires, 33)?)
        .and_then(|total| total.checked_add(constraints.checked_mul(96)?))
        .ok_or_else(|| anyhow!("solver scratch length overflow"))?;
    Ok(solver_peak.max(bytes(domain_size, 96)?))
}

/// Count intcomp values from block headers only; do not decompress their data.
fn integer_column_count(reader: &mut DiskReader<'_>) -> Result<u64> {
    let compressed_words = reader.u64()?;
    if compressed_words == 0 {
        return Ok(0);
    }
    ensure!(compressed_words >= 2, "truncated compressed integer stream");
    let encoded_bytes = compressed_words
        .checked_mul(4)
        .ok_or_else(|| anyhow!("integer stream length overflow"))?;
    let end = checked_sum(reader.position, encoded_bytes)?;
    ensure!(end <= reader.end, "truncated compressed integer stream");
    let content_end = end - 4;
    let mut count = 0u64;
    let mut last_block_words = 0u64;
    while reader.position < content_end {
        let block_start = reader.position;
        let values = reader.word(32)?;
        let words = reader.word(32)?;
        ensure!(
            values > 0 && words >= 3 && (values < 128 || values.is_multiple_of(128)),
            "invalid integer block header"
        );
        let block_bytes = words
            .checked_mul(4)
            .ok_or_else(|| anyhow!("integer block length overflow"))?;
        let block_end = checked_sum(block_start, block_bytes)?;
        ensure!(
            block_end <= content_end && block_end >= reader.position,
            "integer block exceeds stream"
        );
        reader.advance(block_end - reader.position)?;
        count = checked_sum(count, values)?;
        last_block_words = words;
    }
    ensure!(
        reader.position == content_end && reader.word(32)? == last_block_words,
        "invalid compressed stream trailer"
    );
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
    fn directory() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "native-witness-test-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        path
    }
    fn decoded(width: u32, encoded: &[u64]) -> Vec<u64> {
        let directory = directory();
        let path = directory.join("column.bin");
        let mut file = create_scratch(&path).unwrap();
        file.write_all(&(encoded.len() as u64).to_le_bytes())
            .unwrap();
        for word in encoded {
            if width == 32 {
                file.write_all(&(*word as u32).to_le_bytes()).unwrap();
            } else {
                file.write_all(&word.to_le_bytes()).unwrap();
            }
        }
        let mut reader = DiskReader::new(&file, 0, file.metadata().unwrap().len()).unwrap();
        let mut decoded = Vec::new();
        let count = decode_column(&mut reader, width, |value| {
            decoded.push(value);
            Ok(())
        })
        .unwrap();
        assert_eq!(count as usize, decoded.len());
        fs::remove_dir_all(directory).unwrap();
        decoded
    }
    #[test]
    fn uint32_delta_blocks_and_wrapping_varints_follow_gnark_intcomp() {
        assert_eq!(
            decoded(
                32,
                &[128, 8, 0, 0x01010101, 0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff, 8]
            ),
            (0..128).collect::<Vec<_>>()
        );
        assert_eq!(decoded(32, &[128, 4, 123, 0, 4]), vec![123; 128]);
        assert_eq!(
            decoded(32, &[3, 4, 0x0103feff, 0xffff0f80, 4]),
            vec![1, 4, 2]
        );
    }
    #[test]
    fn uint64_start_calldata_offsets_decode_without_truncation() {
        let first = 1u64 << 40;
        assert_eq!(
            decoded(
                64,
                &[
                    (7 << 32) | 256,
                    first,
                    0x01010101,
                    u64::MAX - 1,
                    u64::MAX,
                    u64::MAX,
                    u64::MAX,
                    7
                ]
            ),
            (first..first + 256).collect::<Vec<_>>()
        );
    }
    #[test]
    fn field_rows_and_page_eviction_preserve_raw_montgomery_limbs() {
        let directory = directory();
        let path = directory.join("scalars.bin");
        let mut scalars = PagedFile::create(&path, PAGE_BYTES as u64 * 3, 1).unwrap();
        let index = PAGE_BYTES as u64 / 32;
        let expected = [Fr::from(7u64), -Fr::from(13u64), Fr::from(29u64)];
        for (page, value) in expected.into_iter().enumerate() {
            scalars.set_scalar(page as u64 * index, value).unwrap();
        }
        for (page, value) in expected.into_iter().enumerate() {
            assert_eq!(scalars.scalar(page as u64 * index).unwrap(), value);
        }
        scalars.flush().unwrap();
        let mut encoded = [0u8; 32];
        scalars
            .file
            .read_exact_at(&mut encoded, index * 32)
            .unwrap();
        assert_eq!(encoded, scalar_bytes(expected[1]));
        fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn generic_r1c_and_bits_hint_match_gnark_wire_semantics() {
        let directory = directory();
        let mut wires = PagedFile::create(&directory.join("wires.bin"), 8 * 32, 1).unwrap();
        let mut flags = PagedFile::create(&directory.join("flags.bin"), 8, 1).unwrap();
        let coefficients = [Fr::zero(), Fr::one()];
        let hints = HashMap::from([(
            41u32,
            "github.com/consensys/gnark/std/math/bits.nBits".into(),
        )]);
        let mut solver = Solver {
            wires: &mut wires,
            flags: &mut flags,
            coefficients: &coefficients,
            hints: &hints,
        };
        solver.assign(0, Fr::one()).unwrap();
        solver.assign(1, Fr::from(3u64)).unwrap();
        solver.assign(2, Fr::from(5u64)).unwrap();
        assert_eq!(
            solver.r1c(&[10, 1, 1, 1, 1, 1, 1, 2, 1, 3]).unwrap(),
            [Fr::from(3u64), Fr::from(5u64), Fr::from(15u64)]
        );
        solver.hint(&[8, 41, 1, 1, 1, 3, 4, 8]).unwrap();
        for index in 4..8 {
            assert_eq!(solver.wires.scalar(index).unwrap(), Fr::one());
        }
        assert!(solver.r1c(&[10, 1, 1, 1, 1, 1, 1, 1, 1, 3]).is_err());
        fs::remove_dir_all(directory).unwrap();
    }
}

#[cfg(test)]
mod scratch_tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT_FILE: AtomicU64 = AtomicU64::new(0);
    fn text(bytes: &mut Vec<u8>, value: &str) {
        assert!(value.len() < 24);
        bytes.push(0x60 + value.len() as u8);
        bytes.extend_from_slice(value.as_bytes());
    }
    fn fixture() -> (PathBuf, File) {
        let path = std::env::temp_dir().join(format!(
            "native-witness-scratch-estimate-{}-{}",
            std::process::id(),
            NEXT_FILE.fetch_add(1, Ordering::Relaxed)
        ));
        let mut body = vec![0xa5];
        text(&mut body, "Type");
        body.push(1);
        text(&mut body, "Public");
        body.push(0x82);
        text(&mut body, "1");
        text(&mut body, "p");
        text(&mut body, "Secret");
        body.push(0x80);
        text(&mut body, "NbInternalVariables");
        body.push(3);
        text(&mut body, "NbConstraints");
        body.push(4);
        let mut instructions = Vec::new();
        for _ in 0..3 {
            instructions.extend_from_slice(&4u64.to_le_bytes());
            for word in [4u32, 3, 0x00010101, 3] {
                instructions.extend_from_slice(&word.to_le_bytes());
            }
        }
        instructions.extend_from_slice(&3u64.to_le_bytes());
        for word in [(2u64 << 32) | 4, 0x000a0a0a80808080, 2] {
            instructions.extend_from_slice(&word.to_le_bytes());
        }
        let mut calldata = 40u64.to_le_bytes().to_vec();
        calldata.extend_from_slice(&[0u8; 40]);
        let mut file = create_scratch(&path).unwrap();
        for word in [
            32 + instructions.len() as u64 + calldata.len() as u64 + body.len() as u64 + 8,
            0,
            16,
            3,
            0,
            instructions.len() as u64,
            calldata.len() as u64,
            body.len() as u64,
        ] {
            file.write_all(&word.to_le_bytes()).unwrap();
        }
        file.write_all(&instructions).unwrap();
        file.write_all(&calldata).unwrap();
        file.write_all(&body).unwrap();
        file.write_all(&0u64.to_le_bytes()).unwrap();
        (path, file)
    }
    #[test]
    fn estimates_larger_of_solver_and_padded_fft_without_creating_spools() {
        let (path, file) = fixture();
        // Four instruction records, five wires and four unpadded rows; calldata is not spooled.
        assert_eq!(
            scratch_bytes(&file, 0, 4).unwrap(),
            4 * 20 + 5 * 33 + 4 * 96
        );
        assert_eq!(scratch_bytes(&file, 0, 8).unwrap(), 8 * 96);
        assert_eq!(scratch_bytes(&file, 0, 16).unwrap(), 16 * 96);
        assert!(scratch_bytes(&file, 0, 3).is_err());
        assert!(scratch_bytes(&file, 0, 2).is_err());
        assert!(scratch_bytes(&file, u64::MAX, 8).is_err());
        fs::remove_file(path).unwrap();
    }
}

#[cfg(test)]
mod clock_tests {
    use super::*;
    use std::{
        collections::HashSet,
        sync::atomic::{AtomicU64, Ordering},
    };
    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn clock_cache_bounds_reuses_buffers_and_preserves_dirty_cross_page_writes() {
        for capacity in [1, 2] {
            let directory = std::env::temp_dir().join(format!(
                "native-witness-clock-test-{}-{}",
                std::process::id(),
                NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&directory).unwrap();
            let path = directory.join("pages.bin");
            let len = PAGE_BYTES * 5 + 13;
            let mut expected = vec![0u8; len];
            let mut cache = PagedFile::create(&path, len as u64, capacity).unwrap();
            let mut allocations = HashSet::new();
            for id in 0..capacity as u64 {
                allocations.insert(cache.page(id).unwrap().bytes.as_ptr());
            }
            for (offset, bytes) in [
                (PAGE_BYTES - 11, vec![0x37; 37]),
                (PAGE_BYTES * 3 + 1, vec![0xa4; 45]),
                (PAGE_BYTES * 5, vec![0xf3; 13]),
                (PAGE_BYTES * 2 - 7, vec![0x29; 19]),
            ] {
                cache.set_bytes(offset as u64, &bytes).unwrap();
                expected[offset..offset + bytes.len()].copy_from_slice(&bytes);
                assert!(cache.pages.len() <= capacity);
                assert_eq!(cache.clock.len(), cache.pages.len());
            }
            for page in [4, 1, 3, 0, 5, 2, 0, 3, 5, 1, 4] {
                let offset = page * PAGE_BYTES + 2;
                assert_eq!(
                    cache.bytes::<8>(offset as u64).unwrap().as_slice(),
                    &expected[offset..offset + 8]
                );
                assert!(cache.pages.len() <= capacity);
                assert_eq!(cache.clock.len(), cache.pages.len());
                assert_eq!(
                    cache.clock.iter().copied().collect::<HashSet<_>>().len(),
                    cache.clock.len()
                );
                assert!(cache
                    .pages
                    .values()
                    .all(|page| allocations.contains(&page.bytes.as_ptr())));
            }
            assert_eq!(
                cache
                    .bytes::<37>((PAGE_BYTES - 11) as u64)
                    .unwrap()
                    .as_slice(),
                &expected[PAGE_BYTES - 11..PAGE_BYTES + 26]
            );
            assert!(cache.bytes::<8>((len - 3) as u64).is_err());
            cache.flush().unwrap();
            assert_eq!(fs::read(&path).unwrap(), expected);
            assert!(PagedFile::open_existing(&path, 0).is_err());
            fs::remove_dir_all(directory).unwrap();
        }
    }
}

#[cfg(test)]
mod readiness_tests {
    use super::*;
    #[test]
    fn forward_r1c_and_hint_dependencies_fail_before_assigning_outputs() {
        let path = std::env::temp_dir().join(format!(
            "native-witness-readiness-test-{}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        let mut wires = PagedFile::create(&path.join("wires.bin"), 8 * 32, 1).unwrap();
        let mut flags = PagedFile::create(&path.join("flags.bin"), 8, 1).unwrap();
        let coefficients = [Fr::zero(), Fr::one()];
        let hints = HashMap::from([(
            41u32,
            "github.com/consensys/gnark/std/math/bits.nBits".into(),
        )]);
        let mut solver = Solver {
            wires: &mut wires,
            flags: &mut flags,
            coefficients: &coefficients,
            hints: &hints,
        };
        solver.assign(0, Fr::one()).unwrap();
        assert!(solver
            .r1c(&[10, 1, 1, 1, 1, 1, 1, 2, 1, 3])
            .unwrap_err()
            .to_string()
            .contains("more than one unsolved"));
        assert!(solver
            .hint(&[8, 41, 1, 1, 1, 1, 4, 8])
            .unwrap_err()
            .to_string()
            .contains("unsolved wire"));
        assert!(solver
            .batch_inverse(&[5, 1, 1, 1, 1], 4)
            .unwrap_err()
            .to_string()
            .contains("unsolved wire"));
        for wire in 1..8 {
            assert!(!solver.solved(wire).unwrap());
        }
        fs::remove_dir_all(path).unwrap();
    }
}

#[cfg(test)]
mod calldata_tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT_FILE: AtomicU64 = AtomicU64::new(0);
    fn encoded_file(words: u64, encoded: &[u8]) -> (PathBuf, File) {
        let path = std::env::temp_dir().join(format!(
            "native-witness-calldata-test-{}-{}",
            std::process::id(),
            NEXT_FILE.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = create_scratch(&path).unwrap();
        file.write_all(&words.to_le_bytes()).unwrap();
        file.write_all(encoded).unwrap();
        (path, file)
    }
    fn stream(file: &File) -> CalldataStream<'_> {
        CalldataStream::new(DiskReader::new(file, 0, file.metadata().unwrap().len()).unwrap())
            .unwrap()
    }
    #[test]
    fn serialized_instructions_require_contiguous_word_offsets() {
        let (path, file) = encoded_file(5, &[3, 9, 8, 2, 7]);
        let mut calldata = stream(&file);
        assert!(calldata
            .instruction(1)
            .unwrap_err()
            .to_string()
            .contains("noncontiguous"));
        assert_eq!(calldata.instruction(0).unwrap(), vec![3, 9, 8]);
        assert!(calldata
            .instruction(4)
            .unwrap_err()
            .to_string()
            .contains("noncontiguous"));
        assert!(calldata.finish().is_err());
        assert_eq!(calldata.instruction(3).unwrap(), vec![2, 7]);
        calldata.finish().unwrap();
        assert!(calldata.instruction(5).is_err());
        fs::remove_file(path).unwrap();
    }
    #[test]
    fn malformed_serialized_lengths_varints_and_trailing_bytes_are_rejected() {
        for (words, encoded) in [
            (2u64, vec![2, 0x80]),
            (2, vec![3, 1, 1]),
            (1, vec![0x80, 0x80, 0x80, 0x80, 0x10]),
            (1, vec![0]),
            (1, vec![0x80; 10]),
        ] {
            let (path, file) = encoded_file(words, &encoded);
            assert!(stream(&file).instruction(0).is_err());
            fs::remove_file(path).unwrap();
        }
        let (path, file) = encoded_file(2, &[2, 1, 0]);
        let mut calldata = stream(&file);
        assert_eq!(calldata.instruction(0).unwrap(), vec![2, 1]);
        assert!(calldata
            .finish()
            .unwrap_err()
            .to_string()
            .contains("trailing"));
        fs::remove_file(path).unwrap();
    }
}
