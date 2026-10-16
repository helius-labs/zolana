use ark_bn254::Fr;
use ark_ff::{BigInt, BigInteger, PrimeField};

#[cfg(feature = "setup")]
use super::synthesis::{CircuitMatrices, R1csMatrices};
#[cfg(feature = "setup")]
use crate::circuit::{labels, LabelKind, VariableRole};
use crate::{ProverError, ProverErrorKind};

const FIELD_BYTES: u32 = 32;

#[cfg(feature = "setup")]
pub(crate) fn r1cs(matrices: &R1csMatrices) -> Result<Vec<u8>, ProverError> {
    let variables = matrices.num_instance_variables + matrices.num_witness_variables;
    let wires: Vec<usize> = (0..variables).collect();
    r1cs_in_wire_order(matrices, &wires, 0, matrices.num_witness_variables)
}

/// Picus checks that the outputs are fixed once the inputs are, so the
/// witnesses gadgets allocate become the outputs, the proof inputs' witnesses
/// the private inputs, and the equality tests' inverse hints, free by design
/// when the sides are equal, come last where Picus leaves them unchecked.
#[cfg(feature = "setup")]
pub(crate) fn picus_r1cs(circuit: &CircuitMatrices) -> Result<Vec<u8>, ProverError> {
    let matrices = circuit.matrices();
    let instance = matrices.num_instance_variables;
    let (mut outputs, mut inputs, mut hints) = (Vec::new(), Vec::new(), Vec::new());
    for witness in 0..matrices.num_witness_variables {
        let group = match labels::allocation_of(circuit.labels(), witness).map(|label| label.kind) {
            Some(LabelKind::Allocation(VariableRole::Constrained | VariableRole::Carried)) => {
                &mut inputs
            }
            Some(LabelKind::Allocation(VariableRole::Multiplier)) => &mut hints,
            _ => &mut outputs,
        };
        group.push(instance + witness);
    }
    let wires: Vec<usize> = core::iter::once(0)
        .chain(outputs.iter().copied())
        .chain(1..instance)
        .chain(inputs.iter().copied())
        .chain(hints)
        .collect();
    r1cs_in_wire_order(matrices, &wires, outputs.len(), inputs.len())
}

/// `wires[wire]` is the variable at `wire`; the label of each wire is its
/// variable, so a wire Picus reports maps back to the circuit's labels.
#[cfg(feature = "setup")]
fn r1cs_in_wire_order(
    matrices: &R1csMatrices,
    wires: &[usize],
    outputs: usize,
    private_inputs: usize,
) -> Result<Vec<u8>, ProverError> {
    let variables = wires.len();
    let mut wire_of = vec![0; variables];
    for (wire, variable) in wires.iter().enumerate() {
        *wire_of
            .get_mut(*variable)
            .ok_or(ProverErrorKind::ExportFailed(
                "a wire holds a variable the circuit does not have",
            ))? = wire;
    }

    let mut header = Vec::new();
    header.extend_from_slice(&FIELD_BYTES.to_le_bytes());
    header.extend_from_slice(&Fr::MODULUS.to_bytes_le());
    put_u32(&mut header, variables)?;
    put_u32(&mut header, outputs)?;
    put_u32(
        &mut header,
        matrices.num_instance_variables.saturating_sub(1),
    )?;
    put_u32(&mut header, private_inputs)?;
    header.extend_from_slice(&u64_of(variables)?.to_le_bytes());
    put_u32(&mut header, matrices.num_constraints)?;

    let complete = [matrices.a(), matrices.b(), matrices.c()]
        .iter()
        .all(|rows| rows.len() == matrices.num_constraints);
    if !complete {
        return Err(ProverErrorKind::ExportFailed(
            "the constraint matrices do not hold every constraint",
        )
        .into());
    }

    let mut constraints = Vec::new();
    let rows = matrices.a().iter().zip(matrices.b()).zip(matrices.c());
    for ((a, b), c) in rows {
        for row in [a, b, c] {
            put_u32(&mut constraints, row.len())?;
            for (coefficient, variable) in row {
                let wire = wire_of.get(*variable).ok_or(ProverErrorKind::ExportFailed(
                    "a constraint reads a variable no wire holds",
                ))?;
                put_u32(&mut constraints, *wire)?;
                constraints.extend_from_slice(&coefficient.into_bigint().to_bytes_le());
            }
        }
    }

    let mut labels = Vec::new();
    for variable in wires {
        labels.extend_from_slice(&u64_of(*variable)?.to_le_bytes());
    }

    binary_file(b"r1cs", 1, &[(1, &header), (2, &constraints), (3, &labels)])
}

pub(crate) fn wtns(assignment: &[Fr]) -> Result<Vec<u8>, ProverError> {
    let mut header = Vec::new();
    header.extend_from_slice(&FIELD_BYTES.to_le_bytes());
    header.extend_from_slice(&Fr::MODULUS.to_bytes_le());
    put_u32(&mut header, assignment.len())?;

    let mut values = Vec::new();
    for value in assignment {
        values.extend_from_slice(&value.into_bigint().to_bytes_le());
    }

    binary_file(b"wtns", 2, &[(1, &header), (2, &values)])
}

pub(crate) fn read_wtns(bytes: &[u8]) -> Result<Vec<Fr>, ProverError> {
    let invalid = ProverErrorKind::InvalidProofInputs;
    let [header, values] = Cursor::new(bytes, invalid).file(b"wtns", 2, [1, 2])?;

    let mut header = Cursor::new(
        header.ok_or(invalid("the header section is missing"))?,
        invalid,
    );
    if !header.over_scalar_field()? {
        return Err(invalid("the values belong to another proof system").into());
    }
    let count = header.usize()?;
    header.finish()?;

    let values = values.ok_or(invalid("the values section is missing"))?;
    if count.checked_mul(FIELD_BYTES as usize) != Some(values.len()) {
        return Err(invalid("the count does not match the values section").into());
    }
    Ok(values
        .as_chunks::<32>()
        .0
        .iter()
        .map(|chunk| field_element(chunk).ok_or(ProverErrorKind::ProofInputTooLarge))
        .collect::<Result<_, _>>()?)
}

#[cfg(feature = "setup")]
pub(crate) fn read_r1cs(bytes: &[u8]) -> Result<R1csMatrices, ProverError> {
    let invalid = ProverErrorKind::InvalidR1cs;
    let [header, constraints, _labels] = Cursor::new(bytes, invalid).file(b"r1cs", 1, [1, 2, 3])?;

    let mut header = Cursor::new(
        header.ok_or(invalid("the header section is missing"))?,
        invalid,
    );
    if !header.over_scalar_field()? {
        return Err(invalid("the constraints belong to another proof system").into());
    }
    let variables = header.usize()?;
    let public_outputs = header.usize()?;
    let public_inputs = header.usize()?;
    header.u32()?;
    header.u64()?;
    let constraint_count = header.usize()?;
    header.finish()?;
    let instance_variables = public_outputs
        .checked_add(public_inputs)
        .and_then(|public| public.checked_add(1))
        .filter(|instance| *instance <= variables)
        .ok_or(invalid("the public inputs outnumber the variables"))?;

    let mut body = Cursor::new(
        constraints.ok_or(invalid("the constraints section is missing"))?,
        invalid,
    );
    let mut matrices: [Vec<Vec<(Fr, usize)>>; 3] = Default::default();
    for _ in 0..constraint_count {
        for matrix in &mut matrices {
            let mut row = Vec::new();
            for _ in 0..body.usize()? {
                let variable = body.usize()?;
                if variable >= variables {
                    return Err(
                        invalid("a constraint reads a variable the r1cs does not have").into(),
                    );
                }
                let coefficient = field_element(&body.array()?)
                    .ok_or(invalid("a coefficient is not below the field modulus"))?;
                row.push((coefficient, variable));
            }
            matrix.push(row);
        }
    }
    body.finish()?;
    Ok(R1csMatrices::new(
        matrices,
        instance_variables,
        variables - instance_variables,
        constraint_count,
    ))
}

fn field_element(bytes: &[u8; 32]) -> Option<Fr> {
    let mut limbs = [0u64; 4];
    for (limb, bytes) in limbs.iter_mut().zip(bytes.as_chunks::<8>().0) {
        *limb = u64::from_le_bytes(*bytes);
    }
    Fr::from_bigint(BigInt::new(limbs))
}

struct Cursor<'a> {
    bytes: &'a [u8],
    invalid: fn(&'static str) -> ProverErrorKind,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8], invalid: fn(&'static str) -> ProverErrorKind) -> Self {
        Self { bytes, invalid }
    }

    fn file<const N: usize>(
        mut self,
        magic: &[u8; 4],
        version: u32,
        kinds: [u32; N],
    ) -> Result<[Option<&'a [u8]>; N], ProverError> {
        let invalid = self.invalid;
        if self.take(4)? != magic {
            return Err(invalid("the bytes are not of the expected file type").into());
        }
        if self.u32()? != version {
            return Err(invalid("the file version is not supported").into());
        }
        let mut sections = [None; N];
        for _ in 0..self.u32()? {
            let kind = self.u32()?;
            let size =
                usize::try_from(self.u64()?).map_err(|_| invalid("a section is too large"))?;
            let payload = self.take(size)?;
            let section = kinds
                .iter()
                .position(|known| *known == kind)
                .and_then(|index| sections.get_mut(index))
                .ok_or(invalid("the file has an unknown section"))?;
            if section.replace(payload).is_some() {
                return Err(invalid("a section is repeated").into());
            }
        }
        self.finish()?;
        Ok(sections)
    }

    fn over_scalar_field(&mut self) -> Result<bool, ProverError> {
        Ok(self.u32()? == FIELD_BYTES
            && self.take(FIELD_BYTES as usize)? == Fr::MODULUS.to_bytes_le().as_slice())
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], ProverError> {
        if count > self.bytes.len() {
            return Err((self.invalid)("the file ends early").into());
        }
        let (taken, rest) = self.bytes.split_at(count);
        self.bytes = rest;
        Ok(taken)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ProverError> {
        let invalid = self.invalid;
        Ok(self
            .take(N)?
            .try_into()
            .map_err(|_| invalid("the file ends early"))?)
    }

    fn u32(&mut self) -> Result<u32, ProverError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, ProverError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn usize(&mut self) -> Result<usize, ProverError> {
        let invalid = self.invalid;
        usize::try_from(self.u32()?).map_err(|_| invalid("a count is too large").into())
    }

    fn finish(&self) -> Result<(), ProverError> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err((self.invalid)("a section has trailing bytes").into())
        }
    }
}

fn binary_file(
    magic: &[u8; 4],
    version: u32,
    sections: &[(u32, &[u8])],
) -> Result<Vec<u8>, ProverError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(magic);
    bytes.extend_from_slice(&version.to_le_bytes());
    put_u32(&mut bytes, sections.len())?;
    for (kind, payload) in sections {
        bytes.extend_from_slice(&kind.to_le_bytes());
        bytes.extend_from_slice(&u64_of(payload.len())?.to_le_bytes());
        bytes.extend_from_slice(payload);
    }
    Ok(bytes)
}

fn put_u32(bytes: &mut Vec<u8>, value: usize) -> Result<(), ProverError> {
    let value = u32::try_from(value)
        .map_err(|_| ProverErrorKind::ExportTooLarge("an r1cs count does not fit in 32 bits"))?;
    bytes.extend_from_slice(&value.to_le_bytes());
    Ok(())
}

fn u64_of(value: usize) -> Result<u64, ProverError> {
    Ok(u64::try_from(value)
        .map_err(|_| ProverErrorKind::ExportTooLarge("an r1cs size does not fit in 64 bits"))?)
}
