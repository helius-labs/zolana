use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, Zero};

pub type Row = Vec<(Fr, usize)>;

const FIELD_SIZE: u32 = 32;

#[derive(Debug, PartialEq, Eq)]
pub struct R1csHeader {
    pub field_size: u32,
    pub prime: Vec<u8>,
    pub variables: usize,
    pub public_outputs: usize,
    pub public_inputs: usize,
    pub private_inputs: usize,
    pub labels: u64,
    pub constraints: usize,
}

impl R1csHeader {
    pub fn bn254(
        variables: usize,
        public_inputs: usize,
        private_inputs: usize,
        constraints: usize,
    ) -> Self {
        Self {
            field_size: FIELD_SIZE,
            prime: scalar_prime(),
            variables,
            public_outputs: 0,
            public_inputs,
            private_inputs,
            labels: u64::try_from(variables).expect("label count"),
            constraints,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct R1cs {
    pub header: R1csHeader,
    pub a: Vec<Row>,
    pub b: Vec<Row>,
    pub c: Vec<Row>,
    pub wire_labels: Vec<u64>,
}

impl R1cs {
    pub fn rows(&self) -> impl Iterator<Item = (&Row, &Row, &Row)> {
        self.a
            .iter()
            .zip(&self.b)
            .zip(&self.c)
            .map(|((a, b), c)| (a, b, c))
    }

    pub fn first_unsatisfied(&self, witness: &[Fr]) -> Option<usize> {
        assert_eq!(witness.len(), self.header.variables, "witness length");
        let evaluate = |row: &Row| {
            row.iter().fold(Fr::zero(), |sum, (coefficient, variable)| {
                sum + *coefficient * witness.get(*variable).expect("witness variable")
            })
        };
        self.rows()
            .position(|(a, b, c)| evaluate(a) * evaluate(b) != evaluate(c))
    }
}

pub fn scalar_prime() -> Vec<u8> {
    Fr::MODULUS.to_bytes_le()
}

pub fn read_r1cs(bytes: &[u8]) -> R1cs {
    let sections = read_sections(bytes, b"r1cs", 1);
    let mut header = Reader(section(&sections, 1));
    let field_size = header.u32();
    let header = R1csHeader {
        field_size,
        prime: header
            .take(usize::try_from(field_size).expect("field size"))
            .to_vec(),
        variables: header.usize(),
        public_outputs: header.usize(),
        public_inputs: header.usize(),
        private_inputs: header.usize(),
        labels: header.u64(),
        constraints: header.usize(),
    };

    let mut body = Reader(section(&sections, 2));
    let (mut a, mut b, mut c) = (Vec::new(), Vec::new(), Vec::new());
    for _ in 0..header.constraints {
        a.push(body.row());
        b.push(body.row());
        c.push(body.row());
    }
    assert!(body.0.is_empty(), "trailing constraint bytes");

    let mut labels = Reader(section(&sections, 3));
    let wire_labels = (0..header.variables).map(|_| labels.u64()).collect();
    assert!(labels.0.is_empty(), "trailing label bytes");

    R1cs {
        header,
        a,
        b,
        c,
        wire_labels,
    }
}

pub fn read_wtns(bytes: &[u8]) -> Vec<Fr> {
    let sections = read_sections(bytes, b"wtns", 2);
    let mut header = Reader(section(&sections, 1));
    assert_eq!(header.u32(), FIELD_SIZE, "wtns field size");
    assert_eq!(header.take(32), scalar_prime().as_slice(), "wtns prime");
    let count = header.usize();
    assert!(header.0.is_empty(), "trailing wtns header bytes");
    let mut values = Reader(section(&sections, 2));
    let witness = (0..count).map(|_| values.field()).collect();
    assert!(values.0.is_empty(), "trailing witness bytes");
    witness
}

pub fn write_wtns(witness: &[Fr]) -> Vec<u8> {
    let mut header = FIELD_SIZE.to_le_bytes().to_vec();
    header.extend_from_slice(&scalar_prime());
    header.extend_from_slice(&u32::try_from(witness.len()).expect("count").to_le_bytes());
    let values: Vec<u8> = witness
        .iter()
        .flat_map(|value| value.into_bigint().to_bytes_le())
        .collect();

    let mut bytes = b"wtns".to_vec();
    bytes.extend_from_slice(&2u32.to_le_bytes());
    bytes.extend_from_slice(&2u32.to_le_bytes());
    for (kind, payload) in [(1u32, header), (2, values)] {
        bytes.extend_from_slice(&kind.to_le_bytes());
        bytes.extend_from_slice(&u64::try_from(payload.len()).expect("size").to_le_bytes());
        bytes.extend_from_slice(&payload);
    }
    bytes
}

fn read_sections<'a>(bytes: &'a [u8], magic: &[u8], version: u32) -> Vec<(u32, &'a [u8])> {
    let mut reader = Reader(bytes);
    assert_eq!(reader.take(4), magic, "magic");
    assert_eq!(reader.u32(), version, "version");
    let count = reader.u32();
    let sections = (0..count)
        .map(|_| {
            let kind = reader.u32();
            let size = usize::try_from(reader.u64()).expect("section size");
            (kind, reader.take(size))
        })
        .collect();
    assert!(reader.0.is_empty(), "trailing bytes");
    sections
}

fn section<'a>(sections: &[(u32, &'a [u8])], kind: u32) -> &'a [u8] {
    sections
        .iter()
        .find(|(id, _)| *id == kind)
        .map(|(_, payload)| *payload)
        .expect("section")
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> &'a [u8] {
        let (taken, rest) = self.0.split_at_checked(count).expect("enough bytes");
        self.0 = rest;
        taken
    }

    fn u32(&mut self) -> u32 {
        u32::from_le_bytes(self.take(4).try_into().expect("u32"))
    }

    fn u64(&mut self) -> u64 {
        u64::from_le_bytes(self.take(8).try_into().expect("u64"))
    }

    fn usize(&mut self) -> usize {
        usize::try_from(self.u32()).expect("count")
    }

    fn field(&mut self) -> Fr {
        let bytes = self.take(32);
        let value = Fr::from_le_bytes_mod_order(bytes);
        assert_eq!(
            value.into_bigint().to_bytes_le(),
            bytes,
            "canonical field element"
        );
        value
    }

    fn row(&mut self) -> Row {
        let terms = self.usize();
        (0..terms)
            .map(|_| {
                let variable = self.usize();
                (self.field(), variable)
            })
            .collect()
    }
}
