mod read;

pub use read::ReadProofInputs;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitId {
    Read,
}

impl zolana_gnark_ffi_prover::Circuit for CircuitId {
    const ALL: &'static [Self] = &[Self::Read];

    fn name(self) -> &'static str {
        match self {
            Self::Read => "read",
        }
    }
}

pub static PROVER: zolana_gnark_ffi_prover::Prover<CircuitId> =
    zolana_gnark_ffi_prover::prover!(concat!(env!("CARGO_MANIFEST_DIR"), "/../build/gnark"));
