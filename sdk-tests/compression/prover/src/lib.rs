mod read;

pub use read::ReadProofInputs;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitId {
    Read,
}

impl spr_gnark_ffi_prover::Circuit for CircuitId {
    const ALL: &'static [Self] = &[Self::Read];

    fn name(self) -> &'static str {
        match self {
            Self::Read => "read",
        }
    }
}

pub static PROVER: spr_gnark_ffi_prover::Prover<CircuitId> =
    spr_gnark_ffi_prover::prover!(concat!(env!("CARGO_MANIFEST_DIR"), "/../build/gnark"));
