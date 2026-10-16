use super::CircuitVar;

/// A circuit's result and its binding to the proof's public inputs.
///
/// Supported outputs are `()` (no public inputs) and every [`PublicHashOutput`]
/// (one public input, the public hash). The binding is sealed so the SDK controls
/// the allocation and constraint rules for each supported output.
pub trait CircuitOutput: private::Binding {}

impl CircuitOutput for () {}

impl<T: PublicHashOutput> CircuitOutput for T {}

/// An output whose public hash is the proof's one public input. The output only
/// names the hash; the SDK allocates the public input and constrains the two
/// equal.
pub trait PublicHashOutput: Sized {
    fn public_hash(&self) -> &CircuitVar;
}

#[cfg(feature = "client")]
pub(crate) use private::Binding;

mod private {
    use ark_bn254::Fr;

    use super::PublicHashOutput;
    use crate::{
        circuit::{labels, value, CircuitSystem, CircuitVar},
        CircuitError,
    };

    pub trait Binding: Sized {
        type Statement: Copy + Default;
        const PUBLIC_INPUTS: usize;

        fn statement(self) -> Result<Self::Statement, CircuitError>;
        fn constrain(
            cs: &CircuitSystem,
            statement: &Self::Statement,
            run: impl FnOnce() -> Result<Self, CircuitError>,
        ) -> Result<(), CircuitError>;
    }

    impl Binding for () {
        type Statement = ();
        const PUBLIC_INPUTS: usize = 0;

        fn statement(self) -> Result<(), CircuitError> {
            Ok(self)
        }

        fn constrain(
            _cs: &CircuitSystem,
            _statement: &(),
            run: impl FnOnce() -> Result<Self, CircuitError>,
        ) -> Result<(), CircuitError> {
            run()
        }
    }

    impl<T: PublicHashOutput> Binding for T {
        type Statement = Fr;
        const PUBLIC_INPUTS: usize = 1;

        fn statement(self) -> Result<Fr, CircuitError> {
            Ok(value(self.public_hash())?.into())
        }

        fn constrain(
            cs: &CircuitSystem,
            statement: &Fr,
            run: impl FnOnce() -> Result<Self, CircuitError>,
        ) -> Result<(), CircuitError> {
            // The public hash must be allocated before `run` instantiates any
            // private input: it is variable 1 of every program's R1CS, and
            // moving it changes every proving key.
            let public_input = CircuitVar::input(cs, || Ok(*statement))?;
            let checked = run()?;
            labels::check(
                cs,
                "the circuit's public hash is not the proof's public input",
                || checked.public_hash().enforce_equal(&public_input),
            )
        }
    }
}
