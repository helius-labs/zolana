use super::{Bool, Bytes, CircuitVar, Uint};

/// A circuit's result and its binding to the proof's public inputs.
///
/// Supported outputs are `()` (no public inputs), every [`PublicHashOutput`]
/// (one public input, the public hash) and [`Public`] (each public value its
/// own public inputs). The binding is sealed so the SDK controls the allocation
/// and constraint rules for each supported output.
pub trait CircuitOutput: private::Binding {}

impl CircuitOutput for () {}

impl<T: PublicHashOutput> CircuitOutput for T {}

impl<T: PublicValue> CircuitOutput for Public<T> {}

/// An output whose public hash is the proof's one public input. The output only
/// names the hash; the SDK allocates the public input and constrains the two
/// equal.
pub trait PublicHashOutput: Sized {
    fn public_hash(&self) -> &CircuitVar;
}

/// An output whose value is bound directly as the proof's public inputs, in
/// the order [`PublicValue::public_inputs`] lists them. No hashing: the
/// verifier receives every public input itself.
#[derive(Clone, Debug)]
pub struct Public<T>(pub T);

/// A circuit value bound directly as public inputs.
///
/// Integers, bools and field values take one public input each. `Bytes<N>`
/// packs into 31-byte big-endian chunks, one public input per chunk, the same
/// packing as `zolana_hasher::primitives::pack_be`. Arrays and structs list
/// their items in order. `#[derive(PublicInputs)]` implements it for a struct.
pub trait PublicValue {
    const PUBLIC_INPUTS: usize;

    fn public_inputs(&self, inputs: &mut Vec<CircuitVar>);
}

impl PublicValue for CircuitVar {
    const PUBLIC_INPUTS: usize = 1;

    fn public_inputs(&self, inputs: &mut Vec<CircuitVar>) {
        inputs.push(self.clone());
    }
}

impl PublicValue for Bool {
    const PUBLIC_INPUTS: usize = 1;

    fn public_inputs(&self, inputs: &mut Vec<CircuitVar>) {
        inputs.push(self.var());
    }
}

impl<const BITS: usize> PublicValue for Uint<BITS> {
    const PUBLIC_INPUTS: usize = 1;

    fn public_inputs(&self, inputs: &mut Vec<CircuitVar>) {
        inputs.push(self.var());
    }
}

impl<const N: usize> PublicValue for Bytes<N> {
    const PUBLIC_INPUTS: usize = zolana_hasher::primitives::pack_be_chunks(N);

    fn public_inputs(&self, inputs: &mut Vec<CircuitVar>) {
        inputs.extend(self.packed());
    }
}

impl<T: PublicValue, const N: usize> PublicValue for [T; N] {
    const PUBLIC_INPUTS: usize = N * T::PUBLIC_INPUTS;

    fn public_inputs(&self, inputs: &mut Vec<CircuitVar>) {
        for item in self {
            item.public_inputs(inputs);
        }
    }
}

#[cfg(feature = "client")]
pub(crate) use private::Binding;

mod private {
    use ark_bn254::Fr;

    use ark_relations::gr1cs::SynthesisError;

    use super::{Public, PublicHashOutput, PublicValue};
    use crate::{
        circuit::{labels, value, CircuitSystem, CircuitVar},
        CircuitError, CircuitErrorKind,
    };

    pub trait Binding: Sized {
        type Statement: Clone + Default;
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

    impl<T: PublicValue> Binding for Public<T> {
        type Statement = Vec<Fr>;
        const PUBLIC_INPUTS: usize = T::PUBLIC_INPUTS;

        fn statement(self) -> Result<Vec<Fr>, CircuitError> {
            public_inputs(&self.0)?
                .iter()
                .map(|input| Ok(value(input)?.into()))
                .collect()
        }

        fn constrain(
            cs: &CircuitSystem,
            statement: &Vec<Fr>,
            run: impl FnOnce() -> Result<Self, CircuitError>,
        ) -> Result<(), CircuitError> {
            // The public inputs are allocated before `run` instantiates any
            // private input, so they are variables 1..=N of the R1CS.
            let allocated = (0..T::PUBLIC_INPUTS)
                .map(|index| {
                    CircuitVar::input(cs, || {
                        statement
                            .get(index)
                            .copied()
                            .ok_or(SynthesisError::AssignmentMissing)
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let public = run()?;
            let values = public_inputs(&public.0)?;
            labels::check(cs, "a public value is not its proof's public input", || {
                values
                    .iter()
                    .zip(&allocated)
                    .try_for_each(|(value, input)| value.enforce_equal(input))
            })
        }
    }

    /// The public inputs a value lists, checked against its declared count.
    fn public_inputs<T: PublicValue>(public: &T) -> Result<Vec<CircuitVar>, CircuitError> {
        let mut inputs = Vec::with_capacity(T::PUBLIC_INPUTS);
        public.public_inputs(&mut inputs);
        if inputs.len() != T::PUBLIC_INPUTS {
            return Err(CircuitErrorKind::WrongLength(
                "a public value lists another number of public inputs than it declares",
            )
            .into());
        }
        Ok(inputs)
    }
}
