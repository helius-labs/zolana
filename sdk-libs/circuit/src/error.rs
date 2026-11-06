use core::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CircuitErrorKind {
    RuleBroken(&'static str),
    /// A `require` or `require_eq` failed during native execution, at this
    /// source location.
    RequirementFailed {
        file: &'static str,
        line: u32,
        column: u32,
    },
    TooManyItems {
        capacity: usize,
        found: usize,
    },
    UnsupportedHashArity(usize),
    NonCanonicalField,
    InvalidInput(&'static str),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CircuitError {
    kind: CircuitErrorKind,
}

impl CircuitError {
    pub fn kind(&self) -> &CircuitErrorKind {
        &self.kind
    }

    pub fn broken_rule(&self) -> Option<&'static str> {
        match self.kind {
            CircuitErrorKind::RuleBroken(rule) => Some(rule),
            _ => None,
        }
    }
}

impl From<CircuitErrorKind> for CircuitError {
    fn from(kind: CircuitErrorKind) -> Self {
        Self { kind }
    }
}

impl fmt::Display for CircuitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            CircuitErrorKind::RuleBroken(rule) | CircuitErrorKind::InvalidInput(rule) => {
                f.write_str(rule)
            }
            CircuitErrorKind::RequirementFailed { file, line, column } => {
                write!(f, "requirement failed at {file}:{line}:{column}")
            }
            CircuitErrorKind::TooManyItems { capacity, found } => {
                write!(f, "{found} items exceed the capacity of {capacity}")
            }
            CircuitErrorKind::UnsupportedHashArity(arity) => {
                write!(f, "poseidon takes 1 to 12 inputs, received {arity}")
            }
            CircuitErrorKind::NonCanonicalField => f.write_str("noncanonical field encoding"),
        }
    }
}

impl core::error::Error for CircuitError {}
