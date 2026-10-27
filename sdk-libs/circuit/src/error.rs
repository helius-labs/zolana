use core::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CircuitErrorKind {
    RuleBroken(&'static str),
    ValueTooLarge { bits: usize },
    BitWidthTooLarge { bits: usize },
    WrongLength { expected: usize, found: usize },
    TooManyItems { capacity: usize, found: usize },
    NonCanonicalField,
    InvalidInput(&'static str),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CircuitError {
    kind: CircuitErrorKind,
}

impl CircuitError {
    pub fn kind(&self) -> &CircuitErrorKind { &self.kind }

    pub fn broken_rule(&self) -> Option<&'static str> {
        match self.kind {
            CircuitErrorKind::RuleBroken(rule) => Some(rule),
            _ => None,
        }
    }
}

impl From<CircuitErrorKind> for CircuitError {
    fn from(kind: CircuitErrorKind) -> Self { Self { kind } }
}

impl fmt::Display for CircuitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            CircuitErrorKind::RuleBroken(rule) | CircuitErrorKind::InvalidInput(rule) => f.write_str(rule),
            kind => write!(f, "{kind:?}"),
        }
    }
}

impl std::error::Error for CircuitError {}
