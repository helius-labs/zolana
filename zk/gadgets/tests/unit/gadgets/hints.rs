//! The inverse hint of an equality test is the one private variable no row
//! fixes when the two sides are equal (`0 * hint = 0`): the free-variable
//! report tolerates it as a multiplier.

use zolana_program::{
    circuit::{CircuitLabel, LabelKind, VariableRole},
    testing::{FreeVariable, PrivateVariableReport},
};

pub const TEXT: &str = "the inverse hint of an equality test";

#[derive(Clone, Copy, Debug)]
pub struct Site {
    pub file: &'static str,
    pub line: u32,
    pub column: u32,
}

/// The hint of the equality test whose two rows end before `row`, held in
/// private variable `variable`.
pub fn inverse_hint(site: Site, row: usize, variable: usize) -> FreeVariable {
    FreeVariable {
        variable,
        role: VariableRole::Multiplier,
        allocation: Some(CircuitLabel {
            kind: LabelKind::Allocation(VariableRole::Multiplier),
            text: TEXT,
            file: site.file,
            line: site.line,
            column: site.column,
            rows: row..row,
            private_variables: variable..variable + 1,
        }),
    }
}

pub fn only_hints_tolerated(
    constraints: usize,
    private_variables: usize,
    tolerated: Vec<FreeVariable>,
) -> PrivateVariableReport {
    PrivateVariableReport {
        constraints,
        private_variables,
        free: vec![],
        tolerated,
    }
}
