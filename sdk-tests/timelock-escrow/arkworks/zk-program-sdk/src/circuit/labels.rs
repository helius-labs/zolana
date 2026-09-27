use core::{any::TypeId, fmt, ops::Range, panic::Location};

use super::CircuitSystem;
use crate::CircuitError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LabelKind {
    Check,
    Scope,
    Allocation(VariableRole),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VariableRole {
    Constrained,
    Multiplier,
    Carried,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CircuitLabel {
    pub kind: LabelKind,
    pub text: &'static str,
    pub file: &'static str,
    pub line: u32,
    pub column: u32,
    pub rows: Range<usize>,
    pub private_variables: Range<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FailedConstraint {
    pub row: usize,
    pub label: Option<CircuitLabel>,
}

impl fmt::Display for CircuitLabel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} ({}:{})", self.text, self.file, self.line)
    }
}

impl fmt::Display for FailedConstraint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.label {
            Some(label) if label.kind == LabelKind::Check => {
                write!(formatter, "row {}: {label}", self.row)
            }
            Some(label) => write!(formatter, "row {}, inside {label}", self.row),
            None => write!(formatter, "row {}", self.row),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CircuitSize {
    pub constraints: usize,
    pub public_variables: usize,
    pub private_variables: usize,
}

impl fmt::Display for CircuitSize {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} constraints over {} public and {} private variables",
            self.constraints, self.public_variables, self.private_variables
        )
    }
}

#[derive(Default)]
struct ConstraintLabels(Vec<CircuitLabel>);

#[track_caller]
pub(crate) fn check<T>(
    cs: &CircuitSystem,
    text: &'static str,
    body: impl FnOnce() -> Result<T, CircuitError>,
) -> Result<T, CircuitError> {
    let location = Location::caller();
    let open = Open::new(LabelKind::Check, location, cs, text);
    let result = body().map_err(|error| error.restamp(location));
    open.close();
    result
}

#[track_caller]
pub(crate) fn allocate<T>(
    cs: &CircuitSystem,
    text: &'static str,
    role: VariableRole,
    body: impl FnOnce() -> T,
) -> T {
    let open = Open::new(LabelKind::Allocation(role), Location::caller(), cs, text);
    let result = body();
    open.close();
    result
}

#[track_caller]
pub(crate) fn mark(
    cs: &CircuitSystem,
    private_variables: Range<usize>,
    text: &'static str,
    role: VariableRole,
) {
    if cs.is_none() || private_variables.is_empty() {
        return;
    }
    let location = Location::caller();
    let rows = cs.num_constraints();
    push(
        cs,
        CircuitLabel {
            kind: LabelKind::Allocation(role),
            text,
            file: location.file(),
            line: location.line(),
            column: location.column(),
            rows: rows..rows,
            private_variables,
        },
    );
}

#[must_use]
pub(crate) struct Scope(Option<Open>);

impl Scope {
    #[track_caller]
    pub(crate) fn open(cs: &CircuitSystem, text: &'static str) -> Self {
        Self(Some(Open::new(
            LabelKind::Scope,
            Location::caller(),
            cs,
            text,
        )))
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        if let Some(open) = self.0.take() {
            open.close();
        }
    }
}

struct Open {
    kind: LabelKind,
    location: &'static Location<'static>,
    cs: CircuitSystem,
    text: &'static str,
    rows: usize,
    private_variables: usize,
}

impl Open {
    fn new(
        kind: LabelKind,
        location: &'static Location<'static>,
        cs: &CircuitSystem,
        text: &'static str,
    ) -> Self {
        Self {
            kind,
            location,
            cs: cs.clone(),
            text,
            rows: cs.num_constraints(),
            private_variables: cs.num_witness_variables(),
        }
    }

    fn close(self) {
        if self.cs.is_none() {
            return;
        }
        let label = CircuitLabel {
            kind: self.kind,
            text: self.text,
            file: self.location.file(),
            line: self.location.line(),
            column: self.location.column(),
            rows: self.rows..self.cs.num_constraints(),
            private_variables: self.private_variables..self.cs.num_witness_variables(),
        };
        if !label.rows.is_empty() || !label.private_variables.is_empty() {
            push(&self.cs, label);
        }
    }
}

fn push(cs: &CircuitSystem, label: CircuitLabel) {
    let Some(system) = cs.borrow() else {
        return;
    };
    let mut cache = system.cache_map.borrow_mut();
    let labels = cache
        .entry(TypeId::of::<ConstraintLabels>())
        .or_insert_with(|| Box::new(ConstraintLabels::default()));
    if let Some(labels) = labels.downcast_mut::<ConstraintLabels>() {
        labels.0.push(label);
    }
}

#[cfg(feature = "client")]
pub(crate) fn take(cs: &CircuitSystem) -> Vec<CircuitLabel> {
    cs.borrow()
        .and_then(|system| {
            system
                .cache_map
                .borrow_mut()
                .remove(&TypeId::of::<ConstraintLabels>())
        })
        .and_then(|labels| labels.downcast::<ConstraintLabels>().ok())
        .map(|labels| labels.0)
        .unwrap_or_default()
}

#[cfg(feature = "client")]
pub(crate) fn first_apart(
    setup: &[CircuitLabel],
    proof: &[CircuitLabel],
) -> Option<Box<CircuitLabel>> {
    setup
        .iter()
        .zip(proof)
        .find(|(setup, proof)| setup != proof)
        .map(|(_, proof)| proof)
        .or_else(|| proof.get(setup.len()))
        .or_else(|| setup.get(proof.len()))
        .cloned()
        .map(Box::new)
}

#[cfg(feature = "client")]
pub(crate) fn allocation_of(labels: &[CircuitLabel], variable: usize) -> Option<&CircuitLabel> {
    labels
        .iter()
        .rev()
        .filter(|label| {
            matches!(label.kind, LabelKind::Allocation(_))
                && label.private_variables.contains(&variable)
        })
        .max_by_key(|label| {
            (
                label.private_variables.start,
                core::cmp::Reverse(label.private_variables.end),
            )
        })
}

#[cfg(feature = "client")]
pub(crate) fn report(labels: &[CircuitLabel], row: usize) -> FailedConstraint {
    let innermost = |kind: LabelKind| {
        labels
            .iter()
            .rev()
            .filter(|label| label.kind == kind && label.rows.contains(&row))
            .max_by_key(|label| (label.rows.start, core::cmp::Reverse(label.rows.end)))
    };
    FailedConstraint {
        row,
        label: innermost(LabelKind::Check)
            .or_else(|| innermost(LabelKind::Scope))
            .cloned(),
    }
}
