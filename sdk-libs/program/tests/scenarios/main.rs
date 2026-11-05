//! Programs written against the circuit traits without the `spr-macros`
//! derives: each spells out its circuit types and its `ProofInput`,
//! `Placeholder` and `PublicInputs` impls. s13 is a flat state, s19 a state
//! with typed fields, s21 nested structs and arrays, and s50 a unique data
//! UTXO. The derive scenarios are in `sdk-libs/macros/tests/scenarios`.

mod shared;

mod s13_counter_create;
mod s19_typed_state_create;
mod s21_nested_array_state;
mod s50_unique_counter_create;
