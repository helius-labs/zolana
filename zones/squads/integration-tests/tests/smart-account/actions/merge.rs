//! Auto-merge assertion step.
//!
//! The background settlement crank consolidates any owner's fragmented spendable
//! UTXOs of an asset into a single UTXO tagged with the owner's account view tag.
//! This step polls the backend until that consolidation has happened, asserting the
//! account ends with exactly one UTXO of the expected summed amount.
