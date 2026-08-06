// `withdraw_liquidity` shares the `pool_update` circuit with
// `deposit_liquidity` -- the proof-input construction (hashing, field
// encoding) is identical; only `delta`'s sign differs between the two
// instructions (see `PoolUpdateProofInputParams::delta`'s doc). Reused
// verbatim rather than duplicated.
pub use crate::instructions::deposit_liquidity::PoolUpdateProofInputParams;
