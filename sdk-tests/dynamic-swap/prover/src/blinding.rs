/// Per-output-slot domains folded into the deterministic output-blinding
/// derivation (`Poseidon(blinding, domain)`). These MUST stay byte-for-byte in
/// sync with the Go copies in `prover/circuits/blinding/blinding.go` and
/// `prover/circuits/escrow_cancel/escrow_cancel.go`.
///
/// Only the taker-facing outputs derive deterministically (the taker
/// precomputes its payout/refund note at creation from the order blinding it
/// picked). The maker-side outputs (pool change, maker receipt, rebalance
/// outputs) use free maker-chosen blindings: the maker builds those proofs
/// itself.
pub const RECIPIENT_BLINDING_DOMAIN: u64 = 0x5354_4C52_4543_4950; // "STLRECIP"

/// The cancel refund output's blinding domain, distinct from the settle
/// recipient domain deriving from the same order blinding.
pub const CANCEL_REFUND_BLINDING_DOMAIN: u64 = 0x434E_4C52_4546_4E44; // "CNLREFND"
