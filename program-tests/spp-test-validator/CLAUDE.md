### Local-validator tests

Run `just test-spp-validator`.

`tests/lifecycle.rs` contains ordinary serial Rust tests. `harness.rs` owns the
validator, Photon, actors, and shared state; `actions/` contains the reusable
instruction operations. Actions use the client SDK, and functional assertions
live in `program-tests/test-utils/src/test_validator_asserts`.

Keep failure checks exact, compare complete deterministic state, and assert every
observable part of transitions containing random values. Avoid dead code and
duplicate helpers.
