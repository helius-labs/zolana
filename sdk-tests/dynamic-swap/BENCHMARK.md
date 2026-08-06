# Dynamic Swap Benchmark

The previous numbers described the escrow-only implementation and do not apply
to the shared-liquidity transactions:

- `pool_update`: 2 inputs / 2 outputs;
- `create_escrow`: 1 input / 1 output;
- `settle`: 2 inputs / 3 outputs; and
- `refund_expired`: 1 input / 1 output.

Rebaseline compute units, proof time, and transaction size after the new
Mollusk fixtures are added. The generated circuits currently contain 7,270,
5,421, 10,072, and 2,627 constraints respectively.
