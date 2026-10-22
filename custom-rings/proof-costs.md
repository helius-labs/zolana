# Proof costs

SPP and the ring program each verify their own proofs. A prover plans its
memory and proving time by the constraint count of each circuit family. Each
count is the R1CS constraint count of the circuit its key compiles.
`TestRingKeyCatalog` holds every ring key to the count
`prover/server/prover-test/ringkey/ringkey.go` pins.
`TestCircuitFingerprintsMatchRotatedKeys` and `TestMergeRingConstraintCounts`
hold the SPP counts. A circuit change that moves a count fails these tests. A
shape such as 2x4 names 2 inputs and 4 outputs.

## What each transaction proves

- A confidential transfer proves SPP's ring statement and one audit statement.
  A policy ring adds one policy statement.
- An anonymous transfer proves SPP's anonymous statement and one anonymous
  audit statement. A policy ring adds one policy statement.
- A delegate move proves SPP's ring authority statement, one audit statement
  and one delegate policy statement.
- An audited deposit proves one deposit statement, and SPP's `ring_deposit`
  takes no proof.
- A merge proves SPP's ring merge statement. A merge on an anonymous ring adds
  one merge disclosure statement.
- A key registration proves one register key statement. An application of the
  record queue proves one apply statement.

## SPP statements

The SPP statement grows mostly with the inputs, because each input proves its
leaf under a tree root. At the 2x4 shape the confidential ring statement has
57,708 constraints, 150 more than the default ring's 57,558. The anonymous
statement also verifies the owner's EdDSA signature and has 129,120 at 2x4. The
ring authority statement of a delegate move has 51,925 at 2x2.

A ring merge has 184,534 constraints at width 8, 531,750 at width 24 and
1,140,682 at width 52. At width 24 it costs 4,062 more than the default-ring
merge.

## Audit statements

A confidential transfer or a delegate move of 2 or 4 outputs uses the packed
audit layout, at 53,502 and 64,827 constraints. At 8 and 16 outputs the audit
proof also proves each output's delivery to its recipient. The delivered layout
costs 284,405 at 8 outputs and 524,519 at 16.

The anonymous audit statement also names the hidden sender to the auditor. Its
keys come in input classes per output count, and the outputs dominate the cost.
The 4-input class has 123,527 constraints at 2 outputs, 185,360 at 4 and
310,756 at 8. The 32-input class has 171,190 at 2 outputs, and the 1-input
class has 554,690 at 16. A transfer that spends a default-ring note uses the
entry key, which opens every spent note. The entry key has 138,067 constraints
at 2 outputs, 199,900 at 4 and 325,296 at 8.

## Policy statements

The policy circuit holds a record opening for the sender and for every output's
owner and asset, so its cost grows with the outputs. The member key of a
confidential or anonymous transfer has 48,455 constraints at 2 outputs, 82,348
at 4, 150,253 at 8 and 286,047 at 16. The delegate key also reopens the spent
notes and adds 1,353 constraints per input. It has 48,736 at 1x2 and 101,503 at
40x2.

`TestPolicyKeys` holds every member key of 2 or 4 outputs below 100,000
constraints and every delegate key of 2 or 4 outputs below 150,000. The wider
keys have no such bound. Transaction size limits the shapes each rail serves.
See [the shapes](README.md#shapes).

## Registry, deposits and merge disclosures

An application of one queued write proves 15,492 constraints. Any larger queue
uses the 16-write key, at 232,892. A key registration proves 36,991. An audited
deposit of up to eight entries proves 148,936. The merge disclosure of an
anonymous ring has 56,192 constraints at width 8 and 81,698 at width 24.
