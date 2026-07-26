# T28: what zone binding validation should be

Analysis and recommendation. No behaviour is changed here.

The owner asked what behaviour we want if you look at the user flows, rather than
what is tidiest in the abstract. The three permissive behaviours recorded in
[transaction-b.md](transaction-b.md) under "T28, still adverse, with the rule
recorded" are the input.

## Recommendation

Take clause three first and on its own. Take clause one next, as conformance with
a rule the specification already states and the zone-authority rail already
enforces in both languages. Reshape clause two: normalize the explicit zero
rather than refuse it.

None of the three is load-bearing for a caller that exists today. I looked for
one in the SDK tests, the client tests, the program tests, and the TypeScript
fixtures, and found no caller that passes the zero zone address
(`Address::default()`) and none that passes `Some([0u8; 32])` as an output zone
data hash. The two occurrences of
`Some([0u8; 32])` in the transaction crate assert the opposite: that a dummy
carrying one is rejected.

## The specification is not silent

It settles clause one and it fixes the encoding that clause two turns on.

`docs/spec.md:508` gives `zone_hash = Poseidon(zone_data_hash,
pk_field(zone_program_id))`. Line 512 then draws the distinction this row is
about: an absent `zone_program_id` is `0`, and the spec says so in the form "not
`pk_field(0)`". Absence is the literal zero field, and `pk_field(0)` is named
only to exclude it. Line 514 adds that a non-zero `zone_data_hash` requires a
non-zero `zone_program_id`, which both languages already enforce
(`sdk-libs/transaction/src/utxo.rs:124` and `:136`,
`sdk-libs/ts/transaction/src/utxo.ts:54`).

What a bound zone is comes from `docs/spec.md:1236`: the `zone_config.program_id`
field is "read as the UTXO `zone_program_id`", and `zone_config` is an SPP-owned
account at the `zone_auth` PDA derived under the zone program, which has to sign.
So a bound zone is the id of a zone program that holds a `zone_config`. The
zero address is not one of those, and the specification does not describe it
as a zone.

`docs/spec.md:249` covers clause three by type discipline rather than by a zone
rule: a `[u8; 32]` in a Poseidon preimage is a BN254 field element. A value at or
above the modulus is not one.

## What the code computes

Read rather than inferred, because the encoding is the whole question.

Both languages map an absent zone to the zero field and a present zone to
`hash_field` of the address. Rust `program_id_field`
(`sdk-libs/transaction/src/utxo.rs:68-71`) returns `hash_field(id)` for `Some(id)`
and `[0u8; 32]` for `None`. TypeScript does the same at
`sdk-libs/ts/transaction/src/utxo.ts:57-59`, and the two agree on the zero
address for a reason worth stating: the zero address is the base58 string
`11111111111111111111111111111111`, which is truthy, so it takes the `hashField`
branch rather than the absent branch.

The consequence is that `Some(zero_address)` commits to `pk_field(0) =
Poseidon(0, 0)`, a specific non-zero field element, and not to the absence
marker. So a UTXO bound to the zero address is not an unbound UTXO with extra
steps. It is a third state, and `docs/spec.md:998` says how the circuit reads it:
a UTXO whose zone field is non-zero must equal the public `zone_program_id`,
while one at zero is exempt. `pk_field(0)` is non-zero, so such a UTXO is treated
as zone-bound and is held to the public zone.

That is what makes the zero zone unreachable on chain rather than merely
unusual. The public zone field is not caller-supplied. `merge_zone` reads it from
a signing `zone_config` (`programs/shielded-pool/src/instructions/merge_zone/account.rs:25`)
and hashes it with `solana_pk_hash`
(`.../merge_zone/processor.rs:62`). For a proof over `pk_field(0)` to verify,
there would have to be a `zone_config` whose `program_id` is the zero
address. There cannot be. `create_zone_config` requires the `zone_config` account
to sign (`programs/shielded-pool/src/instructions/zone_config/create.rs:30`) and
requires its address to equal `find_program_address([ZONE_AUTH_PDA_SEED],
program_id)` (`:33-38`, `:76-78`) before writing `cfg.program_id = data.program_id`
(`:69`). Only the program the PDA derives under can produce that signature
through `invoke_signed`, and the system program has no such path.

So a zero-zone build cannot settle on any rail, and refusing it at construction
cannot strand value that already exists.

## One precision point about the existing guards

The zone-authority rail already refuses the zero zone address in both
languages: `TransactionError::MissingZoneAuthorityProgramId`
(`sdk-libs/transaction/src/instructions/zone_authority.rs:56-58`,
`sdk-libs/transaction/src/error.rs:115-116`) and
`TRANSACTION_MISSING_ZONE_AUTHORITY_PROGRAM_ID`
(`sdk-libs/ts/transaction/src/instructions/builders.ts:556-586`), with a
cross-language oracle case in
`sdk-libs/ts/transaction/test/oracles/transaction-parity-v1.json`.

The circuit has a guard on the same rail, `AssertIsDifferent(c.ZoneProgramID, 0)`
at `prover/server/circuits/spp_transaction/circuit.go:219-221`, but it is not the
same test. The circuit compares the field element, and `pk_field(0)` is non-zero,
so the circuit would accept a zero-address zone that the SDK refuses. This
matters for how the recommendation is justified: the reason the zero address is
unreachable is the `zone_config` PDA requirement above, not the circuit
assertion. Anyone extending the guard should not cite `circuit.go:219-221` as the
chain-side equivalent, because it is not.

## The flows

Zone-bound UTXOs are constructed by whoever operates a zone: the zone program
itself before its CPI, and the relayer or service building the merge for it. The
`zone_program_id` such a caller holds comes from the zone it is acting for, known
statically or read from the `zone_config` account. Neither source yields the
zero address.

The one realistic client flow in the tree is
`sdk-libs/client/tests/merge_zone/steps.rs:88-96`, which passes a real zone
address and builds `output_zone_data_hash` as a 32-byte value with a single
non-zero low byte. It supplies a small canonical field element, which is what a
policy digest reduced into the field looks like.

For clause three, what the caller sees today is
`sdk-libs/keypair/src/hash.rs:6-8`: `poseidon` maps any hasher failure to
`KeypairError::Poseidon`, which reaches TypeScript as `TRANSACTION_KEYPAIR`. The
error names neither the field nor the call that supplied it, and it arrives when
the output is hashed rather than when the value is passed. Working back from it
means knowing that Poseidon rejects out-of-field limbs and then guessing which of
the several 32-byte values in the transaction was the bad one.

## Clause by clause

### Clause three, the out-of-field hash: take it, first

Refuse a zone data hash at or above the BN254 modulus where the caller supplies
it, with a named error. This refuses nothing that succeeds today, so it is not a
behaviour change and does not need to land in Rust before TypeScript for
divergence reasons. It converts a `TRANSACTION_KEYPAIR` raised at hashing time
into a named error raised at the supplying call.

Apply it wherever a caller hands over a zone data hash: the
`output_zone_data_hash` parameter of `MergeZone::new`, the
`SppProofOutputUtxo` zone builders, and `with_zone_data_hash` on inputs, with the
TypeScript counterparts `withZoneData`, `withZoneDataHash`, and the
`zoneDataHash` fields.

The same argument applies to the per-UTXO `data_hash`, which reaches Poseidon by
the same path and fails the same way. Widening the check to cover it costs one
more call site and turns the same late `TRANSACTION_KEYPAIR` into a named one.

### Clause one, the zero zone address: take it, as conformance

Refuse a `zone_program_id` equal to the zero address at `MergeZone::new` and
the output zone builders, with a named error.

This is a behaviour change in the narrow sense that a build which succeeds today
would fail, so it lands in Rust first and TypeScript second. The risk of breaking
a caller is as close to nil as this kind of change gets: no caller in the tree
passes it, and a build that did pass it could not settle, because no `zone_config`
can name the system program. The change moves a proof-verification failure the
caller would reach anyway to the call that caused it.

Framing matters for the ruling. This is not a tidiness argument. The
specification says a bound zone is a `zone_config.program_id`, the zone-authority
rail already refuses the zero address in both languages, and `merge_zone` and the
output builders are the gap in a rule the codebase otherwise keeps.

### Clause two, the explicit zero hash: normalize rather than refuse

This is the weakest of the three, and I recommend a different shape from the one
recorded in transaction-b.md.

The mechanism is `sdk-libs/transaction/src/instructions/types.rs:124`, which
takes `spend.zone_data_hash.unwrap_or_default()`, so `Some([0u8; 32])` and `None`
reach the commitment as the same value. The prepared struct keeps them apart
while the commitment cannot, and that gap is the actual defect.

Refusing `Some([0u8; 32])` closes it in the direction that costs a caller more. A
zone that computes a policy digest generically and passes it through would have
to special-case the empty digest before calling. That caller shape is plausible
rather than hypothetical: the zone-deposit fixtures already use `[u8; 32]` zero
as the no-zone-data value in a fixed-width struct
(`program-tests/zone-test-program/tests/steps/zone_deposit.rs:46`, alongside
`zone_data: Vec::new()`), so an adapter from that struct to the `Option` API
lands on `Some([0u8; 32])` without meaning anything by it.

Normalizing `Some([0u8; 32])` to `None` at construction closes the same gap and
refuses nothing. The prepared value then agrees with the commitment, which is
what was wrong. No commitment moves, because the committed field was already
zero.

The argument on the other side, which the owner should weigh rather than have me
settle: the SDKs already refuse an explicit zero rather than normalize it in the
canonical-dummy check. A dummy carrying `zone_data_hash: Some([0u8; 32])` is
rejected with field `zone_data_hash`
(`sdk-libs/transaction/src/instructions/types.rs:79-80` and the test at
`:209-211`, mirrored at `sdk-libs/ts/transaction/src/utxo.ts:284`), even though
its committed value would be identical to a canonical dummy's. So refusing would
be consistent with that rule, and normalizing would leave the SDK doing two
different things with the same input in two places.

I still prefer normalizing, because the dummy rule exists to catch a caller who
built a dummy wrong, where masking the mistake would be the harm, and no
equivalent mistake is being masked on a real output. If the owner prefers
consistency over caller cost, refusing is defensible and the dummy rule is the
precedent to cite.

## Sequencing

Clause three is separable and can be taken alone, in either language first.

Clauses one and two change what the constructors accept, so they land in Rust
first and are ported after, to avoid the divergence this queue has recorded on
other rows where TypeScript was tightened alone.

Clause two should not block clause one. Clause one has a specification behind it
and a matching rule on a sibling rail; clause two is an API-shape decision with a
genuine trade-off and is the one of the three most worth leaving open.
