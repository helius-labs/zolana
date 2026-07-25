# Are the new builder rejections stricter than the chain?

The TypeScript port added roughly 21 `TransactionError` variants to
`sdk-libs/transaction/src/error.rs`. Most name a rejection that already existed.
A subset refuses input the SDK previously accepted and sent. This document asks,
for each of those, whether the deployed program or the Go circuit refuses it too.

An SDK that is too lax builds a transaction that fails on chain, which is visible
and recoverable. An SDK that is too strict makes a legal operation impossible to
express, and nobody finds out until a user needs it. The second failure is the
one this review hunts.

Scope: only SDK code may change. `programs/`, `program-libs/`, `prover/`, and
`docs/spec.md` were read as the authority on what is enforced, never as
candidates for edits.

## Bottom line

Two findings are `OVER-STRICT`. One matters.

**`ZoneAuthorityWithdrawalNotAllowed` rejects deposits as well as withdrawals,
and neither the program nor the circuit rejects either.** The guard in
`sdk-libs/transaction/src/instructions/zone_authority.rs:72-80` fires on any
nonzero public amount in either direction. A positive public amount moves value
*into* the zone, so no reading of the rule the fixer was implementing covers it.
For the negative direction the picture is a genuine conflict rather than a plain
mistake: `docs/spec.md` states value cannot leave the zone here, while the
program settles a zone-authority public leg through the same code path as an
ordinary `transact` and the protocol's own instruction builder carries a
`withdrawal` field for it. That half needs an owner ruling. The deposit half does
not.

**`SplitInputIsDummy` rejects an input the circuit accepts**, because the circuit
skips the ownership check for a padding slot rather than failing on it. The
justification written for this variant is wrong. The input class it removes is a
zero-value no-op split, so the capability lost is empty and relaxing it buys
nobody anything. Recorded for accuracy, not for action.

Everything else in the list is `JUSTIFIED`. Three of the zone-authority rules
turn out to be enforced more exactly than the fixer claimed, by named circuit
tests. The two slot-ordinal rejections remove no input class the chain can see.

One correction to the reasoning recorded in `rust-sdk-changes.md`, independent of
any verdict: the commit message and the doc both assert that nobody signs a
zone-authority spend. Somebody does. The zone's `zone_config` PDA must sign, and
only the zone program can sign for it
(`programs/shielded-pool/src/instructions/zone_transact/account.rs:28-38`). The
UTXO *owners* do not sign, which is the accurate form of the claim. The zone
binding is not the sole containment; it sits behind a program signature and the
zone's own policy.

## Verdicts

| Variant | Chain also rejects it | Verdict |
| --- | --- | --- |
| `MissingZoneAuthorityProgramId` | Yes, circuit `circuit.go:219-221` | `JUSTIFIED` |
| `ZoneAuthorityInputZoneMismatch` | Yes, circuit `inputs.go:28-40, 70` | `JUSTIFIED` |
| `ZoneAuthorityOutputZoneMismatch` | Yes, circuit `inputs.go:28-40` via `outputs.go:17` | `JUSTIFIED` |
| `ZoneAuthorityWithdrawalNotAllowed` | No | `OVER-STRICT` (deposit half); `UNDETERMINED` (withdrawal half) |
| `SplitInputIsDummy` | No | `OVER-STRICT`, empty capability |
| `SplitInputOwnerMismatch` | Yes, circuit `inputs.go:100-104` | `JUSTIFIED` |
| `SplitInputNullifierKeyMismatch` | Yes, circuit `inputs.go:100-104, 140-147` | `JUSTIFIED` |
| `WithdrawalAssetMismatch` | Yes, both directions, program `transact/account.rs:41-77` plus the external-data hash | `JUSTIFIED` |
| `OutputSlotOverflow` | Unreachable; no input class removed | `JUSTIFIED` |
| `ExcessOutputSlots` | Not chain-visible; the surplus never reached the instruction | `JUSTIFIED` |
| `MissingZoneProgramId` (`6882ca25`) | Yes, circuit `inputs.go:35, 47-50` | `JUSTIFIED` |
| `ReservedAssetId(0)` (`6882ca25`) | Yes, spec reserves it; the counter starts at `2` | `JUSTIFIED` |
| `NoncanonicalDummyInput` (`bc55a9b9`) | Yes, circuit `inputs.go:61-67` | `JUSTIFIED` |
| `from_utxos` cardinality and owner rules (`7c697c2c`) | Not chain-visible | `JUSTIFIED` |
| `WalletBalanceOverflow`, `InvalidTagWindow` (`3d444a6c`) | Not chain-visible | `JUSTIFIED` |

## Claim 1: zone authority requires a nonzero zone program id

Variant: `MissingZoneAuthorityProgramId`
(`sdk-libs/transaction/src/instructions/zone_authority.rs:52-54`).

Verdict: `JUSTIFIED`.

The zone-authority circuit constrains the public zone field to be nonzero and
nothing else does:

```go
if c.ZoneAuthority {
    api.AssertIsDifferent(c.ZoneProgramID, 0)
}
```

That is `prover/server/circuits/spp_transaction/circuit.go:219-221`, and it is
the only place the constraint appears. The confidential variants take the
opposite branch two lines above (`circuit.go:216-218`, `AssertIsEqual(c.ZoneProgramID, 0)`).
A named test covers it: `TestZoneAuthorityCircuitRejectsZeroZoneProgramID`
(`prover/server/circuits/spp_transaction/zone_authority_test.go:76-86`) asserts
`SolvingFailed` for a zero public zone.

The removed default-zone exemption was load-bearing in the sense that removing it
was correct. `docs/spec.md:983` (in the committed tree) says so directly: the
public `zone_program_id` is pinned non-zero and every non-dummy input and output
must equal it, strict binding, no zero exemption. A zero zone here is not a
legitimate default-zone case, it is an unprovable one.

One caveat that does not change the verdict. The SDK compares
`zone_program_id == Address::default()`, an all-zero Solana address, while the
circuit compares a field element that the program derives with
`solana_pk_hash` (`zone_authority_transact/processor.rs:43`). The hash of the
all-zero address is not zero, so the two guards are not the same test.
It costs nothing, because a zone config for the all-zero program id cannot
exist: the config is an SPP-owned account at the `zone_auth` PDA derived under
the zone program, and the program reads the zone id out of that validated
account rather than from instruction data
(`zone_transact/account.rs:31-35`).

## Claim 2: every zone-authority input and output is bound to the pinned zone

Variants: `ZoneAuthorityInputZoneMismatch`, `ZoneAuthorityOutputZoneMismatch`
(`zone_authority.rs:60-62` and `64-71`).

Verdict: `JUSTIFIED`, and enforced more exactly than the fixer claimed.

The circuit carries a `strictZone` flag that is set from `ZoneAuthority` and from
nothing else. `prover/server/circuits/spp_transaction/inputs.go:28-40`:

```go
func constrainProgramZone(api frontend.API, notDummy frontend.Variable, u UtxoCircuitFields, zone, strictZone bool, zoneProgramID frontend.Variable) {
	if zone {
		if strictZone {
			assertEqualWhen(api, notDummy, u.ZoneProgramID, zoneProgramID)
		} else {
			bindIfSet(api, notDummy, u.ZoneProgramID, zoneProgramID)
		}
```

The `strictZone` branch is an unconditional equality for every non-dummy UTXO.
The other branch, which the ordinary `zone_transact` takes, is `bindIfSet`
(`inputs.go:42-45`): it binds only when the field is already nonzero, which is
exactly the default-zone exemption the authority variant must not have. Inputs
reach this through `constrainInput` (`inputs.go:70`), outputs through
`constrainOutput` (`outputs.go:17`), both passing `zoneAuthority` as
`strictZone`.

Two named tests pin both halves:
`TestZoneAuthorityCircuitRejectsDefaultZoneInput`
(`zone_authority_test.go:64-74`) and
`TestZoneAuthorityCircuitRejectsDefaultZoneOutput`
(`zone_authority_test.go:88-99`).

The reasoning the fixer wrote does not match what is enforced, even though the
rule does. The claim was that nobody signs a zone-authority spend, so the zone
binding is the only containment. In fact the zone's `zone_config` PDA must sign,
and only the zone program can sign for it, and the program additionally requires
`zone_authority_transact_is_enabled`
(`zone_transact/account.rs:26-38`). The correct statement is that the UTXO owners
do not sign. The zone binding is one containment among three, and it happens to
be the one the circuit enforces. This distinction matters for claim 3.

An independent confirmation of the strict rule sits in the program tests. The
contract note at
`program-tests/zone-test-program/tests/steps/zone_authority_transact.rs:501-506`
cites the same circuit constraint and the same two tests as the reason its
re-owned output must carry the zone id.

## Claim 3: a zone authority cannot move value out of the zone

Variant: `ZoneAuthorityWithdrawalNotAllowed` (`zone_authority.rs:72-80`).

Verdict: `OVER-STRICT` for a positive public amount. `UNDETERMINED` for a
negative one, pending an owner ruling on a conflict between the spec prose and
the program.

The guard rejects any nonzero public amount in either direction:

```rust
if external_data
    .public_sol_amount
    .is_some_and(|amount| amount != 0)
    || external_data
        .public_spl_amount
        .is_some_and(|amount| amount != 0)
{
    return Err(TransactionError::ZoneAuthorityWithdrawalNotAllowed);
}
```

`docs/spec.md:1255-1263` (committed tree, `is_deposit` in
`program-libs/interface/src/instruction/instruction_data/transact.rs:255-263`)
fixes the sign convention: a positive public amount deposits into the pool, a
negative one withdraws. So the guard refuses a zone-authority *deposit* under an
error named for withdrawal, which no reading of "value cannot leave the zone"
justifies.

### What the chain enforces

Nothing gates a public leg on the zone-authority variant. The evidence is three
independent readings that agree.

The program shares one settlement path across all three transact variants.
`zone_authority_transact` calls `process_transact_core::<true, true>`
(`programs/shielded-pool/src/instructions/zone_authority_transact/processor.rs:45-52`),
and that function settles without consulting either const parameter:

```rust
match transact_accounts.settlement.as_ref() {
    Some(Settlement::Sol(sol)) => {
        settle_sol(sol, public_amount(ix.public_sol_amount)?, ix.is_deposit())?
    }
    Some(Settlement::Spl(spl)) => settle_spl(spl, public_amount(ix.public_spl_amount)?)?,
    None => {}
}
```

That is `transact/processor.rs:170-176`. `IS_ZONE` and `IS_AUTHORITY` are read in
exactly two places, `prepare_proof_inputs` (`processor.rs:101-106`) and
`TransactProof::verify` (`verify.rs:70-116`), and neither touches the public
amounts. The settlement accounts are parsed by
`TransactAccounts::from_iter` (`transact/account.rs:34-85`), which branches on
`ix.is_deposit_or_withdrawal()` and `ix.is_spl()` and knows nothing about the
calling variant. A grep of `programs/` and `program-libs/` for `IS_AUTHORITY`
returns those two sites and their doc comments.

The circuit does not constrain it either.
`assertBalanceConservation` (`prover/server/circuits/spp_transaction/balance.go:15-72`)
range-checks both public amounts as signed 64-bit values and folds them into the
per-asset sums. It applies the same rules to every variant; the only
variant-specific constraints in `Define` are the two zone-field assertions at
`circuit.go:216-221`. Nothing forces `PublicSolAmount` or `PublicSplAmount` to
zero on the authority rail.

The protocol's own instruction builder makes the operation expressible. `program-libs/interface/src/instruction/builders/zone_authority_transact.rs:21`
declares `pub withdrawal: Option<TransactWithdrawal>`, and lines 54-70 push the
SOL or SPL settlement accounts into the account list for it. That field is in
`program-libs/`, which the port does not touch, so it is a protocol statement
about what the instruction can carry.

### What the spec says

`docs/spec.md:983` (committed tree) states the opposite intent:

> Because owners do not authorize the spend, value cannot leave the zone here:
> the public `zone_program_id` is pinned non-zero and **every** non-dummy input
> *and* output `zone_program_id` must equal it (strict binding, no zero
> exemption). A default-zone UTXO can neither be spent nor created, so the
> authority cannot move funds out of the policy zone without an owner-signed
> path.

This paragraph predates the port. `git log -S` places it in `39465e8c`, "feat:
zone circuits and instructions (#91)", so it is not a fixer writing their own
justification into the spec.

Read closely, the paragraph's stated mechanism does not reach a withdrawal. The
mechanism is the strict UTXO zone binding, and the conclusion drawn from it is
that a default-zone UTXO can neither be spent nor created. A withdrawal creates
no default-zone UTXO. It settles to an external Solana account through the public
leg, which the strict binding does not touch. So the sentence "value cannot leave
the zone here" is an intent the paragraph asserts but the mechanism it cites does
not deliver, and the program does not deliver it either.

### Smallest relaxation

For the deposit half, which needs no ruling: reject only a negative public
amount, leaving a positive one to build.

```rust
if external_data
    .public_sol_amount
    .is_some_and(|amount| amount < 0)
    || external_data
        .public_spl_amount
        .is_some_and(|amount| amount < 0)
{
    return Err(TransactionError::ZoneAuthorityWithdrawalNotAllowed);
}
```

For the withdrawal half, the smallest relaxation is to drop the guard entirely
and let the caller build what the program will accept. Whether to take it is an
owner decision, because it trades a spec-stated safety property against a
capability the program exposes. The two candidate readings are that the spec
describes an invariant the program fails to enforce (in which case the program
has a gap and the SDK should not paper over it), or that the spec overstates a
consequence of the zone binding (in which case the SDK is removing a legal
operation). Both are consistent with everything read here.

### Evidence that would settle the withdrawal half

A `program-tests` scenario that submits a `zone_authority_transact` carrying a
negative `public_sol_amount` with a real zone-authority proof, and observes
whether the validator settles it or rejects it. The existing zone-authority
scenario passes `withdrawal: None`
(`program-tests/zone-test-program/tests/steps/zone_authority_transact.rs:99`),
so no test exercises the path today. The reading above says it would settle. That
test is outside SDK scope and is offered as the evidence to request, not as work
to do here.

### A separate observation about the guard's reach

Every field of `PreparedZoneAuthority` is public
(`zone_authority.rs:23-34`), so `new` is an opt-in validator rather than a gate.
`sdk-libs/client/tests/zone_authority/steps.rs:157` already builds the struct by
literal and skips every check. The TypeScript side has the same shape: the
`PreparedZoneAuthority` interface
(`sdk-libs/ts/transaction/src/instructions/builders.ts:486-494`) admits any
object literal, so `prepareZoneAuthority` (`builders.ts:495-525`) is equally
bypassable. This is the pattern `bc55a9b9` fixed for `ProofInputUtxo::with_zone`
by moving the check into `hash()`. No equivalent re-check exists here. It cuts
both ways: it softens the capability regression, and it means the checks that are
`JUSTIFIED` do not actually bind.

## Claim 4: split rejects a dummy, a foreign owner, and a foreign nullifier key

Variants: `SplitInputIsDummy`, `SplitInputOwnerMismatch`,
`SplitInputNullifierKeyMismatch`
(`sdk-libs/transaction/src/instructions/transact/split.rs:67-75`).

Verdicts: owner and nullifier key `JUSTIFIED`. Dummy `OVER-STRICT` with an empty
capability.

### Owner and nullifier key

The circuit derives the owner commitment from the nullifier secret and checks it
against the UTXO's stored owner. `prover/server/circuits/spp_transaction/inputs.go:100-104`:

```go
ownerHash := abstractor.Call(api, OwnerHashGadget{
    OwnerKeyHash: ownerKeyHash,
    NullifierPk:  nullifierPk,
})
assertEqualWhen(api, spendOrAddress, ownerHash, in.Utxo.Owner)
```

`nullifierPk` comes from `NullifierPkGadget`, which is `Poseidon(nullifierSecret)`
(`inputs.go:140-147`, called at `circuit.go:190-192`), and `OwnerHashGadget` is
`Poseidon(ownerKeyHash, nullifierPk)` (`utxo.go:45-47`). A spender holding a
different signing key produces a different `ownerKeyHash`, and one holding a
different nullifier secret produces a different `nullifierPk`. Either way the
equality fails and the transaction is unprovable. The claim holds exactly as
written.

### Dummy

The claim does not hold. The circuit does not fail on a dummy input, it skips the
ownership check for one. `inputs.go:56-59` classifies a zero-data dummy as
padding and sets `spendOrAddress` to zero, which is the guard on the owner
equality quoted above and on the nullifier equality at `inputs.go:112`. The
inclusion and non-inclusion checks are likewise skipped
(`inputs.go:82`, `inputs.go:124-125`). A dummy is a slot the circuit treats as
absent, not one it rejects.

So a 1-input, 8-output split whose only input is a dummy is provable. The
canonical dummy has amount zero (`instructions/types.rs:40-55`), so the
builder's balance check forces `per_output_amount` to zero, and the result is
eight zero-value self-owned outputs. Balance conservation holds and the chain
would accept it.

That is the entire input class the variant removes: a split of nothing into
nothing. No user loses an operation they could want. The smallest relaxation
would be to delete the `is_dummy` branch and let `SplitAmountMismatch` speak for
the degenerate cases, but the recommendation is to keep the guard and correct the
comment at `split.rs:64-66`, which currently states a reason the circuit does not
support.

## Claim 5: withdrawal asset routing

Variant: `WithdrawalAssetMismatch`
(`sdk-libs/transaction/src/instructions/transact/transfer.rs:133-142`).

Verdict: `JUSTIFIED` in both directions.

The two sides of the pair are read from different places. The public leg is
chosen by the asset (`transfer.rs:279-281`: `withdrawal.asset == SOL_MINT`
selects `public_sol_amount`, otherwise `public_spl_amount`), while the external
accounts are chosen by the target (`transfer.rs:319-330`). The program then picks
its settlement branch from the public leg alone: `is_spl()` is
`public_spl_amount.is_some()`
(`program-libs/interface/src/instruction/instruction_data/transact.rs:245-247`),
consumed at `programs/shielded-pool/src/instructions/transact/account.rs:41-42`.

A SOL asset routed at a token account therefore sets `public_sol_amount`, and the
program walks the SOL branch (`transact/account.rs:65-74`), reading the next
account as `sol_interface` and validating it against the canonical SOL-custody
PDA (`settlement/validate.rs:15-28`). The builder placed the SPL token interface
there, so `validate_sol_interface` returns `InvalidSettlementAccounts`. The
reverse crossing sets `public_spl_amount`, the program walks the SPL branch, and
`validate_cpi_authority` (`validate.rs:31-37`) or `validate_spl_settlement`
(`validate.rs:39-70`) fails on accounts assembled for a SOL withdrawal.

A second, independent rejection backs both directions. The settlement account
addresses enter the `external_data_hash` preimage, and the program recomputes them
from the accounts it actually parsed
(`transact/processor.rs:143-160` with `settlement_accounts` at `processor.rs:189-199`).
A crossed pair puts the SPL accounts in the SDK's preimage and the SOL recipient
in the program's, so the recomputed hash differs and
`TransactProofVerificationFailed` fires even if the account validation somehow
passed.

The circuit adds a third for one direction: `balance.go:28-31` asserts that a
nonzero public SPL amount cannot target the SOL asset.

## Claim 6: slot ordinals

Variants: `OutputSlotOverflow` and `ExcessOutputSlots`
(`sdk-libs/transaction/src/instructions/transact/slots.rs:22-23` and
`transfer.rs:356-362`).

Verdicts: both `JUSTIFIED`. Neither removes an input class the chain would
accept, for different reasons.

`OutputSlotOverflow` is unreachable. It guards `u32::try_from(position)` where
`position` indexes the output list, and the widest supported shape is
`IN1_OUT8`, eight outputs (`program-libs/interface/src/shape.rs:44-46`). A
position cannot approach `u32::MAX`. The check is a guard against a future shape
change, not a rejection of anything a caller can construct today.

`ExcessOutputSlots` is not chain-visible. `finalize` reads slots by output
position (`transfer.rs:336-341`), so a longer list was never encoded into the
instruction. The old behaviour dropped the tail silently and the chain saw the
same transaction either way. The new behaviour refuses to build. The only caller
affected is one relying on truncation, which is an SDK-internal contract rather
than a protocol capability.

On the open half of row T22: `docs/spec.md:560-562` (committed tree) defines the
ciphertext ordinal as the number of `data = Some` outputs preceding this one,
while the Rust code uses the raw output position. That disagreement is left open
here as instructed. Both new rejections are consistent with either reading,
because both readings bound the ordinal by the output count, and the output count
is bounded by eight. Neither the overflow guard nor the slot-count guard depends
on which definition wins.

## The six previously-accepted input classes

`rust-sdk-changes.md:129-143` lists six classes that compile unchanged and now
fail at runtime. Two are covered above (the `cda42f01` builders, and by extension
the slot rules). The other four:

**Asset id `0` (`6882ca25`).** `JUSTIFIED`. `docs/spec.md:1112-1113` (committed
tree) reserves `asset_id = 1` for native SOL, gives SPL mints `asset_id >= 2`,
and initializes the global asset counter to `2`. The program can never assign
`0`, so no registry entry the chain would produce is now unregistrable. The same
commit's `MissingZoneProgramId` is also `JUSTIFIED`, and precisely so: the
circuit's `requireIdWhenDataSet` (`inputs.go:47-50`, called from `inputs.go:35`)
forces a nonzero zone program id whenever a non-dummy UTXO carries a nonzero zone
data hash, which is the same rule the SDK now applies at `utxo.rs:136-138`.

**Zero-owner inputs carrying other nonzero fields (`bc55a9b9`).** `JUSTIFIED`.
The circuit zeroes exactly these fields for a padding slot: amount at
`inputs.go:61`, owner at `inputs.go:62`, and blinding, asset, zone data hash, and
zone program id at `inputs.go:64-67`. An input carrying them under a zero owner
commits to a hash no key reproduces, matching the rule at
`instructions/types.rs:65-90`.

One nearby case was checked and is clear. The circuit has an "address input", a
slot with `IsDummy = 1` and a nonzero data hash (`inputs.go:56-58`), which
`check_canonical_dummy` would break if it caught it. It does not: the SDK's
`is_dummy()` tests the owner rather than the dummy flag
(`types.rs:57-59`), and a circuit address input has a real owner, so
`check_canonical_dummy` returns early. The address-input capability survives.
Whether the SDK can *express* an address input is a separate question this review
did not pursue; the transact witness builder sets `is_dummy` from the zero-owner
test (`sdk-libs/client/src/prover/transact/p256_and_eddsa.rs:319` and
`prover/inputs.rs:44`), which suggests it cannot, but that gap predates these
commits.

**Wallet balance overflow and zero tag window (`3d444a6c`).** `JUSTIFIED`, and
outside the question. Both are local wallet bookkeeping. A saturating balance
and a silently empty scan produce wrong answers in the SDK; neither builds a
transaction, so the chain has no opinion. No capability is expressible through
them.

**The seven `from_utxos` conversions (`7c697c2c`).** `JUSTIFIED`, and outside the
question. These encode the plaintext a recipient decrypts. A conversion that
reinterpreted the caller's UTXO set produced a ciphertext describing a different
transaction than the one built, which is a wallet-correctness defect, not a
chain-acceptance one. The chain sees only the ciphertext bytes and the committed
`external_data_hash`, and both are unchanged in shape.

## What was verified by reading, and what was inferred

Read directly, and quoted or cited by line above:

- The zone-authority circuit constraints (`circuit.go:216-221`), the strict-zone
  branch (`inputs.go:28-40`) and both of its call sites (`inputs.go:70`,
  `outputs.go:17`), and the four named circuit tests
  (`zone_authority_test.go:50-99`).
- The owner and nullifier binding (`inputs.go:100-104`, `140-147`, `utxo.go:45-47`)
  and the dummy skip conditions (`inputs.go:56-59`, `82`, `112`, `124-125`).
- Balance conservation and its variant-independence (`balance.go:15-72`).
- The program's shared settlement path
  (`transact/processor.rs:116-178`, `account.rs:34-85`,
  `zone_authority_transact/processor.rs:25-53`), the `zone_config` signer
  requirement (`zone_transact/account.rs:26-38`), and every use of `IS_AUTHORITY`
  in `programs/` and `program-libs/`.
- The settlement account validators (`settlement/validate.rs`).
- The interface builder's `withdrawal` field
  (`builders/zone_authority_transact.rs:16-78`).
- The spec paragraphs at lines 560-562, 983, and 1112-1113 of the committed tree,
  and the commit that introduced the zone-authority paragraph.
- The SDK guards themselves and the struct-literal bypasses in Rust and
  TypeScript.

Inferred rather than observed:

- **That a zone-authority withdrawal would succeed on chain.** This follows from
  three readings that agree (no program gate, no circuit constraint, an interface
  builder that plumbs the accounts), but no test submits one. The confidence is
  high and the verification named above is cheap.
- **That a dummy-input split would succeed on chain.** This follows from the
  circuit's dummy handling and from balance conservation over an all-zero
  transaction. No test constructs it, and it is worth constructing only if
  someone disputes the `OVER-STRICT` label, which carries no consequence either
  way.
- **That the crossed withdrawal pairs fail at account validation before the
  proof check.** The ordering of the two rejections was read from the call order
  in `process_transact_core`, not observed. Either rejection is sufficient, so the
  ordering does not affect the verdict.
- **That no zone config can exist for the all-zero program id.** This follows
  from the `zone_auth` PDA derivation and the loader reading the id out of the
  validated account. The creation path in `zone_config/create.rs` was not read
  line by line.

`docs/spec.md` carried uncommitted edits from another agent while this review ran
(an `owner_pk_field` rename). All spec citations are to `git show HEAD:docs/spec.md`
so the line numbers are stable against that work.
