# `merge_transact` and the `user_record` account

**No. The `user_record` account is not adequately validated.** `merge_transact`
accepts any account owned by the user-registry program that carries a
`UserRecord` discriminator, and derives the merged owner's identity, the viewing
key the output is encrypted to, and the merge opt-in from it. Nothing binds that
record to the owner whose UTXOs are being merged. The regression test added with
this report asserts the missing property and fails.

The gap is not reachable by an unauthenticated party. Exploiting it requires the
owner's `nullifier_secret` and the blindings of the UTXOs being merged, which the
protocol hands to a sync delegate by design. The consequence is loss of access to
funds, not theft.

This confirms, with a running test, Finding 1 of
`planning/typescript-sdk-port/owner-hash-collision-audit.md:321-449`, which
reached the same conclusion by reading. Where this report adds something: the
property is now pinned by a test in the repository, and the degenerate-`(0,0)`
question that audit left open at line 295 is settled below.

## 1. What `merge_transact` validates about `user_record`

The loader takes three accounts and validates the record by two facts:

```10:26:programs/shielded-pool/src/instructions/merge/account.rs
pub struct MergeTransactAccounts<'a> {
    pub tree: &'a mut AccountView,
    pub user_record: &'a AccountView,
}

impl<'a> MergeTransactAccounts<'a> {
    pub fn validate_and_parse(
        _program_id: &Address,
        accounts: &'a mut [AccountView],
    ) -> Result<Self, ProgramError> {
        let mut iter = AccountIterator::new(accounts);
        let tree = iter.next_mut("tree")?;
        let _payer = iter.next_signer("payer")?;
        let user_record = iter.next_account("user_record")?;
        Ok(Self { tree, user_record })
    }
}
```

- **Owner program**: `account.owned_by(&registry_id)`, `merge/account.rs:54-57`.
- **Discriminator and body**: `UserRecord::try_from_account_data`,
  `merge/account.rs:61-62`, whose whole check is the first byte plus a Borsh
  decode (`program-libs/user-registry-interface/src/state.rs:52-57`).
- **PDA derivation**: none. The record stores both `owner` and `bump`
  (`state.rs:22-23`), and the registry itself has
  `check_record_pda_with_bump` (`programs/user-registry/src/instructions/common.rs:37-52`),
  but `load_user_record` never calls anything like it.
- **Signer relationship**: none. The only signer is `payer`, bound to `_payer`
  and discarded (`merge/account.rs:22`). By design: any caller may run a merge
  (`docs/spec.md:1667`).

On the loader convention, the repository is consistent with itself and the code
does use a `load`-prefixed function, `load_user_record`
(`merge/account.rs:49-81`). `CLAUDE.md` permits owner-plus-discriminator loading
for initialized accounts "if access control does not rely on the derivation
itself", and requires a stored or supplied bump when it does. The question is
therefore not whether a loader exists but whether this account carries access
control. It does: `merging_enabled` is an authorization flag, read from the same
unbound account (below).

## 2. What the registry verifies about the keys it writes

`register` authenticates exactly one field. The owner must sign
(`programs/user-registry/src/instructions/register.rs:21-23`), the record must be
that owner's canonical PDA (`register.rs:30`, `common.rs:23-34`), and `owner` is
taken from the signing account (`register.rs:29`, `register.rs:46`). Everything
else is copied from instruction data:

```45:54:programs/user-registry/src/instructions/register.rs
    let state = UserRecord {
        owner: (*owner_address.as_array()).into(),
        bump,
        owner_p256: data.owner_p256,
        nullifier_pubkey: data.nullifier_pubkey,
        viewing_pubkey: data.viewing_pubkey,
        sync_delegate: None,
        entries: Vec::new(),
        merging_enabled: false,
    };
```

There is no proof of possession for `owner_p256` and none for `viewing_pubkey`.
`update_keys` lets the record's owner overwrite both at any time, again with no
possession check (`update_keys.rs:30-32`); it does verify the signer is the
record's owner and re-derives the PDA from the stored bump
(`update_keys.rs:20-28`). `set_merging_enabled` is likewise owner-signed and
PDA-checked (`set_merging_enabled.rs:19-28`), and `owner` is written once at
registration and never mutated afterwards.

The net effect: `record.owner` is authentic, and every other key in the record is
an unverified claim by whoever signed the registration.

## 3. Which fields the merge consumes, and what depends on them

```41:55:programs/shielded-pool/src/instructions/merge/processor.rs
    let pk_fields = load_user_record(merge_accounts.user_record, ix.eddsa_owner)?;

    // Per-user merge opt-in: the owner must have enabled merging. Any caller may
    // then run the merge.
    if !pk_fields.merging_enabled {
        return Err(ShieldedPoolError::MergeDisabled.into());
    }

    let signing_pk_field = pk_fields.signing_pk_field;
    let viewing_pk_field = pk_field(&pk_fields.viewing)?;
```

Three fields, each load-bearing:

- **`owner_p256` or `owner`** (rail selected by the caller-supplied
  `ix.eddsa_owner`, `merge/account.rs:65-74`) becomes the `signing_pk_field`
  public input (`merge/verify.rs:111-126`). The circuit binds the same value to
  the input and output UTXO owner hashes (`spp_merge/circuit.go:134-140`,
  `:150`, `:162`), so this field cannot be swapped for a different owner's key
  without invalidating the proof. It is the one field the proof defends.
- **`viewing_pubkey`** becomes the `viewing_pk_field` public input and is the key
  the merged output is verifiably encrypted to
  (`spp_merge/circuit.go:179-188`, `spp_merge/encryption.go:28-49`). The
  plaintext is `amount || asset || blinding` (`encryption.go:59-67`). If this
  field is not the merged owner's key, the owner never learns the output's
  blinding and cannot compute its nullifier, so the consolidated balance is
  unspendable. Nothing else binds it: the proof is *consistent* with whatever key
  SPP supplies, so authenticity has to come from the account.
- **`merging_enabled`** is the entire authorization for the instruction
  (`merge/processor.rs:45-47`, `docs/spec.md:2093`). If it is read from a record
  the owner does not control, the opt-in and its revocation
  (`docs/spec.md:2379`) mean nothing.

## 4. Sibling instructions

`merge_zone` is the direct comparison, and it is stricter on exactly this point.
It loads its `zone_config` by owner plus discriminator, the same shape as
`load_user_record`, and then **requires that account to sign**:

```6:29:programs/shielded-pool/src/instructions/merge_zone/account.rs
/// Validated accounts for `merge_zone`, in loader order: `tree` (writable),
/// `zone_config` (the zone's `zone_auth` PDA, signer), `payer` (signer). The
/// `zone_config` must sign and be a valid SPP-owned config: only the zone program
/// can sign for its `zone_auth` PDA, so the signature plus the owner + discriminator
/// check is the zone's authorization.
```

`load_zone_config` states the rule the repository follows elsewhere: the
create-time `zone_auth` derivation already bound the account to its program, so
callers add only an `is_signer` check and do not re-derive
(`programs/shielded-pool/src/instructions/zone_config/loader.rs:9-28`). The other
multi-instance accounts SPP reads for authorization are tied to a signature:
`load_and_validate_zone_authority_mut` (`zone_config/loader.rs:53-64`) and
`load_and_validate_protocol_authority` (`protocol_config/loader.rs:56-70`). The
singleton `protocol_config` needs no tie because only one such account can exist.

`user_record` is the only multi-instance account SPP reads for authorization data
with neither a signature nor a derivation tying it to the principal it speaks
for. The inconsistency points at `merge_transact`.

## 5. The regression test and its outcome

`program-tests/shielded-pool/tests/merge_user_record.rs`, wired in as the
`merge_user_record` test target. Two tests, both asserting that
`merge_transact` rejects a record that is not the merged owner's canonical
record, and **both fail**.

The tests submit a merge with a zeroed proof, which separates the account check
from the proof check cleanly: a record SPP accepts runs on to proof verification
and fails with `TransactProofVerificationFailed` (7008), a record SPP rejects
fails earlier with `InvalidUserRecord` (7018). Each test first establishes the
baseline, that the merged owner's own record is accepted and reaches the proof,
so the later result is attributable to the record and not to the zeroed proof.

1. `merge_transact_rejects_a_record_registered_under_another_owner`. A second
   registrant claims the merged owner's `owner_p256` in their own record, with
   their own `viewing_pubkey` and `merging_enabled = true`. This is reachable
   on-chain today, since registration takes `owner_p256` on trust. Result:
   accepted, reaching 7008 rather than 7018.
2. `merge_transact_rejects_a_non_canonical_record_address`. A registry-owned copy
   of a real record planted at an address that is not its PDA. This state is
   **not** reachable on-chain, since the registry creates records only at
   canonical PDAs and an attacker who assigns an account to the registry program
   cannot write record bytes into it. The test therefore pins the derivation
   check rather than a live attack. Result: accepted, reaching 7008 rather than
   7018.

Run output, both failures (verified by running):

```
a record whose owner_p256 was claimed by a different registrant:
  expected Custom(7018), got: InstructionError(1, Custom(7008))
a registry-owned record copy at a non-canonical address:
  expected Custom(7018), got: InstructionError(1, Custom(7008))
```

The test is written to pass under either plausible fix: if a future registry
enforces proof of possession, the impostor registration fails and the first test
returns early rather than asserting on the merge.

## 6. The degenerate `(0,0)` witness

Settled by `test.IsSolved` against the pinned gnark v0.14.0, in a scratch package
that was deleted after the run (no circuit was modified).

**The ECDSA gadget is not satisfiable for `(0,0)` through the prover's own
witness path.** `PublicKey.IsValid` with `Pub = (0,0)` fails to solve with
`NewHint: no modular inverse`, for both `want=0` and `want=1`. Controls with the
same non-degenerate `(r, s)` against a real P256 key solve cleanly and report `0`
for a forged signature and `1` for a real one, so the failure is attributable to
the key and not to the scalars. The mechanism is visible in the trace: gnark's
ECDSA calls `JointScalarMulBase` with no `algopts`
(`gnark@v0.14.0/std/signature/ecdsa/ecdsa.go:71`), P256 has no endomorphism, so
it dispatches to the incomplete `jointScalarMulFakeGLV`
(`sw_emulated/point.go:790-807`), whose precomputation divides by `2y = 0`.

Two limits worth stating rather than glossing. `test.IsSolved` runs the hint
path, so it establishes that no *hinted* witness exists; the divisions on `(0,0)`
are `0/0` in places, where the emitted constraint `res·b == a` is satisfied by
any `res`, so this run does not by itself rule out a hand-crafted witness. And it
tests the gadget in isolation, not a full transfer shape.

**The owner encoding does accept `(0,0)`, and it does land on the zero Solana
address.** `OwnerPkFieldFromPubkeyCircuit` solves for `(0,0)`, because gnark's
`AssertIsOnCurve` admits it as the point at infinity, and the value it produces
is `Poseidon(0, 0)`, checked in the same run against a native
`poseidon.Hash([0, 0])`:
`14744269619966411208579211824598458697587494354926760081771325075741142829156`.
That is byte-identical to what the program derives for the all-zero Solana
address, since `solana_pk_hash` is Poseidon over the same two right-aligned
128-bit limbs (`programs/shielded-pool/src/instructions/hash.rs:15-29` versus
`program-libs/interface/src/merge_utils.rs:37-52`).

What follows for owner identity: on the transact P256 rail, nothing, because the
signature gadget will not solve for that witness. The merge circuit is a
different matter, since it verifies no signature at all and `(0,0)` is the
dummy point its ed25519 rail relies on (`spp_merge/circuit.go:56-60`,
`:138-139`). That is safe only because the selected `pkField` must equal the
value SPP derived from the registry record and folded into the public input hash
(`merge/verify.rs:111-126`), so the prover has no freedom there. The security of
the merge rail therefore rests on the record binding examined in this report, not
on the circuit.

The same collision is why the record gap reaches ed25519 owners too, which is
worth being explicit about: `owner_pk_field_compressed(0x02 || S)` equals
`solana_pk_hash(S)` for any 32 bytes `S`, and neither function checks that the
x-coordinate is on the curve. An impostor record can therefore carry
`0x02 || victim_solana_address` in `owner_p256` and impersonate an ed25519 owner
through the P256 branch. This is the audit's Finding 1 attack shape
(`owner-hash-collision-audit.md:388-406`); I verified the two hash functions
agree by reading them, not by running.

## 7. The smallest fix, and what it is worth

Described here and left unapplied, per the ruling that this port changes SDK code
only.

**Smallest fix: require proof of possession for `owner_p256` in the registry**,
at `register` and `update_keys`: a P256 signature over a message binding the
record's `owner` address and the program id, verified through the secp256r1
precompile. That single change closes both shapes. An impostor cannot claim a
real P256 owner's key without holding it, and cannot claim
`0x02 || victim_address` either, because that value is not a key anyone can sign
with. It restores the transitive binding `merge_transact` already assumes: a
record carrying key `K` was created by `K`'s holder, so its `viewing_pubkey` and
`merging_enabled` are that owner's.

A PDA check in `load_user_record` is **not** a substitute. The impostor record is
the canonical PDA of the impostor's own Solana address, so re-deriving from
`record.owner` and the stored bump accepts it. It is still worth adding as a
cheap invariant (one `derive_address`, and the bump is already in the account,
which is the form `CLAUDE.md` prescribes), but it closes only the planted-account
case, which is not reachable on-chain anyway.

Requiring the merged owner to sign would close it but contradicts the design:
`merge_transact` is explicitly permissionless once the owner opts in
(`docs/spec.md:1667`, `:2093`).

**What an unauthenticated party can cause: nothing.** The merge proof requires
the owner's `nullifier_secret`, because the circuit asserts
`Poseidon(nullifier_secret) == nullifier_pk` and derives each input nullifier
from it (`spp_merge/circuit.go:143-144`, `spp_merge/inputs.go:56-63`), and it
requires the `blinding` of each input UTXO. Without those there is no proof, and the account
gap is unreachable. `docs/spec.md:2108` makes exactly this argument.

**What requires a prior relationship: everything else.** The party who holds that
material is a current or former sync delegate; the spec assigns it the nullifier
key by design and acknowledges that a revoked delegate keeps it along with the
blindings it decrypted (`docs/spec.md:2255-2257`). Against such a party the
record gap defeats two guarantees the spec states: that disabling
`merging_enabled` stops merges for that owner (`docs/spec.md:2379`), and that the
merge service "cannot encrypt incorrectly because `merge_transact` binds the
output to the owner's registered `viewing_pk`" (`docs/spec.md:2108`).

**Consequence: denial of access, not loss to an attacker.** The merged output's
owner hash is the victim's, and spending it needs the victim's signing key, so
the attacker gains nothing. What the attacker takes away is the victim's ability
to spend: the inputs are nullified, and the output's `blinding` exists only
inside a ciphertext encrypted to the attacker's viewing key. The victim can see
the event, which still carries their owner tag (`merge/processor.rs:55`), and
cannot decrypt it. Up to eight UTXOs per call, permanently, unless the attacker
hands over the blinding.

## 8. Verified by running versus concluded by reading

Verified by running:

- Both regression tests fail with `Custom(7008)` where `Custom(7018)` is
  required; the canonical-record baseline in each test reaches proof
  verification, so the merge accepted the impostor and the planted record.
- The ECDSA gadget does not solve for `Pub = (0,0)`; the real-key controls solve
  and report invalid then valid.
- `OwnerPkFieldFromPubkeyCircuit((0,0))` solves and equals native
  `Poseidon(0,0)`.
- `cargo check -p shielded-pool-tests --tests` passes with the new target.

Concluded by reading:

- That `load_user_record` performs no PDA and no signer check, and that no other
  code path compensates.
- That the registry writes `owner_p256` and `viewing_pubkey` without possession
  proof, and that `owner` is authentic and immutable after registration.
- That `owner_pk_field_compressed(0x02 || S) == solana_pk_hash(S)`, from the two
  implementations.
- That a registry-owned account at a non-canonical address cannot be created
  on-chain with valid record bytes.
- The attacker capability model (nullifier secret plus blindings), from the
  merge circuit and the spec's sync-delegate section.

## 9. Coordination

`planning/typescript-sdk-port/row-updates/double-spend-analysis.md` had not
landed when this was written, so there is nothing to agree or differ with yet.
The two investigations touch the same manifest:
`program-tests/shielded-pool/Cargo.toml` carries both the `merge_user_record`
target and that investigation's `double_spend` target.
