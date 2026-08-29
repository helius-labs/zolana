# Changelog Rules

`CHANGELOG.md` is a contract with integrators. Every line is a verified fact
about the shipped package, written for a developer deciding whether and how
to upgrade. The root `CLAUDE.md` register applies with the tighter limits
below. Where they disagree, these rules win.

## Procedure

- List versions from the history of the `version` field in
  `sdk-libs/ts/package.json` (`git log -p --follow` on that file). Every
  version value that ever appeared gets an entry, published or not, under
  any registry, plus any published version the history misses (a release
  cut from a side branch). A value replaced before anything shipped under
  it folds into the entry that first shipped.
- Date an entry with the npm publish date (`npm view @heliuslabs/zolana
time`) when the version is published, else with the bump commit date.
- Find the newest version already recorded in `CHANGELOG.md` and backfill
  every later version plus the working tree's `package.json` version.
- For each version, study the commits between its cut point and the
  previous one (`git log -- sdk-libs/ts`), and verify the surface in the
  shipped tarball (`npm pack @heliuslabs/zolana@<version>`, read the
  `.d.ts`), else in the tree at the bump commit. A symbol the shipped types
  do not export does not exist. Commit titles corroborate, the artifact
  decides.

## Truth

- One entry per version, newest first, heading `## <version> — <YYYY-MM-DD>`.
- The entry for the next release is written in the same branch as the
  change, headed `## <version> — unreleased`. The publisher replaces
  `unreleased` with the date when cutting the release. `prepack` refuses to
  pack without a dated first entry matching `package.json`.
- A behavioral change with no surface change is listed only when a test
  pins it.

## Form

- No prose outside the entries, the file is the `# Changelog` heading and
  the entries.
- An entry opens with a summary of two or three sentences, the release's
  architectural changes and key features at the highest level.
- Sections per entry, in order, only when non-empty. `Breaking`, `Added`,
  `Changed`, `Fixed`, `Dependencies`.
- One item is one sentence a developer outside the project understands on
  first read. State the effect on the integrator, not the implementation.
- Name the exported symbol the item is about, then say in plain words what
  callers can do, or what changed for them.
- A `Fixed` item says what was wrong and what holds after the fix.
- A `Breaking` item carries its migration in the same sentence after `→`.
- Merge sibling facts into one sentence before cutting any fact. Twelve
  items per version is the target, twenty the ceiling.
- Forbidden. Jargon, internal file paths, implementation details,
  adjectives, motivation, history, "improved", "enhanced", "refactored",
  and any sentence that does not change what an integrator does. A PR
  number in parentheses is the only reference.
- `Dependencies` lists runtime `dependencies` changes only, as
  `name range (was range)`.

## Template

```markdown
## 0.2.0-alpha — 2026-09-14

Ring holdings move out of the pool balances into their own view, and one
transaction moves value out of a ring back to the pool. Selection covers
a fragmented balance with the fewest notes.

Breaking

- `Wallet.balances()` no longer counts notes locked to a custom ring →
  call `Wallet.ringBalances()` for ring holdings.

Added

- `buildRingExitTransaction(params)` moves value out of a custom ring back
  into the default pool in one transaction.
- `AssetRegistry.register(assetId, mint)` binds a token id to its mint
  once and refuses a conflicting binding.

Changed

- Ring transfers pick the largest notes first, a balance split across many
  small notes covers a payment with the fewest inputs.

Fixed

- A transfer funded by notes of more than one owner built a proof the
  chain rejects, the proof carries every owner's signature slot (#312).

Dependencies

- `@solana/kit` ^4.0.0 (was ^3.2.0).
```
