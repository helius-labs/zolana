# Releases

All contributors use this checklist when preparing or publishing a release.
Record the exact source commit and shipped packages or assets in one release
record.

## Choose the release

| Release | Tag | Publication guide |
|---|---|---|
| TypeScript SDK | `ts-sdk-v<version>` | [TypeScript](typescript.md) |
| Rust SDK | `rust-sdk-v<version>` | [Rust crates](crates.md) |
| Protocol and localnet bundle | `v<version>` | [GitHub](github.md) |

GitHub Releases describe the tagged component. Record compatible TypeScript,
Rust, and protocol versions. Their version numbers may differ.

## Shared checklist

1. Fetch the release branch and tags. Check the remote, source commit, existing
   GitHub Releases, and registry versions before preparing the release. Use a
   clean checkout of the intended source.
2. Select the exact packages, versions, source commit, and release channel.
   Follow SemVer and document breaking changes, including changes before 1.0.
   Mark an alpha as a prerelease on GitHub. For npm, use the `alpha` tag. Choose
   explicitly whether to move npm `latest` or select GitHub's latest release.
3. Update manifests, dependency requirements, lockfiles, and the component's
   changelog in the release PR. Write notes from that component's changes since
   its previous release, with migration steps and compatibility requirements.
4. Run the component's required checks and inspect the packaged files. Test a
   consumer of the packaged artifact. Record commands, results, and checks not
   run. Resolve failures in required checks before publishing. Keep those checks
   enabled and preserve their coverage.
5. Get a review of the release PR and exact publication actions. Wait for required
   CI checks to pass on the final source commit. Recheck packages if the source
   changes. Get approval for the actions you will perform: PR merge, package
   publication, tag push, GitHub Release, or deployment.
6. Publish the verified packages, verify the registry results, then create or
   verify the source tag and GitHub Release using the component guide. Keep
   published tags and assets unchanged. Use each package version only once.
7. Read back the public release and registry metadata. Verify versions, source,
   checksums, release notes, channel, and installation from the registry. Record
   the actual URLs and publication dates. Record build, publication, and
   deployment results separately.

If publication stops partway through, check every destination before retrying.
Record what succeeded and resume only the missing actions. Fix published code
with a new version; review any deprecation or yank separately.

## Release record

Prepare `releases/<tag>.md` in the release PR. Update the publication results
after verification. The source commit identifies the released code, not a later
commit that adds publication results.

```markdown
# <component> <version>

## Source and scope

- Source repository and full commit:
- Tag:
- Packages or assets, with each version:
- Channel and GitHub latest choice:
- Compatible SDK, program, prover, and indexer versions, where applicable:

## Changes

- User-facing changes:
- Breaking changes and migration steps:

## Validation

- Commands, results, and CI links for the source commit:
- Packaged consumer checks and artifact checksums:
- Checks not run and remaining blockers:

## Publication

- Registry and GitHub URLs, publication dates, and verified checksums:
- Documentation workflow result, where applicable:
- Remaining actions:
```

For companion packages from another repository, record that repository's source
commit and validation separately. Use the reviewed changes and migration steps
as GitHub release notes; keep internal validation evidence in the release record.

Photon container releases retain the procedure in
[Releasing Photon](../CLAUDE.md#releasing-photon) and separate deployment approval.
