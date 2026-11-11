# GitHub Releases

Use the [shared checklist](README.md) and distinguish SDK release notes from
protocol bundles. Manage the tag and GitHub Release as separate steps.

## SDK release notes

1. Verify the remote tag resolves to the released source commit and the registry
   packages match that source. Use the changelog and source history at that tag.
2. Prepare notes scoped to the TypeScript or Rust SDK. Include package links,
   versions, breaking changes, migration steps, and compatibility requirements.
   Filter monorepo-generated notes to the released SDK.
3. Create a draft against the verified existing tag. From the repository root,
   set `release_tag` and `release_notes` to the reviewed tag and notes file.
   For an alpha release:

   ```bash
   gh release create "$release_tag" --verify-tag --draft \
     --title "$release_tag" --notes-file "$release_notes" \
     --prerelease --latest=false
   ```

4. Review the draft, then publish it when authorized:

   ```bash
   gh release edit "$release_tag" --verify-tag --draft=false --prerelease --latest=false
   gh release view "$release_tag" --json tagName,isDraft,isPrerelease,publishedAt,url,body
   ```

   For a stable release, omit `--prerelease` when creating it and use
   `--prerelease=false` when editing it. Choose `--latest=true` only when this
   release is intended to become the repository's latest release. Otherwise
   retain `--latest=false`, including when adding an older missing release.
5. Verify the public page, tag commit, notes, registry links, and latest status.
   Record the GitHub publication date separately from the tag and package dates.

Adding a missing GitHub Release updates only its release metadata. Preserve the
SDK's tag, version, and original package publication date.

## Protocol and localnet bundles

The [release recipe](../justfile) invokes
[`xtask create-release`](../xtask/src/create_release.rs). It stages versioned
programs, snapshots, prover and Photon binaries, and CLI artifacts.

```bash
just release "$release_tag"
```

This builds artifacts and rewrites `cli/release-artifacts.lock` even without
`--upload`. Review the generated lockfile and follow the shared checklist before
publication. Commit intended source and lockfile changes, rebuild from that
commit, and confirm staging leaves the source unchanged.

After authorization, the upload form is:

```bash
just release "$release_tag" --upload --prerelease
```

Omit `--prerelease` for an approved stable release. The helper creates a release
targeting `HEAD`, or uploads assets when an existing release has that same target.
It rejects an existing release with a different target. Verify an existing tag's
commit before upload. Preserve published assets and tags.
Read back the assets, checksums, prerelease flag, and latest status after upload;
the helper leaves the latest choice to GitHub.

Reference: [GitHub release documentation](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases).
