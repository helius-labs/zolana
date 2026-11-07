# TypeScript SDK releases

Use the [shared checklist](README.md), [SDK instructions](../sdk-libs/ts/AGENTS.md),
and [changelog rules](../sdk-libs/ts/CHANGELOG-RULES.md). Read the package name,
version, exports, engines, and peer dependencies from
[`package.json`](../sdk-libs/ts/package.json); the package is `@heliuslabs/spr`.

## Prepare and verify

1. Update the package version and lockfile, date its changelog entry, and include
   breaking changes and migration steps. Use `ts-sdk-v<version>` for the tag.
   Check whether the version already exists on npm before preparing a publish.
2. From the repository root, install the locked workspace dependencies:

   ```bash
   npm ci
   ```

   Then, from `sdk-libs/ts`, run:

   ```bash
   npm run check
   npm run changelog:check -- --release
   npm pack --dry-run
   npm pack
   ```

3. Inspect the tarball and record its checksum. Install that exact tarball in a
   separate consumer with the supported Node and peer dependency versions.
   Compile imports of named exports and supported subpaths with
   `skipLibCheck: false`, and exercise the changed API. `check:dist` alone does
   not verify package consumers. Run relevant E2E checks for changed network
   flows; `npm run check` excludes `test/e2e`.
4. Finish the release PR, verify CI on the final commit, and repeat package
   checks if its source changes. Retain the tested tarball for publication.

## Publish and verify

After authorization, publish the tested tarball with an explicit npm tag.
Set `release_tarball` to its absolute path. For an alpha:

```bash
npm publish "$release_tarball" --tag alpha --access public
```

The release changelog check above is required even when publishing a tarball;
do not rely on directory lifecycle hooks to run for that form. Use `--tag latest`
only for a release explicitly intended to replace the npm default version.

Read back the exact version, dist-tags, integrity, and source metadata:

```bash
npm view "$release_package@$release_version" version gitHead dist --json
npm view "$release_package" dist-tags --json
```

Set `release_package` and `release_version` from the reviewed manifest. Download
the registry tarball, compare it with the tested tarball, and install the exact
registry version in the consumer. Check `gitHead` when present; use the recorded
source commit and artifact comparison when it is absent.

Only after registry verification, create and push the annotated
`ts-sdk-v<version>` tag at the released source commit when authorized. Never move
an existing published tag. The
[TypeScript docs workflow](../.github/workflows/typescript-docs.yml) publishes API
docs on `ts-sdk-v*` tag pushes; its manual run builds without publishing. Verify
authorization covers that documentation publication before pushing the tag.
Verify the tag workflow, then follow the [GitHub guide](github.md) for release notes.

If npm already contains the version, verify it and complete only missing tag,
documentation, or GitHub steps. Do not publish it again.

Reference: [npm publish documentation](https://docs.npmjs.com/cli/v11/commands/npm-publish/).
