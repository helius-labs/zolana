# Agent Notes — @heliuslabs/zolana

- Any change to the published surface updates `CHANGELOG.md` in the same
  branch, written under `CHANGELOG-RULES.md`. `npm run changelog:check`
  validates the entry, `prepack` runs it with `--release` and refuses to
  pack without a dated entry for the packaged version.
- Release. Set `version` in `package.json`, replace `unreleased` with the
  publish date in the changelog entry, run `npm run check`, `npm publish`,
  then push the matching `ts-sdk-v<version>` tag for the docs workflow.
