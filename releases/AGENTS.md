# Release instructions for agents

Read [README.md](README.md) first. Its checklist applies to all contributors.
Use [github.md](github.md), [typescript.md](typescript.md), or
[crates.md](crates.md) for the selected release. Keep release policy in these
repository guides. Use current manifests for package names and versions.

- Verify the current remote, branch, manifests, tags, release metadata, and
  registry state before acting. Follow component instructions, including
  [the TypeScript SDK instructions](../sdk-libs/ts/AGENTS.md).
- Prepare the release record, notes, package checks, and exact publication
  actions before requesting approval. Publish or push tags only when the user
  has authorized those specific actions. Continue with steps covered by existing
  authorization.
- Ask for explicit approval before merging a specific PR or deploying a
  specific change.
- Keep unrelated changes out of the release. Report source checks, package
  checks, registry publication, GitHub publication, and deployment separately.
- For a missing GitHub Release on an existing published tag, verify the tag and
  registry source, then prepare only the missing release metadata.
