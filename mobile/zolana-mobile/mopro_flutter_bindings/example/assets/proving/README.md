Place the staged proving key and solved assignment in this directory.

From the repository root, run:

```sh
mobile/stage-demo-assets.sh
```

The script downloads and verifies `transfer_confidential_2_3.key` when needed,
uses Go/gnark to regenerate `assignment-2x3.bin`, and copies both here. The
binary assets are ignored by Git.
