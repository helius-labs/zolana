# Custom ring template

Run `just custom-ring-new NAME DESTINATION` from the Zolana checkout. The command generates a new program keypair, records its program ID, and pins the current Zolana revision.

The generated repository obtains the pinned source with `just source`. Run `just pipeline` after the revision is available from the configured Zolana repository.

Set `CUSTOM_RING_AUTHORITY_KEYPAIR` before generation to replace the authority path. Put endpoint values in the generated `.env` file.

Use an HTTPS repository URL without user information and a credential helper, or use an SSH repository URL.
