# {{project-name}}

A generated repository deploys one confidential custom ring with auditor visibility. Normal transfers use the default Zolana transfer prover. The custom ring program verifies the fixed proof that binds transaction viewing key encryption. Ring RPC decrypts the bound audit message.

## Setup

`just source` obtains Zolana revision `{{zolana_revision}}` when `{{zolana_path}}` is `.zolana`. The revision fixes the program, SDK, native audit circuit, and Ring RPC used by the ring.

Keep the authority key and files under `keys/` out of version control. The program keypair fixes program ID `{{program_id}}`. Store `keys/program-keypair.json` and `keys/auditor.key` in the deployment secret store. A fresh checkout must mount both files and set `CUSTOM_RING_PROGRAM_KEYPAIR_FILE` and `CUSTOM_RING_AUDITOR_KEY_FILE` before `just pipeline`.

Run `just pipeline` to build, deploy, create the auditor key, create the ring config, and register the ring with the shielded pool. The cluster must permit ring creation. A rerun skips config and registration accounts that already exist.

Copy `.env.example` to `.env` and set the cluster endpoints. Set `RING_RPC_ALLOW_ORIGINS` to the production HTTPS browser origins. Set `RING_RPC_WEBAUTHN_RP_ID` to their host or valid parent domain. Run `just ring-rpc` behind a TLS proxy. Ring RPC reads Photon and checks reader grants through Solana RPC.

## Readers

`just grant-reader <key>` creates the canonical reader record. `just revoke-reader <key>` closes it. A reader key is a canonical Ed25519 public key or a compressed P256 public key.

The config authority has no implicit read access. Grant its reader key when it also needs audit access.

## Limits

The auditor can recover outputs created by the supported client. The released transfer proof does not prove that ciphertext matches a committed output. Ring RPC reports undecryptable slots.
