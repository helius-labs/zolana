# GPU prover and indexer

These scripts install the Aeglos prover and Photon on an existing Vast or EC2
host. Prover requests reach Photon over loopback. PostgreSQL stays on the same
host. Deployment does not allocate cloud instances or change devnet services.

Use Linux x86-64 with CUDA 12.8 and a compatible NVIDIA driver. The host needs
PostgreSQL 16 and its client tools, Supervisor, Python 3, curl, and Bash.
Create a dedicated empty database and role before the first deployment.
Keep PostgreSQL on loopback. Allow SSH only in the EC2 security group or Vast
port mapping. Photon listens on all interfaces, and its port must stay private.
The prover and its metrics bind to loopback by default.

## Build

Build on Linux with Go and Rust versions from the repository, CUDA development
tools, and the Photon build dependencies from `services/photon/Dockerfile`.
Git must have access to the private Aeglos repository. The source lock pins its
commit and archive digest. Credentials stay on the build host.

```sh
CUDA_ARCH=sm_120 tools/gpu/build.sh target/gpu-bundle
```

Use `sm_89` for L4 or L40S, `sm_120` for RTX 5090, and `sm_100` for B200.
Without `CUDA_ARCH`, the build reads the first local GPU. Installation checks
the target GPU against the bundle. `GOAMD64` defaults to `v3` and can be set to
`v1` for CPUs without AVX2. Build from a clean checkout. The bundle records the
Zolana commit and file digests. Build and target hosts need compatible system
libraries. Each release directory accepts one bundle digest.

## Deploy

Copy `deployment.env.example` into an ignored directory such as `target/`.
Set the private RPC URL and local database credentials, quote shell values,
and restrict the file to its owner with `chmod 600`. Deployment files are
trusted shell input. Keep the same `DEPLOYMENT_NAME` for upgrades.
Database URLs require a loopback IP and cannot contain connection query options.
Upgrades preserve the database host, port, name, and user. Password rotation is
allowed.

```sh
SSH_PORT=40056 SSH_KEY=~/.ssh/vast_key \
  tools/gpu/deploy.sh vast root@HOST target/gpu-bundle target/gpu.env

SSH_KEY=~/.ssh/ec2_key \
  tools/gpu/deploy.sh ec2 ubuntu@HOST target/gpu-bundle target/gpu.env
```

Vast requires a root SSH target. EC2 requires passwordless sudo and starts the
stack through a dedicated systemd unit. Each stack has its own Supervisor
socket, release directory, key cache, and rotating logs under
`/opt/zolana-gpu/DEPLOYMENT_NAME`. Upgrades restart that stack only and preserve
its database and proving keys. Proving keys are fetched and checked against
the prover lockfile on demand. GPU calls share the engine admission lock.

For Vast container restarts, configure the instance startup command to run
`supervisord -c /opt/zolana-gpu/DEPLOYMENT_NAME/supervisord.conf` after PostgreSQL
is ready. Use persistent storage for the database and deployment directory.

## Reuse indexer data

Take a PostgreSQL custom-format dump from an authorized source or replica with
`pg_dump --format=custom --no-owner --no-privileges --lock-wait-timeout=5s`.
Use a read-only source account or a previously exported cache. A dump adds
read load but does not stop the source indexer. Keep credentials out of shell
history by using a PostgreSQL service file and `.pgpass`.

Pass the dump as the last deployment argument. Restoration is transactional
and runs only before first startup against an empty local database. Existing
deployments reject cache restoration. Photon resumes indexing from restored
data and applies migrations from the bundled source revision.

Deployments check Photon `/readiness` and prover `/ready`. Lazy key loading
means readiness does not guarantee a warm first proof. Set
`PROVER_PRELOAD_CIRCUITS` to preload selected keys. The existing
[prover monitoring](../../prover/server/TRANSFER_SERVICE.md) covers metrics,
capacity alerts, and request timings. Failed readiness leaves the release
installed and reports an error. Inspect the stack logs before retrying.
