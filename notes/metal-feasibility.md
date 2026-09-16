# Apple GPU feasibility

The current CPU profile attributes much of backend time to elliptic-curve MSMs. ICICLE provides an Apple Metal backend, so an isolated correctness probe was prepared under `target/admitted-bench/icicle` without changing the production Go dependencies or shared module cache.

The official v3.8.0 macOS frontend and Metal backend archives were downloaded from the [ICICLE release](https://github.com/ingonyama-zk/icicle/releases/tag/v3.8.0). Their SHA-256 hashes are `693726f17622668d04be300e71d5a2e0af50e8ec0dda97842d919c31f033c7d6` and `8b473e49cb755f31a061046294e45c8c888c351ede401b4e6604d0322a8f858a`. They were unpacked locally; no system libraries were installed.

The C++ probe compiled, loaded the libraries and computed a CPU reference. Selecting the Metal device failed with error 13: the default Research and Development license server at `license.icicle.ingonyama.com` refused the connection. No GPU MSM ran, and no GPU timing or proof speedup is claimed. The program checked the device-selection error and exited instead of silently timing a CPU fallback.

The [vendor documentation](https://dev.ingonyama.com/start/architecture/install_gpu_backend) describes the default development-license server and separate production licensing. A working licensed backend is needed to continue this specific experiment; other CPU, circuit and upload work can proceed independently.

The installed gnark v0.16.3 integration uses `icicle-gnark/v3` v3.2.2. Its `METAL` enum is reserved, but its backend string conversion returns `unknown` for that value. Its own package documentation describes newer Metal backends as untested. A verified adapter and compatible frontend are therefore still required, even after device initialization works.

Any later GPU comparison must apply the same available acceleration to the PR #320 comparator, retain keys and device initialization outside resident-key timing, include per-payment conversions/transfers, and verify every resulting proof. CPU versus GPU asymmetry would not establish an architectural 10× gain.
