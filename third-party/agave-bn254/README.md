# Agave BN254 batch crates

Sources are **not** copied. Symlinks under each package `src/` point at:

- `../agave/bn254-batch-syscall`
- `../agave/bn254-groth16-batch`

Pinned agave commit: `5134c411752fb0935e469f04d6c52a409cde1476`.

```bash
cd ../agave && git rev-parse HEAD
# rebuild shims after agave moves:
# re-create symlinks if needed
```
