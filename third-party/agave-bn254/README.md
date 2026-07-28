# Agave BN254 batch crates

Sources are **not** copied. Each package's `src/` is a symlink into a sibling
agave checkout:

- `bn254-batch-syscall/src` → `../agave/bn254-batch-syscall/src`
- `bn254-groth16-batch/src` → `../agave/bn254-groth16-batch/src`

**The workspace does not compile without that checkout at the pin below.**

## Required setup

```bash
# sibling to the zolana checkout
cd ..
git clone <agave-remote> agave
cd agave
git checkout helius/bn254-b1-zolana-pin
git rev-parse HEAD   # expect 7090028bb328e63b5207e35cfcea864728fea0b7
```

The pin branch is `helius/bn254-b1-arkworks-baseline` (`5134c411…`) plus one
commit making the fold SBF-safe for these path deps: `VerifyingKey::trust()`
(shape + digest only, for compile-time constant keys where curve checks are
unavailable; hosts keep `validate()`), `hashv`-based transcript and vk digests,
and host-free `Fr` parsing.

If agave moves, update the pin here and re-check the symlinks; drift shows up
as compile errors in `solana-bn254-groth16-batch`, not at runtime.
