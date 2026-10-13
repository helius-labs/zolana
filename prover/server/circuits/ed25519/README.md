# Ed25519 verification

`Verify` asserts the Ed25519 signature predicate used by Solana's [Ed25519 precompile](https://github.com/anza-xyz/agave/blob/master/precompiles/src/ed25519.rs), pinned to `ed25519-dalek 1.0.1` and `curve25519-dalek 3.2.0`. It computes `h=SHA-512(R||A||M) mod L` inside the circuit and checks the complete signature equation. The input message length is fixed when compiling; 32-byte messages are the target.

```go
type Circuit struct {
    PublicKey [32]frontend.Variable `gnark:",public"`
    Message   [32]frontend.Variable `gnark:",public"`
    Signature [64]frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
    ed25519.Verify(api, ed25519.Inputs{
        PublicKey: c.PublicKey,
        Signature: c.Signature,
        Message: c.Message[:],
    })
    return nil
}
```

Public keys and R use compressed Edwards-y encoding; S is little endian and strictly less than L. The gadget rejects malformed and small-order points, accepts mixed torsion, and preserves the precompile's noncanonical point-encoding behavior. Both original encodings enter SHA-512, which range-checks every byte of R, the key and the message. The surrounding circuit chooses public inputs; the example exposes the key and message while keeping the signature private.

The custom-ring owner-signature rail (`circuits/spp_transaction/custom/ed25519.go`) uses this gadget over the 32-byte SPP signing digest.

## Layout

| Path | Contents |
| --- | --- |
| `verify.go`, `curve.go`, `short.go`, `montgomery.go`, `bytes.go` | The gadget: decoding, torsion split, short Weierstrass ladder, fixed-base comb, byte re-limbing. |
| `../verifiable-encryption/p256/emcurve/emfield` | Emulated-field arithmetic with lookup range checks, shared with the P-256 circuits. `curve.go` instantiates it with six 43-bit limbs and `ArithmeticV2`; the P-256 circuits keep `ArithmeticV1`, so their constraint systems and Lean proofs do not change with this gadget. |
| `internal/lookup` | Row lookups bound under the shared BSB22 commitment. |
| `internal/r1c` | Direct R1CS product rows. |
| `internal/sha512` | Lookup SHA-512 over a fixed-length byte message. |

Hints register in package `init` functions; importing the gadget registers them for any prover that compiles or solves a circuit using it.

## Arithmetic

The field uses six 43-bit limbs and eleven-bit lookup pieces. Three complete doublings prove each split `P=[8]W+T`, giving a prime component and a constrained eight-torsion selector. A separate equation checks the torsion contributions.

Extended Euclid supplies 127-bit u,v with `u*h=v mod L` and u nonzero. The prime equation becomes `[u]R0+[v]A0=[u*S]B`. A signed radix-four joint ladder uses a prover-selected offset `J=jB`, with j in 1..256; fewer than 256 choices can cause an exceptional intermediate, so every valid signature has a usable offset. Exact native-field alias guards and a final cubic curve check bind the lazy arithmetic. The fixed-base side uses signed eight-bit windows, positive-magnitude tables and packed constant selection. Host witness multiplication uses complete extended coordinates and one final inversion.

The arithmetic and encoding checks take 29,756 constraints. Complete 32-byte-message verification, including SHA-512, takes 50,648 constraints (BN254 R1CS, gnark v0.16.4). Groth16 proving measurements, batch costs and the layout/window sweeps live with the original experiment in `gnark-gadgets/ed25519/BENCHMARKS.md` of the zk-experiments repository.

## Verification

```sh
cd prover/server
go test ./circuits/ed25519/...
go vet ./circuits/ed25519/...
```

The tests compare 914 CCTV cases against the exact Solana library, 320 supplied-challenge cases across all torsion classes, scalar boundaries, 69 native-field alias cases, malformed inputs, forged hints, and a coincident-chord attack. SHA-512 tests cover nine message lengths and alternate slice carries; host arithmetic is checked against independent affine formulas on 1,076 cases. The statement, bounds, polynomial identities and verifier obligations are written up in the zk-experiments repository (`gnark-gadgets/audit/ed25519`). This uses BN254 Groth16 with the commitment-aware BSB22 verifier.
