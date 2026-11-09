1. this package contains only circuits no other logic
2. this package must not depend on other packages in github.com/helius-labs/zolana/prover/server other packages may depend on it
3. every circuit should have its own directory, or file if the directory would only contain one file
4. github.com/helius-labs/zolana/prover/server/prover defines marshall and proving system glue code
5. prover/server/server implements the prover server that clients call to get proofs
6. non _test.go files must not contain any code that is only used in tests
7. crypto/ holds generic cryptography and never imports protocol packages
8. a gadget checks each precondition that compilation can decide in the code that relies on it, and the check fails compilation. Witness-value bounds and canonicality stay caller obligations that constraints prove.
   - a deferred argument refuses queries after it snapshots them, and a row table refuses inserts after its first lookup
   - a builder keeps its own copy of every slice it holds for deferred use
   - a nonnative hint encoder checks the signed window its decoder assumes, the ed25519 and x25519 hint encoders pass raw limbs and every such hint feeds a constrained output
   - a failed optimization precondition falls back, and a failed correctness precondition panics
   - an element carries the layout of its field and no field operation accepts another layout
   - a field refuses a layout whose top limb would hold no modulus bit, in construction and in hint headers
