# Padding-independent private transaction hash

Status: proposal, 2026-09-25. Not implemented in the SPP circuits or in
[`spec.md`](spec.md). `sdk-tests/timelock-escrow/arkworks` assumes it.

## Problem

A ZK program's logic proof shares [`private_tx_hash`](spec.md#private-transaction-hash)
with the SPP proof. The hash chains fixed slot vectors with `HashChain4`: one entry per input
slot and per output slot, with `0` for every padding slot. Padding therefore enters the chains
by position, and a logic proof pairs only with an SPP proof whose shape and padding layout it
reproduces exactly:

- A logic circuit is compiled for one SPP shape. `TokenUtxo<2>` with one real input still
  hashes two input slots, and the client has to put the SPP's dummy in the slot the logic
  circuit left empty.
- A logic circuit cannot spend a variable number of UTXOs without paying for the largest shape
  and fixing where the SPP places its dummies.
- Clients pad outputs with owner-bound zero-value outputs, not [empty UTXOs](spec.md#empty-utxo).
  A padding output is then a real output, so its hash enters the output chain and the logic
  circuit has to create it.

The hash also covers `external_data_hash`, so a logic proof cannot be computed before the outputs
are encrypted.

## Proposal

### Nonzero hash chain

```
nonzero_hash_chain(values):
    acc = 0
    for v in values:
        acc = (v == 0) ? acc : Poseidon(acc, v)
    return acc
```

The result depends only on the nonzero entries and their order. Zero entries can be anywhere,
and a list without nonzero entries hashes to `0`.

### Private transaction hash

```
private_tx_hash = Poseidon(nonzero_hash_chain(input_utxo_hashes),
                           nonzero_hash_chain(output_utxo_hashes),
                           nonzero_hash_chain(address_nullifiers),
                           private_tx_blinding)
```

- The slot vectors are the ones the SPP circuit builds today: real UTXO hashes and `0` elsewhere
  for inputs and outputs, address nullifiers and `0` elsewhere for addresses.
- `external_data_hash` leaves the hash. It stays a separate public input of the SPP proof, which
  SPP recomputes from the instruction data, so the SPP proof still covers the external data.
- P256 owners sign `SHA-256(private_tx_hash || external_data_hash)`. SPP computes the digest.
  Ed25519 owners are covered by the Solana transaction signature, as today.

### Output padding

Unused output slots hold [empty UTXOs](spec.md#empty-utxo), as the spec already describes. An
empty UTXO contributes `0` to the output chain, so it is skipped.

An empty output publishes what an owner-bound padding output publishes today: the owner tag and a
ciphertext of a zero-amount SOL plaintext for a real output owner, the sender when it owns one.
The circuit already accepts that tag (see "Output owner tag" in
[SPP Proof](spec.md#spp-proof---solana-privacy-zk-proof)). A wallet that decrypts the ciphertext
recomputes an owned UTXO hash, which does not match the empty UTXO's, and skips the slot.

A transaction without a real output cannot pad this way when its only owner signer is the payer:
no participant is left for the tag. Its logic circuit creates a zero-value output instead.

## Soundness

- **Collision resistance.** Two different sequences of nonzero entries hash to the same chain only
  if Poseidon has a collision or `Poseidon(acc, v) = 0` for some step, which is a preimage of `0`.
  Walking both chains back from the equal result, each step either finds a collision or strips one
  equal entry from both sequences. If one sequence runs out first, the other chain reached `0`
  after a nonzero step.
- **Real entries are nonzero.** A UTXO hash or address nullifier equal to `0` is a Poseidon
  preimage of `0`. Skipping zero entries therefore never drops a real UTXO or address.
- **What positions still bind.**
  - Output `i`'s hash includes its [blinding](spec.md#output-blinding) `blinding_i`, so an
    output is still bound to its slot. The logic circuit derives the blinding from its own output
    index, and the SPP proof places real outputs first, in that order.
  - `first_nullifier` enters through `private_tx_blinding` as before, so slot 0 stays bound.
  - The order of real inputs, of real outputs and of addresses is bound. Only the positions of
    dummies are not.
- **External data.** Removing `external_data_hash` unbinds the logic proof from the ciphertexts
  and the instruction fields, not the SPP proof. The SPP proof keeps it as a public input, the
  P256 signature covers it, and the Solana transaction signatures cover the instruction. The
  logic proof binds the UTXOs it spends and creates, and each input's nullifier stops a replay
  into a second instruction. Public deposits and withdrawals are external data, so a logic
  proof whose rules depend on them binds them in its own public input.

## Effect on ZK programs

- A logic circuit chains only the UTXOs it spends and creates. Any SPP shape with enough input
  and output slots pairs with the logic proof, and the client picks the smallest one.
- Dummies inside the logic circuit, such as unused `TokenUtxo<N>` slots, hash to `0` and are
  skipped as well. The SPP pads with its own dummies in any slot the input tree order allows.
- The logic proof no longer depends on the encryption, so it can be computed before or in
  parallel with the ciphertexts.

## Required changes

All of the following change together, in one key rotation.

| Component | Change |
| --- | --- |
| Go gadget | `NonZeroHashChain` next to `HashChain4` in `prover/server/circuits/gadget/hashchain.go`. |
| SPP transfer circuits | `shared/private_tx_hash.go` chains with `NonZeroHashChain` and drops `ExternalDataHash`. `shared/transaction.go` and the P256 rail take the new digest. |
| Other circuits that recompute the hash | `spp_merge/shared/transaction.go`, `circuits/ring-utils/private_tx_hash.go`, `sdk-libs/gnark-sdk/hash.go` and the gnark example circuits (`sdk-tests/dynamic-swap/prover`, timelock-escrow). |
| Host mirrors | `prover/server/prover-test/spp/protocol/transcript.go` and `spptest`. |
| Native hashers | A `nonzero_hash_chain` in `zolana-hasher`, used by `zolana_program::PrivateTxHash`, `SppProofInputs::private_tx_hash` (`sdk-libs/transaction`), the client proof assembly (`sdk-libs/client`), `custom-rings/policy` and the TS SDK (`client/prover`, `ring`, `transaction/instructions/transact.ts`). |
| Output padding | `sdk-libs/transaction` pads with owner-bound zero outputs and pads with empty UTXOs instead. The TS SDK already pads with empty UTXOs, with random bytes in place of a ciphertext. |
| SPP program | The P256 digest in `programs/shielded-pool/src/instructions/transact/verify.rs` covers `private_tx_hash || external_data_hash`. |
| ZK program examples | The SDKs that recompute the hash for their logic proofs (`sdk-tests/dynamic-swap/sdk`) switch to the new definition. |
| Keys | Every transfer, merge, ring, policy and example circuit that computes the hash gets new proving and verifying keys, following [the rotation rules](spec.md#circuit-variants). |
| Test vectors | `sdk-libs/transaction/tests/hash_vectors.rs`, `sdk-libs/client/tests/assembly_vectors.rs`, the Go protocol tests and the recorded photon fixtures that embed transact instruction data. |
| Spec | [Private transaction hash](spec.md#private-transaction-hash), the `external_data_hash` paragraph and the P256 message hash row in [SPP Proof](spec.md#spp-proof---solana-privacy-zk-proof). |

## Cost

Per chain of `n` slots, `HashChain4` costs `ceil((n - 1) / 3)` width-5 Poseidon permutations. The
nonzero chain costs `n` width-3 permutations, one zero test and one select. The SPP circuit hashes
`2 * n_inputs + n_outputs` slots. The largest shape, `36x2`, goes from 25 width-5 permutations to
74 width-3 ones. The shape's 36 inclusion and non-inclusion proofs dominate either way.

A logic circuit pays only for the UTXOs it handles. A slot that is a constant `0` costs nothing.

## Alternatives considered

- **No protocol change.** The logic circuit takes the SPP shape as a private input, chains its
  entries with the SPP's padding and selects the intermediate chain value at the real count. It
  pays for the largest shape it supports and has to know the SPP's padding layout, so it is still
  coupled to the SPP.
- **Real entries first, then a count.** The SPP proves that slots from `k` on are dummies and
  publishes the chain over the first `k`. It needs the same width-3 chain, because `HashChain4`'s
  groups of three do not give a prefix value at every `k`, and it forbids dummies between real
  inputs, which the input tree order uses.

## Acceptance

- The Go gadget, the Go host mirror and the Rust and TS native chains agree on vectors with zero
  entries at every position, including an all-zero list.
- For the same real UTXOs, `private_tx_hash` is equal under every supported shape and every dummy
  placement the builders produce.
- The SPP, merge, ring and policy test suites pass with the rotated keys.
- The arkworks timelock escrow pairs one logic proof with both the `1x2` and the `2x2` SPP shape.
