
### Issues:
1. P256 proof generation is too slow for client side proof generation
2. Implementation overhead to test it on many platforms



### Split the proof up - Mitigation against slow proof generation
| 29 | UtxoProof | Groth16 proof: proves ownership + balance conservation |
| 30 | TreeProof | Groth16 proof: proves that UTXOs exist in a UTXO tree and nullifiers don't exist yet in a Nullifier tree |
The TreeProof can be computed by a third party without disclosing any of the transaction information.
With a new syscall we can batch the verification.
