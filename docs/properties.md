## Circuits

### SPP Circuit

1. Every input must be able to originate from a different Merkle tree.
2. **Balance check**
    1. For every asset the sum input amounts must equal sum output + public amount.
    2. public amount must belong to an asset
3. **Nullifier**
    1. it must not be possible to create a dummy nullifier that collides with a real nullifier
    2. must be deterministically derived from their UTXO
    3. all nullifiers in a transaction must be unique
4. **Inputs**
    1. UTXO hash is well formed
    2. nullifier hash is well formed
    3. **inclusion - merkle proof verifies inclusion for the utxo hash for a root that is a public input**
    4. **non inclusion - non-inclusion proof verifies non inclusion of the nullifier for a root that is a public input**
    5. owner must be either marked as signer by public input or have signed with a p256 signature
5. **Outputs**
    1. well formed
    2. dummy: all zero except blinding
6. External data hash is constrained
7. **Confidentiality**
    1. for every input and output the owner public key must be a public input
8. **Anonymity**
    1. owners of UTXOs are not 
9. **Privacy:**
    1. UTXO hash does not reveal, owner, amount, asset, or data stored inside
    2. nullifier does not reveal which UTXO it belongs to
10. **Address:**
    1. only a signer can create an address for herself
    2. an address cannot collide with a nullifier of a real UTXO
11. **Private Transaction Hash**
    1. contains all input, output, address UTXO hashes

### Merge Circuit

1. no signer check
2. cannot change owner
3. input, output, balance check same as transfer circuit, no address creation
4. verifiable encryption

### Zone Authority Circuit

1. no signer check
2. input, output, balance check same as transfer circuit


## Shielded Pool Program

1. **transact**
    1. Every UTXO hash is inserted into a Merkle tree
    2. at most 1 output Merkle tree per instruction
    3. multiple input Merkle trees are allowed
    4. input tree can be different from output trees
    5. every output utxo hash
        1. is public input to the zk proof verification
        2. is inserted into the output Merkle tree
        3. exists a view tag that is included in the zk proof verification
    6. every nullifier
        1. is inserted into the correct nullifier queue
        2. is included in the zk proof verification 
    7. ring circuits cannot be used from
2. **deposit**
    1. produces a well formed UTXO that is appended to the Merkle tree
    2. transfers correct deposited asset amount
3. **merge**
    1. merge must be enabled in registry account 
4. **ring instructions**
    1. Same as default + ring authority check (ring pda must be inited, active and signer)
    2. deposit
    3. transact
5. **batch update nullifier tree**
    1. only forester authority can execute
    2. Batched tree:
      1. cannot deadlock
      2. can only update the tree with values from queue
      3. can only update the tree with values from complete zkp batches in the queue
