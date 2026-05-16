
## Design Principles

1. Simplicity
    1. the system program is a basic shielded pool program with minimal functionality.
2. Versatility
    1. utxos can have a program owner

## General Requirements

1. P256 signature verification in circuit
2. eddsa signature verified by the shielded pool solana program (account info is signer) that is  
3. protocol program structure: many policy programs that are not security relevant beyond the pocket they enforce the policy for, one minimal shielded pool program
4. Shielded pool program is utxo serialiyzation agnostic, we will implement different schemas
5. spl tokens that back utxo balances live in spl interface token accounts owned by the shielded pool program 
6.

## Encryption Requirements:

1. cipher text MUST be as small as possible
2. asset SHOULD be a u64 ID not a Pubkey
3. ephemeral_pubkey secret derivation KDF(user/shared secret, first nullifier)
4. we SHOULD have different encryption schemas:

TODO:
1. shield without proof doesnt store decrypted utxos, we need to handle this in the user flow diagrams and photon indexer
2. Be smart about Utxo hash, group the owner, and blinding into a sub hash, so that we
3. Pubkeys are encoded as Poseidon(pubkey_low, pubkey_high) Should this encoding include a prefix which signature scheme the pubkey is of?


Options for Fetch Performance:
1. user nonce + nonce nullifier
  1. a nullifier is derived from the nonce and inserted into the nullifier tree
  2. we can rerandomize the nonce_nullifier and use it to fetch encrypted utxos. Rerandomization makes it harder to cluster failed requests. Does that work?
  3. issues this doesnt work for unsolicited transfers for that we need FMD or sth else
  4. users should request transfers and include an address in the request
2. FMD
3. Encrypt the pubkeys to an RPC
4. Encrypt the whole cipher text to an RPC
