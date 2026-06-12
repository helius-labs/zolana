## Questions:

# Naming
1. shield, unshield
2. wrap, unwrap
3. deposit, withdraw

# Nullifier Key derivation
1. consider to derive it from the root viewing key, then it would rotate with every viewing key rotation but that should be fine since we commit to the nullifier pubkey in the utxo hash.
