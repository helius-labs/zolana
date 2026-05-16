## Questions:

1. can the pocket authority signature and pocket the utxo is in be public?
2. what are critical user flows?
    1. unsolicited transfer
3. Should we use P256 or Poseidon EDDSA as proof of utxo ownership?
    1. tradeoffs:
        1. Proving time: 350ms (m4max) vs 15ms (m4max), 5s (solana seeker) vs 350ms (solana seeker), 1s (TEE aws nitro)
        2. pro (P256):  can be used for both encryption (ECDF) and signature, Passkey signature (wallets already support it)
        3. con (P256): proving time (requires server proofs)
        4. pro (Poseidon eddsa): low proving time
        5. con (Poseidon EDDSA): low ecosystem support
4. Does splitting into two proofs make sense?
    1. pro: we can split proof generation and preserve privacy utxo proof and tree proof
    2. pro: even if we generate both proofs in the server we can parallelize proof generation
    3. con: additional instruction data 128 bytes and 100k CU
5. Tree heights
    1. nullifier tree 40
    2. state tree 40 (we need benchmarks)
6. Own ledger
    1. deposit limits, withdraw limits, 
7. rfq
    1. completely off-chain
    2. just two signatures
8. TODO:
    1. define all RPC user flows
    2. define utxo data structure
    2. encryption of outputs (actual 
    3. shielded escrow (PSP) diagram akin to the 
    4. mapping
    5. **Docs**
        1. you are institution how can you use it
        2. how you can use it
        3. tradeoffs
        4. here is how you can integrate
    6. add PSP seeds hash
    7. what if we define blinding Poseidon(rnd, current slot) to add an additional safeguard that every utxo is different
