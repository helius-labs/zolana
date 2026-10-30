Goal:

1. streamline rust and ts client sdks and make them consistent
2. refactor repo structure so that rules which pr should modify which crates and which it should not modify are easier to enforce
3.



Ideas:

1. rust and typescript sdks should have matching external apis and test vectors
2. apis are defined in a sdk\_spec.md (current public api md is a start), test vectors are defined in json and run in unit&amp;integration tests in both rust and typescript
3. new directory structure: sdks/rust-client sdks/typescript-client sdks/program
4. cli should move into sdks
5. circuits should move into program-libs, or move program-libs into programs/libs programs/circuits
6. or shielded-pool/program shielded-pool/libs, shielded-pool/circuits, user-registry/program, user-registry/interface, user-registry/tests
7. services/photon services/prover
8. Should 
9. move gnark ffi to  zk tools



Add review rules:

1.



Questions:

1. can we reduce program-tests dependence on sdks? (maybe limiting to transaction and )
