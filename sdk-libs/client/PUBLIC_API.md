# Public functions in `spr-client`

The marked changes below are implemented. The numbered inventory retains the earlier signatures for migration reference; the request, message-construction and scanning sections at the end describe the replacement API. Ring builders now expose `assemble`, and `prover::requests` supplies the circuit requests accepted by `Prover::prove` and `AsyncProverClient::prove`.

Public API specification based on [`src/lib.rs`](src/lib.rs) and its modules. Entries marked **Proposed** describe intended API changes. Entries marked **To be deleted** retain the current signatures for migration planning; unmarked entries describe the current implementation. Paths use the shortest public reexport. Signatures retain the source type names, which may need imports from their defining crates.

Total: **315 entries**, including proposed API changes, blocking and async variants, methods declared by public traits, explicit implementations of standard traits, and the three directly reexported TEE functions.

Trait methods are listed under their trait rather than repeated for each implementation. Import the trait to call these methods on a client. The implementation table below identifies the concrete clients and adapters. Some RPC methods have default implementations that return an unsupported-operation error; their presence on the trait does not mean every adapter supports them.

Feature requirements are shown on individual entries. `reqwest` is enabled by default; `solana-rpc` enables the concrete Solana adapters, and `client` enables `solana-rpc`. An entry without a feature annotation is available without optional features.

This inventory excludes private and `pub(crate)` items, methods on private helper types, tests, compiler-generated/derived methods, blanket methods from dependency traits, and destructors. Methods defined by dependency-owned reexported types remain documented in their originating crates; the dependency reexports are linked at the end.

## Trait implementations

| Trait | Implementations declared in this crate |
| --- | --- |
| `AsyncIndexer` | `impl<I: AsyncRpc + AsyncWitnessReader> AsyncIndexer for I` |
| `AsyncRpc` | `impl AsyncRpc for AsyncSolanaRpc`<br>`impl AsyncRpc for AsyncZolanaIndexer`<br>`impl<R: AsyncRpc, I: AsyncIndexer> AsyncRpc for AsyncZolanaClient<R, I>`<br>`impl<T: Rpc + Send + Sync + 'static> AsyncRpc for Blocking<T>` |
| `AsyncWitnessReader` | `impl AsyncWitnessReader for AsyncZolanaIndexer`<br>`impl<T: Rpc + WitnessReader + Send + Sync + 'static> AsyncWitnessReader for Blocking<T>` |
| `BlockingIndexer` | `impl<I: Rpc + WitnessReader + Send + Sync + 'static> BlockingIndexer for I` |
| `BlockingRpc` | `impl<R: Rpc + Send + Sync + 'static> BlockingRpc for R` |
| `ProofAuthority` | `impl ProofAuthority for NullifierKey`<br>`impl ProofAuthority for ShieldedKeypair` |
| `ProveRequest` | `impl ProveRequest for AnonymousEddsaTransferInputs` |
| `Prover` | `impl Prover for ProverClient` |
| `ProverExt` | `impl<P: Prover + ?Sized> ProverExt for P` |
| `Rpc` | `impl Rpc for SolanaRpc`<br>`impl Rpc for ZolanaIndexer`<br>`impl<R: BlockingRpc, I: BlockingIndexer> Rpc for ZolanaClient<R, I>` |
| `WitnessReader` | `impl WitnessReader for ZolanaIndexer` |

`SolanaRpc` and `AsyncSolanaRpc` require `solana-rpc`. The marker traits `AsyncIndexer`, `BlockingRpc`, and `BlockingIndexer` add bounds but declare no functions of their own.

## `spr_client::ZolanaClient`

### Constructors

Create a client.

1. `spr_client::ZolanaClient::new` — **Proposed**

    ```rust
    pub fn new(url: impl AsRef<str>, prover_tee: Option<TeePolicy>) -> Result<Self, ClientError>
    ```

    Default constructor: create the RPC, indexer, and prover clients from one service URL.

    Context: `impl ZolanaClient<SolanaRpc, ZolanaIndexer>`.

    Requires: `reqwest` and `solana-rpc`.

    The URL is used as the shared gateway URL for all three adapters. Each adapter appends its service paths. Supply a reviewed TEE policy for remote proving; `None` permits plaintext only for loopback development.

2. `spr_client::ZolanaClient::from_parts` — **Proposed replacement** for [current `new`](src/client/mod.rs#L282) and [`with_prover`](src/client/mod.rs#L291)

    ```rust
    pub fn from_parts(rpc: R, indexer: I, prover: impl Prover + 'static) -> Self
    ```

    Construct a client from services the caller has already created. Accept any implementation of `Prover`, including `ProverClient` or an in-process prover. This replaces the separate `ZolanaClient::with_prover` constructor.

    Context: `impl<R, I> ZolanaClient<R, I>`.

3. `spr_client::ZolanaClient::from_urls` — **Proposed signature change** from [current implementation](src/client/mod.rs#L354)

    ```rust
    pub fn from_urls(rpc_url: impl AsRef<str>, indexer_url: impl AsRef<str>, prover_url: impl AsRef<str>, prover_tee: Option<TeePolicy>) -> Result<Self, ClientError>
    ```

    Construct all three service clients from their URLs. Use `from_parts` for services the caller has already created.

    Context: `impl ZolanaClient<SolanaRpc, ZolanaIndexer>`.

    Requires: `reqwest` and `solana-rpc`.

4. `spr_client::ZolanaClient::from_urls_allowing_insecure_http` — **Proposed signature change** from [current implementation](src/client/mod.rs#L372)

    ```rust
    pub fn from_urls_allowing_insecure_http(rpc_url: impl AsRef<str>, indexer_url: impl AsRef<str>, prover_url: impl AsRef<str>, prover_tee: Option<TeePolicy>) -> Self
    ```

    Construct all three service clients from their URLs without the transport security check.

    Context: `impl ZolanaClient<SolanaRpc, ZolanaIndexer>`.

    Requires: `reqwest` and `solana-rpc`.

### To be deleted

`spr_client::ZolanaClient::with_prover` — **To be deleted** ([current implementation](src/client/mod.rs#L291)).

```rust
pub fn with_prover(rpc: R, indexer: I, prover: impl Prover + 'static) -> Self
```

Replace calls with `ZolanaClient::from_parts(rpc, indexer, prover)`. The proposed `from_parts` accepts any `Prover` implementation, so a separate constructor is unnecessary. This removal note is outside the numbered target API inventory.

### Configuration builders

Consume the client and return it with updated settings.

5. `spr_client::ZolanaClient::with_compute_unit_limit` — [source](src/client/mod.rs#L302)

    ```rust
    pub fn with_compute_unit_limit(mut self, cu_limit: u32) -> Self
    ```

    Context: `impl<R, I> ZolanaClient<R, I>`.

6. `spr_client::ZolanaClient::with_priority_fee` — [source](src/client/mod.rs#L307)

    ```rust
    pub fn with_priority_fee(mut self, lamports: u64) -> Self
    ```

    Context: `impl<R, I> ZolanaClient<R, I>`.

7. `spr_client::ZolanaClient::with_indexer_config` — [source](src/client/mod.rs#L322)

    ```rust
    pub fn with_indexer_config(mut self, config: IndexerRpcConfig) -> Self
    ```

    Context: `impl<R, I> ZolanaClient<R, I>`.

8. `spr_client::ZolanaClient::with_indexer_poll_config` — [source](src/client/mod.rs#L317)

    ```rust
    pub fn with_indexer_poll_config(mut self, config: IndexerPollConfig) -> Self
    ```

    Context: `impl<R, I> ZolanaClient<R, I>`.

9. `spr_client::ZolanaClient::with_proof_data_source` — [source](src/client/mod.rs#L329)

    ```rust
    pub fn with_proof_data_source(mut self, source: ProofDataSource) -> Self
    ```

    Context: `impl<R, I> ZolanaClient<R, I>`.

### Accessors

Read configuration or borrow services.

10. `spr_client::ZolanaClient::compute_budget` — [source](src/client/mod.rs#L313)

    ```rust
    pub fn compute_budget(&self) -> ComputeBudgetConfig
    ```

    Context: `impl<R, I> ZolanaClient<R, I>`.

11. `spr_client::ZolanaClient::rpc` — [source](src/client/mod.rs#L334)

    ```rust
    pub fn rpc(&self) -> &R
    ```

    Context: `impl<R, I> ZolanaClient<R, I>`.

12. `spr_client::ZolanaClient::indexer` — [source](src/client/mod.rs#L338)

    ```rust
    pub fn indexer(&self) -> &I
    ```

    Context: `impl<R, I> ZolanaClient<R, I>`.

### Transaction operations

Prove transactions or wait for confirmation and indexing.

13. `spr_client::ZolanaClient::prove_transact` — **To be deleted** — [source](src/client/transaction.rs#L115)

    ```rust
    pub fn prove_transact(&self, proof_inputs: SppProofInputs, config: Option<IndexerRpcConfig>, authority: &dyn ProofAuthority) -> Result<TransactIxData, ClientError>
    ```

    Context: `impl<R: BlockingRpc, I: BlockingIndexer> ZolanaClient<R, I>`.

14. `spr_client::ZolanaClient::confirm_private_transaction_sync` — [source](src/client/confirmation.rs#L29)

    ```rust
    pub fn confirm_private_transaction_sync(&self, signature: Signature) -> Result<(), ClientError>
    ```

    Context: `impl<R: BlockingRpc, I: BlockingIndexer> ZolanaClient<R, I>`.

## `spr_client::AsyncZolanaClient`

15. `spr_client::AsyncZolanaClient::compute_budget` — [source](src/client/mod.rs#L142)

    ```rust
    pub fn compute_budget(&self) -> ComputeBudgetConfig
    ```

    Context: `impl<R, I> AsyncZolanaClient<R, I>`.

16. `spr_client::AsyncZolanaClient::confirm_private_transaction` — [source](src/client/confirmation.rs#L18)

    ```rust
    pub async fn confirm_private_transaction(&self, signature: Signature) -> Result<(), ClientError>
    ```

    Context: `impl<R: AsyncRpc, I: AsyncIndexer> AsyncZolanaClient<R, I>`.

17. `spr_client::AsyncZolanaClient::from_urls` — [source](src/client/mod.rs#L234)

    ```rust
    pub fn from_urls(rpc: R, indexer_url: impl AsRef<str>, prover_url: impl Into<String>, prover_tee: Option<TeePolicy>) -> Result<Self, ClientError>
    ```

    Context: `impl<R> AsyncZolanaClient<R, AsyncZolanaIndexer>`.

    Requires: `#[cfg(feature = "reqwest")]`.

18. `spr_client::AsyncZolanaClient::from_urls_allowing_insecure_http` — [source](src/client/mod.rs#L256)

    ```rust
    pub fn from_urls_allowing_insecure_http(rpc: R, indexer_url: impl AsRef<str>, prover_url: impl Into<String>, prover_tee: Option<TeePolicy>) -> Self
    ```

    Context: `impl<R> AsyncZolanaClient<R, AsyncZolanaIndexer>`.

    Requires: `#[cfg(feature = "reqwest")]`.

19. `spr_client::AsyncZolanaClient::indexer` — [source](src/client/mod.rs#L177)

    ```rust
    pub fn indexer(&self) -> &I
    ```

    Context: `impl<R, I> AsyncZolanaClient<R, I>`.

20. `spr_client::AsyncZolanaClient::new` — [source](src/client/mod.rs#L106)

    ```rust
    pub fn new(rpc: R, indexer: I, prover: AsyncProverClient) -> Self
    ```

    Context: `impl<R, I> AsyncZolanaClient<R, I>`.

21. `spr_client::AsyncZolanaClient::prove_confidential_transfer_result` — **To be deleted** — [source](src/client/transaction.rs#L48)

    ```rust
    pub async fn prove_confidential_transfer_result(&self, result: &TransferProofResult) -> Result<ProofCompressed, ClientError>
    ```

    Context: `impl<R: AsyncRpc, I: AsyncIndexer> AsyncZolanaClient<R, I>`.

22. `spr_client::AsyncZolanaClient::prove_transact` — **To be deleted** — [source](src/client/transaction.rs#L63)

    ```rust
    pub async fn prove_transact(&self, proof_inputs: SppProofInputs, config: Option<IndexerRpcConfig>, authority: &dyn ProofAuthority) -> Result<TransactIxData, ClientError>
    ```

    Context: `impl<R: AsyncRpc, I: AsyncIndexer> AsyncZolanaClient<R, I>`.

23. `spr_client::AsyncZolanaClient::rpc` — [source](src/client/mod.rs#L173)

    ```rust
    pub fn rpc(&self) -> &R
    ```

    Context: `impl<R, I> AsyncZolanaClient<R, I>`.

24. `spr_client::AsyncZolanaClient::with_compute_unit_limit` — [source](src/client/mod.rs#L130)

    ```rust
    pub fn with_compute_unit_limit(mut self, cu_limit: u32) -> Self
    ```

    Context: `impl<R, I> AsyncZolanaClient<R, I>`.

25. `spr_client::AsyncZolanaClient::with_indexer_config` — [source](src/client/mod.rs#L154)

    ```rust
    pub fn with_indexer_config(mut self, config: IndexerRpcConfig) -> Self
    ```

    Context: `impl<R, I> AsyncZolanaClient<R, I>`.

26. `spr_client::AsyncZolanaClient::with_indexer_poll_config` — [source](src/client/mod.rs#L149)

    ```rust
    pub fn with_indexer_poll_config(mut self, config: IndexerPollConfig) -> Self
    ```

    Context: `impl<R, I> AsyncZolanaClient<R, I>`.

27. `spr_client::AsyncZolanaClient::with_priority_fee` — [source](src/client/mod.rs#L135)

    ```rust
    pub fn with_priority_fee(mut self, lamports: u64) -> Self
    ```

    Context: `impl<R, I> AsyncZolanaClient<R, I>`.

28. `spr_client::AsyncZolanaClient::with_proof_data_source` — [source](src/client/mod.rs#L163)

    ```rust
    pub fn with_proof_data_source(mut self, source: ProofDataSource) -> Self
    ```

    Context: `impl<R, I> AsyncZolanaClient<R, I>`.

29. `spr_client::AsyncZolanaClient::with_prover` — [source](src/client/mod.rs#L115)

    ```rust
    pub fn with_prover(rpc: R, indexer: I, prover: impl Prover + 'static) -> Self
    ```

    Context: `impl<R, I> AsyncZolanaClient<R, I>`.

## `spr_client::Submission`

30. `spr_client::Submission::finish_unsigned` — [source](src/client/transaction.rs#L184)

    ```rust
    pub async fn finish_unsigned<R: AsyncRpc, I: AsyncIndexer>(&self, client: &AsyncZolanaClient<R, I>) -> Result<UnsignedMessage, ClientError>
    ```

    Context: `impl<'a> Submission<'a>`.

31. `spr_client::Submission::finish_unsigned_sync` — [source](src/client/transaction.rs#L276)

    ```rust
    pub fn finish_unsigned_sync<R: BlockingRpc, I: BlockingIndexer>(&self, client: &ZolanaClient<R, I>) -> Result<UnsignedMessage, ClientError>
    ```

    Context: `impl<'a> Submission<'a>`.

32. `spr_client::Submission::new` — [source](src/client/transaction.rs#L152)

    ```rust
    pub fn new(signed: &'a SignedPrivateTransaction, fee_payer: Address, authority: &'a dyn ProofAuthority) -> Self
    ```

    Context: `impl<'a> Submission<'a>`.

33. `spr_client::Submission::send` — [source](src/client/transaction.rs#L263)

    ```rust
    pub async fn send<R: AsyncRpc, I: AsyncIndexer>(&self, client: &AsyncZolanaClient<R, I>, signers: &[&dyn Signer]) -> Result<Signature, ClientError>
    ```

    Context: `impl<'a> Submission<'a>`.

34. `spr_client::Submission::send_sync` — [source](src/client/transaction.rs#L284)

    ```rust
    pub fn send_sync<R: BlockingRpc, I: BlockingIndexer>(&self, client: &ZolanaClient<R, I>, signers: &[&dyn Signer]) -> Result<Signature, ClientError>
    ```

    Context: `impl<'a> Submission<'a>`.

35. `spr_client::Submission::with_prover` — [source](src/client/transaction.rs#L166)

    ```rust
    pub fn with_prover(mut self, prover: Arc<dyn Prover>) -> Self
    ```

    Context: `impl<'a> Submission<'a>`.

## `spr_client::MergeSubmission`

36. `spr_client::MergeSubmission::finish_unsigned` — [source](src/client/merge.rs#L168)

    ```rust
    pub async fn finish_unsigned<R: AsyncRpc, I: AsyncIndexer>(&self, client: &AsyncZolanaClient<R, I>, fee_payer: Address) -> Result<UnsignedMessage, ClientError>
    ```

    Context: `impl<'a> MergeSubmission<'a>`.

37. `spr_client::MergeSubmission::finish_unsigned_sync` — [source](src/client/merge.rs#L213)

    ```rust
    pub fn finish_unsigned_sync<R: BlockingRpc, I: BlockingIndexer>(&self, client: &ZolanaClient<R, I>, fee_payer: Address) -> Result<UnsignedMessage, ClientError>
    ```

    Context: `impl<'a> MergeSubmission<'a>`.

38. `spr_client::MergeSubmission::new` — [source](src/client/merge.rs#L96)

    ```rust
    pub fn new(merge: &'a MergeProofInputs, owner: Address, address: &'a ShieldedAddress, nullifier_key: &'a NullifierKey) -> Self
    ```

    Context: `impl<'a> MergeSubmission<'a>`.

39. `spr_client::MergeSubmission::prove` — [source](src/client/merge.rs#L119)

    ```rust
    pub async fn prove<R: AsyncRpc, I: AsyncIndexer>(&self, client: &AsyncZolanaClient<R, I>) -> Result<ProvedMerge, ClientError>
    ```

    Context: `impl<'a> MergeSubmission<'a>`.

40. `spr_client::MergeSubmission::prove_sync` — [source](src/client/merge.rs#L205)

    ```rust
    pub fn prove_sync<R: BlockingRpc, I: BlockingIndexer>(&self, client: &ZolanaClient<R, I>) -> Result<ProvedMerge, ClientError>
    ```

    Context: `impl<'a> MergeSubmission<'a>`.

41. `spr_client::MergeSubmission::send` — [source](src/client/merge.rs#L191)

    ```rust
    pub async fn send<R: AsyncRpc, I: AsyncIndexer>(&self, client: &AsyncZolanaClient<R, I>, fee_payer: &dyn Signer) -> Result<Signature, ClientError>
    ```

    Context: `impl<'a> MergeSubmission<'a>`.

42. `spr_client::MergeSubmission::send_sync` — [source](src/client/merge.rs#L222)

    ```rust
    pub fn send_sync<R: BlockingRpc, I: BlockingIndexer>(&self, client: &ZolanaClient<R, I>, fee_payer: &dyn Signer) -> Result<Signature, ClientError>
    ```

    Context: `impl<'a> MergeSubmission<'a>`.

43. `spr_client::MergeSubmission::with_prover` — [source](src/client/merge.rs#L112)

    ```rust
    pub fn with_prover(mut self, prover: Arc<dyn Prover>) -> Self
    ```

    Context: `impl<'a> MergeSubmission<'a>`.

## `spr_client::ProvedMerge`

44. `spr_client::ProvedMerge::instruction` — [source](src/client/merge.rs#L82)

    ```rust
    pub fn instruction(&self, payer: Address) -> Instruction
    ```

    Context: `impl ProvedMerge`.

## Free functions

45. `spr_client::assemble` — [source](src/prover/transact/witness.rs#L182)

    ```rust
    pub fn assemble(proof_inputs: SppProofInputs, input_proofs: &[SpendProof], dummy_nullifier_proofs: &[NonInclusionProof]) -> Result<AssembledTransfer, ClientError>
    ```

46. `spr_client::assemble_with_dummy_policy` — [source](src/prover/transact/witness.rs#L190)

    ```rust
    pub fn assemble_with_dummy_policy(proof_inputs: SppProofInputs, input_proofs: &[SpendProof], dummy_nullifier_proofs: &[NonInclusionProof], allow_dummy_inputs: bool) -> Result<AssembledTransfer, ClientError>
    ```

47. `spr_client::attach_input_proofs` — [source](src/prover/transact/witness.rs#L85)

    ```rust
    pub fn attach_input_proofs(inputs: Vec<SppProofInputUtxo>, proofs: &[SpendProof], dummy_nullifier_proofs: &[NonInclusionProof]) -> Result<Vec<TransferInputUtxo>, ClientError>
    ```

48. `spr_client::check_merge_record` — [source](src/client/merge.rs#L236)

    ```rust
    pub fn check_merge_record(record: &UserRecord, owner: Address, address: &ShieldedAddress) -> Result<(), ClientError>
    ```

49. `spr_client::check_service_url` — [source](src/client/validation.rs#L11)

    ```rust
    pub fn check_service_url(url: &str, field: &'static str) -> Result<(), ClientError>
    ```

50. `spr_client::compile_message` — [source](src/rpc/transaction.rs#L19)

    ```rust
    pub fn compile_message(payer: &Address, instructions: &[Instruction], recent_blockhash: Hash, compute_budget: ComputeBudgetConfig) -> Result<VersionedMessage, ClientError>
    ```

51. `spr_client::fetch_asset_id` — [source](src/scan.rs#L295)

    ```rust
    pub fn fetch_asset_id<R: Rpc + ?Sized>(rpc: &R, asset: Address) -> Result<u64, ClientError>
    ```

52. `spr_client::fetch_spl_asset_registrations` — [source](src/scan.rs#L262)

    ```rust
    pub fn fetch_spl_asset_registrations<R: Rpc + ?Sized>(rpc: &R, min_context_slot: Option<u64>) -> Result<Vec<Mint>, ClientError>
    ```

53. `spr_client::indexer::decode_shielded_transaction` — [source](src/indexer/conversion.rs#L99)

    ```rust
    pub fn decode_shielded_transaction(item: spr_api::ShieldedTransaction) -> Result<ShieldedTransaction, ClientError>
    ```

54. `spr_client::input_utxos_from_nullifiers` — [source](src/prover/transact/assembly.rs#L615)

    ```rust
    pub fn input_utxos_from_nullifiers(nullifiers: &[[u8; 32]], tree_indexes: &[u8]) -> Result<Vec<InputUtxo>, ClientError>
    ```

55. `spr_client::prover::field::be` — [source](src/prover/field.rs#L21)

    ```rust
    pub fn be(value: &[u8; 32]) -> BigUint
    ```

56. `spr_client::prover::field::right_align` — [source](src/prover/field.rs#L5)

    ```rust
    pub fn right_align<const N: usize>(bytes: &[u8; N]) -> [u8; 32]
    ```

57. `spr_client::prover::field::right_align_slice` — [source](src/prover/field.rs#L12)

    ```rust
    pub fn right_align_slice(bytes: &[u8]) -> Result<[u8; 32], ClientError>
    ```

58. `spr_client::prover::known_proving_keys` — [source](src/prover/proving_key.rs#L123)

    ```rust
    pub fn known_proving_keys() -> impl Iterator<Item = (&'static str, [u8; 32])>
    ```

59. `spr_client::prover::redact_api_key` — [source](src/prover/endpoint.rs#L126)

    ```rust
    pub fn redact_api_key(url: &str) -> String
    ```

60. `spr_client::prover::transact::anonymous_ring_eddsa::anonymous_signer_pk_hashes` — **To be deleted** — [source](src/prover/transact/anonymous_ring_eddsa.rs#L187)

    ```rust
    pub fn anonymous_signer_pk_hashes(transaction: &SppProofInputs, owner: &PublicKey) -> Result<Vec<[u8; 32]>, ClientError>
    ```

61. `spr_client::prover::verify_proof_statement` — [source](src/prover/verify.rs#L183)

    ```rust
    pub fn verify_proof_statement(proof: &Proof, public_input_hash: [u8; 32], verifying_key: &'static Groth16Verifyingkey<'static>) -> Result<(), ClientError>
    ```

62. `spr_client::rpc::solana_rpc::transact_output_view_tags_from_instruction_groups` — [source](src/rpc/solana_rpc/transaction.rs#L39)

    ```rust
    pub fn transact_output_view_tags_from_instruction_groups(groups: &ConfirmedInstructionGroups) -> Result<Vec<[u8; 32]>, ClientError>
    ```

    Requires: `#[cfg(feature = "solana-rpc")]`.

63. `spr_client::sign_transaction` — [source](src/rpc/transaction.rs#L51)

    ```rust
    pub fn sign_transaction(message: VersionedMessage, signers: &[&dyn Signer]) -> Result<VersionedTransaction, ClientError>
    ```

64. `spr_client::spawn_prover` — [source](src/prover/client.rs#L1130)

    ```rust
    pub fn spawn_prover() -> Result<(), ClientError>
    ```

    Requires: `#[cfg(feature = "reqwest")]`.

65. `spr_client::timing::note` — [source](src/prover/timing.rs#L18)

    ```rust
    pub fn note(round: usize, key: &str, value: usize)
    ```

66. `spr_client::transaction_size` — [source](src/rpc/transaction_size.rs#L37)

    ```rust
    pub fn transaction_size(payer: &Address, instructions: &[Instruction], compute_budget: ComputeBudgetConfig) -> Result<TransactionSize, ClientError>
    ```

67. `spr_client::user_registry::build_key_update_transaction` — [source](src/user_registry.rs#L213)

    ```rust
    pub async fn build_key_update_transaction<R: AsyncRpc>(rpc: &R, owner: Pubkey, address: &ShieldedAddress, payer: Option<Pubkey>) -> Result<Option<VersionedMessage>, ClientError>
    ```

68. `spr_client::user_registry::build_key_update_transaction_sync` — [source](src/user_registry.rs#L229)

    ```rust
    pub fn build_key_update_transaction_sync<R: Rpc>(rpc: &R, owner: Pubkey, address: &ShieldedAddress, payer: Option<Pubkey>) -> Result<Option<VersionedMessage>, ClientError>
    ```

69. `spr_client::user_registry::build_registration_transaction` — [source](src/user_registry.rs#L169)

    ```rust
    pub async fn build_registration_transaction<R: AsyncRpc>(rpc: &R, owner: Pubkey, address: &ShieldedAddress, payer: Option<Pubkey>) -> Result<Option<VersionedMessage>, ClientError>
    ```

70. `spr_client::user_registry::build_registration_transaction_sync` — [source](src/user_registry.rs#L186)

    ```rust
    pub fn build_registration_transaction_sync<R: Rpc>(rpc: &R, owner: Pubkey, address: &ShieldedAddress, payer: Option<Pubkey>) -> Result<Option<VersionedMessage>, ClientError>
    ```

71. `spr_client::user_registry::decode_user_record_account` — [source](src/user_registry.rs#L412)

    ```rust
    pub fn decode_user_record_account(account: &solana_account::Account) -> Result<UserRecord, ClientError>
    ```

72. `spr_client::user_registry::ensure_registered` — [source](src/user_registry.rs#L70)

    ```rust
    pub fn ensure_registered<R: Rpc>(rpc: &R, funding: &dyn Signer, keypair: &ShieldedKeypair) -> Result<Option<Signature>, ClientError>
    ```

73. `spr_client::user_registry::fetch_user_record_checked` — [source](src/user_registry.rs#L334)

    ```rust
    pub fn fetch_user_record_checked<R: Rpc>(rpc: &R, owner: Pubkey) -> Result<UserRecord, ClientError>
    ```

74. `spr_client::user_registry::fetch_user_record_optional_checked` — [source](src/user_registry.rs#L348)

    ```rust
    pub fn fetch_user_record_optional_checked<R: Rpc>(rpc: &R, owner: Pubkey) -> Result<Option<UserRecord>, ClientError>
    ```

75. `spr_client::user_registry::fetch_user_record_optional_checked_async` — [source](src/user_registry.rs#L361)

    ```rust
    pub async fn fetch_user_record_optional_checked_async<R: AsyncRpc>(rpc: &R, owner: Pubkey) -> Result<Option<UserRecord>, ClientError>
    ```

76. `spr_client::user_registry::fetch_viewing_key_owners` — [source](src/user_registry.rs#L378)

    ```rust
    pub fn fetch_viewing_key_owners<R: Rpc>(rpc: &R) -> Result<HashMap<[u8; X25519_PUBKEY_LEN], Pubkey>, ClientError>
    ```

77. `spr_client::user_registry::fetch_viewing_key_owners_async` — [source](src/user_registry.rs#L386)

    ```rust
    pub async fn fetch_viewing_key_owners_async<R: AsyncRpc>(rpc: &R) -> Result<HashMap<[u8; X25519_PUBKEY_LEN], Pubkey>, ClientError>
    ```

78. `spr_client::user_registry::is_wallet_registered` — [source](src/user_registry.rs#L497)

    ```rust
    pub async fn is_wallet_registered<R: AsyncRpc>(rpc: &R, owner: Pubkey) -> Result<bool, ClientError>
    ```

79. `spr_client::user_registry::is_wallet_registered_sync` — [source](src/user_registry.rs#L507)

    ```rust
    pub fn is_wallet_registered_sync<R: Rpc>(rpc: &R, owner: Pubkey) -> Result<bool, ClientError>
    ```

80. `spr_client::user_registry::recipient_confidential_view_tag` — [source](src/user_registry.rs#L515)

    ```rust
    pub async fn recipient_confidential_view_tag<R: AsyncRpc>(rpc: &R, recipient: Pubkey) -> Result<ViewTag, ClientError>
    ```

81. `spr_client::user_registry::recipient_confidential_view_tag_sync` — [source](src/user_registry.rs#L531)

    ```rust
    pub fn recipient_confidential_view_tag_sync<R: Rpc>(rpc: &R, recipient: Pubkey) -> Result<ViewTag, ClientError>
    ```

82. `spr_client::user_registry::register_if_absent` — [source](src/user_registry.rs#L130)

    ```rust
    pub fn register_if_absent<R: Rpc>(rpc: &R, funding: &dyn Signer, keypair: &ShieldedKeypair) -> Result<StrictRegistration, ClientError>
    ```

83. `spr_client::user_registry::resolve_registered_address` — [source](src/user_registry.rs#L462)

    ```rust
    pub fn resolve_registered_address<R: Rpc>(rpc: &R, owner: Pubkey) -> Result<ResolvedAddress, ClientError>
    ```

84. `spr_client::user_registry::resolved_address_from_record` — [source](src/user_registry.rs#L547)

    ```rust
    pub fn resolved_address_from_record(owner: Pubkey, record: &UserRecord) -> Result<ResolvedAddress, ClientError>
    ```

85. `spr_client::user_registry::set_merge_encryption_instruction` — [source](src/user_registry.rs#L327)

    ```rust
    pub fn set_merge_encryption_instruction(owner: Pubkey, scheme: MergeEncryptionScheme) -> Instruction
    ```

86. `spr_client::user_registry::try_resolve_registered_address` — [source](src/user_registry.rs#L472)

    ```rust
    pub fn try_resolve_registered_address<R: Rpc>(rpc: &R, owner: Pubkey) -> Result<Option<ResolvedAddress>, ClientError>
    ```

87. `spr_client::user_registry::try_resolve_registered_address_async` — [source](src/user_registry.rs#L484)

    ```rust
    pub async fn try_resolve_registered_address_async<R: AsyncRpc>(rpc: &R, owner: Pubkey) -> Result<Option<ResolvedAddress>, ClientError>
    ```

88. `spr_client::user_registry::validate_registered_keypair` — [source](src/user_registry.rs#L446)

    ```rust
    pub fn validate_registered_keypair<R: Rpc>(rpc: &R, owner: Pubkey, keypair: &ShieldedKeypair) -> Result<(), ClientError>
    ```

89. `spr_client::verify_confidential_transfer_inputs` — [source](src/prover/verify.rs#L43)

    ```rust
    pub fn verify_confidential_transfer_inputs(inputs: &TransferInputs, public_input_hash: [u8; 32], proof: &Proof) -> Result<(), ClientError>
    ```

90. `spr_client::verify_confidential_transfer_proof` — [source](src/prover/verify.rs#L34)

    ```rust
    pub fn verify_confidential_transfer_proof(result: &TransferProofResult, proof: &Proof) -> Result<(), ClientError>
    ```

## `spr_client::Rpc`

91. `spr_client::Rpc::confirm_transaction` — [source](src/rpc/traits.rs#L133)

    ```rust
    fn confirm_transaction(&self, signature: Signature) -> Result<bool, ClientError>
    ```

92. `spr_client::Rpc::create_and_send_transaction` — [source](src/rpc/traits.rs#L119)

    ```rust
    fn create_and_send_transaction(&self, instructions: &[Instruction], payer: Address, signers: &[&dyn Signer], compute_budget: ComputeBudgetConfig) -> Result<Signature, ClientError>
    ```

93. `spr_client::Rpc::get_account` — [source](src/rpc/traits.rs#L33)

    ```rust
    fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError>
    ```

94. `spr_client::Rpc::get_balance` — [source](src/rpc/traits.rs#L64)

    ```rust
    fn get_balance(&self, address: Address) -> Result<u64, ClientError>
    ```

95. `spr_client::Rpc::get_block_height` — [source](src/rpc/traits.rs#L72)

    ```rust
    fn get_block_height(&self) -> Result<u64, ClientError>
    ```

96. `spr_client::Rpc::get_encrypted_utxos_by_tags` — [source](src/rpc/traits.rs#L154)

    ```rust
    fn get_encrypted_utxos_by_tags(&self, tags: Vec<[u8; 32]>, cursor: Option<Vec<u8>>, limit: Option<u32>, config: Option<IndexerRpcConfig>) -> Result<GetEncryptedUtxosByTagsResponse, ClientError>
    ```

97. `spr_client::Rpc::get_input_merkle_proofs` — [source](src/rpc/traits.rs#L242)

    ```rust
    fn get_input_merkle_proofs(&self, input_utxos: &[&SppProofInputUtxo], config: Option<IndexerRpcConfig>) -> Result<Vec<SpendProof>, ClientError>
    ```

98. `spr_client::Rpc::get_latest_blockhash` — [source](src/rpc/traits.rs#L68)

    ```rust
    fn get_latest_blockhash(&self) -> Result<(Hash, u64), ClientError>
    ```

99. `spr_client::Rpc::get_merkle_proofs` — [source](src/rpc/traits.rs#L207)

    ```rust
    fn get_merkle_proofs(&self, tree_account: Address, leaves: Vec<[u8; 32]>, config: Option<IndexerRpcConfig>) -> Result<GetMerkleProofsResponse, ClientError>
    ```

100. `spr_client::Rpc::get_minimum_balance_for_rent_exemption` — [source](src/rpc/traits.rs#L91)

    ```rust
    fn get_minimum_balance_for_rent_exemption(&self, data_len: usize) -> Result<u64, ClientError>
    ```

101. `spr_client::Rpc::get_multiple_accounts` — [source](src/rpc/traits.rs#L37)

    ```rust
    fn get_multiple_accounts(&self, addresses: Vec<Address>) -> Result<Vec<Option<Account>>, ClientError>
    ```

102. `spr_client::Rpc::get_non_inclusion_proofs` — [source](src/rpc/traits.rs#L216)

    ```rust
    fn get_non_inclusion_proofs(&self, tree_account: Address, leaves: Vec<[u8; 32]>, config: Option<IndexerRpcConfig>) -> Result<GetNonInclusionProofsResponse, ClientError>
    ```

103. `spr_client::Rpc::get_program_accounts` — [source](src/rpc/traits.rs#L44)

    ```rust
    fn get_program_accounts(&self, program_id: Address) -> Result<Vec<(Address, Account)>, ClientError>
    ```

104. `spr_client::Rpc::get_program_accounts_filtered` — [source](src/rpc/traits.rs#L54)

    ```rust
    fn get_program_accounts_filtered(&self, program_id: Address, filter: &ProgramAccountsFilter) -> Result<Vec<(Address, Account)>, ClientError>
    ```

105. `spr_client::Rpc::get_shielded_transactions_by_nullifiers` — [source](src/rpc/traits.rs#L190)

    ```rust
    fn get_shielded_transactions_by_nullifiers(&self, nullifiers: Vec<[u8; 32]>, cursor: Option<Vec<u8>>, limit: Option<u32>, config: Option<IndexerRpcConfig>) -> Result<GetShieldedTransactionsByNullifiersResponse, ClientError>
    ```

106. `spr_client::Rpc::get_shielded_transactions_by_ring` — [source](src/rpc/traits.rs#L174)

    ```rust
    fn get_shielded_transactions_by_ring(&self, options: RingHistoryOptions, config: Option<IndexerRpcConfig>) -> Result<GetShieldedTransactionsByTagsResponse, ClientError>
    ```

107. `spr_client::Rpc::get_shielded_transactions_by_signature` — [source](src/rpc/traits.rs#L182)

    ```rust
    fn get_shielded_transactions_by_signature(&self, signature: Signature, config: Option<IndexerRpcConfig>) -> Result<GetShieldedTransactionsBySignatureResponse, ClientError>
    ```

108. `spr_client::Rpc::get_shielded_transactions_by_tags` — [source](src/rpc/traits.rs#L164)

    ```rust
    fn get_shielded_transactions_by_tags(&self, tags: Vec<[u8; 32]>, cursor: Option<Vec<u8>>, limit: Option<u32>, config: Option<IndexerRpcConfig>) -> Result<GetShieldedTransactionsByTagsResponse, ClientError>
    ```

109. `spr_client::Rpc::get_signature_statuses` — [source](src/rpc/traits.rs#L84)

    ```rust
    fn get_signature_statuses(&self, signatures: Vec<Signature>) -> Result<Vec<Option<TransactionStatus>>, ClientError>
    ```

110. `spr_client::Rpc::get_slot` — [source](src/rpc/traits.rs#L76)

    ```rust
    fn get_slot(&self) -> Result<u64, ClientError>
    ```

111. `spr_client::Rpc::get_transaction_slot` — [source](src/rpc/traits.rs#L80)

    ```rust
    fn get_transaction_slot(&self, signature: Signature) -> Result<u64, ClientError>
    ```

112. `spr_client::Rpc::get_user_records` — [source](src/rpc/traits.rs#L227)

    ```rust
    fn get_user_records(&self, owners: Vec<Address>, config: Option<IndexerRpcConfig>) -> Result<GetUserRecordsResponse, ClientError>
    ```

113. `spr_client::Rpc::health` — [source](src/rpc/traits.rs#L95)

    ```rust
    fn health(&self) -> Result<(), ClientError>
    ```

114. `spr_client::Rpc::process_transaction` — [source](src/rpc/traits.rs#L109)

    ```rust
    fn process_transaction(&self, transaction: VersionedTransaction) -> Result<Signature, ClientError>
    ```

115. `spr_client::Rpc::prove` — **To be deleted** — [source](src/rpc/traits.rs#L256)

    ```rust
    fn prove(&self, proof_inputs: SppProofInputs, authority: &dyn ProofAuthority) -> Result<ProveResult, ClientError>
    ```

116. `spr_client::Rpc::send_and_prove` — **To be deleted** — [source](src/rpc/traits.rs#L264)

    ```rust
    fn send_and_prove(&self, proof_inputs: SppProofInputs) -> Result<Signature, ClientError>
    ```

117. `spr_client::Rpc::send_transaction_with_config` — [source](src/rpc/traits.rs#L101)

    ```rust
    fn send_transaction_with_config(&self, transaction: &VersionedTransaction, config: RpcSendTransactionConfig) -> Result<Signature, ClientError>
    ```

118. `spr_client::Rpc::should_retry` — [source](src/rpc/traits.rs#L148)

    ```rust
    fn should_retry(&self, error: &ClientError) -> bool
    ```

119. `spr_client::Rpc::subscribe_to_shielded_transactions_by_tags` — [source](src/rpc/traits.rs#L200)

    ```rust
    fn subscribe_to_shielded_transactions_by_tags(&self, tags: Vec<[u8; 32]>) -> Result<ShieldedTransactionStream, ClientError>
    ```

120. `spr_client::Rpc::transact_output_view_tags_from_signature` — [source](src/rpc/traits.rs#L137)

    ```rust
    fn transact_output_view_tags_from_signature(&self, signature: Signature) -> Result<Vec<[u8; 32]>, ClientError>
    ```

## `spr_client::AsyncRpc`

121. `spr_client::AsyncRpc::confirm_transaction` — [source](src/rpc/traits.rs#L352)

    ```rust
    async fn confirm_transaction(&self, signature: Signature) -> Result<bool, ClientError>
    ```

122. `spr_client::AsyncRpc::get_account` — [source](src/rpc/traits.rs#L281)

    ```rust
    async fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError>
    ```

123. `spr_client::AsyncRpc::get_balance` — [source](src/rpc/traits.rs#L299)

    ```rust
    async fn get_balance(&self, address: Address) -> Result<u64, ClientError>
    ```

124. `spr_client::AsyncRpc::get_block_height` — [source](src/rpc/traits.rs#L307)

    ```rust
    async fn get_block_height(&self) -> Result<u64, ClientError>
    ```

125. `spr_client::AsyncRpc::get_encrypted_utxos_by_tags` — [source](src/rpc/traits.rs#L371)

    ```rust
    async fn get_encrypted_utxos_by_tags(&self, tags: Vec<[u8; 32]>, cursor: Option<Vec<u8>>, limit: Option<u32>, config: Option<IndexerRpcConfig>) -> Result<GetEncryptedUtxosByTagsResponse, ClientError>
    ```

126. `spr_client::AsyncRpc::get_input_merkle_proofs` — [source](src/rpc/traits.rs#L451)

    ```rust
    async fn get_input_merkle_proofs(&self, input_utxos: &[&SppProofInputUtxo], config: Option<IndexerRpcConfig>) -> Result<Vec<SpendProof>, ClientError>
    ```

127. `spr_client::AsyncRpc::get_latest_blockhash` — [source](src/rpc/traits.rs#L303)

    ```rust
    async fn get_latest_blockhash(&self) -> Result<(Hash, u64), ClientError>
    ```

128. `spr_client::AsyncRpc::get_merkle_proofs` — [source](src/rpc/traits.rs#L424)

    ```rust
    async fn get_merkle_proofs(&self, tree_account: Address, leaves: Vec<[u8; 32]>, config: Option<IndexerRpcConfig>) -> Result<GetMerkleProofsResponse, ClientError>
    ```

129. `spr_client::AsyncRpc::get_minimum_balance_for_rent_exemption` — [source](src/rpc/traits.rs#L326)

    ```rust
    async fn get_minimum_balance_for_rent_exemption(&self, data_len: usize) -> Result<u64, ClientError>
    ```

130. `spr_client::AsyncRpc::get_multiple_accounts` — [source](src/rpc/traits.rs#L285)

    ```rust
    async fn get_multiple_accounts(&self, addresses: Vec<Address>) -> Result<Vec<Option<Account>>, ClientError>
    ```

131. `spr_client::AsyncRpc::get_non_inclusion_proofs` — [source](src/rpc/traits.rs#L433)

    ```rust
    async fn get_non_inclusion_proofs(&self, tree_account: Address, leaves: Vec<[u8; 32]>, config: Option<IndexerRpcConfig>) -> Result<GetNonInclusionProofsResponse, ClientError>
    ```

132. `spr_client::AsyncRpc::get_program_accounts` — [source](src/rpc/traits.rs#L292)

    ```rust
    async fn get_program_accounts(&self, program_id: Address) -> Result<Vec<(Address, Account)>, ClientError>
    ```

133. `spr_client::AsyncRpc::get_program_accounts_filtered` — [source](src/rpc/traits.rs#L274)

    ```rust
    async fn get_program_accounts_filtered(&self, program_id: Address, filter: &ProgramAccountsFilter) -> Result<Vec<(Address, Account)>, ClientError>
    ```

134. `spr_client::AsyncRpc::get_shielded_transactions_by_nullifiers` — [source](src/rpc/traits.rs#L407)

    ```rust
    async fn get_shielded_transactions_by_nullifiers(&self, nullifiers: Vec<[u8; 32]>, cursor: Option<Vec<u8>>, limit: Option<u32>, config: Option<IndexerRpcConfig>) -> Result<GetShieldedTransactionsByNullifiersResponse, ClientError>
    ```

135. `spr_client::AsyncRpc::get_shielded_transactions_by_ring` — [source](src/rpc/traits.rs#L391)

    ```rust
    async fn get_shielded_transactions_by_ring(&self, options: RingHistoryOptions, config: Option<IndexerRpcConfig>) -> Result<GetShieldedTransactionsByTagsResponse, ClientError>
    ```

136. `spr_client::AsyncRpc::get_shielded_transactions_by_signature` — [source](src/rpc/traits.rs#L399)

    ```rust
    async fn get_shielded_transactions_by_signature(&self, signature: Signature, config: Option<IndexerRpcConfig>) -> Result<GetShieldedTransactionsBySignatureResponse, ClientError>
    ```

137. `spr_client::AsyncRpc::get_shielded_transactions_by_tags` — [source](src/rpc/traits.rs#L381)

    ```rust
    async fn get_shielded_transactions_by_tags(&self, tags: Vec<[u8; 32]>, cursor: Option<Vec<u8>>, limit: Option<u32>, config: Option<IndexerRpcConfig>) -> Result<GetShieldedTransactionsByTagsResponse, ClientError>
    ```

138. `spr_client::AsyncRpc::get_signature_statuses` — [source](src/rpc/traits.rs#L319)

    ```rust
    async fn get_signature_statuses(&self, signatures: Vec<Signature>) -> Result<Vec<Option<TransactionStatus>>, ClientError>
    ```

139. `spr_client::AsyncRpc::get_slot` — [source](src/rpc/traits.rs#L311)

    ```rust
    async fn get_slot(&self) -> Result<u64, ClientError>
    ```

140. `spr_client::AsyncRpc::get_transaction_slot` — [source](src/rpc/traits.rs#L315)

    ```rust
    async fn get_transaction_slot(&self, signature: Signature) -> Result<u64, ClientError>
    ```

141. `spr_client::AsyncRpc::get_user_records` — [source](src/rpc/traits.rs#L443)

    ```rust
    async fn get_user_records(&self, owners: Vec<Address>, config: Option<IndexerRpcConfig>) -> Result<GetUserRecordsResponse, ClientError>
    ```

142. `spr_client::AsyncRpc::health` — [source](src/rpc/traits.rs#L333)

    ```rust
    async fn health(&self) -> Result<(), ClientError>
    ```

143. `spr_client::AsyncRpc::process_transaction` — [source](src/rpc/traits.rs#L345)

    ```rust
    async fn process_transaction(&self, transaction: VersionedTransaction) -> Result<Signature, ClientError>
    ```

144. `spr_client::AsyncRpc::prove` — **To be deleted** — [source](src/rpc/traits.rs#L460)

    ```rust
    async fn prove(&self, proof_inputs: SppProofInputs, authority: &dyn ProofAuthority) -> Result<ProveResult, ClientError>
    ```

145. `spr_client::AsyncRpc::send_transaction_with_config` — [source](src/rpc/traits.rs#L337)

    ```rust
    async fn send_transaction_with_config(&self, transaction: &VersionedTransaction, config: RpcSendTransactionConfig) -> Result<Signature, ClientError>
    ```

146. `spr_client::AsyncRpc::should_retry` — [source](src/rpc/traits.rs#L367)

    ```rust
    fn should_retry(&self, error: &ClientError) -> bool
    ```

147. `spr_client::AsyncRpc::subscribe_to_shielded_transactions_by_tags` — [source](src/rpc/traits.rs#L417)

    ```rust
    async fn subscribe_to_shielded_transactions_by_tags(&self, tags: Vec<[u8; 32]>) -> Result<ShieldedTransactionStream, ClientError>
    ```

148. `spr_client::AsyncRpc::transact_output_view_tags_from_signature` — [source](src/rpc/traits.rs#L356)

    ```rust
    async fn transact_output_view_tags_from_signature(&self, signature: Signature) -> Result<Vec<[u8; 32]>, ClientError>
    ```

## `spr_client::WitnessReader`

149. `spr_client::WitnessReader::input_witnesses` — [source](src/prover/witness.rs#L84)

    ```rust
    fn input_witnesses(&self, inputs: &[&SppProofInputUtxo], dummy_nullifiers: &[[u8; 32]], config: Option<IndexerRpcConfig>) -> Result<InputWitnesses, ClientError> where Self: Rpc,
    ```

150. `spr_client::WitnessReader::transaction_proofs` — [source](src/prover/witness.rs#L57)

    ```rust
    fn transaction_proofs(&self, inputs: &[SppProofInputUtxo], config: Option<IndexerRpcConfig>) -> Result<InputWitnesses, ClientError> where Self: Rpc,
    ```

## `spr_client::AsyncWitnessReader`

151. `spr_client::AsyncWitnessReader::input_witnesses` — [source](src/prover/witness.rs#L164)

    ```rust
    fn input_witnesses(&self, inputs: &[&SppProofInputUtxo], dummy_nullifiers: &[[u8; 32]], config: Option<IndexerRpcConfig>) -> impl std::future::Future<Output = Result<InputWitnesses, ClientError>> + Send
    ```

152. `spr_client::AsyncWitnessReader::transaction_proofs` — [source](src/prover/witness.rs#L129)

    ```rust
    fn transaction_proofs(&self, inputs: &[SppProofInputUtxo], config: Option<IndexerRpcConfig>) -> impl std::future::Future<Output = Result<InputWitnesses, ClientError>> + Send where Self: AsyncRpc + Sync,
    ```

## `spr_client::ProofAuthority`

153. `spr_client::ProofAuthority::complete_inputs` — [source](src/authority.rs#L46)

    ```rust
    fn complete_inputs(&self, inputs: &mut [TransferInput]) -> Result<(), ClientError>
    ```

## `spr_client::Prover`

154. `spr_client::Prover::prove` — [source](src/prover/backend.rs#L42)

    ```rust
    fn prove(&self, request: &dyn ProveRequest) -> Result<Proof, ClientError>
    ```

## `spr_client::ProverExt`

155. `spr_client::ProverExt::prove_batch_address_append` — [source](src/prover/backend.rs#L82)

    ```rust
    fn prove_batch_address_append(&self, inputs: &BatchAddressAppendInputs) -> Result<Proof, ClientError>
    ```

156. `spr_client::ProverExt::prove_merge` — [source](src/prover/backend.rs#L59)

    ```rust
    fn prove_merge(&self, inputs: &MergeInputs) -> Result<Proof, ClientError>
    ```

157. `spr_client::ProverExt::prove_merge_ring` — **To be deleted** — [source](src/prover/backend.rs#L70)

    ```rust
    fn prove_merge_ring(&self, inputs: &MergeInputs) -> Result<Proof, ClientError>
    ```

158. `spr_client::ProverExt::prove_ring_authority` — **To be deleted** — [source](src/prover/backend.rs#L65)

    ```rust
    fn prove_ring_authority(&self, inputs: &TransferInputs) -> Result<Proof, ClientError>
    ```

159. `spr_client::ProverExt::prove_transact` — [source](src/prover/backend.rs#L92)

    ```rust
    fn prove_transact(&self, proof_inputs: SppProofInputs, input_proofs: &[SpendProof], dummy_nullifier_proofs: &[NonInclusionProof], authority: &dyn ProofAuthority) -> Result<TransactIxData, ClientError>
    ```

160. `spr_client::ProverExt::prove_transact_with_dummy_policy` — [source](src/prover/backend.rs#L108)

    ```rust
    fn prove_transact_with_dummy_policy(&self, proof_inputs: SppProofInputs, input_proofs: &[SpendProof], dummy_nullifier_proofs: &[NonInclusionProof], allow_dummy_inputs: bool, authority: &dyn ProofAuthority) -> Result<TransactIxData, ClientError>
    ```

161. `spr_client::ProverExt::prove_transfer` — [source](src/prover/backend.rs#L54)

    ```rust
    fn prove_transfer(&self, inputs: &TransferInputs) -> Result<Proof, ClientError>
    ```

162. `spr_client::ProverExt::prove_transfer_ring` — **To be deleted** — [source](src/prover/backend.rs#L75)

    ```rust
    fn prove_transfer_ring(&self, inputs: &TransferInputs) -> Result<Proof, ClientError>
    ```

## `spr_client::ProveRequest`

163. `spr_client::ProveRequest::body` — [source](src/prover/client.rs#L120)

    ```rust
    fn body(&self) -> Result<Zeroizing<String>, ClientError>
    ```

164. `spr_client::ProveRequest::delivery` — [source](src/prover/client.rs#L127)

    ```rust
    fn delivery(&self) -> Delivery
    ```

165. `spr_client::ProveRequest::proving_key` — [source](src/prover/client.rs#L124)

    ```rust
    fn proving_key(&self) -> Result<ExpectedProvingKey, ClientError>
    ```

## `spr_client::AnonymousRingEddsaProver`

166. `spr_client::AnonymousRingEddsaProver::build` — **To be deleted** — [source](src/prover/transact/anonymous_ring_eddsa.rs#L87)

    ```rust
    pub fn build(self) -> Result<AnonymousRingEddsaProofResult, ClientError>
    ```

    Context: `impl AnonymousRingEddsaProver<'_>`.

## `spr_client::AssembledTransfer`

167. `spr_client::AssembledTransfer::prove` — [source](src/prover/transact/witness.rs#L164)

    ```rust
    pub fn prove<P: Prover + ?Sized>(&mut self, prover: &P, authority: &dyn ProofAuthority) -> Result<TransactProof, ClientError>
    ```

    Context: `impl AssembledTransfer`.

168. `spr_client::AssembledTransfer::with_proof` — [source](src/prover/transact/witness.rs#L152)

    ```rust
    pub fn with_proof(mut self, proof: TransactProof) -> TransactIxData
    ```

    Context: `impl AssembledTransfer`.

## `spr_client::AsyncPollConfig`

169. `<spr_client::AsyncPollConfig as Default>::default` — [source](src/prover/client.rs#L173)

    ```rust
    fn default() -> Self
    ```

    Context: `impl Default for AsyncPollConfig`.

## `spr_client::AsyncProverClient`

170. `<spr_client::AsyncProverClient as Default>::default` — [source](src/prover/client.rs#L288)

    ```rust
    fn default() -> Self
    ```

    Context: `impl Default for AsyncProverClient`.

    Requires: `#[cfg(feature = "reqwest")]`.

171. `spr_client::AsyncProverClient::attest` — [source](src/prover/client.rs#L928)

    ```rust
    pub async fn attest(&self) -> Result<AttestedProver, ClientError>
    ```

    Context: `impl AsyncProverClient`.

172. `spr_client::AsyncProverClient::check_indexed` — [source](src/prover/client.rs#L866)

    ```rust
    pub async fn check_indexed(&self) -> Result<(), ClientError>
    ```

    Context: `impl AsyncProverClient`.

173. `spr_client::AsyncProverClient::check_proving_keys` — [source](src/prover/client.rs#L861)

    ```rust
    pub async fn check_proving_keys(&self) -> Result<ProvingKeyReport, ClientError>
    ```

    Context: `impl AsyncProverClient`.

174. `spr_client::AsyncProverClient::for_tree_batches` — [source](src/prover/client.rs#L766)

    ```rust
    pub fn for_tree_batches(mut self) -> Self
    ```

    Context: `impl AsyncProverClient`.

175. `spr_client::AsyncProverClient::has_tee` — [source](src/prover/client.rs#L773)

    ```rust
    pub fn has_tee(&self) -> bool
    ```

    Context: `impl AsyncProverClient`.

176. `spr_client::AsyncProverClient::into_blocking` — [source](src/prover/client.rs#L682)

    ```rust
    pub fn into_blocking(self) -> ProverClient
    ```

    Context: `impl AsyncProverClient`.

177. `spr_client::AsyncProverClient::local` — [source](src/prover/client.rs#L700)

    ```rust
    pub fn local() -> Self
    ```

    Context: `impl AsyncProverClient`.

    Requires: `#[cfg(feature = "reqwest")]`.

178. `spr_client::AsyncProverClient::new` — [source](src/prover/client.rs#L705)

    ```rust
    pub fn new(server_address: String) -> Self
    ```

    Context: `impl AsyncProverClient`.

    Requires: `#[cfg(feature = "reqwest")]`.

179. `spr_client::AsyncProverClient::proof_data_source` — [source](src/prover/client.rs#L695)

    ```rust
    pub fn proof_data_source(&self) -> ProofDataSource
    ```

    Context: `impl AsyncProverClient`.

180. `spr_client::AsyncProverClient::prove` — [source](src/prover/client.rs#L829)

    ```rust
    pub async fn prove(&self, request: &(impl ProveRequest + ?Sized)) -> Result<Proof, ClientError>
    ```

    Context: `impl AsyncProverClient`.

181. `spr_client::AsyncProverClient::prove_batch_address_append` — [source](src/prover/client.rs#L853)

    ```rust
    pub async fn prove_batch_address_append(&self, inputs: &BatchAddressAppendInputs) -> Result<Proof, ClientError>
    ```

    Context: `impl AsyncProverClient`.

182. `spr_client::AsyncProverClient::prove_indexed` — [source](src/prover/client.rs#L838)

    ```rust
    pub async fn prove_indexed<R: Request>(&self, request: &R) -> Result<R::Output, ClientError>
    ```

    Context: `impl AsyncProverClient`.

183. `spr_client::AsyncProverClient::prove_merge` — [source](src/prover/client.rs#L808)

    ```rust
    pub async fn prove_merge(&self, inputs: &MergeInputs) -> Result<Proof, ClientError>
    ```

    Context: `impl AsyncProverClient`.

184. `spr_client::AsyncProverClient::prove_merge_ring` — **To be deleted** — [source](src/prover/client.rs#L819)

    ```rust
    pub async fn prove_merge_ring(&self, inputs: &MergeInputs) -> Result<Proof, ClientError>
    ```

    Context: `impl AsyncProverClient`.

185. `spr_client::AsyncProverClient::prove_ring_authority` — **To be deleted** — [source](src/prover/client.rs#L812)

    ```rust
    pub async fn prove_ring_authority(&self, inputs: &TransferInputs) -> Result<Proof, ClientError>
    ```

    Context: `impl AsyncProverClient`.

186. `spr_client::AsyncProverClient::prove_transfer` — [source](src/prover/client.rs#L804)

    ```rust
    pub async fn prove_transfer(&self, inputs: &TransferInputs) -> Result<Proof, ClientError>
    ```

    Context: `impl AsyncProverClient`.

187. `spr_client::AsyncProverClient::prove_transfer_ring` — **To be deleted** — [source](src/prover/client.rs#L823)

    ```rust
    pub async fn prove_transfer_ring(&self, inputs: &TransferInputs) -> Result<Proof, ClientError>
    ```

    Context: `impl AsyncProverClient`.

188. `spr_client::AsyncProverClient::with_async_poll_config` — [source](src/prover/client.rs#L778)

    ```rust
    pub fn with_async_poll_config(mut self, config: AsyncPollConfig) -> Self
    ```

    Context: `impl AsyncProverClient`.

189. `spr_client::AsyncProverClient::with_client` — [source](src/prover/client.rs#L718)

    ```rust
    pub fn with_client(server_address: String, http: impl HttpClient + 'static) -> Self
    ```

    Context: `impl AsyncProverClient`.

190. `spr_client::AsyncProverClient::with_proof_data_source` — [source](src/prover/client.rs#L675)

    ```rust
    pub fn with_proof_data_source(mut self, source: ProofDataSource) -> Self
    ```

    Context: `impl AsyncProverClient`.

191. `spr_client::AsyncProverClient::with_proof_timeout` — [source](src/prover/client.rs#L787)

    ```rust
    pub fn with_proof_timeout(mut self, timeout: Duration) -> Self
    ```

    Context: `impl AsyncProverClient`.

192. `spr_client::AsyncProverClient::with_proxy` — [source](src/prover/client.rs#L746)

    ```rust
    pub fn with_proxy(mut self, proxy_url: &str) -> Result<Self, ClientError>
    ```

    Context: `impl AsyncProverClient`.

    Requires: `#[cfg(feature = "reqwest")]`.

193. `spr_client::AsyncProverClient::with_queued_proofs` — [source](src/prover/client.rs#L797)

    ```rust
    pub fn with_queued_proofs(mut self) -> Self
    ```

    Context: `impl AsyncProverClient`.

194. `spr_client::AsyncProverClient::with_tee` — [source](src/prover/client.rs#L759)

    ```rust
    pub fn with_tee(mut self, policy: TeePolicy) -> Self
    ```

    Context: `impl AsyncProverClient`.

## `spr_client::AsyncSolanaRpc`

195. `spr_client::AsyncSolanaRpc::client` — [source](src/rpc/solana_rpc/nonblocking.rs#L59)

    ```rust
    pub fn client(&self) -> &NonblockingRpcClient
    ```

    Context: `impl AsyncSolanaRpc`.

    Requires: `#[cfg(feature = "solana-rpc")]`.

196. `spr_client::AsyncSolanaRpc::fetch_confirmed_instruction_groups` — [source](src/rpc/solana_rpc/nonblocking.rs#L114)

    ```rust
    pub async fn fetch_confirmed_instruction_groups(&self, signature: &Signature) -> Result<ConfirmedInstructionGroups, ClientError>
    ```

    Context: `impl AsyncSolanaRpc`.

    Requires: `#[cfg(feature = "solana-rpc")]`.

197. `spr_client::AsyncSolanaRpc::fetch_confirmed_transaction` — [source](src/rpc/solana_rpc/nonblocking.rs#L85)

    ```rust
    pub async fn fetch_confirmed_transaction(&self, signature: &Signature) -> Result<EncodedConfirmedTransactionWithStatusMeta, ClientError>
    ```

    Context: `impl AsyncSolanaRpc`.

    Requires: `#[cfg(feature = "solana-rpc")]`.

198. `spr_client::AsyncSolanaRpc::genesis_hash` — [source](src/rpc/solana_rpc/nonblocking.rs#L77)

    ```rust
    pub async fn genesis_hash(&self) -> Result<[u8; 32], ClientError>
    ```

    Context: `impl AsyncSolanaRpc`.

    Requires: `#[cfg(feature = "solana-rpc")]`.

199. `spr_client::AsyncSolanaRpc::get_program_accounts_filtered` — [source](src/rpc/solana_rpc/nonblocking.rs#L64)

    ```rust
    pub async fn get_program_accounts_filtered(&self, program_id: Address, filter: &ProgramAccountsFilter) -> Result<Vec<(Address, Account)>, ClientError>
    ```

    Context: `impl AsyncSolanaRpc`.

    Requires: `#[cfg(feature = "solana-rpc")]`.

200. `spr_client::AsyncSolanaRpc::new` — [source](src/rpc/solana_rpc/nonblocking.rs#L37)

    ```rust
    pub fn new(url: impl Into<String>) -> Self
    ```

    Context: `impl AsyncSolanaRpc`.

    Requires: `#[cfg(feature = "solana-rpc")]`.

201. `spr_client::AsyncSolanaRpc::transact_output_view_tags_from_signature` — [source](src/rpc/solana_rpc/nonblocking.rs#L123)

    ```rust
    pub async fn transact_output_view_tags_from_signature(&self, signature: &Signature) -> Result<Vec<[u8; 32]>, ClientError>
    ```

    Context: `impl AsyncSolanaRpc`.

    Requires: `#[cfg(feature = "solana-rpc")]`.

202. `spr_client::AsyncSolanaRpc::with_client` — [source](src/rpc/solana_rpc/nonblocking.rs#L44)

    ```rust
    pub fn with_client(client: NonblockingRpcClient) -> Self
    ```

    Context: `impl AsyncSolanaRpc`.

    Requires: `#[cfg(feature = "solana-rpc")]`.

203. `spr_client::AsyncSolanaRpc::with_poll_interval` — [source](src/rpc/solana_rpc/nonblocking.rs#L54)

    ```rust
    pub fn with_poll_interval(mut self, interval: Duration) -> Self
    ```

    Context: `impl AsyncSolanaRpc`.

    Requires: `#[cfg(feature = "solana-rpc")]`.

## `spr_client::AsyncZolanaIndexer`

204. `spr_client::AsyncZolanaIndexer::api` — [source](src/indexer/nonblocking.rs#L62)

    ```rust
    pub fn api(&self) -> &ZolanaApi
    ```

    Context: `impl AsyncZolanaIndexer`.

205. `spr_client::AsyncZolanaIndexer::into_blocking` — [source](src/indexer/blocking.rs#L104)

    ```rust
    pub fn into_blocking(self) -> ZolanaIndexer
    ```

    Context: `impl AsyncZolanaIndexer`.

206. `spr_client::AsyncZolanaIndexer::new` — [source](src/indexer/nonblocking.rs#L47)

    ```rust
    pub fn new(url: impl AsRef<str>) -> Self
    ```

    Context: `impl AsyncZolanaIndexer`.

    Requires: `#[cfg(feature = "reqwest")]`.

207. `spr_client::AsyncZolanaIndexer::with_api` — [source](src/indexer/nonblocking.rs#L53)

    ```rust
    pub fn with_api(api: ZolanaApi) -> Self
    ```

    Context: `impl AsyncZolanaIndexer`.

208. `spr_client::AsyncZolanaIndexer::with_http_trace` — [source](src/indexer/nonblocking.rs#L57)

    ```rust
    pub fn with_http_trace(mut self) -> Self
    ```

    Context: `impl AsyncZolanaIndexer`.

## `spr_client::Blocking`

209. `<spr_client::Blocking as Clone>::clone` — [source](src/rpc/blocking.rs#L37)

    ```rust
    fn clone(&self) -> Self
    ```

    Context: `impl<T> Clone for Blocking<T>`.

210. `spr_client::Blocking::inner` — [source](src/rpc/blocking.rs#L47)

    ```rust
    pub fn inner(&self) -> &T
    ```

    Context: `impl<T> Blocking<T>`.

211. `spr_client::Blocking::new` — [source](src/rpc/blocking.rs#L43)

    ```rust
    pub fn new(inner: T) -> Self
    ```

    Context: `impl<T> Blocking<T>`.

## `spr_client::CacheReadInputs`

212. `spr_client::CacheReadInputs::uncached` — [source](src/prover/cache.rs#L29)

    ```rust
    pub fn uncached(public_fields: [[u8; 32]; 2]) -> Self
    ```

    Context: `impl CacheReadInputs`.

## `spr_client::ClientError`

213. `spr_client::ClientError::for_signature` — [source](src/error.rs#L482)

    ```rust
    pub fn for_signature(self, signature: &solana_signature::Signature) -> Self
    ```

    Context: `impl ClientError`.

## `spr_client::ComputeBudgetConfig`

214. `spr_client::ComputeBudgetConfig::for_instruction_count` — [source](src/rpc/compute_budget.rs#L40)

    ```rust
    pub const fn for_instruction_count(instructions: usize) -> Self
    ```

    Context: `impl ComputeBudgetConfig`.

215. `spr_client::ComputeBudgetConfig::new` — [source](src/rpc/compute_budget.rs#L26)

    ```rust
    pub const fn new(cu_limit: u32) -> Self
    ```

    Context: `impl ComputeBudgetConfig`.

216. `spr_client::ComputeBudgetConfig::transaction_config` — [source](src/rpc/compute_budget.rs#L62)

    ```rust
    pub fn transaction_config(&self) -> v1::TransactionConfig
    ```

    Context: `impl ComputeBudgetConfig`.

217. `spr_client::ComputeBudgetConfig::with_priority_fee` — [source](src/rpc/compute_budget.rs#L57)

    ```rust
    pub const fn with_priority_fee(mut self, lamports: u64) -> Self
    ```

    Context: `impl ComputeBudgetConfig`.

## `spr_client::ConfirmedInstructionGroups`

218. `<spr_client::ConfirmedInstructionGroups as TryFrom<EncodedConfirmedTransactionWithStatusMeta>>::try_from` — [source](src/rpc/solana_rpc/transaction.rs#L28)

    ```rust
    fn try_from(transaction: EncodedConfirmedTransactionWithStatusMeta) -> Result<Self, Self::Error>
    ```

    Context: `impl TryFrom<EncodedConfirmedTransactionWithStatusMeta> for ConfirmedInstructionGroups`.

    Requires: `#[cfg(feature = "solana-rpc")]`.

## `spr_client::EncryptedUtxoMatch`

219. `spr_client::EncryptedUtxoMatch::into_proofless_transaction` — [source](src/rpc/types.rs#L53)

    ```rust
    pub fn into_proofless_transaction(self) -> Option<ShieldedTransaction>
    ```

    Context: `impl EncryptedUtxoMatch`.

## `spr_client::IndexerPollConfig`

220. `<spr_client::IndexerPollConfig as Default>::default` — [source](src/rpc/retry.rs#L13)

    ```rust
    fn default() -> Self
    ```

    Context: `impl Default for IndexerPollConfig`.

221. `spr_client::IndexerPollConfig::backoff` — [source](src/rpc/retry.rs#L31)

    ```rust
    pub fn backoff(&self) -> impl Iterator<Item = Duration> + '_
    ```

    Context: `impl IndexerPollConfig`.

222. `spr_client::IndexerPollConfig::new` — [source](src/rpc/retry.rs#L23)

    ```rust
    pub fn new(num_retries: u32, delay_ms: u64, max_delay_ms: u64) -> Self
    ```

    Context: `impl IndexerPollConfig`.

223. `spr_client::IndexerPollConfig::poll_until` — [source](src/rpc/retry.rs#L44)

    ```rust
    pub fn poll_until<T>(&self, mut request: impl FnMut() -> Result<T, ClientError>, mut accept: impl FnMut(&T) -> bool) -> Result<T, ClientError>
    ```

    Context: `impl IndexerPollConfig`.

## `spr_client::IndexerRpcConfig`

224. `spr_client::IndexerRpcConfig::at_slot` — [source](src/rpc/retry.rs#L77)

    ```rust
    pub fn at_slot(slot: u64) -> Self
    ```

    Context: `impl IndexerRpcConfig`.

## `spr_client::MergeProofResult`

225. `spr_client::MergeProofResult::instruction_data` — [source](src/prover/merge.rs#L91)

    ```rust
    pub fn instruction_data(&self, proof: MergeProof) -> MergeTransactIxData
    ```

    Context: `impl MergeProofResult`.

226. `spr_client::MergeProofResult::ring_instruction_data` — **To be deleted** — [source](src/prover/merge.rs#L112)

    ```rust
    pub fn ring_instruction_data(&self, proof: MergeProof) -> MergeRingIxData
    ```

    Context: `impl MergeProofResult`.

## `spr_client::MergeProver`

227. `spr_client::MergeProver::build` — [source](src/prover/merge.rs#L144)

    ```rust
    pub fn build(self) -> Result<MergeProofResult, ClientError>
    ```

    Context: `impl MergeProver`.

## `spr_client::ProgramAccountsFilter`

228. `spr_client::ProgramAccountsFilter::data_size` — [source](src/rpc/accounts.rs#L54)

    ```rust
    pub fn data_size(&self) -> usize
    ```

    Context: `impl ProgramAccountsFilter`.

229. `spr_client::ProgramAccountsFilter::matches` — [source](src/rpc/accounts.rs#L46)

    ```rust
    pub fn matches(&self, data: &[u8]) -> bool
    ```

    Context: `impl ProgramAccountsFilter`.

230. `spr_client::ProgramAccountsFilter::memcmp_filters` — [source](src/rpc/accounts.rs#L59)

    ```rust
    pub fn memcmp_filters(&self) -> impl Iterator<Item = (usize, &[u8])>
    ```

    Context: `impl ProgramAccountsFilter`.

231. `spr_client::ProgramAccountsFilter::min_context_slot` — [source](src/rpc/accounts.rs#L42)

    ```rust
    pub fn min_context_slot(&self) -> Option<u64>
    ```

    Context: `impl ProgramAccountsFilter`.

232. `spr_client::ProgramAccountsFilter::new` — [source](src/rpc/accounts.rs#L18)

    ```rust
    pub fn new(data_size: usize) -> Self
    ```

    Context: `impl ProgramAccountsFilter`.

233. `spr_client::ProgramAccountsFilter::rpc_config` — [source](src/rpc/solana_rpc/accounts.rs#L17)

    ```rust
    pub fn rpc_config(&self) -> RpcProgramAccountsConfig
    ```

    Context: `impl ProgramAccountsFilter`.

    Requires: `#[cfg(feature = "solana-rpc")]`.

234. `spr_client::ProgramAccountsFilter::with_memcmp` — [source](src/rpc/accounts.rs#L27)

    ```rust
    pub fn with_memcmp(mut self, offset: usize, bytes: impl Into<Vec<u8>>) -> Self
    ```

    Context: `impl ProgramAccountsFilter`.

235. `spr_client::ProgramAccountsFilter::with_min_context_slot` — [source](src/rpc/accounts.rs#L37)

    ```rust
    pub fn with_min_context_slot(mut self, slot: u64) -> Self
    ```

    Context: `impl ProgramAccountsFilter`.

## `spr_client::Proof`

236. `spr_client::Proof::from_gnark_json` — [source](src/prover/proof.rs#L194)

    ```rust
    pub fn from_gnark_json(json: &str) -> Result<Self, ClientError>
    ```

    Context: `impl Proof`.

## `spr_client::ProofCompressed`

237. `<spr_client::ProofCompressed as TryFrom<Proof>>::try_from` — [source](src/prover/proof.rs#L63)

    ```rust
    fn try_from(proof: Proof) -> Result<Self, Self::Error>
    ```

    Context: `impl TryFrom<Proof> for ProofCompressed`.

238. `spr_client::ProofCompressed::into_committed_transact_parts` — [source](src/prover/proof.rs#L98)

    ```rust
    pub fn into_committed_transact_parts(self) -> Result<(TransactProof, Bsb22Commitment), ClientError>
    ```

    Context: `impl ProofCompressed`.

239. `spr_client::ProofCompressed::to_merge_proof` — [source](src/prover/proof.rs#L119)

    ```rust
    pub fn to_merge_proof(&self) -> Result<MergeProof, ClientError>
    ```

    Context: `impl ProofCompressed`.

240. `spr_client::ProofCompressed::to_nullifier_tree_proof` — [source](src/prover/proof.rs#L136)

    ```rust
    pub fn to_nullifier_tree_proof(&self) -> Result<NullifierTreeProof, ClientError>
    ```

    Context: `impl ProofCompressed`.

241. `spr_client::ProofCompressed::to_transact_proof` — [source](src/prover/proof.rs#L87)

    ```rust
    pub fn to_transact_proof(self) -> TransactProof
    ```

    Context: `impl ProofCompressed`.

## `spr_client::ProverClient`

242. `<spr_client::ProverClient as Default>::default` — [source](src/prover/client.rs#L281)

    ```rust
    fn default() -> Self
    ```

    Context: `impl Default for ProverClient`.

    Requires: `#[cfg(feature = "reqwest")]`.

243. `spr_client::ProverClient::attest` — [source](src/prover/client.rs#L361)

    ```rust
    pub fn attest(&self) -> Result<AttestedProver, ClientError>
    ```

    Context: `impl ProverClient`.

244. `spr_client::ProverClient::check_indexed` — [source](src/prover/client.rs#L395)

    ```rust
    pub fn check_indexed(&self) -> Result<(), ClientError>
    ```

    Context: `impl ProverClient`.

245. `spr_client::ProverClient::check_proving_keys` — [source](src/prover/client.rs#L391)

    ```rust
    pub fn check_proving_keys(&self) -> Result<ProvingKeyReport, ClientError>
    ```

    Context: `impl ProverClient`.

246. `spr_client::ProverClient::check_setup` — [source](src/prover/client.rs#L410)

    ```rust
    pub fn check_setup(&self, indexer: IndexerRequirement) -> Result<ProvingKeyReport, ClientError>
    ```

    Context: `impl ProverClient`.

247. `spr_client::ProverClient::for_tree_batches` — [source](src/prover/client.rs#L350)

    ```rust
    pub fn for_tree_batches(mut self) -> Self
    ```

    Context: `impl ProverClient`.

248. `spr_client::ProverClient::has_tee` — [source](src/prover/client.rs#L356)

    ```rust
    pub fn has_tee(&self) -> bool
    ```

    Context: `impl ProverClient`.

249. `spr_client::ProverClient::into_parts` — [source](src/prover/client.rs#L308)

    ```rust
    pub fn into_parts(self) -> (AsyncProverClient, Arc<BlockingRuntime>)
    ```

    Context: `impl ProverClient`.

250. `spr_client::ProverClient::local` — [source](src/prover/client.rs#L313)

    ```rust
    pub fn local() -> Self
    ```

    Context: `impl ProverClient`.

    Requires: `#[cfg(feature = "reqwest")]`.

251. `spr_client::ProverClient::new` — [source](src/prover/client.rs#L318)

    ```rust
    pub fn new(server_address: String) -> Self
    ```

    Context: `impl ProverClient`.

    Requires: `#[cfg(feature = "reqwest")]`.

252. `spr_client::ProverClient::proof_data_source` — [source](src/prover/client.rs#L302)

    ```rust
    pub fn proof_data_source(&self) -> ProofDataSource
    ```

    Context: `impl ProverClient`.

253. `spr_client::ProverClient::prove_indexed` — [source](src/prover/client.rs#L384)

    ```rust
    pub fn prove_indexed<R: Request>(&self, request: &R) -> Result<R::Output, ClientError>
    ```

    Context: `impl ProverClient`.

254. `spr_client::ProverClient::with_async_poll_config` — [source](src/prover/client.rs#L366)

    ```rust
    pub fn with_async_poll_config(mut self, config: AsyncPollConfig) -> Self
    ```

    Context: `impl ProverClient`.

255. `spr_client::ProverClient::with_client` — [source](src/prover/client.rs#L328)

    ```rust
    pub fn with_client(server_address: String, http: impl BlockingHttpClient + 'static) -> Self
    ```

    Context: `impl ProverClient`.

256. `spr_client::ProverClient::with_proof_data_source` — [source](src/prover/client.rs#L297)

    ```rust
    pub fn with_proof_data_source(mut self, source: ProofDataSource) -> Self
    ```

    Context: `impl ProverClient`.

257. `spr_client::ProverClient::with_proof_timeout` — [source](src/prover/client.rs#L372)

    ```rust
    pub fn with_proof_timeout(mut self, timeout: Duration) -> Self
    ```

    Context: `impl ProverClient`.

258. `spr_client::ProverClient::with_proxy` — [source](src/prover/client.rs#L335)

    ```rust
    pub fn with_proxy(mut self, proxy_url: &str) -> Result<Self, ClientError>
    ```

    Context: `impl ProverClient`.

    Requires: `#[cfg(feature = "reqwest")]`.

259. `spr_client::ProverClient::with_queued_proofs` — [source](src/prover/client.rs#L379)

    ```rust
    pub fn with_queued_proofs(mut self) -> Self
    ```

    Context: `impl ProverClient`.

260. `spr_client::ProverClient::with_tee` — [source](src/prover/client.rs#L343)

    ```rust
    pub fn with_tee(mut self, policy: TeePolicy) -> Self
    ```

    Context: `impl ProverClient`.

## `spr_client::ProverLaunch`

261. `spr_client::ProverLaunch::new_with_cli` — [source](src/prover/client.rs#L1154)

    ```rust
    pub fn new_with_cli(cli_bin: impl AsRef<Path>) -> Result<Self, ClientError>
    ```

    Context: `impl ProverLaunch`.

    Requires: `#[cfg(feature = "reqwest")]`.

262. `spr_client::ProverLaunch::spawn` — [source](src/prover/client.rs#L1194)

    ```rust
    pub fn spawn(self) -> Result<(), ClientError>
    ```

    Context: `impl ProverLaunch`.

    Requires: `#[cfg(feature = "reqwest")]`.

263. `spr_client::ProverLaunch::with_indexer` — [source](src/prover/client.rs#L1187)

    ```rust
    pub fn with_indexer(mut self, url: impl Into<String>, indexer: IndexerRequirement) -> Self
    ```

    Context: `impl ProverLaunch`.

    Requires: `#[cfg(feature = "reqwest")]`.

264. `spr_client::ProverLaunch::with_keys_dir` — [source](src/prover/client.rs#L1169)

    ```rust
    pub fn with_keys_dir(mut self, keys_dir: impl AsRef<Path>) -> Result<Self, ClientError>
    ```

    Context: `impl ProverLaunch`.

    Requires: `#[cfg(feature = "reqwest")]`.

## `spr_client::PublicInputs`

265. `spr_client::PublicInputs::hash` — [source](src/prover/transact/assembly.rs#L563)

    ```rust
    pub fn hash(&self) -> Result<[u8; 32], ClientError>
    ```

    Context: `impl PublicInputs<'_>`.

266. `spr_client::PublicInputs::without_roots` — [source](src/prover/transact/assembly.rs#L578)

    ```rust
    pub fn without_roots(&self, after_private_tx: &[[u8; 32]]) -> Result<Vec<[u8; 32]>, ClientError>
    ```

    Context: `impl<Roots> PublicInputs<'_, Roots>`.

## `spr_client::RingAuthorityProver`

267. `spr_client::RingAuthorityProver::build` — **To be deleted** — [source](src/prover/ring_authority.rs#L74)

    ```rust
    pub fn build(self) -> Result<RingAuthorityProofResult, ClientError>
    ```

    Context: `impl RingAuthorityProver`.

## `spr_client::RingTransferProver`

268. `spr_client::RingTransferProver::build` — **To be deleted** — [source](src/prover/transact/ring_eddsa.rs#L64)

    ```rust
    pub fn build(self) -> Result<RingTransferProofResult, ClientError>
    ```

    Context: `impl RingTransferProver`.

## `spr_client::SettlementAccountValidation`

269. `spr_client::SettlementAccountValidation::validate` — [source](src/rpc/transaction.rs#L81)

    ```rust
    pub fn validate(self) -> Result<(), ClientError>
    ```

    Context: `impl SettlementAccountValidation<'_>`.

## `spr_client::SolanaRpc`

270. `spr_client::SolanaRpc::airdrop` — [source](src/rpc/solana_rpc/blocking.rs#L99)

    ```rust
    pub fn airdrop(&mut self, pubkey: &Pubkey, lamports: u64) -> Result<Signature, ClientError>
    ```

    Context: `impl SolanaRpc`.

    Requires: `#[cfg(feature = "solana-rpc")]`.

271. `spr_client::SolanaRpc::assert_executable` — [source](src/rpc/solana_rpc/blocking.rs#L86)

    ```rust
    pub fn assert_executable(&self, program_id: &Pubkey) -> Result<(), ClientError>
    ```

    Context: `impl SolanaRpc`.

    Requires: `#[cfg(feature = "solana-rpc")]`.

272. `spr_client::SolanaRpc::client` — [source](src/rpc/solana_rpc/blocking.rs#L62)

    ```rust
    pub fn client(&self) -> &RpcClient
    ```

    Context: `impl SolanaRpc`.

    Requires: `#[cfg(feature = "solana-rpc")]`.

273. `spr_client::SolanaRpc::fetch_confirmed_instruction_groups` — [source](src/rpc/solana_rpc/blocking.rs#L124)

    ```rust
    pub fn fetch_confirmed_instruction_groups(&self, signature: &Signature) -> Result<ConfirmedInstructionGroups, ClientError>
    ```

    Context: `impl SolanaRpc`.

    Requires: `#[cfg(feature = "solana-rpc")]`.

274. `spr_client::SolanaRpc::fetch_confirmed_transaction` — [source](src/rpc/solana_rpc/blocking.rs#L141)

    ```rust
    pub fn fetch_confirmed_transaction(&self, signature: &Signature) -> Result<EncodedConfirmedTransactionWithStatusMeta, ClientError>
    ```

    Context: `impl SolanaRpc`.

    Requires: `#[cfg(feature = "solana-rpc")]`.

275. `spr_client::SolanaRpc::genesis_hash` — [source](src/rpc/solana_rpc/blocking.rs#L79)

    ```rust
    pub fn genesis_hash(&self) -> Result<[u8; 32], ClientError>
    ```

    Context: `impl SolanaRpc`.

    Requires: `#[cfg(feature = "solana-rpc")]`.

276. `spr_client::SolanaRpc::get_program_accounts_filtered` — [source](src/rpc/solana_rpc/blocking.rs#L67)

    ```rust
    pub fn get_program_accounts_filtered(&self, program_id: Address, filter: &ProgramAccountsFilter) -> Result<Vec<(Address, Account)>, ClientError>
    ```

    Context: `impl SolanaRpc`.

    Requires: `#[cfg(feature = "solana-rpc")]`.

277. `spr_client::SolanaRpc::new` — [source](src/rpc/solana_rpc/blocking.rs#L39)

    ```rust
    pub fn new(url: impl Into<String>) -> Self
    ```

    Context: `impl SolanaRpc`.

    Requires: `#[cfg(feature = "solana-rpc")]`.

278. `spr_client::SolanaRpc::transact_output_view_tags_from_signature` — [source](src/rpc/solana_rpc/blocking.rs#L133)

    ```rust
    pub fn transact_output_view_tags_from_signature(&self, signature: &Signature) -> Result<Vec<[u8; 32]>, ClientError>
    ```

    Context: `impl SolanaRpc`.

    Requires: `#[cfg(feature = "solana-rpc")]`.

279. `spr_client::SolanaRpc::with_client` — [source](src/rpc/solana_rpc/blocking.rs#L46)

    ```rust
    pub fn with_client(client: RpcClient) -> Self
    ```

    Context: `impl SolanaRpc`.

    Requires: `#[cfg(feature = "solana-rpc")]`.

280. `spr_client::SolanaRpc::with_poll_interval` — [source](src/rpc/solana_rpc/blocking.rs#L57)

    ```rust
    pub fn with_poll_interval(mut self, interval: Duration) -> Self
    ```

    Context: `impl SolanaRpc`.

    Requires: `#[cfg(feature = "solana-rpc")]`.

## `spr_client::TransactionSize`

281. `spr_client::TransactionSize::fits` — [source](src/rpc/transaction_size.rs#L28)

    ```rust
    pub fn fits(&self) -> bool
    ```

    Context: `impl TransactionSize`.

## `spr_client::TransferProver`

282. `spr_client::TransferProver::build` — [source](src/prover/transact/eddsa.rs#L64)

    ```rust
    pub fn build(self) -> Result<TransferProofResult, ClientError>
    ```

    Context: `impl TransferProver`.

## `spr_client::TreeSlotFields`

283. `<spr_client::TreeSlotFields as From<&TreeSlot>>::from` — [source](src/prover/inputs.rs#L19)

    ```rust
    fn from(slot: &TreeSlot) -> Self
    ```

    Context: `impl From<&TreeSlot> for TreeSlotFields`.

284. `spr_client::TreeSlotFields::encode_all` — [source](src/prover/inputs.rs#L30)

    ```rust
    pub fn encode_all(slots: &[TreeSlot; INPUT_TREES]) -> [Self; INPUT_TREES]
    ```

    Context: `impl TreeSlotFields`.

## `spr_client::UtxoScan`

285. `spr_client::UtxoScan::fetch` — **Proposed signature change** from [current implementation](src/scan.rs#L131)

    ```rust
    pub fn fetch<I: Rpc + ?Sized>(&self, indexer: &I, assets: &AssetRegistry) -> Result<UtxoScanResult, ClientError>
    ```

    Context: `impl<'a, K: ShieldedKeys + ?Sized> UtxoScan<'a, K>`.

286. `spr_client::UtxoScan::new` — **Proposed signature change** from [current implementation](src/scan.rs#L72)

    ```rust
    pub fn new(keys: &'a K) -> Self
    ```

    Context: `impl<'a, K: ShieldedKeys + ?Sized> UtxoScan<'a, K>`.

287. `spr_client::UtxoScan::disable_asset_discovery` — **Proposed replacement** for [current `with_asset_discovery`](src/scan.rs#L110)

    ```rust
    pub fn disable_asset_discovery(mut self) -> Self
    ```

    Context: `impl<'a, K: ShieldedKeys + ?Sized> UtxoScan<'a, K>`.

    Asset discovery is enabled by default. Opt out to use only the supplied registry and report unknown assets as unresolved.

288. `spr_client::UtxoScan::with_indexer_config` — [source](src/scan.rs#L89)

    ```rust
    pub fn with_indexer_config(mut self, config: IndexerRpcConfig) -> Self
    ```

    Context: `impl<'a, K: ShieldedKeys + ?Sized> UtxoScan<'a, K>`.

289. `spr_client::UtxoScan::with_ring_deposit_payload` — **To be deleted** — [source](src/scan.rs#L118)

    ```rust
    pub fn with_ring_deposit_payload(mut self, ring_program_id: Address, deposit_payload: DepositPayload) -> Self
    ```

    Context: `impl<'a, K: ShieldedKeys + ?Sized> UtxoScan<'a, K>`.

## `spr_client::ZolanaIndexer`

290. `spr_client::ZolanaIndexer::api` — [source](src/indexer/blocking.rs#L58)

    ```rust
    pub fn api(&self) -> &ZolanaApi
    ```

    Context: `impl ZolanaIndexer`.

291. `spr_client::ZolanaIndexer::new` — [source](src/indexer/blocking.rs#L41)

    ```rust
    pub fn new(url: impl AsRef<str>) -> Self
    ```

    Context: `impl ZolanaIndexer`.

    Requires: `#[cfg(feature = "reqwest")]`.

292. `spr_client::ZolanaIndexer::prove_transact` — **To be deleted** — [source](src/indexer/blocking.rs#L86)

    ```rust
    pub fn prove_transact(&self, proof_inputs: SppProofInputs, authority: &dyn ProofAuthority) -> Result<TransactIxData, ClientError>
    ```

    Context: `impl ZolanaIndexer`.

    Requires: `#[cfg(feature = "reqwest")]`.

293. `spr_client::ZolanaIndexer::runtime` — [source](src/indexer/blocking.rs#L64)

    ```rust
    pub fn runtime(&self) -> Arc<BlockingRuntime>
    ```

    Context: `impl ZolanaIndexer`.

294. `spr_client::ZolanaIndexer::with_api` — [source](src/indexer/blocking.rs#L45)

    ```rust
    pub fn with_api(api: BlockingZolanaApi) -> Self
    ```

    Context: `impl ZolanaIndexer`.

295. `spr_client::ZolanaIndexer::with_http_trace` — [source](src/indexer/blocking.rs#L53)

    ```rust
    pub fn with_http_trace(mut self) -> Self
    ```

    Context: `impl ZolanaIndexer`.

## `spr_client::prover::ProverKeys`

296. `spr_client::prover::ProverKeys::check` — [source](src/prover/proving_key.rs#L64)

    ```rust
    pub fn check(&self) -> Result<ProvingKeyReport, ClientError>
    ```

    Context: `impl ProverKeys`.

## `spr_client::prover::indexed::IndexedMergePreparation`

297. `spr_client::prover::indexed::IndexedMergePreparation::prepare` — [source](src/prover/indexed/merge.rs#L56)

    ```rust
    pub fn prepare(self) -> Result<PreparedIndexedMerge, ClientError>
    ```

    Context: `impl IndexedMergePreparation`.

298. `spr_client::prover::indexed::IndexedMergePreparation::prepare_for_cache` — [source](src/prover/indexed/merge.rs#L60)

    ```rust
    pub fn prepare_for_cache(self, cache: crate::prover::MergeCacheTarget) -> Result<PreparedIndexedMerge, ClientError>
    ```

    Context: `impl IndexedMergePreparation`.

## `spr_client::prover::indexed::IndexedProofRequest`

299. `spr_client::prover::indexed::IndexedProofRequest::input_trees` — [source](src/prover/indexed.rs#L309)

    ```rust
    pub fn input_trees(&self) -> &[IndexedTree]
    ```

    Context: `impl IndexedProofRequest`.

300. `spr_client::prover::indexed::IndexedProofRequest::new` — [source](src/prover/indexed.rs#L147)

    ```rust
    pub fn new(data: IndexedProofData) -> Result<Self, ClientError>
    ```

    Context: `impl IndexedProofRequest`.

301. `spr_client::prover::indexed::IndexedProofRequest::with_min_context_slot` — [source](src/prover/indexed.rs#L314)

    ```rust
    pub fn with_min_context_slot(mut self, slot: u64) -> Self
    ```

    Context: `impl IndexedProofRequest`.

## `spr_client::prover::indexed::IndexedTransferPreparation`

302. `spr_client::prover::indexed::IndexedTransferPreparation::prepare` — [source](src/prover/indexed/transfer.rs#L59)

    ```rust
    pub fn prepare(self, authority: &dyn ProofAuthority) -> Result<PreparedIndexedTransfer, ClientError>
    ```

    Context: `impl IndexedTransferPreparation<'_>`.

303. `spr_client::prover::indexed::IndexedTransferPreparation::prepare_with_dummy_policy` — [source](src/prover/indexed/transfer.rs#L66)

    ```rust
    pub fn prepare_with_dummy_policy(self, authority: &dyn ProofAuthority, allow_dummy_inputs: bool) -> Result<PreparedIndexedTransfer, ClientError>
    ```

    Context: `impl IndexedTransferPreparation<'_>`.

## `spr_client::prover::indexed::PreparedIndexedMerge`

304. `spr_client::prover::indexed::PreparedIndexedMerge::with_min_context_slot` — [source](src/prover/indexed/merge.rs#L283)

    ```rust
    pub fn with_min_context_slot(mut self, slot: u64) -> Self
    ```

    Context: `impl PreparedIndexedMerge`.

## `spr_client::prover::indexed::PreparedIndexedTransfer`

305. `spr_client::prover::indexed::PreparedIndexedTransfer::new` — [source](src/prover/indexed/transfer.rs#L381)

    ```rust
    pub fn new(transaction: SppProofInputs, authority: &dyn ProofAuthority) -> Result<Self, ClientError>
    ```

    Context: `impl PreparedIndexedTransfer`.

306. `spr_client::prover::indexed::PreparedIndexedTransfer::private_tx_hash` — [source](src/prover/indexed/transfer.rs#L398)

    ```rust
    pub fn private_tx_hash(&self) -> [u8; 32]
    ```

    Context: `impl PreparedIndexedTransfer`.

307. `spr_client::prover::indexed::PreparedIndexedTransfer::with_min_context_slot` — [source](src/prover/indexed/transfer.rs#L393)

    ```rust
    pub fn with_min_context_slot(mut self, slot: u64) -> Self
    ```

    Context: `impl PreparedIndexedTransfer`.

## `spr_client::prover::indexed::ProofResolution`

308. `spr_client::prover::indexed::ProofResolution::hash` — [source](src/prover/indexed.rs#L411)

    ```rust
    pub fn hash(&self, public_inputs: &[[u8; 32]]) -> Result<[u8; 32], ClientError>
    ```

    Context: `impl ProofResolution`.

309. `spr_client::prover::indexed::ProofResolution::tree_slots` — [source](src/prover/indexed.rs#L387)

    ```rust
    pub fn tree_slots(&self) -> Result<[TreeSlot; INPUT_TREES], ClientError>
    ```

    Context: `impl ProofResolution`.

## `spr_client::prover::merge::MergePublicInputs`

310. `spr_client::prover::merge::MergePublicInputs::elements` — [source](src/prover/merge/public_inputs.rs#L36)

    ```rust
    pub fn elements(&self, tree_slots_hash: Option<[u8; 32]>) -> Result<Vec<[u8; 32]>, ClientError>
    ```

    Context: `impl MergePublicInputs<'_>`.

311. `spr_client::prover::merge::MergePublicInputs::hash` — [source](src/prover/merge/public_inputs.rs#L75)

    ```rust
    pub fn hash(&self, tree_slots_hash: [u8; 32]) -> Result<[u8; 32], ClientError>
    ```

    Context: `impl MergePublicInputs<'_>`.

## `spr_client::timing::Phase`

312. `spr_client::timing::Phase::start` — [source](src/prover/timing.rs#L32)

    ```rust
    pub fn start(name: &'static str, round: usize) -> Self
    ```

    Context: `impl Phase`.

## Reexported TEE functions

313. `spr_client::prover::tee::inspect` — [source](../prover-tee/src/verify.rs#L49)

    ```rust
    pub fn inspect(attestation: Attestation, now_secs: u64) -> Result<AttestedIdentity, TeeError>
    ```

314. `spr_client::prover::tee::verify` — [source](../prover-tee/src/verify.rs#L55)

    ```rust
    pub fn verify(attestation: Attestation, policy: &TeePolicy, nonce: &[u8; NONCE_SIZE], now_secs: u64) -> Result<AttestedProver, TeeError>
    ```

315. `spr_client::prover::tee::verify_with` — [source](../prover-tee/src/verify.rs#L65)

    ```rust
    pub fn verify_with(attestation: Attestation, policy: &TeePolicy, nonce: &[u8; NONCE_SIZE], now_secs: u64, anchors: &Anchors) -> Result<AttestedProver, TeeError>
    ```

## Dependency-owned type reexports

The following exports also expose the methods of their originating types. Those dependency implementations are outside this crate’s function declarations:

| Public exports | Defining source |
| --- | --- |
| `Shape`, `PublicTransfers` | [`spr-transaction` instruction types](../transaction/src/instructions/transact/mod.rs) |
| `ProofInputUtxo` | [`spr-transaction` UTXO types](../transaction/src/utxo/mod.rs) |
| `ShieldedTransaction`, `OutputContext`, `OutputSlot` | [`spr-transaction` exports](../transaction/src/lib.rs) |
| `UserRecord` | [`spr-user-registry-interface`](../../program-libs/user-registry-interface/src/lib.rs) |
| `RpcSendTransactionConfig` | `solana_rpc_client_api::config` |
| TEE policy, identity, attestation, encryption, and key-provider types | [`spr-prover-tee` exports](../prover-tee/src/lib.rs), reexported by [`prover::tee`](src/prover/tee.rs) |

## Proposed proving API consolidation

Consolidate high-level transaction proving around `TransactionProofRequest` and `MergeProofRequest` (the proposed names below). The seven client, indexer, and RPC proving entries marked **To be deleted** are replaced by this request flow.

Before removing those APIs, add a proof-only stage to `TransactionProofRequest` that returns a proved transaction convertible into a Solana instruction. Preserve custom transaction composition, unsigned message preparation for mobile wallets and external signers, and the complete prove, sign, send, confirm, and index flow. `MergeProofRequest` retains the corresponding stages, including its existing `ProvedMerge` result.

The underlying `Prover`, `ProverExt`, `AsyncProverClient`, and witness assembly APIs remain available as the primitives used by the request flow, except for individual methods explicitly marked **To be deleted**.

Both request types expose `prove` and `prove_sync` for staged execution, returning `ProvedTransaction` or `ProvedMerge`. Keep the complete-flow convenience methods on the requests and rename `send` to `prove_and_send`, and `send_sync` to `prove_and_send_sync`.

`prove_and_send` and `prove_and_send_sync` generate and verify the proof, obtain a fresh blockhash, build and sign the Solana message, submit it, and wait for confirmation and indexing. They take an `AsyncZolanaClient` or `ZolanaClient` respectively, plus the required Solana signers; the merge variants take the fee-payer signer. Their names make the included proving work explicit.

Callers who need control over the stages use `prove` or `prove_sync`, then `proved.build_solana_message` with an explicit blockhash, followed by separate signing and RPC submission.

## Proposed transaction proof request

`TransactionProofRequest` owns the proof inputs directly and builds and validates settlement accounts from the transaction's public transfers:

```rust
impl<'a> TransactionProofRequest<'a> {
    pub fn new(
        transaction: SppProofInputs,
        authorities: &'a [&'a dyn ProofAuthority],
    ) -> Result<Self, ClientError>

    pub fn with_confidential_eddsa_owner(self, owner: &'a SigningKey) -> Self
}
```

The optional owner capability preserves in-circuit Ed25519 authorization. Select its shape with `with_transaction_signers` before encryption; the resulting Solana message omits that owner's signer account.

Keep encryption as its own statement:

```rust
let proof_inputs = transaction.encrypt(&sender)?;
let authorities: &[&dyn ProofAuthority] = &[&sender, &program_authority];
let request = TransactionProofRequest::new(proof_inputs, authorities)?;
let proved = request.prove_sync(&client)?;
let (blockhash, last_valid_block_height) = client.get_latest_blockhash()?;
let unsigned = proved.build_solana_message(
    blockhash,
    last_valid_block_height,
    client.compute_budget(),
)?;
```

Accept a slice of proof authorities directly. A normal wallet supplies one authority; a transaction combining inputs with different nullifier keys can supply several, including authorities for program-owned notes. Match each input to its appropriate authority and require every real input that needs proof completion to be completed and validated. Authority selection must be explicit; propagate provider and validation errors rather than treating arbitrary failures as a reason to try another authority. A separate composite-authority type is not required.

Read the fee payer from `transaction.payer`; do not accept a duplicate fee-payer argument in the constructor. The proof-authority slice is separate from the Solana signers used later to sign the message, and PDA/program authorization remains a separate requirement.

**To be deleted:** [`SignedPrivateTransaction`](src/client/transaction.rs#L40) and its public reexports. Its intermediate wrapping step moves into `TransactionProofRequest::new`; the proposed `SignedPrivateTransaction::new` constructor is superseded by this design.

For SOL, derive each settlement account from the recipient already stored in `external_data.interface_transfers`. Preserve transfer order and validate the mappings. Keep the request's proof inputs and derived settlement accounts private so callers cannot independently mutate them.

SPL settlement resolves the mint's token program through the Solana RPC during proving. It validates the token account's program and mint and reads its owner as the deposit token authority. The resolved settlement accounts remain private within the request flow and proved result.

## Proposed merge keys and proof request

Add `MergeKeys` as the capability that provides the shielded address and operations needed to prepare a merge proof. Expose the required operations through the trait rather than requiring callers to extract raw nullifier secret material.

Implement `MergeKeys` for `ShieldedKeypair`, so a normal wallet can pass its existing keys directly. Add `LocalMergeKeys` as the concrete implementation for callers holding only a `ShieldedAddress` and `NullifierKey`. Its constructor validates that the nullifier key's public key matches the address.

`MergeProofRequest` owns the encrypted merge inputs and borrows its merge keys:

```rust
impl<'a> MergeProofRequest<'a> {
    pub fn new(
        merge: MergeProofInputs,
        keys: &'a dyn MergeKeys,
    ) -> Result<Self, ClientError>
}
```

```rust
let merge = transaction.encrypt(&sender)?;
let request = MergeProofRequest::new(merge, &sender)?;
```

Read the shielded address through `MergeKeys` and derive the registry owner from its signing public key. This replaces the separate owner, address, and nullifier-key arguments of `MergeSubmission::new`.

The merge proof does not bind a fee payer. Keep the fee payer as an argument when building the Solana message, so a relayer can pay without changing or regenerating the proof.

## Proposed Solana message construction

Proving returns a proved result containing the verified proof and instruction data. Put `build_solana_message` on that result. The caller supplies a recent blockhash, its corresponding last valid block height, and the compute budget explicitly:

```rust
impl ProvedTransaction {
    pub fn build_solana_message(
        &self,
        blockhash: Hash,
        last_valid_block_height: u64,
        compute_budget: ComputeBudgetConfig,
    ) -> Result<UnsignedMessage, ClientError>
}

impl ProvedMerge {
    pub fn build_solana_message(
        &self,
        fee_payer: Address,
        blockhash: Hash,
        last_valid_block_height: u64,
        compute_budget: ComputeBudgetConfig,
    ) -> Result<UnsignedMessage, ClientError>
}
```

This is a pure synchronous operation: it constructs the instruction and unsigned message without RPC access, proof generation, signing, submission, or confirmation. Blocking and async callers use the same method; there is no `_sync` counterpart.

Fetch the blockhash after proving, and keep it paired with the last valid block height from the same RPC response. The result remains `UnsignedMessage { message: VersionedMessage, last_valid_block_height: u64 }`. A caller can rebuild a message using a fresh blockhash without regenerating its proof, subject to that proof's own root validity and expiry.

## Proposed asset registry and scanning API

Keep `AssetRegistry` caller-owned. `UtxoScan` stores the keys and scan configuration; the registry is an immutable input to each `fetch` call:

```rust
impl<'a, K: ShieldedKeys + ?Sized> UtxoScan<'a, K> {
    pub fn new(keys: &'a K) -> Self

    pub fn disable_asset_discovery(mut self) -> Self

    pub fn fetch<I: Rpc + ?Sized>(
        &self,
        indexer: &I,
        assets: &AssetRegistry,
    ) -> Result<UtxoScanResult, ClientError>
}

impl AssetRegistry {
    pub fn extend(&mut self, other: &AssetRegistry) -> Result<(), TransactionError>
}
```

```rust
let scanner = UtxoScan::new(&sender);
let scan = scanner.fetch(&client, &assets)?;
assets.extend(&scan.asset_registry)?;
```

Asset discovery is enabled by default. `fetch` returns a new registry in `UtxoScanResult::asset_registry`, containing the supplied mappings plus validated on-chain discoveries. The supplied registry stays unchanged. Unknown assets without validated registrations remain unresolved.

`UtxoScan::new(&sender).disable_asset_discovery()` opts out of discovery. That scan uses only the supplied registry and reports other assets as unresolved.

`AssetRegistry::extend` adds unknown mappings, accepts identical mappings, and rejects conflicting asset IDs or mint addresses. Check all mappings before applying changes so an error leaves the registry unchanged.

The scanner holds no registry borrow between calls, so callers can extend or replace their registry and reuse the scanner with it on the next fetch.

### Output diagnostics

Add per-output diagnostics in `UtxoScanResult::unresolved_outputs`, alongside the existing aggregate `unknown_asset_ids` and `unknown_mints`. Each entry identifies the transaction signature, event index when available, output slot, and output context, with a reason:

| Reason | Meaning |
| --- | --- |
| `UnknownAssetId` | An output was decoded but its asset ID could not be resolved using the supplied registry or enabled discovery. |
| `UnknownMint` | A mint named by an authenticated owned output has no registry mapping. |
| `NotDecryptable` | No supplied viewing key produced usable plaintext for an encrypted candidate output. This does not establish ownership or identify whether a key is missing or the payload is invalid. |

Report the final unresolved outputs after discovery and reprocessing; outputs successfully resolved during the scan must not remain in the diagnostics. Keep identifiable framing, unsupported-encoding, and commitment-validation failures distinct from decryption failures.

Published dummy outputs carry length-matched random payloads and a participant's view tag. They can therefore appear among fetched candidates and fail framing or decryption normally. A failed attempt alone cannot reliably distinguish dummy padding, another recipient's output, missing viewing keys, or invalid data; diagnostics must not label these as missing funds or confirmed corruption. Compact dummy outputs are omitted from the published output list and do not appear in a scan. Do not identify dummies by a zero amount: an owned zero-value output can be a real committed output.

**Open design improvement:** provide a clean, reliable way for the scanner to identify dummy outputs and exclude them from unresolved-output diagnostics. The mechanism should preserve the intended privacy of padding; whether identification is public or available only to the wallet remains to be designed.

An undecryptable candidate can belong to another recipient, so it is diagnostic information, not proof of a missing wallet balance. Continue scanning other outputs. Failures of the key provider itself, such as an unavailable provider or an incomplete response, remain scan errors rather than per-output `NotDecryptable` results.

## Proposed renamings

| Current name | Proposed name | Reason |
| --- | --- | --- |
| `Submission` | `TransactionProofRequest` | Owns the transaction proof inputs, including their fee payer, and accepts a slice of proof authorities plus an optional prover override. Supports proof-only execution or the complete prove-and-send flow, including withdrawals. |
| `MergeSubmission` | `MergeProofRequest` | Describes a merge proof request with proof-only and complete prove-and-send execution. |
| `send` | `prove_and_send` | On both request types, explicitly names the complete async prove, sign, submit, confirm, and index flow. |
| `send_sync` | `prove_and_send_sync` | Blocking counterpart on both request types. |
| `finish_unsigned` | `prove` followed by `proved.build_solana_message` | Separate async proving from pure message construction with an explicit blockhash. |
| `finish_unsigned_sync` | `prove_sync` followed by `proved.build_solana_message` | Separate blocking proving from the same pure message builder. |
| `UtxoScan::with_asset_discovery` | `UtxoScan::disable_asset_discovery` | Discovery is enabled by default; provide an explicit opt-out. |

The proof request fetches the required proof data and generates and verifies the proof. The proved result builds the Solana message using the caller's blockhash, expiry, and compute budget. It returns an `UnsignedMessage` for signing.

Apply these renames to the types and their public reexports. The inventory above retains the current names so existing declarations remain easy to locate while the API is being designed.
