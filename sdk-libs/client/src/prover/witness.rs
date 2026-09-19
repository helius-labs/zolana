//! Input witnesses, behind one call.
//!
//! The circuit needs two things per input tree: a state-inclusion proof for
//! every real input, and a nullifier non-inclusion proof for every slot,
//! padding included. Those came from two indexer methods and three round
//! trips, and every caller stitched them together itself -- one of them by
//! hand-rolling a scoped thread to overlap two of the three.
//!
//! [`WitnessReader`] is that stitching, shaped as the Photon RPC it is meant to
//! become: slots in, complete witnesses out. Moving it to the server later is
//! then a change of implementation rather than of every call site.

use zolana_interface::pda;
use zolana_transaction::utxo::SppProofInputUtxo;

use crate::{
    error::ClientError,
    indexer::{AsyncZolanaIndexer, ZolanaIndexer},
    prover::transact::witness::SpendProof,
    rpc::{
        AsyncRpc, GetMerkleProofsResponse, GetNonInclusionProofsResponse, IndexerRpcConfig,
        NonInclusionProof, Rpc,
    },
};

/// Everything the circuit witnesses about one transaction's inputs.
#[derive(Clone, Default)]
pub struct InputWitnesses {
    /// One per real input, in the order `inputs` was given.
    ///
    /// That order is the real-input subsequence, not the slot vector:
    /// callers supply only non-dummy inputs, and `attach_input_proofs`
    /// matches on the same convention. A reader that
    /// returned these in slot order would attach every witness to the wrong
    /// input, silently.
    pub spend_proofs: Vec<SpendProof>,
    /// One per padding slot, in slot order. The circuit checks non-inclusion
    /// for every slot, so a dummy needs a real low-element witness too.
    pub dummy_nullifier_proofs: Vec<NonInclusionProof>,
}

/// Reads the witnesses for one transaction's inputs.
///
/// The inputs name their own trees, so no caller supplies one. Inputs from
/// several trees are fetched per tree and the results are put back in the
/// caller's order.
pub trait WitnessReader {
    fn input_witnesses(
        &self,
        inputs: &[&SppProofInputUtxo],
        dummy_nullifiers: &[[u8; 32]],
        config: Option<IndexerRpcConfig>,
    ) -> Result<InputWitnesses, ClientError>;
}

/// The async counterpart. Separate from [`WitnessReader`] because the trait
/// would otherwise need an async method, and the two indexers are distinct
/// types rather than one behind a runtime flag.
pub trait AsyncWitnessReader {
    fn input_witnesses(
        &self,
        inputs: &[&SppProofInputUtxo],
        dummy_nullifiers: &[[u8; 32]],
        config: Option<IndexerRpcConfig>,
    ) -> impl std::future::Future<Output = Result<InputWitnesses, ClientError>> + Send;
}

/// One tree's share of the inputs: the raw id its proofs are fetched under,
/// and the inputs themselves paired with where they sat in the caller's
/// vector.
///
/// The positions travel with the group because
/// [`InputWitnesses::spend_proofs`] is consumed positionally. Concatenating
/// per-tree results would yield tree-major order and attach every witness to
/// the wrong input.
struct TreeGroup<'a> {
    tree_id: u16,
    positions: Vec<usize>,
    inputs: Vec<&'a SppProofInputUtxo>,
}

impl TreeGroup<'_> {
    fn leaves(&self) -> Vec<[u8; 32]> {
        self.inputs.iter().map(|input| input.utxo_hash).collect()
    }

    fn nullifiers(&self) -> Vec<[u8; 32]> {
        self.inputs.iter().map(|input| input.nullifier).collect()
    }
}

/// Split the inputs by the tree each names, trees in first-use order and each
/// tree's inputs in the caller's order.
fn group_by_tree<'a>(inputs: &[&'a SppProofInputUtxo]) -> Vec<TreeGroup<'a>> {
    let mut groups: Vec<TreeGroup> = Vec::with_capacity(1);
    for (position, &input) in inputs.iter().enumerate() {
        match groups
            .iter_mut()
            .find(|group| group.tree_id == input.tree_id)
        {
            Some(group) => {
                group.positions.push(position);
                group.inputs.push(input);
            }
            None => groups.push(TreeGroup {
                tree_id: input.tree_id,
                positions: vec![position],
                inputs: vec![input],
            }),
        }
    }
    groups
}

/// The tree a padding slot's non-inclusion proof is fetched from.
///
/// Padding is hashed under the first input tree (`pad_input_utxos`), and
/// assembly requires every slot in a tree's run to share that tree's nullifier
/// root, so the first group is the only right answer. Without a real input
/// there is no tree at all.
fn padding_tree_id(groups: &[TreeGroup]) -> Result<u16, ClientError> {
    groups
        .first()
        .map(|group| group.tree_id)
        .ok_or(ClientError::NoInputs)
}

/// Put each tree's validated proofs back where its inputs came from.
fn scatter(mut placed: Vec<(usize, SpendProof)>) -> Vec<SpendProof> {
    placed.sort_by_key(|(position, _)| *position);
    placed.into_iter().map(|(_, proof)| proof).collect()
}

impl WitnessReader for ZolanaIndexer {
    fn input_witnesses(
        &self,
        inputs: &[&SppProofInputUtxo],
        dummy_nullifiers: &[[u8; 32]],
        config: Option<IndexerRpcConfig>,
    ) -> Result<InputWitnesses, ClientError> {
        let groups = group_by_tree(inputs);
        let dummy_tree = if dummy_nullifiers.is_empty() {
            None
        } else {
            Some(pda::tree(padding_tree_id(&groups)?))
        };

        // Independent round trips (317ms and 114ms on devnet for the first
        // two), run together for the reason the async path uses `try_join!`:
        // different methods, none consuming another's output. Serially this
        // cost the sum on every transfer. A second input tree adds two more
        // requests, which overlap with the rest rather than queueing behind
        // them.
        let (per_tree, dummy) = std::thread::scope(|scope| {
            let per_tree: Vec<_> = groups
                .iter()
                .map(|group| {
                    let tree = pda::tree(group.tree_id);
                    let state = scope.spawn(move || {
                        let _t = crate::prover::timing::Phase::start("get_merkle_proofs", 0);
                        self.get_merkle_proofs(tree, group.leaves(), config)
                    });
                    let nullifier = scope.spawn(move || {
                        let _t = crate::prover::timing::Phase::start("get_non_inclusion_proofs", 0);
                        self.get_non_inclusion_proofs(tree, group.nullifiers(), config)
                    });
                    (state, nullifier)
                })
                .collect();
            let dummy = scope.spawn(|| {
                let Some(tree) = dummy_tree else {
                    return Ok(Vec::new());
                };
                let _t = crate::prover::timing::Phase::start("get_dummy_non_inclusion_proofs", 0);
                self.get_non_inclusion_proofs(tree, dummy_nullifiers.to_vec(), config)
                    .map(|response| response.proofs)
            });
            let per_tree: Vec<_> = per_tree
                .into_iter()
                .map(|(state, nullifier)| (state.join(), nullifier.join()))
                .collect();
            (per_tree, dummy.join())
        });
        // A panic in any of them is a bug in the indexer client, not an
        // unreachable indexer.
        let dummy_nullifier_proofs =
            dummy.unwrap_or_else(|payload| std::panic::resume_unwind(payload))?;

        let mut placed = Vec::with_capacity(inputs.len());
        for (group, (state, nullifier)) in groups.iter().zip(per_tree) {
            let state = state.unwrap_or_else(|payload| std::panic::resume_unwind(payload))?;
            let nullifier =
                nullifier.unwrap_or_else(|payload| std::panic::resume_unwind(payload))?;
            placed.extend(
                group.positions.iter().copied().zip(validate_spend_proofs(
                    group
                        .positions
                        .iter()
                        .copied()
                        .zip(group.inputs.iter().copied()),
                    state.proofs,
                    nullifier.proofs,
                )?),
            );
        }

        Ok(InputWitnesses {
            spend_proofs: scatter(placed),
            dummy_nullifier_proofs,
        })
    }
}

impl AsyncWitnessReader for AsyncZolanaIndexer {
    async fn input_witnesses(
        &self,
        inputs: &[&SppProofInputUtxo],
        dummy_nullifiers: &[[u8; 32]],
        config: Option<IndexerRpcConfig>,
    ) -> Result<InputWitnesses, ClientError> {
        let groups = group_by_tree(inputs);
        let dummy_tree = if dummy_nullifiers.is_empty() {
            None
        } else {
            Some(pda::tree(padding_tree_id(&groups)?))
        };

        let per_tree = futures::future::try_join_all(groups.iter().map(|group| {
            let tree = pda::tree(group.tree_id);
            async move {
                tokio::try_join!(
                    self.get_merkle_proofs(tree, group.leaves(), config),
                    self.get_non_inclusion_proofs(tree, group.nullifiers(), config),
                )
            }
        }));
        let dummy = async {
            let Some(tree) = dummy_tree else {
                return Ok(Vec::new());
            };
            self.get_non_inclusion_proofs(tree, dummy_nullifiers.to_vec(), config)
                .await
                .map(|response| response.proofs)
        };
        let (per_tree, dummy_nullifier_proofs): (
            Vec<(GetMerkleProofsResponse, GetNonInclusionProofsResponse)>,
            Vec<NonInclusionProof>,
        ) = tokio::try_join!(per_tree, dummy)?;

        let mut placed = Vec::with_capacity(inputs.len());
        for (group, (state, nullifier)) in groups.iter().zip(per_tree) {
            placed.extend(
                group.positions.iter().copied().zip(validate_spend_proofs(
                    group
                        .positions
                        .iter()
                        .copied()
                        .zip(group.inputs.iter().copied()),
                    state.proofs,
                    nullifier.proofs,
                )?),
            );
        }

        Ok(InputWitnesses {
            spend_proofs: scatter(placed),
            dummy_nullifier_proofs,
        })
    }
}

/// Bind each fetched proof to the input that asked for it.
///
/// The tree is not a parameter: an input names its own, and both its
/// commitment and its nullifier fold that id in, so the account a proof came
/// from must be `pda::tree(input.tree_id)`. Reported indexes are the input's
/// original position among the real inputs, so an error still points at the
/// right input when the proofs were fetched per tree.
fn validate_spend_proofs<'a>(
    inputs: impl ExactSizeIterator<Item = (usize, &'a SppProofInputUtxo)>,
    state_proofs: Vec<crate::rpc::MerkleProof>,
    nullifier_proofs: Vec<crate::rpc::NonInclusionProof>,
) -> Result<Vec<SpendProof>, ClientError> {
    if state_proofs.len() != inputs.len() || nullifier_proofs.len() != inputs.len() {
        return Err(ClientError::IncompleteInputProofs {
            expected: inputs.len(),
            state: state_proofs.len(),
            nullifier: nullifier_proofs.len(),
        });
    }

    state_proofs
        .into_iter()
        .zip(nullifier_proofs)
        .zip(inputs)
        .map(|((state, nullifier), (index, input))| {
            let proof = SpendProof { state, nullifier };
            proof.validate(input, index)?;
            Ok(proof)
        })
        .collect()
}
