use anyhow::{anyhow, Context, Result};
use num_bigint::BigUint;
use solana_address::Address;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::Transaction;
use zolana_client::{
    BatchAddressAppendInputs, ProofCompressed, ProverClient, Rpc, SolanaRpc, NULLIFIER_TREE_HEIGHT,
};
use zolana_hasher::hash_chain::create_hash_chain_from_array;
use zolana_interface::instruction::{BatchUpdateNullifierTree, BatchUpdateNullifierTreeData};
use zolana_merkle_tree::indexed::IndexedMerkleTree;
use zolana_test_utils::smart_account;
use zolana_transaction::instructions::transact::signed_transaction::BN254_MODULUS_DEC;
use zolana_tree::TreeAccount;

type NullifierTree = IndexedMerkleTree<zolana_hasher::Poseidon, usize>;

#[derive(Default)]
pub struct NullifierTestForester {
    inserted_nullifiers: Vec<[u8; 32]>,
}

#[derive(Clone, Copy)]
pub struct ForesterAuthority<'a> {
    pub signer: &'a Keypair,
    pub settings: Pubkey,
    pub account_index: u8,
    pub vault: Pubkey,
}

impl NullifierTestForester {
    pub fn run(
        &mut self,
        rpc: &mut SolanaRpc,
        authority: ForesterAuthority<'_>,
        pool_tree: Pubkey,
        queued_nullifiers: &[[u8; 32]],
    ) -> Result<Signature> {
        let (batch_update, batch_len) =
            self.build_instruction(rpc, authority.vault, pool_tree, queued_nullifiers)?;
        let execute = smart_account::execute_sync_ix(
            &authority.settings,
            authority.account_index,
            &[authority.signer.pubkey()],
            &[batch_update],
        );
        let fee_payer = authority.signer.pubkey();
        let (blockhash, _) = rpc.get_latest_blockhash()?;
        let message = Message::new(&[execute], Some(&fee_payer));
        let tx = Transaction::new(&[authority.signer], message, blockhash);
        let signature = rpc.send_transaction(&tx)?;
        self.mark_batch_inserted(queued_nullifiers, batch_len);
        Ok(signature)
    }

    fn build_instruction(
        &self,
        rpc: &SolanaRpc,
        authority: Pubkey,
        pool_tree: Pubkey,
        queued_nullifiers: &[[u8; 32]],
    ) -> Result<(solana_instruction::Instruction, usize)> {
        let plan = ForesterPlan::from_chain(rpc, pool_tree)?;
        let start = self.inserted_nullifiers.len();
        let end = start + plan.zkp_batch_size;
        if queued_nullifiers.len() < end {
            return Err(anyhow!(
                "queued nullifiers {} < next batch end {} (zkp batch size {})",
                queued_nullifiers.len(),
                end,
                plan.zkp_batch_size
            ));
        }
        let batch_values = &queued_nullifiers[start..end];
        let (inputs, new_root) = self.build_inputs(&plan, batch_values)?;
        let proof = ProverClient::local().prove_batch_address_append(&inputs)?;
        let compressed = ProofCompressed::try_from(proof)?;
        let batch_update = BatchUpdateNullifierTreeData {
            new_root,
            old_root: plan.current_root,
            hash_chain_index: plan.hash_chain_index,
            compressed_proof: zolana_interface::instruction::CompressedProof {
                a: compressed.a,
                b: compressed.b,
                c: compressed.c,
            },
        };

        Ok((
            BatchUpdateNullifierTree {
                authority,
                tree: pool_tree,
                new_root: batch_update.new_root,
                old_root: batch_update.old_root,
                hash_chain_index: batch_update.hash_chain_index,
                compressed_proof_a: batch_update.compressed_proof.a,
                compressed_proof_b: batch_update.compressed_proof.b,
                compressed_proof_c: batch_update.compressed_proof.c,
            }
            .instruction(),
            batch_values.len(),
        ))
    }

    fn mark_batch_inserted(&mut self, queued_nullifiers: &[[u8; 32]], batch_len: usize) {
        let start = self.inserted_nullifiers.len();
        self.inserted_nullifiers
            .extend_from_slice(&queued_nullifiers[start..start + batch_len]);
    }

    fn build_inputs(
        &self,
        plan: &ForesterPlan,
        batch_values: &[[u8; 32]],
    ) -> Result<(BatchAddressAppendInputs, [u8; 32])> {
        let mut reference = reference_nullifier_tree()?;
        for value in &self.inserted_nullifiers {
            reference.append(&BigUint::from_bytes_be(value))?;
        }
        if reference.root() != plan.current_root {
            return Err(anyhow!(
                "reference nullifier root does not match on-chain root"
            ));
        }

        let mut low_element_values = Vec::with_capacity(batch_values.len());
        let mut low_element_indices = Vec::with_capacity(batch_values.len());
        let mut low_element_next_values = Vec::with_capacity(batch_values.len());
        let mut new_element_values = Vec::with_capacity(batch_values.len());
        let mut low_element_proofs = Vec::with_capacity(batch_values.len());
        let mut new_element_proofs = Vec::with_capacity(batch_values.len());

        for (offset, value_bytes) in batch_values.iter().enumerate() {
            let value = BigUint::from_bytes_be(value_bytes);
            let non_inclusion = reference.get_non_inclusion_proof(&value)?;
            low_element_values.push(BigUint::from_bytes_be(
                &non_inclusion.leaf_lower_range_value,
            ));
            low_element_indices.push(BigUint::from(non_inclusion.leaf_index as u64));
            low_element_next_values.push(BigUint::from_bytes_be(
                &non_inclusion.leaf_higher_range_value,
            ));
            low_element_proofs.push(bytes_path_to_biguint(non_inclusion.merkle_proof));
            new_element_values.push(value.clone());

            reference.append(&value)?;
            let new_index = plan.start_index as usize + offset;
            let new_proof = reference
                .get_proof_of_leaf(new_index, true)
                .with_context(|| format!("new element proof at index {new_index}"))?;
            new_element_proofs.push(bytes_path_to_biguint(new_proof));
        }

        let new_root = reference.root();
        let mut start_index_bytes = [0u8; 32];
        start_index_bytes[24..].copy_from_slice(&plan.start_index.to_be_bytes());
        let public_input_hash = create_hash_chain_from_array([
            plan.current_root,
            new_root,
            plan.leaves_hash_chain,
            start_index_bytes,
        ])?;

        Ok((
            BatchAddressAppendInputs {
                public_input_hash: BigUint::from_bytes_be(&public_input_hash),
                old_root: BigUint::from_bytes_be(&plan.current_root),
                new_root: BigUint::from_bytes_be(&new_root),
                hashchain_hash: BigUint::from_bytes_be(&plan.leaves_hash_chain),
                start_index: plan.start_index,
                low_element_values,
                low_element_indices,
                low_element_next_values,
                new_element_values,
                low_element_proofs,
                new_element_proofs,
                tree_height: plan.tree_height,
                batch_size: batch_values.len() as u32,
            },
            new_root,
        ))
    }
}

struct ForesterPlan {
    current_root: [u8; 32],
    leaves_hash_chain: [u8; 32],
    start_index: u64,
    tree_height: u32,
    zkp_batch_size: usize,
    hash_chain_index: u16,
}

impl ForesterPlan {
    fn from_chain(rpc: &SolanaRpc, pool_tree: Pubkey) -> Result<Self> {
        let mut data = rpc
            .get_account(Address::new_from_array(pool_tree.to_bytes()))?
            .ok_or_else(|| anyhow!("tree account not found: {pool_tree}"))?
            .data;
        let mut tree = TreeAccount::from_bytes(&mut data, pool_tree.to_bytes())
            .map_err(|err| anyhow!("load tree account: {err:?}"))?;
        let nullifier_tree = tree.nullifer_tree();
        let metadata = *nullifier_tree.get_metadata();
        let pending_batch_index = metadata.queue_batches.pending_batch_index as usize;
        let batch = metadata
            .queue_batches
            .batches
            .get(pending_batch_index)
            .ok_or_else(|| anyhow!("pending batch index out of range: {pending_batch_index}"))?;
        let zkp_batch_index = batch
            .get_first_ready_zkp_batch()
            .map_err(|err| anyhow!("no ready nullifier zkp batch: {err:?}"))?
            as usize;
        let hash_chain_index = u16::try_from(zkp_batch_index)
            .map_err(|_| anyhow!("zkp batch index {zkp_batch_index} exceeds u16"))?;
        let leaves_hash_chain = nullifier_tree
            .get_hash_chain(pending_batch_index, zkp_batch_index)
            .ok_or_else(|| {
                anyhow!("missing hash chain for batch {pending_batch_index} zkp {zkp_batch_index}")
            })?;
        let current_root = nullifier_tree
            .get_root()
            .ok_or_else(|| anyhow!("nullifier tree has no current root"))?;

        Ok(Self {
            current_root,
            leaves_hash_chain,
            start_index: metadata.next_index,
            tree_height: metadata.height,
            zkp_batch_size: metadata.queue_batches.zkp_batch_size as usize,
            hash_chain_index,
        })
    }
}

fn reference_nullifier_tree() -> Result<NullifierTree> {
    let modulus_minus_one = BigUint::parse_bytes(BN254_MODULUS_DEC.as_bytes(), 10)
        .context("parse bn254 modulus")?
        - 1u32;
    Ok(
        IndexedMerkleTree::<zolana_hasher::Poseidon, usize>::new_with_next_value(
            NULLIFIER_TREE_HEIGHT,
            0,
            modulus_minus_one,
        )?,
    )
}

fn bytes_path_to_biguint(path: Vec<[u8; 32]>) -> Vec<BigUint> {
    path.into_iter()
        .map(|item| BigUint::from_bytes_be(&item))
        .collect()
}
