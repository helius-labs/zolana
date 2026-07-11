use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_interface::{
    instruction::{MergeTransact, Transact, TransactWithdrawal},
    pda, SPL_TOKEN_PROGRAM_ID,
};
use zolana_keypair::{hash::sha256_be, NullifierKey};
use zolana_transaction::{
    instructions::{
        merge::PreparedMerge,
        transact::{ExternalData, SignedTransaction},
        types::InputCommitment,
    },
    Address,
};

use crate::{
    error::ClientError,
    prover::{
        merge::{MergeProver, MergeWitness},
        transact::{assemble, ProverInputs, SpendProof},
        ProofCompressed, ProverClient,
    },
    rpc::Rpc,
    user_registry::{base_address_from_record, fetch_user_record_checked},
};
use zolana_user_registry_interface::user_record_pda;

const PRIVATE_TX_COMPUTE_UNIT_LIMIT: u32 = 1_400_000;

/// Prove and submit an already signed shielded transaction. Indexing waits are
/// intentionally caller policy; this action ends when the chain RPC accepts it.
pub struct SubmitPrivateTransaction<'a, R: Rpc + ?Sized, I: Rpc + ?Sized> {
    pub rpc: &'a R,
    pub indexer: &'a I,
    pub funding: &'a Keypair,
    pub tree: Pubkey,
    pub prover_url: &'a str,
    pub withdrawal: Option<TransactWithdrawal>,
    pub signed: SignedTransaction,
}

pub fn submit_private_transaction<R: Rpc + ?Sized, I: Rpc + ?Sized>(
    request: SubmitPrivateTransaction<'_, R, I>,
) -> Result<Signature, ClientError> {
    validate_private_submission(
        &request.signed,
        request.funding,
        request.withdrawal.as_ref(),
    )?;
    let commitments = request.signed.input_commitments()?;
    let proofs = spend_proofs(request.indexer, request.tree, &commitments)?;
    let assembled = assemble(request.signed, &proofs)?;
    let prover = ProverClient::new(request.prover_url.to_string());
    let proof = match &assembled.prover_inputs {
        ProverInputs::P256(inputs) => prover.prove_transfer_p256(inputs)?,
        ProverInputs::Eddsa(inputs) => prover.prove_transfer(inputs)?,
    };
    let proof = ProofCompressed::try_from(proof)?.to_transact_proof();
    let data = assembled.with_proof(proof);
    let instruction = Transact {
        payer: request.funding.pubkey(),
        tree: request.tree,
        withdrawal: request.withdrawal,
        data,
    }
    .instruction();
    let instructions = [
        solana_compute_budget_interface::ComputeBudgetInstruction::set_compute_unit_limit(
            PRIVATE_TX_COMPUTE_UNIT_LIMIT,
        ),
        instruction,
    ];
    request.rpc.create_and_send_transaction(
        &instructions,
        Address::new_from_array(request.funding.pubkey().to_bytes()),
        &[request.funding],
    )
}

fn validate_private_submission(
    signed: &SignedTransaction,
    funding: &Keypair,
    withdrawal: Option<&TransactWithdrawal>,
) -> Result<(), ClientError> {
    let owner = funding.pubkey();
    if signed.payer_pubkey_hash != sha256_be(&owner.to_bytes()) {
        return Err(ClientError::SubmissionMismatch(format!(
            "funding key {owner} is not the signed transaction payer"
        )));
    }
    validate_withdrawal(&signed.external_data, withdrawal)
}

fn validate_withdrawal(
    external: &ExternalData,
    withdrawal: Option<&TransactWithdrawal>,
) -> Result<(), ClientError> {
    let empty = Address::default();
    match (
        external.public_sol_amount,
        external.public_spl_amount,
        withdrawal,
    ) {
        (None, None, None)
            if external.user_sol_account == empty
                && external.user_spl_token == empty
                && external.spl_token_interface == empty =>
        {
            Ok(())
        }
        (Some(amount), None, Some(TransactWithdrawal::Sol(sol)))
            if amount < 0
                && external.user_sol_account
                    == Address::new_from_array(sol.recipient.to_bytes())
                && external.user_spl_token == empty
                && external.spl_token_interface == empty =>
        {
            Ok(())
        }
        (None, Some(amount), Some(TransactWithdrawal::Spl(spl)))
            if amount < 0
                && external.user_sol_account == empty
                && external.user_spl_token
                    == Address::new_from_array(spl.user_token_account.to_bytes())
                && external.spl_token_interface
                    == Address::new_from_array(spl.spl_token_interface.to_bytes())
                && spl.cpi_authority == Some(pda::shielded_pool_cpi_authority())
                && spl.token_program == Pubkey::new_from_array(SPL_TOKEN_PROGRAM_ID) =>
        {
            Ok(())
        }
        _ => Err(ClientError::SubmissionMismatch(
            "withdrawal accounts do not match the signed transaction's public settlement"
                .to_string(),
        )),
    }
}

/// Prove and submit a prepared note consolidation.
pub struct SubmitMergeTransaction<'a, R: Rpc + ?Sized, I: Rpc + ?Sized> {
    pub rpc: &'a R,
    pub indexer: &'a I,
    /// Registry owner whose notes are being consolidated.
    pub owner: Pubkey,
    /// Fee payer and signer. This may differ from `owner` for relayed merges.
    pub payer: &'a Keypair,
    pub nullifier_key: &'a NullifierKey,
    pub tree: Pubkey,
    pub prover_url: &'a str,
    pub prepared: PreparedMerge,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubmittedMerge {
    pub signature: Signature,
    pub output_hash: [u8; 32],
}

pub fn submit_merge_transaction<R: Rpc + ?Sized, I: Rpc + ?Sized>(
    request: SubmitMergeTransaction<'_, R, I>,
) -> Result<SubmittedMerge, ClientError> {
    let owner = request.owner;
    let payer = request.payer.pubkey();
    validate_merge_submission(request.rpc, owner, request.nullifier_key, &request.prepared)?;
    let commitments = request.prepared.input_commitments()?;
    let proofs = spend_proofs(request.indexer, request.tree, &commitments)?;
    let result = MergeProver::try_from(MergeWitness {
        prepared: request.prepared,
        nullifier_key: request.nullifier_key.clone(),
        proofs,
    })?
    .build()?;
    let prover = ProverClient::new(request.prover_url.to_string());
    let proof = ProofCompressed::try_from(prover.prove_merge(&result.inputs)?)?.to_merge_proof()?;
    let instruction = MergeTransact {
        tree: request.tree,
        payer,
        user_record: user_record_pda(&owner).0,
        data: result.instruction_data(proof),
    }
    .instruction();
    let instructions = [
        solana_compute_budget_interface::ComputeBudgetInstruction::set_compute_unit_limit(
            PRIVATE_TX_COMPUTE_UNIT_LIMIT,
        ),
        instruction,
    ];
    let signature = request.rpc.create_and_send_transaction(
        &instructions,
        Address::new_from_array(payer.to_bytes()),
        &[request.payer],
    )?;
    Ok(SubmittedMerge {
        signature,
        output_hash: result.output_hash,
    })
}

fn validate_merge_submission<R: Rpc + ?Sized>(
    rpc: &R,
    owner: Pubkey,
    nullifier_key: &NullifierKey,
    prepared: &PreparedMerge,
) -> Result<(), ClientError> {
    let record = fetch_user_record_checked(rpc, owner)?;
    if !record.merging_enabled {
        return Err(ClientError::MergeDisabled { owner });
    }
    // On-chain merge validation reads the record's base viewing key. An active
    // sync delegate changes only the sender-facing projection.
    let address = base_address_from_record(owner, &record)?;
    if prepared.signing_pubkey != address.signing_pubkey {
        return Err(ClientError::SubmissionMismatch(format!(
            "merge signing key does not match owner {owner}'s registry record"
        )));
    }
    if prepared.user_viewing_pk != address.viewing_pubkey {
        return Err(ClientError::SubmissionMismatch(format!(
            "merge viewing key does not match owner {owner}'s registry record"
        )));
    }
    if nullifier_key.pubkey()? != address.nullifier_pubkey {
        return Err(ClientError::SubmissionMismatch(format!(
            "merge nullifier key does not match owner {owner}'s registry record"
        )));
    }
    Ok(())
}

fn spend_proofs<I: Rpc + ?Sized>(
    indexer: &I,
    tree: Pubkey,
    commitments: &[InputCommitment],
) -> Result<Vec<SpendProof>, ClientError> {
    let tree_address = Address::new_from_array(tree.to_bytes());
    let leaves = commitments
        .iter()
        .map(|commitment| commitment.utxo_hash)
        .collect();
    let nullifiers = commitments
        .iter()
        .map(|commitment| commitment.nullifier)
        .collect();
    let state_proofs = indexer.get_merkle_proofs(tree_address, leaves)?.proofs;
    let nullifier_proofs = indexer
        .get_non_inclusion_proofs(tree_address, nullifiers)?
        .proofs;
    if state_proofs.len() != commitments.len() || nullifier_proofs.len() != commitments.len() {
        return Err(ClientError::Rpc(format!(
            "indexer returned incomplete input proofs: expected {}, got {} state and {} nullifier proofs",
            commitments.len(),
            state_proofs.len(),
            nullifier_proofs.len()
        )));
    }

    let mut proofs = Vec::with_capacity(commitments.len());
    for ((commitment, state), nullifier) in
        commitments.iter().zip(state_proofs).zip(nullifier_proofs)
    {
        if state.leaf != commitment.utxo_hash {
            return Err(ClientError::Rpc(format!(
                "indexer returned state proof for input {} with leaf {}, expected {}",
                commitment.index,
                hex::encode(state.leaf),
                hex::encode(commitment.utxo_hash)
            )));
        }
        if state.merkle_context.tree != tree_address {
            return Err(ClientError::Rpc(format!(
                "indexer returned state proof for input {} from tree {}, expected {}",
                commitment.index, state.merkle_context.tree, tree_address
            )));
        }
        if nullifier.leaf != commitment.nullifier {
            return Err(ClientError::Rpc(format!(
                "indexer returned nullifier proof for input {} with leaf {}, expected {}",
                commitment.index,
                hex::encode(nullifier.leaf),
                hex::encode(commitment.nullifier)
            )));
        }
        if nullifier.merkle_context.tree != tree_address {
            return Err(ClientError::Rpc(format!(
                "indexer returned nullifier proof for input {} from tree {}, expected {}",
                commitment.index, nullifier.merkle_context.tree, tree_address
            )));
        }
        proofs.push(SpendProof { state, nullifier });
    }
    Ok(proofs)
}

#[cfg(test)]
mod tests {
    use borsh::to_vec;
    use solana_account::Account;
    use zolana_interface::instruction::{TransactSolWithdrawal, TransactSplWithdrawal};
    use zolana_keypair::ShieldedKeypair;
    use zolana_transaction::instructions::transact::{PublicAmounts, Shape};
    use zolana_transaction::OutputUtxo;
    use zolana_user_registry_interface::{user_registry_program_id, SyncDelegateEntry, UserRecord};

    use crate::rpc::{
        Context, GetMerkleProofsResponse, GetNonInclusionProofsResponse, MerkleContext,
        MerkleProof, NonInclusionProof,
    };

    use super::*;

    struct ProofRpc {
        state: Vec<MerkleProof>,
        nullifier: Vec<NonInclusionProof>,
    }

    struct RegistryRpc {
        address: Address,
        account: Account,
    }

    impl Rpc for ProofRpc {
        fn get_merkle_proofs(
            &self,
            _tree_account: Address,
            _leaves: Vec<[u8; 32]>,
        ) -> Result<GetMerkleProofsResponse, ClientError> {
            Ok(GetMerkleProofsResponse {
                context: Context { slot: 1 },
                proofs: self.state.clone(),
            })
        }

        fn get_non_inclusion_proofs(
            &self,
            _tree_account: Address,
            _leaves: Vec<[u8; 32]>,
        ) -> Result<GetNonInclusionProofsResponse, ClientError> {
            Ok(GetNonInclusionProofsResponse {
                context: Context { slot: 1 },
                proofs: self.nullifier.clone(),
            })
        }
    }

    impl Rpc for RegistryRpc {
        fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
            Ok((address == self.address).then(|| self.account.clone()))
        }
    }

    fn commitment(index: usize, byte: u8) -> InputCommitment {
        InputCommitment {
            index,
            utxo_hash: [byte; 32],
            nullifier: [byte.wrapping_add(10); 32],
        }
    }

    fn state_proof(tree: Address, leaf: [u8; 32]) -> MerkleProof {
        MerkleProof {
            leaf,
            merkle_context: MerkleContext { tree_type: 0, tree },
            path: Vec::new(),
            leaf_index: 0,
            root: [0u8; 32],
            root_seq: 0,
            root_index: 0,
        }
    }

    fn nullifier_proof(tree: Address, leaf: [u8; 32]) -> NonInclusionProof {
        NonInclusionProof {
            leaf,
            merkle_context: MerkleContext { tree_type: 1, tree },
            path: Vec::new(),
            low_element: [0u8; 32],
            low_element_index: 0,
            high_element: [0xff; 32],
            high_element_index: 1,
            root: [0u8; 32],
            root_seq: 0,
            root_index: 0,
        }
    }

    fn proof_rpc(tree: Address, commitments: &[InputCommitment]) -> ProofRpc {
        ProofRpc {
            state: commitments
                .iter()
                .map(|item| state_proof(tree, item.utxo_hash))
                .collect(),
            nullifier: commitments
                .iter()
                .map(|item| nullifier_proof(tree, item.nullifier))
                .collect(),
        }
    }

    fn external_data() -> ExternalData {
        ExternalData {
            instruction_discriminator: 0,
            expiry_unix_ts: 0,
            relayer_fee: 0,
            public_sol_amount: None,
            public_spl_amount: None,
            user_sol_account: Address::default(),
            user_spl_token: Address::default(),
            spl_token_interface: Address::default(),
            data_hash: None,
            zone_data_hash: None,
            tx_viewing_pk: [0u8; 33],
            salt: [0u8; 16],
            output_utxo_hashes: Vec::new(),
            output_ciphertexts: Vec::new(),
        }
    }

    fn signed_transaction(funding: &Keypair, external_data: ExternalData) -> SignedTransaction {
        SignedTransaction {
            inputs: Vec::new(),
            outputs: Vec::new(),
            public_amounts: PublicAmounts {
                sol: [0u8; 32],
                spl: [0u8; 32],
                asset: [0u8; 32],
            },
            external_data,
            payer_pubkey_hash: sha256_be(&funding.pubkey().to_bytes()),
            shape: Shape::new(1, 1),
            p256_owner: None,
        }
    }

    fn assert_submission_mismatch(result: Result<(), ClientError>) {
        assert!(matches!(result, Err(ClientError::SubmissionMismatch(_))));
    }

    fn registry_record(
        owner: Pubkey,
        keypair: &ShieldedKeypair,
        merging_enabled: bool,
    ) -> UserRecord {
        let (_, bump) = user_record_pda(&owner);
        UserRecord {
            owner: owner.to_bytes().into(),
            bump,
            owner_p256: Some(*keypair.signing_pubkey().as_p256().unwrap().as_bytes()),
            nullifier_pubkey: keypair.nullifier_key.pubkey().unwrap(),
            viewing_pubkey: *keypair.viewing_pubkey().as_bytes(),
            sync_delegate: None,
            entries: Vec::new(),
            merging_enabled,
        }
    }

    fn registry_rpc(owner: Pubkey, record: &UserRecord) -> RegistryRpc {
        let (record_address, _) = user_record_pda(&owner);
        let mut data = vec![UserRecord::DISCRIMINATOR];
        data.extend_from_slice(&to_vec(record).expect("serialize registry record"));
        RegistryRpc {
            address: Address::new_from_array(record_address.to_bytes()),
            account: Account {
                lamports: 1,
                data,
                owner: user_registry_program_id(),
                executable: false,
                rent_epoch: 0,
            },
        }
    }

    fn prepared_merge(keypair: &ShieldedKeypair) -> PreparedMerge {
        let mut scalar = [0u8; 32];
        scalar[31] = 1;
        PreparedMerge {
            inputs: Vec::new(),
            output: OutputUtxo {
                owner_address: Some(keypair.shielded_address().unwrap()),
                ..Default::default()
            },
            expiry_unix_ts: u64::MAX,
            signing_pubkey: keypair.signing_pubkey(),
            user_viewing_pk: keypair.viewing_pubkey(),
            tx_viewing_sk: p256::SecretKey::from_slice(&scalar).unwrap(),
        }
    }

    #[test]
    fn private_submission_rejects_another_funding_key() {
        let signed_for = Keypair::new();
        let submitted_by = Keypair::new();
        let signed = signed_transaction(&signed_for, external_data());
        assert_submission_mismatch(validate_private_submission(&signed, &submitted_by, None));
    }

    #[test]
    fn private_submission_rejects_settlement_for_shielded_transfer() {
        let funding = Keypair::new();
        let mut signed = signed_transaction(&funding, external_data());
        let withdrawal = TransactWithdrawal::Sol(TransactSolWithdrawal {
            recipient: Pubkey::new_unique(),
        });

        validate_private_submission(&signed, &funding, None).expect("shielded transfer");
        assert_submission_mismatch(validate_private_submission(
            &signed,
            &funding,
            Some(&withdrawal),
        ));
        signed.external_data.user_spl_token = Address::new_unique();
        assert_submission_mismatch(validate_private_submission(&signed, &funding, None));
    }

    #[test]
    fn private_submission_requires_matching_sol_withdrawal() {
        let funding = Keypair::new();
        let recipient = Pubkey::new_unique();
        let mut external = external_data();
        external.public_sol_amount = Some(-10);
        external.user_sol_account = Address::new_from_array(recipient.to_bytes());
        let signed = signed_transaction(&funding, external);
        let matching = TransactWithdrawal::Sol(TransactSolWithdrawal { recipient });

        validate_private_submission(&signed, &funding, Some(&matching)).expect("matching");
        assert_submission_mismatch(validate_private_submission(&signed, &funding, None));
        let wrong = TransactWithdrawal::Sol(TransactSolWithdrawal {
            recipient: Pubkey::new_unique(),
        });
        assert_submission_mismatch(validate_private_submission(&signed, &funding, Some(&wrong)));
    }

    #[test]
    fn private_submission_requires_canonical_spl_withdrawal() {
        let funding = Keypair::new();
        let user_token_account = Pubkey::new_unique();
        let spl_token_interface = Pubkey::new_unique();
        let mut external = external_data();
        external.public_spl_amount = Some(-10);
        external.user_spl_token = Address::new_from_array(user_token_account.to_bytes());
        external.spl_token_interface = Address::new_from_array(spl_token_interface.to_bytes());
        let signed = signed_transaction(&funding, external);
        let matching = TransactWithdrawal::Spl(TransactSplWithdrawal {
            cpi_authority: Some(pda::shielded_pool_cpi_authority()),
            spl_token_interface,
            recipient: Pubkey::new_unique(),
            user_token_account,
            token_program: Pubkey::new_from_array(SPL_TOKEN_PROGRAM_ID),
        });

        validate_private_submission(&signed, &funding, Some(&matching)).expect("matching");
        let wrong = TransactWithdrawal::Spl(TransactSplWithdrawal {
            cpi_authority: Some(Pubkey::new_unique()),
            ..match matching {
                TransactWithdrawal::Spl(spl) => spl,
                TransactWithdrawal::Sol(_) => unreachable!(),
            }
        });
        assert_submission_mismatch(validate_private_submission(&signed, &funding, Some(&wrong)));
    }

    #[test]
    fn merge_submission_requires_explicit_opt_in() {
        let owner = Pubkey::new_unique();
        let keypair = ShieldedKeypair::new().unwrap();
        let record = registry_record(owner, &keypair, false);
        let rpc = registry_rpc(owner, &record);

        assert!(matches!(
            validate_merge_submission(
                &rpc,
                owner,
                &keypair.nullifier_key,
                &prepared_merge(&keypair)
            ),
            Err(ClientError::MergeDisabled { owner: got }) if got == owner
        ));
    }

    #[test]
    fn merge_submission_uses_base_viewing_key_with_active_delegate() {
        let owner = Pubkey::new_unique();
        let keypair = ShieldedKeypair::new().unwrap();
        let mut record = registry_record(owner, &keypair, true);
        record.sync_delegate = Some([9u8; 32]);
        record.entries.push(SyncDelegateEntry {
            delegate: [9u8; 32],
            sync_pubkey: [8u8; 33],
            viewing_pubkey: [7u8; 33],
            created_at: 0,
        });
        assert_ne!(record.sender_viewing_pubkey(), record.viewing_pubkey);
        let rpc = registry_rpc(owner, &record);

        validate_merge_submission(
            &rpc,
            owner,
            &keypair.nullifier_key,
            &prepared_merge(&keypair),
        )
        .expect("delegate must not replace the owner's base merge identity");
    }

    #[test]
    fn merge_submission_rejects_unregistered_owner_material() {
        let owner = Pubkey::new_unique();
        let registered = ShieldedKeypair::new().unwrap();
        let unrelated = ShieldedKeypair::new().unwrap();
        let record = registry_record(owner, &registered, true);
        let rpc = registry_rpc(owner, &record);

        let mut wrong_signing = prepared_merge(&registered);
        wrong_signing.signing_pubkey = unrelated.signing_pubkey();
        assert_submission_mismatch(validate_merge_submission(
            &rpc,
            owner,
            &registered.nullifier_key,
            &wrong_signing,
        ));

        let mut wrong_viewing = prepared_merge(&registered);
        wrong_viewing.user_viewing_pk = unrelated.viewing_pubkey();
        assert_submission_mismatch(validate_merge_submission(
            &rpc,
            owner,
            &registered.nullifier_key,
            &wrong_viewing,
        ));

        assert_submission_mismatch(validate_merge_submission(
            &rpc,
            owner,
            &unrelated.nullifier_key,
            &prepared_merge(&registered),
        ));
    }

    #[test]
    fn spend_proofs_validate_order_and_tree() {
        let tree = Pubkey::new_unique();
        let tree_address = Address::new_from_array(tree.to_bytes());
        let commitments = [commitment(2, 1), commitment(5, 2)];
        let rpc = proof_rpc(tree_address, &commitments);
        let proofs = spend_proofs(&rpc, tree, &commitments).expect("matching proofs");
        assert_eq!(proofs.len(), 2);

        let mut reordered_state = proof_rpc(tree_address, &commitments);
        reordered_state.state.swap(0, 1);
        assert!(spend_proofs(&reordered_state, tree, &commitments).is_err());

        let mut reordered_nullifier = proof_rpc(tree_address, &commitments);
        reordered_nullifier.nullifier.swap(0, 1);
        assert!(spend_proofs(&reordered_nullifier, tree, &commitments).is_err());

        let mut wrong_state_tree = proof_rpc(tree_address, &commitments[..1]);
        wrong_state_tree.state[0].merkle_context.tree = Address::new_unique();
        assert!(spend_proofs(&wrong_state_tree, tree, &commitments[..1]).is_err());

        let mut wrong_nullifier_tree = proof_rpc(tree_address, &commitments[..1]);
        wrong_nullifier_tree.nullifier[0].merkle_context.tree = Address::new_unique();
        assert!(spend_proofs(&wrong_nullifier_tree, tree, &commitments[..1]).is_err());
    }
}
