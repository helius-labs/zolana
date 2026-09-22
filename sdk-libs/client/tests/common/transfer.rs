use zolana_client::{NonInclusionProof, SpendProof, TransferInputUtxo, TransferProver};
use zolana_transaction::instructions::transact::SppProofInputs;

pub fn transfer_prover(
    tx: SppProofInputs,
    proofs: &[SpendProof],
    dummy: &[NonInclusionProof],
) -> TransferProver {
    let shape = tx.check_shape().expect("shape");
    let signer_pk_hashes = tx.signer_pk_hashes(shape.signer_width()).expect("signers");
    let public_transfers = tx.public_transfers().expect("public transfers");
    let mut proofs = proofs.iter();
    let mut dummy = dummy.iter();
    let inputs = tx
        .input_utxos
        .into_iter()
        .map(|utxo| {
            let (proof, nullifier_proof) = if utxo.is_dummy() {
                (None, Some(dummy.next().expect("dummy proof").clone()))
            } else {
                (Some(proofs.next().expect("spend proof").clone()), None)
            };
            TransferInputUtxo {
                utxo,
                proof,
                nullifier_proof,
            }
        })
        .collect();
    assert!(proofs.next().is_none());
    assert!(dummy.next().is_none());
    TransferProver {
        inputs,
        outputs: tx.output_utxos,
        blinding_seed: tx.blinding_seed,
        output_tree_id: tx.output_tree_id,
        external_data: tx.external_data,
        public_transfers,
        signer_pk_hashes,
        allow_dummy_inputs: true,
        shape,
    }
}
