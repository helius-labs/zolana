use zolana_transaction::{
    utxo::{derive_output_blinding_seed, derive_transact_output_blinding},
    SppProofOutputUtxo,
};

pub fn assign_output_blindings(
    first_nullifier: &[u8; 32],
    outputs: &mut [SppProofOutputUtxo],
    seed: &[u8; 32],
) {
    let seed = derive_output_blinding_seed(first_nullifier, seed).expect("output seed");
    for (index, output) in outputs.iter_mut().enumerate() {
        output.blinding = derive_transact_output_blinding(
            first_nullifier,
            &seed,
            u32::try_from(index).expect("slot index"),
        )
        .expect("output blinding");
    }
}
