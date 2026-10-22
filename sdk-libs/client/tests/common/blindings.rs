use zolana_transaction::{
    utxo::{derive_output_blinding_seed, OutputSlotBlinding},
    SppProofOutputUtxo,
};

pub fn assign_output_blindings(
    first_nullifier: &[u8; 32],
    outputs: &mut [SppProofOutputUtxo],
    seed: &[u8; 32],
) {
    let seed = derive_output_blinding_seed(first_nullifier, seed).expect("output seed");
    for (index, output) in outputs.iter_mut().enumerate() {
        output.blinding = OutputSlotBlinding {
            output,
            first_nullifier,
            output_blinding_seed: &seed,
            slot_index: u32::try_from(index).expect("slot index"),
        }
        .derive()
        .expect("output blinding");
    }
}
