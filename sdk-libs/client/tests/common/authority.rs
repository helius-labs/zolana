use zolana_keypair::NullifierKey;

pub fn complete_inputs(inputs: &mut [zolana_client::TransferInput], keys: &[NullifierKey]) {
    use zolana_client::ProofAuthority;
    for input in inputs {
        if input.nullifier_secret.is_some() {
            continue;
        }
        let hash = input.utxo.hash().unwrap();
        let key = keys
            .iter()
            .find(|key| {
                let nullifier = key.nullifier(&hash, &input.utxo.blinding).unwrap();
                num_bigint::BigUint::from_bytes_be(&nullifier) == input.nullifier
            })
            .expect("owner key for input");
        key.complete_inputs(std::slice::from_mut(input))
            .expect("complete owned input");
    }
}
