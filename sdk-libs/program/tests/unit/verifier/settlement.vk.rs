use groth16_solana::groth16::Groth16Verifyingkey;

static VERIFYINGKEY_VK_IC: &[[u8; 64]] = &[[0u8; 64], [0u8; 64]];

pub const VERIFYINGKEY: Groth16Verifyingkey = Groth16Verifyingkey {
    nr_pubinputs: 1,
    vk_alpha_g1: [0u8; 64],
    vk_beta_g2: [0u8; 128],
    vk_gamma_g2: [0u8; 128],
    vk_delta_g2: [0u8; 128],
    vk_ic: VERIFYINGKEY_VK_IC,
    vk_commitment: None,
};

#[allow(dead_code)]
#[rustfmt::skip]
pub const VERIFYINGKEY_PROVING_KEY_SHA256: [u8; 32] = [0u8; 32];

#[allow(dead_code)]
pub const VERIFYINGKEY_INSECURE_TEST_SETUP: bool = false;

#[unsafe(export_name = "groth16_solana_vk_setup_5e771e0e7f1c0000")]
#[rustfmt::skip]
pub static VERIFYINGKEY_SETUP_TXT: &str = "=======BEGIN GROTH16 VK SETUP V1=======\x00name\x00VERIFYINGKEY\x00insecure_test_setup\x00false\x00proving_key_sha256\x000000000000000000000000000000000000000000000000000000000000000000\x00=======END GROTH16 VK SETUP V1=======\x00";
