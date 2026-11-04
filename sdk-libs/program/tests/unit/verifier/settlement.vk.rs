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

#[rustfmt::skip]
pub const VERIFYINGKEY_VK_SHA256: [u8; 32] = [85, 113, 0, 82, 138, 249, 81, 181, 100, 154, 187, 246, 119, 231, 20, 64, 107, 192, 139, 84, 25, 188, 158, 8, 112, 69, 127, 21, 109, 221, 164, 46];

#[allow(dead_code)]
pub const VERIFYINGKEY_INSECURE_TEST_SETUP: bool = false;

#[unsafe(export_name = "groth16_solana_vk_setup_5e771e0e7f1c0000")]
#[rustfmt::skip]
pub static VERIFYINGKEY_SETUP_TXT: &str = "=======BEGIN GROTH16 VK SETUP V2=======\x00name\x00VERIFYINGKEY\x00insecure_test_setup\x00false\x00vk_sha256\x00557100528af951b5649abbf677e714406bc08b5419bc9e0870457f156ddda42e\x00=======END GROTH16 VK SETUP V2=======\x00";
