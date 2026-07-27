//! Pack a standard Groth16 VK for the compose hub `foreign_vk` account.
//! Layout matches `zolana_groth16_batch::pack_solana_vk` (no Pedersen).

use groth16_solana::groth16::Groth16Verifyingkey;

pub fn pack_standard_vk(vk: &Groth16Verifyingkey<'_>) -> Vec<u8> {
    assert!(
        vk.vk_commitment.is_none(),
        "batch compose packs standard VKs only"
    );
    let mut out = Vec::with_capacity(64 + 128 * 3 + 2 + vk.vk_ic.len() * 64);
    out.extend_from_slice(&vk.vk_alpha_g1);
    out.extend_from_slice(&vk.vk_beta_g2);
    out.extend_from_slice(&vk.vk_gamma_g2);
    out.extend_from_slice(&vk.vk_delta_g2);
    out.extend_from_slice(&(vk.vk_ic.len() as u16).to_le_bytes());
    for ic in vk.vk_ic {
        out.extend_from_slice(ic);
    }
    out
}
