use p256::{
    ecdsa::Signature,
    elliptic_curve::{scalar::IsHigh, sec1::ToEncodedPoint},
};
use zolana_keypair::P256Pubkey;

pub const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

pub fn spki_from_p256(pubkey: &P256Pubkey) -> Vec<u8> {
    let point = pubkey
        .to_p256()
        .expect("valid P-256 pubkey")
        .to_encoded_point(false);
    let mut spki = P256_SPKI_PREFIX.to_vec();
    spki.extend_from_slice(point.as_bytes());
    spki
}

pub fn p256_from_spki(spki: &[u8]) -> P256Pubkey {
    let point = spki
        .strip_prefix(P256_SPKI_PREFIX.as_slice())
        .expect("P-256 SPKI prefix");
    let pubkey = p256::PublicKey::from_sec1_bytes(point).expect("uncompressed P-256 point");
    P256Pubkey::from_p256(&pubkey)
}

pub fn compact_low_s_from_der(der: &[u8]) -> [u8; 64] {
    let signature = Signature::from_der(der).expect("DER ECDSA signature");
    let signature = signature.normalize_s().unwrap_or(signature);
    signature.to_bytes().into()
}

pub fn der_from_compact_high_s(compact: &[u8; 64]) -> Vec<u8> {
    let signature = Signature::from_slice(compact).expect("compact ECDSA signature");
    let s = *signature.s();
    let high_s = if s.is_high().into() { s } else { -s };
    let high = Signature::from_scalars(*signature.r(), high_s).expect("nonzero scalars");
    high.to_der().as_bytes().to_vec()
}
