pub const PUBLIC_KEY_LEN: usize = 34;

pub const P256_PUBKEY_LEN: usize = 33;

pub const BLINDING_LEN: usize = 31;

pub(crate) const ED25519_PUBKEY_LEN: usize = 32;

pub(crate) const CTR_NONCE_LEN: usize = 12;

pub const SALT_LEN: usize = 16;

pub const DST_VIEW_ROOT_P_CONST: &[u8] = b"TSPP/view_root/P_const/v1";

pub const P_CONST_SEC1: [u8; P256_PUBKEY_LEN] = [
    0x03, 0x0e, 0x4d, 0xf9, 0x46, 0xbc, 0xe1, 0x4b, 0x95, 0x29, 0x2f, 0x13, 0xe1, 0x33, 0xd2, 0xb0,
    0xc6, 0x4e, 0x89, 0x8b, 0x56, 0x44, 0xf6, 0x20, 0xa5, 0xbe, 0xd2, 0x5a, 0x06, 0x1a, 0x42, 0xfc,
    0xdb,
];

pub(crate) const INFO_NULLIFIER: &[u8] = b"TSPP/nullifier";

/// BIP-44 coin type for TSPP shielded keys:
/// `SHA-256("luminous.TSPP.v1")[0..4]` as a big-endian `u32`, masked to
/// 31 bits. A provenance test locks the value to this formula so it cannot
/// drift, but the coin type is still a placeholder: it is not finalized or
/// SLIP-0044-registered. Changing it re-derives every identity, so identities
/// derived under it are disposable until it is finalized for production.
pub const TSPP_COIN_TYPE: u32 = 1_392_955_331;

/// `wallet_seed` length in bytes, matching a BIP-39 seed.
pub const WALLET_SEED_LEN: usize = 64;

pub(crate) const INFO_WALLET_SEED: &[u8] = b"TSPP/wallet_seed";

pub(crate) const INFO_SENDER_VIEW_TAG_SECRET: &[u8] = b"TSPP/sender_view_tag";

pub(crate) const INFO_RECIPIENT_VIEW_TAG_SECRET: &[u8] = b"TSPP/recipient_view_tag";

pub(crate) const INFO_MERGE_VIEW_TAG_SECRET: &[u8] = b"TSPP/merge_view_tag";

pub(crate) const INFO_TX_VIEWING: &[u8] = b"TSPP/tx_viewing";

pub(crate) const INFO_SENDER_VIEW_TAG_PREFIX: &[u8] = b"TSPP/sender_view_tag/";

pub(crate) const INFO_RECIPIENT_REQUEST_VIEW_TAG_PREFIX: &[u8] =
    b"TSPP/recipient_request_view_tag/";

pub(crate) const INFO_MERGE_VIEW_TAG_PREFIX: &[u8] = b"TSPP/merge_view_tag/";

pub(crate) const INFO_PAIR_DOMAIN_PREFIX: &[u8] = b"TSPP/pair-domain/";

pub(crate) const INFO_PAIR_HINT_PREFIX: &[u8] = b"TSPP/pair-hint/";

pub const VIEW_TAG_LEN: usize = 32;

pub(crate) const HPKE_PREFIX: &[u8] = b"TSPP/hpke/";

pub(crate) const ENC_INFO_TRANSFER: &[u8] = b"TSPP/tx";
